import type { ReputationObservation } from '@phishlens/shared';
import type { Analyzer } from '../types.js';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { subject } from '../../engine/subjects.js';
import { primaryDomains, registrableOf } from '../../engine/signals.js';
import { sourceKey } from '../../services/reputation/providers.js';
import { networkTargets } from '../targets.js';

const MAX_REPUTATION_DOMAINS = 3;

/**
 * Turns provider observations into indicators. The asymmetry is deliberate:
 * a listing is evidence of risk, but the absence of a listing is not evidence
 * of safety (most new phishing infrastructure is not yet listed), so "not
 * listed" is neutral. Errors, timeouts and stale data are unknown.
 */
export function reputationIndicators(observations: ReputationObservation[]): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const byDomain = new Map<string, ReputationObservation[]>();
  for (const o of observations) byDomain.set(o.subject, [...(byDomain.get(o.subject) ?? []), o]);

  for (const [domain, obs] of byDomain) {
    const subj = subject.domain(domain);
    const src = (o: ReputationObservation) => `${o.providerName}${o.cached ? ` (cached result from ${o.fetchedAt.slice(0, 16)}Z)` : ''}`;
    const base = (o: ReputationObservation) => ({ subject: subj, source: src(o), provenance: 'external' as const, category: 'REPUTATION' as const });
    const dated = (o: ReputationObservation) => (o.dataDate ? ` · provider data ${o.dataDate.slice(0, 10)}` : '');

    for (const o of obs) {
      switch (o.status) {
        case 'listed':
          out.push({
            ...base(o),
            code: 'REPUTATION_LISTED',
            title: `Listed as malicious by ${o.providerName}`,
            description: `${o.providerName} currently lists ${domain} as malicious. A curated listing is strong evidence; listings can lag behind clean-ups and occasionally be wrong, so check the provider reference.`,
            severity: 'high',
            confidence: o.provider === 'virustotal' ? 0.75 : 0.85,
            evidence: `${o.summary}${dated(o)}${o.reference ? ` · ${o.reference}` : ''}`,
          });
          break;
        case 'historical':
          out.push({
            ...base(o),
            code: 'REPUTATION_HISTORICAL',
            title: `Past abuse recorded by ${o.providerName}`,
            description: 'The provider recorded malicious content on this host in the past, none of it currently active. Often a compromised legitimate site that was cleaned up; it may be reused.',
            severity: 'medium',
            confidence: 0.5,
            evidence: `${o.summary}${dated(o)}`,
          });
          break;
        case 'minority':
          out.push({
            ...base(o),
            code: 'REPUTATION_MINORITY_DETECTION',
            title: `Isolated detections on ${o.providerName}`,
            description: 'A small number of engines flag the domain while the majority do not. Isolated detections are a common false-positive pattern; weak evidence that only matters alongside other findings.',
            severity: 'low',
            confidence: 0.3,
            evidence: `${o.summary}${dated(o)}`,
          });
          break;
        case 'popular':
          out.push({
            ...base(o),
            code: 'REPUTATION_POPULAR',
            title: `Sustained popularity (${o.providerName})`,
            description:
              'The domain has ranked among the most-visited sites on most days of the last month in a research-grade ranking that aggregates several traffic sources. Throwaway phishing domains do not accumulate sustained traffic. Popularity is not safety — popular sites get compromised — so it only corroborates.',
            severity: 'info',
            confidence: 0.6,
            polarity: 'benign',
            evidence: `${o.summary}${dated(o)}`,
          });
          break;
        case 'stale':
          if (o.details.lastKnownStatus === 'listed') {
            out.push({
              ...base(o),
              code: 'REPUTATION_LISTED_STALE',
              title: `Previously listed by ${o.providerName} (current status unknown)`,
              description: 'The last successful lookup found a listing, but the live lookup failed. The listing may since have been removed; treated as moderate risk until re-checked.',
              severity: 'medium',
              confidence: 0.5,
              evidence: o.summary,
            });
          } else {
            out.push({ ...base(o), code: 'REPUTATION_UNKNOWN', title: `${o.providerName}: only stale data available`, description: 'Outdated reputation data is neither positive nor negative evidence.', severity: 'info', confidence: 1, polarity: 'unknown', evidence: o.summary });
          }
          break;
        case 'error':
        case 'unavailable':
          out.push({
            ...base(o),
            code: 'REPUTATION_UNKNOWN',
            title: `${o.providerName}: no result`,
            description: 'The lookup did not complete. This is not a clean result; the check simply did not happen.',
            severity: 'info',
            confidence: 1,
            polarity: 'unknown',
            evidence: `${domain}: ${o.summary}`,
          });
          break;
        default:
          break;
      }
    }

    const quiet = obs.filter((o) => o.status === 'not_listed' || o.status === 'not_popular');
    if (quiet.length) {
      out.push({
        subject: subj,
        source: quiet.map((o) => o.providerName).join(', '),
        provenance: 'external',
        category: 'REPUTATION',
        code: 'REPUTATION_NO_LISTING',
        title: `No reputation listing for ${domain}`,
        description: 'None of these providers lists or ranks the domain. Absence of a listing is not evidence of safety: most phishing infrastructure is unlisted when first used.',
        severity: 'info',
        confidence: 1,
        polarity: 'neutral',
        evidence: quiet.map((o) => `${o.providerName}: ${o.summary}`).join(' · '),
      });
    }

    // Independent corroboration: VirusTotal aggregates other feeds, so it only adds
    // independence when its flagging engines include a source no direct provider listed.
    const listed = obs.filter((o) => o.status === 'listed');
    const direct = listed.filter((o) => o.provider !== 'virustotal');
    const directKeys = new Set(direct.flatMap((o) => o.underlyingSources.map(sourceKey)));
    const independent = [...direct.map((o) => o.providerName)];
    const vt = listed.find((o) => o.provider === 'virustotal');
    if (vt && vt.underlyingSources.some((s) => !directKeys.has(sourceKey(s)))) independent.push(vt.providerName);
    if (independent.length >= 2) {
      out.push({
        subject: subj,
        source: independent.join(' + '),
        provenance: 'external',
        category: 'CORRELATION',
        code: 'REPUTATION_CORROBORATED_MALICIOUS',
        title: `Malicious listing confirmed by ${independent.length} independent providers`,
        description: 'Separate threat-intelligence providers with different data sources list this domain. Aggregated results that merely repeat another provider’s data are not counted as independent.',
        severity: 'critical',
        confidence: 0.9,
        evidence: listed.map((o) => `${o.providerName}: ${o.summary}`).join(' · '),
      });
    }
  }
  return out;
}

export const reputationAnalyzer: Analyzer = {
  id: 'reputation',
  label: 'Checking domain reputation',
  dependsOn: ['domain', 'redirects'],
  applies: (ctx) => ctx.state.domains.some((d) => !d.isIp),
  async run(ctx) {
    const svc = ctx.services.reputation;
    if (!svc?.enabled) {
      return { status: 'unavailable', reason: 'No reputation provider configured (GSB_API_KEY, URLHAUS_AUTH_KEY, VIRUSTOTAL_API_KEY or TRANCO_ENABLED). Reputation was not checked; this is not a clean result.' };
    }
    if (!ctx.settings.network.probesEnabled) return { status: 'unavailable', reason: 'Network probing is disabled; reputation providers were not queried.' };

    // Primary subjects first (they decide positive evidence), then other referenced domains (risk only).
    const primary = [...primaryDomains(ctx.state)];
    const others = networkTargets(ctx).map((t) => t.registrableDomain).filter((d): d is string => !!d);
    const finals = ctx.state.redirects.map((r) => (r.finalUrl ? registrableOf(r.finalUrl) : null)).filter((d): d is string => !!d);
    const domains = [...new Set([...primary, ...finals, ...others])].slice(0, MAX_REPUTATION_DOMAINS);
    const targets = domains.map((domain) => ({
      domain,
      urls: ctx.state.urls.filter((u) => u.valid && u.normalized && u.registrableDomain === domain).map((u) => u.normalized!).slice(0, 10),
    }));

    const observations = await svc.lookup(targets);
    ctx.state.reputation = [...(ctx.state.reputation ?? []), ...observations];
    for (const d of reputationIndicators(observations)) ctx.emit(d);

    const answered = observations.filter((o) => !['error', 'unavailable', 'stale'].includes(o.status));
    if (answered.length === 0) return { status: 'failed', reason: observations.map((o) => `${o.providerName}: ${o.summary}`).join('; ') };
    const missing = observations.length - answered.length;
    return {
      status: 'completed',
      detail: `${answered.length}/${observations.length} lookups answered for ${domains.join(', ')}${missing ? ` (${missing} unavailable or stale)` : ''}`,
    };
  },
};
