import { domainToUnicode } from 'node:url';
import type { DomainAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import type { ReferenceLists } from '../../config/lists.js';
import { subject } from '../../engine/subjects.js';
import { isMixedScript } from './confusables.js';

const COMMON_TLDS = new Set(['com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'co', 'io', 'info', 'biz', 'us', 'uk', 'de', 'fr', 'in', 'ru', 'cn', 'jp', 'br', 'au', 'ca']);

/**
 * Structural hostname heuristics. Brand matches must already be populated on `d`.
 * Pure function: no network access.
 */
export function domainHeuristics(d: DomainAnalysis, lists: ReferenceLists): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  if (d.isIp) return out;
  const base = {
    source: `Hostname ${d.hostname} (${d.sources.join(', ') || 'input'})`,
    provenance: 'analysis' as const,
    subject: subject.host(d.hostname),
  };
  // Use the displayed (Unicode) form so punycode's "xn--" prefix is not counted as hyphens.
  const label = d.registrableDomain ? (domainToUnicode(d.registrableDomain) || d.registrableDomain).split('.')[0] ?? '' : '';
  const display = d.hostnameUnicode !== d.hostname ? `${d.hostname} (displays as ${d.hostnameUnicode})` : d.hostname;

  // --- Brand lookalike heuristics -----------------------------------------
  for (const m of d.brandMatches) {
    switch (m.technique) {
      case 'official':
        out.push({
          ...base,
          code: 'DOMAIN_OFFICIAL_BRAND',
          category: 'LOOKALIKE',
          title: `Official ${m.brand} domain`,
          description:
            `${d.registrableDomain} is listed as an official ${m.brand} domain in the brand watchlist. This rules out a lookalike domain, ` +
            'but not a compromised account, an open redirect or user-hosted content on that domain.',
          severity: 'info',
          confidence: 0.8,
          polarity: 'benign',
          evidence: m.detail,
        });
        break;
      case 'official-domain-as-subdomain':
        out.push({
          ...base,
          code: 'LOOKALIKE_OFFICIAL_AS_SUBDOMAIN',
          category: 'LOOKALIKE',
          title: `${m.brand} domain used as a subdomain of an unrelated domain`,
          description:
            'Readers tend to scan a hostname from the left and stop at a familiar name. The organisation that controls this host is the registered domain on the right, not the brand on the left. (Brand heuristic.)',
          severity: 'high',
          confidence: 0.8,
          evidence: `${display}: ${m.detail}`,
        });
        break;
      case 'homoglyph':
        out.push({
          ...base,
          code: 'LOOKALIKE_HOMOGLYPH',
          category: 'LOOKALIKE',
          title: `Hostname visually imitates ${m.brand}`,
          description:
            'The domain uses characters that look like the brand name but are different characters (digit substitution or letters from another script). ' +
            'There is rarely a legitimate reason for a third party to register this. (Brand heuristic.)',
          severity: 'high',
          confidence: 0.8,
          evidence: `${display}: ${m.detail}`,
        });
        break;
      case 'typosquat':
        out.push({
          ...base,
          code: 'LOOKALIKE_TYPOSQUAT',
          category: 'LOOKALIKE',
          title: `Hostname is a near-miss spelling of ${m.brand}`,
          description:
            'The registered name differs from the brand by one or two character edits. Typo domains are registered to catch mistyped addresses and to pass a quick visual check. ' +
            'Some brands defensively register their own typos, so check ownership if in doubt. (Brand heuristic.)',
          severity: 'high',
          confidence: 0.7,
          evidence: `${display}: ${m.detail}`,
        });
        break;
      case 'tld-swap':
        out.push({
          ...base,
          code: 'LOOKALIKE_TLD_SWAP',
          category: 'LOOKALIKE',
          title: `${m.brand} name on an unlisted domain suffix`,
          description:
            'The registered label is exactly the brand name, but the suffix is not in the configured official list. The brand may legitimately own it (country domains are common), ' +
            'so verify ownership before relying on this. (Brand heuristic.)',
          severity: 'medium',
          confidence: 0.45,
          evidence: `${display}: ${m.detail}`,
        });
        break;
      case 'keyword':
        out.push({
          ...base,
          code: 'LOOKALIKE_BRAND_KEYWORD',
          category: 'LOOKALIKE',
          title: `${m.brand} name used in an unrelated domain`,
          description:
            'The brand name is combined with other words or placed in a subdomain of a domain the brand does not operate. Resellers, fan sites and news sites do this too, ' +
            'so the weight depends on what the page or message asks the user to do. (Brand heuristic.)',
          severity: 'medium',
          confidence: 0.55,
          evidence: `${display}: ${m.detail}`,
        });
        break;
    }
  }

  // --- IDN / punycode -------------------------------------------------------
  if (d.isPunycode) {
    const mixedLabel = d.hostnameUnicode.split('.').find((l) => isMixedScript(l));
    const homoglyphFound = d.brandMatches.some((m) => m.technique === 'homoglyph');
    if (mixedLabel && !homoglyphFound) {
      out.push({
        ...base,
        code: 'DOMAIN_MIXED_SCRIPT_IDN',
        category: 'DOMAIN',
        title: 'Internationalised hostname mixes writing systems',
        description:
          `The label "${mixedLabel}" combines characters from ${d.scripts.join(' and ')}. Mixing scripts in one label is the basis of homograph attacks, where a domain renders like a familiar one. ` +
          'Browsers apply similar rules when deciding whether to show punycode instead.',
        severity: 'high',
        confidence: 0.7,
        evidence: `${d.hostname} → ${d.hostnameUnicode}`,
      });
    } else if (!homoglyphFound) {
      out.push({
        ...base,
        code: 'DOMAIN_IDN',
        category: 'DOMAIN',
        title: 'Internationalised (punycode) hostname',
        description: `The hostname is encoded as punycode and displays in ${d.scripts.join(', ') || 'non-ASCII'} script. IDNs are normal for non-English names; recorded so the displayed and encoded forms can be compared.`,
        severity: 'info',
        confidence: 1,
        evidence: `${d.hostname} → ${d.hostnameUnicode}`,
      });
    }
  }

  // --- Structure ------------------------------------------------------------
  // A subdomain that itself looks like a domain name (but not a configured brand, handled above).
  const subLabels = (d.subdomain ?? '').split('.');
  const domainLikeAt = subLabels.findIndex((l, i) => i > 0 && COMMON_TLDS.has(l) && subLabels[i - 1]!.length > 1);
  if (domainLikeAt > 0 && !d.brandMatches.some((m) => m.technique === 'official-domain-as-subdomain')) {
    const imitated = `${subLabels[domainLikeAt - 1]}.${subLabels[domainLikeAt]}`;
    out.push({
      ...base,
      code: 'DOMAIN_DOMAIN_LIKE_SUBDOMAIN',
      category: 'DOMAIN',
      title: 'Subdomain is formatted like a separate domain',
      description: `The subdomain contains "${imitated}", which reads like a complete domain name, while the host actually belongs to ${d.registrableDomain}. This pattern is used to borrow the credibility of another name.`,
      severity: 'medium',
      confidence: 0.6,
      evidence: d.hostname,
    });
  }

  const sharedPlatform = lists.sharedHostingSuffixes.find((s) => d.hostname === s || d.hostname.endsWith(`.${s}`));
  if (d.subdomainDepth >= 4 && !sharedPlatform) {
    out.push({
      ...base,
      code: 'DOMAIN_DEEP_SUBDOMAIN',
      category: 'DOMAIN',
      title: `Deep subdomain nesting (${d.subdomainDepth} levels)`,
      description: 'Many subdomain levels push the registered domain far to the right, where it may be truncated on mobile screens. CDNs and cloud services also use deep names, so this is weak evidence.',
      severity: 'low',
      confidence: 0.35,
      evidence: d.hostname,
    });
  }

  if (d.hostname.length > 60) {
    out.push({
      ...base,
      code: 'DOMAIN_LONG_HOSTNAME',
      category: 'DOMAIN',
      title: `Unusually long hostname (${d.hostname.length} characters)`,
      description: 'Long hostnames are hard to read in full and can hide the registered domain. Weak evidence on its own.',
      severity: 'low',
      confidence: 0.3,
      evidence: d.hostname,
    });
  }

  const hyphens = (label.match(/-/g) ?? []).length;
  if (hyphens >= 3) {
    out.push({
      ...base,
      code: 'DOMAIN_MANY_HYPHENS',
      category: 'DOMAIN',
      title: `Registered name contains ${hyphens} hyphens`,
      description: 'Names like "secure-account-verify-login" chain reassuring words together. Common in throwaway phishing domains, but also in legitimate descriptive names.',
      severity: 'low',
      confidence: 0.35,
      evidence: d.registrableDomain ?? d.hostname,
    });
  }

  const digits = (label.match(/\d/g) ?? []).length;
  if (label.length >= 4 && (digits / label.length >= 0.5 || /\d{5,}/.test(label))) {
    out.push({
      ...base,
      code: 'DOMAIN_NUMERIC',
      category: 'DOMAIN',
      title: 'Registered name is mostly numeric',
      description: 'Numeric names are typical of bulk-registered or algorithmically generated domains, though some legitimate brands use numbers.',
      severity: 'low',
      confidence: 0.3,
      evidence: d.registrableDomain ?? d.hostname,
    });
  }

  if (d.tld && lists.elevatedAbuseTlds.includes(d.tld)) {
    out.push({
      ...base,
      code: 'DOMAIN_ELEVATED_ABUSE_TLD',
      category: 'DOMAIN',
      title: `Top-level domain .${d.tld} is on the elevated-abuse list`,
      description:
        `.${d.tld} is in the configured list of TLDs that appear disproportionately in abuse reporting, usually because registrations are cheap. ` +
        'Most domains under it are not malicious; this only adds weight to other evidence.',
      severity: 'low',
      confidence: 0.3,
      evidence: d.hostname,
    });
  }

  if (sharedPlatform || d.isPrivateSuffix) {
    out.push({
      ...base,
      code: 'DOMAIN_SHARED_HOSTING',
      category: 'DOMAIN',
      title: `Hosted on a shared platform (${sharedPlatform ?? d.publicSuffix})`,
      description:
        'Anyone can publish content under this platform domain, so its reputation says nothing about this specific page. Free hosting platforms are frequently used for phishing pages and also for legitimate sites.',
      severity: 'low',
      confidence: 0.35,
      evidence: d.hostname,
    });
  }

  return out;
}
