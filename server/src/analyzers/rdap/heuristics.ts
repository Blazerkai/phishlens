import type { RdapAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { subject } from '../../engine/subjects.js';

export function rdapHeuristics(r: RdapAnalysis): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  if (r.status !== 'completed') return out;
  const base = { source: r.source, provenance: 'external' as const, subject: subject.rdap(r.domain) };
  const age = r.ageDays;

  if (age !== null && age !== undefined) {
    if (age < 30) {
      out.push({
        ...base,
        code: 'RDAP_NEWLY_REGISTERED',
        category: 'DOMAIN_REGISTRATION',
        title: `Domain registered ${age} day(s) ago`,
        description:
          'Phishing domains are typically used within days of registration and abandoned quickly. A very young domain is a strong signal when combined with impersonation or credential requests; new legitimate businesses and campaigns also register domains.',
        severity: age < 7 ? 'high' : 'medium',
        confidence: age < 7 ? 0.7 : 0.6,
        evidence: `${r.domain} registration date ${r.registered}`,
      });
    } else if (age < 90) {
      out.push({
        ...base,
        code: 'RDAP_RECENTLY_REGISTERED',
        category: 'DOMAIN_REGISTRATION',
        title: `Domain registered ${age} days ago`,
        description: 'The domain is under three months old. Weak evidence on its own.',
        severity: 'low',
        confidence: 0.4,
        evidence: `${r.domain} registration date ${r.registered}`,
      });
    } else if (age <= 730) {
      out.push({
        ...base,
        code: 'RDAP_REGISTRATION_AGE',
        category: 'DOMAIN_REGISTRATION',
        title: `Domain registered ${age} days ago`,
        description: 'Registration context only. Between three months and two years old: neither the very young age typical of throwaway phishing domains nor long-established. Not counted as positive or negative evidence.',
        severity: 'info',
        confidence: 1,
        polarity: 'neutral',
        evidence: `${r.domain} registration date ${r.registered}`,
      });
    } else {
      out.push({
        ...base,
        code: 'RDAP_ESTABLISHED',
        category: 'DOMAIN_REGISTRATION',
        title: `Domain registered ${Math.floor(age / 365)} years ago`,
        description: 'Long-lived domains are less likely to be throwaway phishing infrastructure. Compromised legitimate sites are also used to host phishing, so this does not clear a URL on its own.',
        severity: 'info',
        confidence: 0.4,
        polarity: 'benign',
        evidence: `${r.domain} registration date ${r.registered}`,
      });
    }
  }

  const hold = r.statuses?.find((s) => /hold/i.test(s));
  if (hold) {
    out.push({
      ...base,
      code: 'RDAP_ON_HOLD',
      category: 'DOMAIN_REGISTRATION',
      title: `Domain status "${hold}"`,
      description: 'A hold status removes the domain from DNS. Registries and registrars apply it for non-payment, disputes, or abuse takedowns.',
      severity: 'low',
      confidence: 0.4,
      evidence: `${r.domain} status: ${r.statuses!.join(', ')}`,
    });
  }

  if (r.registrar) {
    out.push({
      ...base,
      code: 'RDAP_REGISTRAR',
      category: 'DOMAIN_REGISTRATION',
      title: `Registrar: ${r.registrar}`,
      description: 'Context only. Registrar choice is not evidence of intent.',
      severity: 'info',
      confidence: 1,
      polarity: 'neutral',
      evidence: `${r.domain} registrar ${r.registrar}`,
    });
  }
  return out;
}
