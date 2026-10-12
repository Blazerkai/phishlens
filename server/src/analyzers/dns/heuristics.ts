import type { DnsAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { subject } from '../../engine/subjects.js';
import { classifyIp } from '../../security/ip.js';
import type { TargetRole } from '../targets.js';
import { isNullMx, PARKING_NS, parseSpfRecords } from './records.js';

const values = (d: DnsAnalysis, type: string) => d.records.find((r) => r.type === type)?.values ?? [];
const status = (d: DnsAnalysis, type: string) => d.records.find((r) => r.type === type)?.status;

/**
 * Turns collected DNS observations into indicators. `roles` says why the name
 * was looked up, because the same observation means different things for a
 * sender domain and for a link target.
 */
export function dnsHeuristics(d: DnsAnalysis, roles: Set<TargetRole>, assessMailPosture: boolean): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const base = { source: d.resolver, provenance: 'network' as const, subject: subject.dns(d.name) };
  // A domain only "is a sender" for NXDOMAIN purposes when it is the exact domain used in an address.
  const isSender = assessMailPosture;
  const roleText = [...roles].join(', ');
  // Which mail checks apply depends on the header the domain came from:
  //   MX    – domains that should receive replies (From, Reply-To, submitted address)
  //   SPF   – the envelope domain (Return-Path), or From when no envelope domain is known
  //   DMARC – the visible From domain (or a submitted address)
  const checkMx = roles.has('sender') || roles.has('reply-to') || roles.has('email-address');
  const checkSpf = roles.has('envelope') || roles.has('sender') || roles.has('email-address');
  const checkDmarc = roles.has('sender') || roles.has('email-address');

  const nx = d.records.some((r) => r.type !== 'DMARC' && r.status === 'nxdomain');
  if (nx) {
    out.push({
      ...base,
      code: isSender ? 'DNS_SENDER_NXDOMAIN' : 'DNS_NXDOMAIN',
      category: 'DNS',
      title: isSender ? 'Sender domain does not exist in DNS' : 'Hostname does not exist in DNS',
      description: isSender
        ? 'The domain used as a sender address returned NXDOMAIN. Mail cannot be authenticated or replied to at a domain that does not exist, which points to a forged or discarded sender domain.'
        : 'The name returned NXDOMAIN, so the link cannot currently be reached. The site may have been taken down, expired, or never registered; this limits what else can be observed.',
      severity: isSender ? 'medium' : 'low',
      confidence: isSender ? 0.6 : 0.4,
      evidence: `${d.name}: NXDOMAIN (role: ${roleText})`,
    });
    return out;
  }

  const addrs = [...values(d, 'A'), ...values(d, 'AAAA')];
  const nonPublic = addrs.filter((ip) => classifyIp(ip).blocked);
  if (nonPublic.length) {
    out.push({
      ...base,
      code: 'DNS_NON_PUBLIC_ADDRESS',
      category: 'DNS',
      title: 'Public name resolves to a non-public address',
      description: `The name points to ${nonPublic.map((ip) => `${ip} (${classifyIp(ip).reason})`).join(', ')}. Internet-facing services do not resolve to internal ranges; this is either a misconfiguration or an attempt to reach internal systems (PhishLens did not connect to it).`,
      severity: 'medium',
      confidence: 0.5,
      evidence: `${d.name} → ${nonPublic.join(', ')}`,
    });
  }

  const ns = values(d, 'NS');
  const parking = ns.find((n) => PARKING_NS.test(n));
  if (parking) {
    out.push({
      ...base,
      code: 'DNS_PARKED',
      category: 'DNS',
      title: 'Domain is delegated to a parking/marketplace service',
      description: 'Its nameservers belong to a domain parking or resale service, which usually means no real site is operated on it. Context only.',
      severity: 'info',
      confidence: 0.7,
      evidence: `NS ${parking}`,
    });
  }

  for (const p of d.providers) {
    out.push({
      ...base,
      code: `DNS_PROVIDER_${p.role.toUpperCase()}`,
      category: 'DNS',
      title: `${p.role === 'dns' ? 'DNS hosted by' : p.role === 'mail' ? 'Mail handled by' : 'Hosted on'} ${p.name}`,
      description: 'Infrastructure identification by hostname pattern. Context only — the provider says nothing about whether this specific domain is legitimate.',
      severity: 'info',
      confidence: 0.9,
      polarity: 'neutral',
      evidence: p.basis,
    });
  }

  // Mail posture is only meaningful for the exact domain used in a sender address.
  if (!assessMailPosture) return out;

  // --- Mail posture of a domain used as a sender ----------------------------
  const mx = values(d, 'MX');
  if (checkMx && isNullMx(mx)) {
    out.push({
      ...base,
      code: 'DNS_SENDER_NULL_MX',
      category: 'DNS',
      title: 'Sender domain publishes a null MX (accepts no mail)',
      description: 'A null MX (RFC 7505) declares that the domain does not handle email. Replies to this sender cannot be delivered, which is inconsistent with a genuine correspondent.',
      severity: 'medium',
      confidence: 0.55,
      evidence: `${d.name} MX ${mx[0]}`,
    });
  } else if (checkMx && status(d, 'MX') === 'nodata') {
    out.push({
      ...base,
      code: 'DNS_SENDER_NO_MX',
      category: 'DNS',
      title: 'Sender domain has no MX records',
      description: 'The domain publishes no mail exchangers, so it is not set up to receive replies (delivery would fall back to its A record, if any). Legitimate organisations that send mail almost always publish MX records.',
      severity: 'low',
      confidence: 0.4,
      evidence: `${d.name}: no MX records`,
    });
  }

  const txt = values(d, 'TXT');
  const spf = parseSpfRecords(txt);
  if (checkSpf && status(d, 'TXT') !== 'error' && status(d, 'TXT') !== 'timeout') {
    if (spf.length === 0) {
      out.push({
        ...base,
        code: 'DNS_NO_SPF',
        category: 'DNS',
        title: 'Sender domain publishes no SPF record',
        description: 'Without SPF, receivers cannot check which servers may send mail for the domain, making it easier to spoof. Many small or non-mail domains lack SPF.',
        severity: 'low',
        confidence: 0.4,
        evidence: `${d.name}: no "v=spf1" TXT record`,
      });
    } else if (spf.length > 1) {
      out.push({
        ...base,
        code: 'DNS_SPF_MULTIPLE',
        category: 'DNS',
        title: 'Multiple SPF records',
        description: 'RFC 7208 requires exactly one SPF record; receivers treat multiple records as a permanent error, so SPF cannot pass for this domain.',
        severity: 'low',
        confidence: 0.6,
        evidence: spf.map((s) => s.raw).join(' | '),
      });
    } else if (spf[0]!.allQualifier === '+') {
      out.push({
        ...base,
        code: 'DNS_SPF_PASS_ALL',
        category: 'DNS',
        title: 'SPF authorises every server on the internet (+all)',
        description: 'A "+all" policy makes SPF pass for any sending IP, which defeats its purpose. It is occasionally a misconfiguration but is also used so forged mail passes SPF.',
        severity: 'medium',
        confidence: 0.6,
        evidence: spf[0]!.raw,
      });
    }
  }

  if (checkDmarc && d.dmarc) {
    const p = d.dmarc.policy;
    if (p === 'reject' || p === 'quarantine') {
      out.push({
        ...base,
        code: 'DNS_DMARC_ENFORCED',
        category: 'DNS',
        title: `Sender domain enforces DMARC (p=${p})`,
        description: 'Receivers are told to reject or quarantine mail that fails authentication for this exact domain, which makes direct spoofing of it difficult. It does not protect against lookalike domains.',
        severity: 'info',
        confidence: 0.6,
        polarity: 'benign',
        evidence: d.dmarc.raw,
      });
    } else {
      out.push({
        ...base,
        code: 'DNS_DMARC_MONITOR_ONLY',
        category: 'DNS',
        title: `Sender domain DMARC policy is "${p ?? 'unspecified'}" (monitoring only)`,
        description: 'The domain publishes DMARC but asks receivers to take no action on failures, so spoofed mail may still be delivered. Common during DMARC roll-out.',
        severity: 'info',
        confidence: 0.8,
        evidence: d.dmarc.raw,
      });
    }
  } else if (checkDmarc && values(d, 'DMARC').length === 0 && status(d, 'DMARC') !== 'error' && status(d, 'DMARC') !== 'timeout') {
    out.push({
      ...base,
      code: 'DNS_NO_DMARC',
      category: 'DNS',
      title: 'Sender domain publishes no DMARC policy',
      description: 'Without DMARC, receivers have no instruction from the domain owner on handling mail that fails SPF/DKIM, so spoofed mail claiming this domain is more likely to be delivered.',
      severity: 'low',
      confidence: 0.4,
      evidence: `_dmarc.${d.name}: no "v=DMARC1" record`,
    });
  }

  return out;
}
