import { parse } from 'tldts';
import type { Indicator, InvestigationArtifacts, PositiveEvidenceClass, PositiveEvidenceFamily } from '@phishlens/shared';
import { isIpLiteral } from '../security/ip.js';

/**
 * Positive-evidence families.
 *
 * Benign indicators are not independent of each other: a valid certificate and
 * an HTTPS upgrade are both properties of one transport configuration (on most
 * hosting platforms the platform provides both automatically); SPF, DKIM and
 * DMARC passes come from one authentication evaluation of one message. Counting
 * them separately would let one fact masquerade as several.
 *
 * So each benign rule belongs to exactly one family, and the verdict counts
 * families, not indicators. Families also have a class:
 *
 *  security_control – hygiene the operator controls. Attackers obtain all of it
 *                     for free (automatic certificates, platform redirects,
 *                     DMARC on their own domain), so it can support but never
 *                     on its own establish legitimacy.
 *  corroboration    – evidence about who operates the domain or its history.
 *
 * Neutral infrastructure metadata (registrar, DNS/mail/hosting provider, SAN
 * contents, mid-range domain age) is not positive evidence and is not listed.
 * Unknown observations (polarity "unknown") never count.
 *
 * Corroboration only counts when it concerns the investigation's primary
 * subject (see primaryDomains): a verified or long-established domain that is
 * merely linked from a message, or that a URL redirects away from, says nothing
 * about the destination being investigated.
 */
interface FamilyDef {
  family: string;
  label: string;
  class: PositiveEvidenceClass;
  reason: string;
}

const TRANSPORT: FamilyDef = {
  family: 'transport',
  label: 'Transport security (HTTPS)',
  class: 'security_control',
  reason: 'Certificate validity, hostname coverage and HTTPS enforcement describe one transport configuration and count once.',
};
const SENDER_AUTH: FamilyDef = {
  family: 'sender_authentication',
  label: 'Sender authentication',
  class: 'security_control',
  reason: 'SPF, DKIM and DMARC results (and the domain’s published policy) come from one authentication evaluation and count once.',
};
const IDENTITY: FamilyDef = {
  family: 'identity',
  label: 'Verified identity',
  class: 'corroboration',
  reason: 'The operator is identified by an analyst-maintained record (brand watchlist official domain or a recorded operator verification). Both express the same claim and count once.',
};
const POPULARITY: FamilyDef = {
  family: 'reputation_popularity',
  label: 'Sustained popularity',
  class: 'corroboration',
  reason: 'Independent traffic-ranking data shows sustained use over the last month — something throwaway phishing domains do not accumulate.',
};
const MATURITY: FamilyDef = {
  family: 'registration_maturity',
  label: 'Registration maturity',
  class: 'corroboration',
  reason: 'Registry records (RDAP) show the domain has existed for years. Weak on its own (aged and compromised domains are abused), so it only counts alongside another family.',
};

export const POSITIVE_SIGNAL_FAMILIES: Record<string, FamilyDef> = {
  TLS_VALID: TRANSPORT,
  TRANSPORT_HTTPS_UPGRADE: TRANSPORT,
  // HSTS is part of the same operator-controlled transport configuration: it joins the family, never adds one.
  TRANSPORT_HSTS: TRANSPORT,
  EMAIL_DMARC_PASS: SENDER_AUTH,
  EMAIL_SPF_PASS: SENDER_AUTH,
  EMAIL_DKIM_PASS: SENDER_AUTH,
  DNS_DMARC_ENFORCED: SENDER_AUTH,
  CORR_CONSISTENT_SENDER: SENDER_AUTH,
  DOMAIN_OFFICIAL_BRAND: IDENTITY,
  IDENTITY_VERIFIED: IDENTITY,
  RDAP_ESTABLISHED: MATURITY,
  REPUTATION_POPULAR: POPULARITY,
};

export function registrableOf(hostOrUrl: string | null | undefined): string | null {
  if (!hostOrUrl) return null;
  let host = hostOrUrl;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(hostOrUrl)) {
    try {
      host = new URL(hostOrUrl).hostname;
    } catch {
      return null;
    }
  }
  host = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (isIpLiteral(host)) return host;
  return parse(host, { allowPrivateDomains: true }).domain ?? null;
}

/**
 * The domains the investigation is about: the submitted domain, the final
 * destination of the submitted URL (or its host if the chain was not
 * completed), and the sender domain / submitted address domain.
 */
export function primaryDomains(a: Pick<InvestigationArtifacts, 'domains' | 'urls' | 'redirects' | 'email' | 'emailAddress'>): Set<string> {
  const out = new Set<string>();
  const add = (v: string | null | undefined) => {
    const r = registrableOf(v);
    if (r) out.add(r);
  };
  for (const d of a.domains) if (d.sources.includes('submitted domain')) add(d.hostname);
  for (const u of a.urls) {
    if (u.origin !== 'input' || !u.valid) continue;
    const chain = a.redirects.find((r) => r.startUrl === u.normalized);
    const final = chain?.status === 'completed' && chain.finalUrl && chain.hops[chain.hops.length - 1]?.kind === 'final' ? chain.finalUrl : null;
    add(final ?? u.hostname);
  }
  add(a.email?.from?.domain);
  add(a.emailAddress?.address.domain);
  return out;
}

function subjectDomain(subject: string | undefined): string | null {
  if (!subject) return null;
  const m = subject.match(/^(host|domain|rdap|dns|cert):(.+)$/);
  if (!m) return null;
  return registrableOf(m[1] === 'cert' ? m[2]!.replace(/:\d+$/, '') : m[2]!);
}

/** Unmapped benign rules are grouped by category and treated as security controls (they can never satisfy corroboration). */
function familyOf(i: Indicator): FamilyDef {
  return (
    POSITIVE_SIGNAL_FAMILIES[i.code] ?? {
      family: `other:${i.category}`,
      label: `Other (${i.category})`,
      class: 'security_control',
      reason: 'Benign rule without an explicit family mapping; grouped by category and not treated as corroboration.',
    }
  );
}

/** Families that must not count because related evidence contradicts them. */
const LISTING_CODES = ['REPUTATION_LISTED', 'REPUTATION_CORROBORATED_MALICIOUS', 'REPUTATION_HISTORICAL', 'REPUTATION_LISTED_STALE'];

export function contradictedFamilies(indicators: Indicator[]): Map<string, string> {
  const out = new Map<string, string>();
  const listing = indicators.find((i) => LISTING_CODES.includes(i.code));
  if (listing) {
    out.set('reputation_popularity', `contradicted by a reputation listing: ${listing.title}`);
    out.set('identity', `contradicted by a reputation listing: ${listing.title} (a verified operator's site can still be compromised)`);
  }
  const tlsConflict = indicators.find((i) => i.code === 'CORR_TLS_OBSERVATION_CONFLICT');
  if (tlsConflict) out.set('transport', `contradicted: ${tlsConflict.title}`);
  const tlsProblem = indicators.find((i) => i.polarity === 'risk' && i.category === 'TLS' && i.severity !== 'info' && i.severity !== 'low');
  if (tlsProblem) out.set('transport', `contradicted by a TLS risk finding: ${tlsProblem.title}`);
  const authFail = indicators.find((i) => i.polarity === 'risk' && ['EMAIL_DMARC_FAIL', 'EMAIL_SPF_FAIL', 'EMAIL_DKIM_FAIL'].includes(i.code));
  if (authFail) out.set('sender_authentication', `contradicted by ${authFail.title}`);
  return out;
}

export function groupPositiveEvidence(indicators: Indicator[], artifacts?: Parameters<typeof primaryDomains>[0]): PositiveEvidenceFamily[] {
  const contradicted = contradictedFamilies(indicators);
  const primary = artifacts ? primaryDomains(artifacts) : null;
  const groups = new Map<string, PositiveEvidenceFamily>();
  for (const i of indicators) {
    if (i.polarity !== 'benign') continue;
    const def = familyOf(i);
    // Corroboration about a domain other than the primary subject is context, not evidence about this investigation.
    if (def.class === 'corroboration' && primary) {
      const d = subjectDomain(i.subject);
      if (!d || !primary.has(d)) continue;
    }
    const g =
      groups.get(def.family) ??
      ({
        family: def.family,
        label: def.label,
        class: def.class,
        counted: !contradicted.has(def.family),
        reason: contradicted.get(def.family) ?? def.reason,
        indicatorIds: [],
        titles: [],
      } satisfies PositiveEvidenceFamily);
    g.indicatorIds.push(i.id);
    g.titles.push(i.title);
    groups.set(def.family, g);
  }
  return [...groups.values()];
}
