import { parse } from 'tldts';
import type { RedirectAnalysis, RedirectHop, UrlAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { subject } from '../../engine/subjects.js';
import { isIpLiteral } from '../../security/ip.js';

const site = (host: string) => (isIpLiteral(host) ? host : parse(host, { allowPrivateDomains: true }).domain ?? host);

/** Parses Strict-Transport-Security (RFC 6797). Returns null when absent or malformed. */
export function parseHsts(value: string | null | undefined): { maxAge: number; includeSubDomains: boolean; preload: boolean } | null {
  if (!value) return null;
  const m = value.match(/(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i);
  if (!m) return null;
  return { maxAge: Number(m[1]), includeSubDomains: /(?:^|;)\s*includesubdomains\s*(?:;|$)/i.test(value), preload: /(?:^|;)\s*preload\s*(?:;|$)/i.test(value) };
}

/**
 * HSTS on a verified HTTPS response. Part of the transport family (same operator-controlled
 * configuration as the certificate and the upgrade), so it never adds an independent family.
 * max-age=0 instructs browsers to forget HSTS and is not credited.
 */
export function hstsIndicators(chain: RedirectAnalysis): IndicatorDraft[] {
  const last = chain.hops[chain.hops.length - 1];
  if (!last || last.kind !== 'final' || last.scheme !== 'https' || !last.tls?.authorized || (last.statusCode ?? 600) >= 400) return [];
  const h = parseHsts(last.hsts);
  if (!h) return [];
  const base = { subject: subject.host(last.hostname), source: `HTTP response from ${last.hostname}`, provenance: 'network' as const, category: 'TLS' as const };
  if (h.maxAge === 0) {
    return [{ ...base, code: 'TRANSPORT_HSTS_DISABLED', title: 'HSTS explicitly disabled (max-age=0)', description: 'The site instructs browsers to forget any HSTS policy. Not credited as a transport control.', severity: 'info', confidence: 1, polarity: 'neutral', evidence: `Strict-Transport-Security: ${last.hsts}` }];
  }
  return [
    {
      ...base,
      code: 'TRANSPORT_HSTS',
      title: `HSTS enforced (max-age ${Math.round(h.maxAge / 86400)} days${h.includeSubDomains ? ', includeSubDomains' : ''}${h.preload ? ', preload' : ''})`,
      description:
        'Browsers that have seen this header will refuse plain-HTTP connections to the host. Counted within the transport-security family together with the certificate and HTTPS upgrade — it is the same operator-controlled configuration, so it adds no independent weight.',
      severity: 'info',
      confidence: 0.9,
      polarity: 'benign',
      evidence: `Strict-Transport-Security: ${last.hsts} on ${last.url}`,
    },
  ];
}

export type HttpTransportOutcome =
  /** HTTP → HTTPS on the same site, every later hop HTTPS, destination served with a verified certificate. */
  | 'upgraded'
  /** Content is served over plain HTTP (no upgrade). */
  | 'plaintext'
  /** An upgrade could not be confirmed (redirect elsewhere, unverified certificate, error, or not inspected). */
  | 'unverified';

export interface TransportAssessment {
  outcome: HttpTransportOutcome;
  reason: string;
  finalHop?: RedirectHop;
}

/**
 * Decides what the redirect chain proves about an http:// URL. The criteria for
 * "upgraded" are deliberately strict: a redirect merely existing is not enough.
 */
export function classifyHttpTransport(chain: RedirectAnalysis | undefined): TransportAssessment {
  if (!chain || chain.hops.length === 0) return { outcome: 'unverified', reason: 'the link was not inspected' };
  if (chain.status !== 'completed') return { outcome: 'unverified', reason: `inspection ${chain.status}${chain.reason ? `: ${chain.reason}` : ''}` };
  const hops = chain.hops;
  const last = hops[hops.length - 1]!;
  if (last.kind !== 'final') return { outcome: 'unverified', reason: chain.reason ?? `chain ended with ${last.kind}${last.error ? `: ${last.error}` : ''}` };
  if (last.scheme === 'http') {
    return last.statusCode !== undefined && last.statusCode < 400
      ? { outcome: 'plaintext', reason: `content returned over HTTP (status ${last.statusCode}) without an upgrade`, finalHop: last }
      : { outcome: 'unverified', reason: `HTTP endpoint returned status ${last.statusCode ?? 'unknown'}` };
  }
  const firstHttps = hops.findIndex((h) => h.scheme === 'https');
  if (hops.slice(firstHttps).some((h) => h.scheme !== 'https')) return { outcome: 'unverified', reason: 'the chain returns to HTTP after upgrading' };
  const startSite = site(hops[0]!.hostname);
  if (hops.some((h) => site(h.hostname) !== startSite)) {
    return { outcome: 'unverified', reason: `the HTTPS destination (${last.hostname}) is on a different site than ${hops[0]!.hostname}` };
  }
  if (last.statusCode === undefined || last.statusCode >= 400) return { outcome: 'unverified', reason: `HTTPS destination returned status ${last.statusCode ?? 'unknown'}` };
  if (!last.tls) return { outcome: 'unverified', reason: 'certificate verification of the HTTPS destination was not recorded' };
  if (!last.tls.authorized) return { outcome: 'unverified', reason: `the HTTPS destination's certificate failed verification (${last.tls.error ?? 'unknown error'})` };
  return { outcome: 'upgraded', reason: `upgraded to ${last.url}; certificate verified for ${last.hostname}`, finalHop: last };
}

/**
 * Exactly one transport outcome per http:// URL, so the initial HTTP URL and its
 * redirect are never scored as two unrelated risks:
 *   upgraded   → positive transport signal; a small residual if HSTS is absent
 *   plaintext  → risk (higher when the page collects passwords)
 *   unverified → the original low-weight warning, because HTTPS was not confirmed
 */
export function httpTransportIndicators(u: UrlAnalysis, chain: RedirectAnalysis | undefined): IndicatorDraft[] {
  if (!u.valid || u.scheme !== 'http' || !u.normalized) return [];
  const a = classifyHttpTransport(chain);
  const base = {
    subject: subject.url(u.normalized),
    source: chain ? `HTTP redirect inspection of ${chain.startUrl}` : 'Submitted URL (not inspected)',
    provenance: (chain ? 'network' : 'analysis') as IndicatorDraft['provenance'],
  };

  if (a.outcome === 'upgraded') {
    const hop = a.finalHop!;
    const out: IndicatorDraft[] = [
      {
        ...base,
        code: 'TRANSPORT_HTTPS_UPGRADE',
        category: 'REDIRECT',
        title: 'HTTP redirects to HTTPS on the same site',
        description:
          'The plain-HTTP URL immediately redirects to HTTPS on the same registrable domain, every later hop stays on HTTPS, and the certificate presented on the connection that served the page verified for the hostname. ' +
          'This is a transport security control; it says nothing about who operates the site.',
        severity: 'info',
        confidence: 0.9,
        polarity: 'benign',
        evidence: `${chain!.hops.map((h) => `${h.statusCode ?? h.kind} ${h.scheme}://${h.hostname}`).join(' → ')}`,
      },
    ];
    if (!parseHsts(hop.hsts)?.maxAge) {
      out.push({
        ...base,
        code: 'TRANSPORT_HTTP_FIRST_REQUEST',
        category: 'REDIRECT',
        title: 'First request is sent over HTTP (no HSTS observed)',
        description:
          'Visitors following the http:// link make one unencrypted request before the upgrade. Without Strict-Transport-Security on the HTTPS response, that first hop can be intercepted and stripped on hostile networks. ' +
          'A hygiene gap, not evidence of phishing.',
        severity: 'low',
        confidence: 0.15,
        evidence: `${u.normalized} → ${hop.url}; ${hop.hsts ? `ineffective Strict-Transport-Security "${hop.hsts}"` : 'no Strict-Transport-Security header'} on the final response`,
      });
    }
    return out;
  }

  if (a.outcome === 'plaintext') {
    const pwd = chain!.page?.hasPasswordField === true;
    return [
      {
        ...base,
        code: 'TRANSPORT_HTTP_CONTENT',
        category: 'REDIRECT',
        title: pwd ? 'Password form served over unencrypted HTTP' : 'Content served over unencrypted HTTP',
        description: pwd
          ? 'The page that collects a password is delivered over plain HTTP, so anything entered is sent unencrypted. Legitimate sign-in pages are HTTPS-only.'
          : 'The site does not upgrade to HTTPS; its content is delivered over plain HTTP. Common on neglected sites, unusual for services that handle accounts or payments.',
        severity: pwd ? 'medium' : 'low',
        confidence: pwd ? 0.6 : 0.45,
        evidence: `${u.normalized} → HTTP ${a.finalHop!.statusCode} at ${a.finalHop!.url}`,
      },
    ];
  }

  return [
    {
      ...base,
      code: 'TRANSPORT_HTTPS_UNVERIFIED',
      category: 'URL_STRUCTURE',
      title: 'Link uses HTTP; a safe upgrade to HTTPS was not confirmed',
      description:
        `Data sent over HTTP is unencrypted. PhishLens could not confirm that this link upgrades to HTTPS on the same site (${a.reason}). ` +
        'Many phishing sites also use HTTPS, so this is weak evidence on its own.',
      severity: 'low',
      confidence: 0.35,
      evidence: u.normalized,
    },
  ];
}
