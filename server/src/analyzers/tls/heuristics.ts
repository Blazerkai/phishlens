import type { TlsAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { subject } from '../../engine/subjects.js';
import { matchingSan } from './certificate.js';

const EXPIRY_WARNING_DAYS = 14;
const FRESH_CERT_DAYS = 3;

/**
 * Indicators from an observed certificate. Note what is NOT here: the issuing CA.
 * Free, automated CAs (Let's Encrypt, ZeroSSL, Google Trust Services…) issue most
 * certificates on the web, for legitimate and malicious sites alike.
 */
export function tlsHeuristics(t: TlsAnalysis): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const base = {
    source: `TLS handshake with ${t.host}:${t.port}${t.remoteAddress ? ` (${t.remoteAddress})` : ''}`,
    provenance: 'network' as const,
    subject: subject.certificate(t.host, t.port),
  };

  if (t.status !== 'completed' || !t.certificate) {
    if (t.status === 'failed') {
      out.push({
        ...base,
        code: 'TLS_UNREACHABLE',
        category: 'TLS',
        title: `TLS verification incomplete for ${t.host}:${t.port}`,
        description: 'The handshake did not complete, so the certificate could not be verified. Recorded as unknown: an observation gap, not evidence either way.',
        severity: 'info',
        confidence: 1,
        polarity: 'unknown',
        evidence: t.reason ?? 'handshake failed',
      });
    }
    return out;
  }

  const c = t.certificate;
  const expired = c.daysRemaining < 0;
  const notYetValid = new Date(c.validFrom).getTime() > new Date(t.inspectedAt).getTime();
  const err = t.authorizationError ?? '';
  const selfSigned = c.selfSigned || /SELF_SIGNED/i.test(err);

  if (expired) {
    out.push({
      ...base,
      code: 'TLS_EXPIRED',
      category: 'TLS',
      title: 'Certificate expired',
      description: `The certificate expired ${-c.daysRemaining} day(s) ago. Browsers show a full-page warning. Abandoned and poorly maintained sites also let certificates lapse.`,
      severity: 'medium',
      confidence: 0.6,
      evidence: `notAfter ${c.validTo}`,
    });
  } else if (notYetValid) {
    out.push({
      ...base,
      code: 'TLS_NOT_YET_VALID',
      category: 'TLS',
      title: 'Certificate is not yet valid',
      description: 'The certificate validity period starts in the future, which browsers reject. Usually a clock or deployment error.',
      severity: 'medium',
      confidence: 0.5,
      evidence: `notBefore ${c.validFrom}`,
    });
  }

  if (t.hostnameMatches === false) {
    out.push({
      ...base,
      code: 'TLS_HOSTNAME_MISMATCH',
      category: 'TLS',
      title: 'Hostname mismatch',
      description: `The certificate presented is not valid for ${t.host}, so a browser would warn that the connection is not private. Shared hosting misconfiguration is a common benign cause.`,
      severity: 'medium',
      confidence: 0.6,
      evidence: `${t.hostnameMismatchReason ?? 'mismatch'} · CN=${c.subjectCN ?? '—'} · SANs: ${c.sans.slice(0, 8).join(', ') || 'none'}`,
    });
  } else {
    const san = matchingSan(t.host, c.sans);
    const cnCovers = !!c.subjectCN && (c.subjectCN.toLowerCase() === t.host || matchingSan(t.host, [c.subjectCN.toLowerCase()]) !== null);
    if (san && !cnCovers) {
      out.push({
        ...base,
        code: 'TLS_SHARED_CERTIFICATE',
        category: 'TLS',
        title: `Shared certificate: subject is ${c.subjectCN ?? 'another name'}, hostname covered by SAN`,
        description:
          `The certificate's subject names a different site, but ${t.host} is listed in its Subject Alternative Names (${c.sans.length} entries), which is what hostname verification uses (RFC 6125; the subject CN is ignored when SANs exist). ` +
          'Multi-tenant hosting and CDN platforms issue such certificates routinely. Not a risk by itself; the other names on the certificate are unrelated tenants, not evidence about this site.',
        severity: 'info',
        confidence: 1,
        polarity: 'neutral',
        evidence: `subject CN=${c.subjectCN ?? '—'} · ${t.host} matched SAN ${san} · ${c.sans.length} SANs · issuer ${c.issuerOrg ?? c.issuerCN ?? 'unknown'}`,
      });
    }
    if (san) {
      out.push({
        ...base,
        code: 'TLS_SAN_MATCH',
        category: 'TLS',
        title: 'Domain appears in SAN list',
        description: `The certificate's Subject Alternative Names include ${san === t.host ? 'the hostname exactly' : `the wildcard ${san}`}. Context only.`,
        severity: 'info',
        confidence: 1,
        polarity: 'neutral',
        evidence: `${t.host} ↔ ${san} (${c.sans.length} SAN entr${c.sans.length === 1 ? 'y' : 'ies'})`,
      });
    }
  }

  if (selfSigned) {
    out.push({
      ...base,
      code: 'TLS_SELF_SIGNED',
      category: 'TLS',
      title: 'Self-signed certificate',
      description: 'The certificate is not issued by a public certificate authority, so browsers do not trust it. Public sites have had free trusted certificates for years; self-signed certificates on public links are unusual.',
      severity: 'medium',
      confidence: 0.6,
      evidence: `subject = issuer: ${c.subjectCN ?? JSON.stringify(c.subject)}`,
    });
  } else if (!t.authorized && !expired && !notYetValid && err && !/ALTNAME/i.test(err)) {
    out.push({
      ...base,
      code: 'TLS_UNTRUSTED_CHAIN',
      category: 'TLS',
      title: 'Certificate chain is not trusted',
      description: 'The chain could not be validated against the trusted root store. Often a server that omits an intermediate certificate; sometimes an untrusted issuer.',
      severity: 'low',
      confidence: 0.45,
      evidence: err,
    });
  }

  if (!expired && c.daysRemaining <= EXPIRY_WARNING_DAYS) {
    out.push({
      ...base,
      code: 'TLS_EXPIRES_SOON',
      category: 'TLS',
      title: `Certificate expires soon (${c.daysRemaining} days)`,
      description: 'Context only. Automated certificates are renewed close to expiry routinely.',
      severity: 'info',
      confidence: 1,
      evidence: `notAfter ${c.validTo}`,
    });
  }

  if (c.daysSinceIssued >= 0 && c.daysSinceIssued <= FRESH_CERT_DAYS) {
    out.push({
      ...base,
      code: 'TLS_RECENTLY_ISSUED',
      category: 'TLS',
      title: `Certificate issued ${c.daysSinceIssued === 0 ? 'today' : `${c.daysSinceIssued} day(s) ago`}`,
      description: 'Context only. Freshly issued certificates are expected for new infrastructure — including newly created phishing sites — but also after any routine renewal. It matters only when combined with other evidence such as a newly registered lookalike domain.',
      severity: 'info',
      confidence: 1,
      evidence: `notBefore ${c.validFrom} · issuer ${c.issuerOrg ?? c.issuerCN ?? 'unknown'}`,
    });
  }

  if (t.protocol && /^TLSv1(\.1)?$/.test(t.protocol)) {
    out.push({
      ...base,
      code: 'TLS_LEGACY_PROTOCOL',
      category: 'TLS',
      title: `Legacy protocol negotiated (${t.protocol})`,
      description: 'TLS 1.0/1.1 are deprecated. This indicates outdated server configuration, not phishing.',
      severity: 'low',
      confidence: 0.3,
      evidence: `${t.protocol} ${t.cipher ?? ''}`,
    });
  }

  if (t.authorized && t.hostnameMatches && !expired && !notYetValid) {
    out.push({
      ...base,
      code: 'TLS_VALID',
      category: 'TLS',
      title: 'Certificate valid',
      description: 'The certificate chains to a trusted root, covers this hostname and is within its validity period. This rules out interception and misconfiguration; it says nothing about the intent of the site owner, since valid certificates are free and widely used by phishing sites.',
      severity: 'info',
      confidence: 0.5,
      polarity: 'benign',
      evidence: `CN=${c.subjectCN ?? '—'} · issuer ${c.issuerOrg ?? c.issuerCN ?? 'unknown'} · valid until ${c.validTo.slice(0, 10)}`,
    });
  }

  return out;
}
