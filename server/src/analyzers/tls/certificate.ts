import tls from 'node:tls';
import type { PeerCertificate } from 'node:tls';
import type { CertificateInfo } from '@phishlens/shared';

const DAY = 86_400_000;

function flatten(dn: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!dn || typeof dn !== 'object') return out;
  for (const [k, v] of Object.entries(dn as Record<string, unknown>)) out[k] = Array.isArray(v) ? v.join(', ') : String(v);
  return out;
}

export function parseSans(subjectaltname: string | undefined): string[] {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(/,\s*/)
    .map((s) => s.trim())
    .filter((s) => /^(DNS|IP Address):/i.test(s))
    .map((s) => s.replace(/^(DNS|IP Address):/i, '').toLowerCase());
}

export function normalizeCertificate(cert: PeerCertificate & { issuerCertificate?: PeerCertificate }, now = new Date()): CertificateInfo {
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const subject = flatten(cert.subject);
  const issuer = flatten(cert.issuer);
  return {
    subject,
    issuer,
    subjectCN: subject.CN ?? null,
    issuerCN: issuer.CN ?? null,
    issuerOrg: issuer.O ?? null,
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining: Math.floor((validTo.getTime() - now.getTime()) / DAY),
    daysSinceIssued: Math.floor((now.getTime() - validFrom.getTime()) / DAY),
    sans: parseSans(cert.subjectaltname),
    serialNumber: cert.serialNumber ?? '',
    fingerprint256: cert.fingerprint256 ?? '',
    selfSigned: JSON.stringify(subject) === JSON.stringify(issuer) && (!cert.issuerCertificate || cert.issuerCertificate.fingerprint256 === cert.fingerprint256),
  };
}

/** Uses Node's RFC 6125 implementation to decide whether the certificate covers the hostname. */
export function hostnameMatch(host: string, cert: PeerCertificate): { matches: boolean; reason: string | null } {
  const err = tls.checkServerIdentity(host, cert);
  return err ? { matches: false, reason: err.message } : { matches: true, reason: null };
}

/** Finds the SAN entry (exact or wildcard) that covers a hostname. */
export function matchingSan(host: string, sans: string[]): string | null {
  const h = host.toLowerCase();
  for (const san of sans) {
    if (san === h) return san;
    if (san.startsWith('*.')) {
      const suffix = san.slice(1);
      if (h.endsWith(suffix) && !h.slice(0, -suffix.length).includes('.')) return san;
    }
  }
  return null;
}
