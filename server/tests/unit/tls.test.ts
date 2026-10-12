import { describe, expect, it } from 'vitest';
import type { PeerCertificate } from 'node:tls';
import type { TlsAnalysis } from '@phishlens/shared';
import { hostnameMatch, matchingSan, normalizeCertificate, parseSans } from '../../src/analyzers/tls/certificate.js';
import { tlsHeuristics } from '../../src/analyzers/tls/heuristics.js';
import { codes } from '../helpers.js';

const NOW = new Date('2026-06-01T00:00:00Z');

function cert(over: Partial<PeerCertificate> = {}): PeerCertificate {
  return {
    subject: { CN: 'www.example.com' },
    issuer: { C: 'US', O: "Let's Encrypt", CN: 'R11' },
    subjectaltname: 'DNS:www.example.com, DNS:example.com, DNS:*.cdn.example.com',
    valid_from: 'May  1 00:00:00 2026 GMT',
    valid_to: 'Jul 30 00:00:00 2026 GMT',
    serialNumber: '03AB',
    fingerprint256: 'AA:BB',
    ...over,
  } as unknown as PeerCertificate;
}

function analysis(over: Partial<TlsAnalysis> = {}, c = cert()): TlsAnalysis {
  return {
    host: 'www.example.com',
    port: 443,
    status: 'completed',
    authorized: true,
    authorizationError: null,
    hostnameMatches: true,
    hostnameMismatchReason: null,
    protocol: 'TLSv1.3',
    certificate: normalizeCertificate(c, NOW),
    inspectedAt: NOW.toISOString(),
    ...over,
  };
}

describe('certificate parsing', () => {
  it('normalises subject, issuer, validity and SANs', () => {
    const c = normalizeCertificate(cert(), NOW);
    expect(c).toMatchObject({ subjectCN: 'www.example.com', issuerOrg: "Let's Encrypt", issuerCN: 'R11', daysRemaining: 59, daysSinceIssued: 31, selfSigned: false });
    expect(c.sans).toEqual(['www.example.com', 'example.com', '*.cdn.example.com']);
  });

  it('parses IP SANs', () => {
    expect(parseSans('DNS:a.example, IP Address:192.0.2.1')).toEqual(['a.example', '192.0.2.1']);
  });

  it('matches hostnames with RFC 6125 rules including single-label wildcards', () => {
    expect(hostnameMatch('www.example.com', cert()).matches).toBe(true);
    expect(hostnameMatch('img.cdn.example.com', cert()).matches).toBe(true);
    expect(hostnameMatch('a.b.cdn.example.com', cert()).matches).toBe(false);
    expect(hostnameMatch('evil.example', cert()).matches).toBe(false);
    expect(matchingSan('img.cdn.example.com', ['*.cdn.example.com'])).toBe('*.cdn.example.com');
    expect(matchingSan('a.b.cdn.example.com', ['*.cdn.example.com'])).toBeNull();
  });
});

describe('TLS heuristics', () => {
  it('reports a valid Let’s Encrypt certificate as valid — the CA is not a risk signal', () => {
    const out = tlsHeuristics(analysis());
    expect(codes(out).sort()).toEqual(['TLS_SAN_MATCH', 'TLS_VALID']);
    expect(out.find((i) => i.code === 'TLS_VALID')!.polarity).toBe('benign');
    expect(out.every((i) => i.severity === 'info')).toBe(true);
  });

  it('flags an expired certificate', () => {
    const c = cert({ valid_from: 'Jan  1 00:00:00 2026 GMT', valid_to: 'Mar  1 00:00:00 2026 GMT' });
    const out = tlsHeuristics(analysis({ authorized: false, authorizationError: 'CERT_HAS_EXPIRED' }, c));
    expect(out.find((i) => i.code === 'TLS_EXPIRED')).toMatchObject({ severity: 'medium' });
    expect(codes(out)).not.toContain('TLS_VALID');
    expect(codes(out)).not.toContain('TLS_UNTRUSTED_CHAIN');
  });

  it('flags a hostname mismatch with the SANs as evidence', () => {
    const out = tlsHeuristics(analysis({ host: 'login.other.example', hostnameMatches: false, hostnameMismatchReason: "Host: login.other.example. is not in the cert's altnames" }));
    const ind = out.find((i) => i.code === 'TLS_HOSTNAME_MISMATCH');
    expect(ind?.severity).toBe('medium');
    expect(ind?.evidence).toContain('www.example.com');
  });

  it('flags self-signed certificates', () => {
    const c = cert({ issuer: { CN: 'www.example.com' } as never });
    const out = tlsHeuristics(analysis({ authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }, c));
    expect(codes(out)).toContain('TLS_SELF_SIGNED');
  });

  it('flags certificates that expire soon and were freshly issued as context only', () => {
    const c = cert({ valid_from: 'May 31 00:00:00 2026 GMT', valid_to: 'Jun 10 00:00:00 2026 GMT' });
    const out = tlsHeuristics(analysis({}, c));
    expect(out.find((i) => i.code === 'TLS_EXPIRES_SOON')?.severity).toBe('info');
    expect(out.find((i) => i.code === 'TLS_RECENTLY_ISSUED')?.severity).toBe('info');
  });

  it('records unreachable endpoints as an observation gap, not a risk', () => {
    const out = tlsHeuristics({ host: 'x.example', port: 443, status: 'failed', reason: 'ECONNREFUSED', inspectedAt: NOW.toISOString() });
    expect(out).toMatchObject([{ code: 'TLS_UNREACHABLE', severity: 'info' }]);
  });
});
