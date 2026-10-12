import { describe, expect, it } from 'vitest';
import type { Indicator } from '@phishlens/shared';
import { fakeDns, fakeHttp } from '../fakes.js';
import { fakeTls, rdapResponse, scenario } from '../scenario.js';
import { brand } from '../helpers.js';
import { hustlanceLike, sharedSans } from '../fixtures/hustlance.js';
import { classifyHttpTransport } from '../../src/analyzers/redirects/transport.js';
import { groupPositiveEvidence } from '../../src/engine/signals.js';

const by = (inds: Indicator[], code: string) => inds.filter((i) => i.code === code);
const html = (body = '<title>ok</title>') => ({ status: 200, headers: { 'content-type': 'text/html' }, body });

/** A site with a configurable transport story; DNS/RDAP succeed unless overridden. */
function site(domain: string, routes: Parameters<typeof fakeHttp>[0], opts: { ageDays?: number; tls?: Parameters<typeof fakeTls>[0] } = {}) {
  const zone: Parameters<typeof fakeDns>[0] = { [domain]: { A: ['93.184.216.80'], NS: ['ns1.dns.example'] } };
  for (const u of Object.keys(routes)) zone[new URL(u).hostname] ??= { A: ['93.184.216.80'] };
  return {
    dns: fakeDns(zone),
    http: fakeHttp({ ...routes, [`https://rdap.test/domain/${domain}`]: rdapResponse(opts.ageDays ?? 400) }),
    tls: fakeTls(opts.tls),
  };
}

describe('HTTP → HTTPS transport assessment', () => {
  it('1. recognises a valid HTTP 301 → HTTPS upgrade on the same site, once', async () => {
    const r = await scenario({ url: 'http://shop.example.org/' }, site('example.org', { 'http://shop.example.org/': { status: 301, headers: { location: 'https://shop.example.org/' } }, 'https://shop.example.org/': html() }));
    expect(by(r.indicators, 'URL_PLAINTEXT_HTTP')[0]).toMatchObject({ severity: 'info', polarity: 'neutral' });
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(1);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')[0]!.polarity).toBe('benign');
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UNVERIFIED')).toHaveLength(0);
    expect(by(r.indicators, 'TRANSPORT_HTTP_CONTENT')).toHaveLength(0);
  });

  it('keeps a small residual risk for the plaintext first hop when HSTS is absent, and none when present', async () => {
    const without = await scenario(hustlanceLike('a-site.com').input, hustlanceLike('a-site.com').services);
    expect(by(without.indicators, 'TRANSPORT_HTTP_FIRST_REQUEST')[0]).toMatchObject({ severity: 'low', polarity: 'risk', confidence: 0.15 });
    const f = hustlanceLike('b-site.com', { hsts: 'max-age=31556926' });
    const withHsts = await scenario(f.input, f.services);
    expect(by(withHsts.indicators, 'TRANSPORT_HTTP_FIRST_REQUEST')).toHaveLength(0);
  });

  it('2. flags HTTP that serves content without upgrading (more when it collects passwords)', async () => {
    const plain = await scenario({ url: 'http://plain.example.org/' }, site('example.org', { 'http://plain.example.org/': html() }));
    expect(by(plain.indicators, 'TRANSPORT_HTTP_CONTENT')[0]).toMatchObject({ severity: 'low', polarity: 'risk' });
    expect(by(plain.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(0);
    const login = await scenario({ url: 'http://plain.example.org/' }, site('example.org', { 'http://plain.example.org/': html('<form><input type="password"></form>') }));
    expect(by(login.indicators, 'TRANSPORT_HTTP_CONTENT')[0]).toMatchObject({ severity: 'medium', title: 'Password form served over unencrypted HTTP' });
  });

  it('does not credit an upgrade whose HTTPS destination fails certificate verification on the serving connection', async () => {
    const r = await scenario(
      { url: 'http://bad.example.org/' },
      site('example.org', {
        'http://bad.example.org/': { status: 301, headers: { location: 'https://bad.example.org/' } },
        'https://bad.example.org/': { ...html(), tls: { authorized: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID', fingerprint256: null } },
      }),
    );
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(0);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UNVERIFIED')[0]!.description).toMatch(/failed verification/);
  });

  it('keeps the original HTTP warning when the redirect could not be inspected', async () => {
    const r = await scenario({ url: 'http://example.org/' }, {}, { probes: false });
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UNVERIFIED')[0]).toMatchObject({ severity: 'low', confidence: 0.35, polarity: 'risk' });
  });
});

describe('TLS verification', () => {
  const tlsCase = (tls: Parameters<typeof fakeTls>[0]) => scenario({ url: 'https://app.example.org/' }, site('example.org', { 'https://app.example.org/': html() }, { tls }));

  it('3. accepts a trusted certificate that covers the hostname', async () => {
    const r = await tlsCase({});
    expect(by(r.indicators, 'TLS_VALID')).toHaveLength(1);
    expect(r.artifacts.tls[0]).toMatchObject({ authorized: true, hostnameMatches: true });
  });

  it('accepts a shared certificate whose subject is another tenant when the SAN covers the host', async () => {
    const r = await tlsCase({ subjectCN: () => 'food4fitness.com.au', sansFor: sharedSans });
    expect(by(r.indicators, 'TLS_VALID')).toHaveLength(1);
    expect(by(r.indicators, 'TLS_SHARED_CERTIFICATE')[0]).toMatchObject({ polarity: 'neutral', severity: 'info' });
    expect(by(r.indicators, 'TLS_HOSTNAME_MISMATCH')).toHaveLength(0);
  });

  it('4. rejects a trusted certificate that does not cover the hostname, even though the chain is valid', async () => {
    const r = await tlsCase({ sansFor: () => ['other.example.net'] });
    expect(by(r.indicators, 'TLS_HOSTNAME_MISMATCH')).toHaveLength(1);
    expect(by(r.indicators, 'TLS_VALID')).toHaveLength(0);
    expect(r.assessment.positiveEvidence?.find((f) => f.family === 'transport')).toBeUndefined();
  });

  it('5. flags expired certificates', async () => {
    const r = await tlsCase({ issuedDaysAgo: 200, validityDays: 90 });
    expect(by(r.indicators, 'TLS_EXPIRED')[0]!.severity).toBe('medium');
    expect(by(r.indicators, 'TLS_VALID')).toHaveLength(0);
  });

  it('6. flags untrusted chains', async () => {
    const r = await tlsCase({ authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' });
    expect(by(r.indicators, 'TLS_UNTRUSTED_CHAIN')).toHaveLength(1);
    expect(by(r.indicators, 'TLS_VALID')).toHaveLength(0);
  });

  it('records an incomplete handshake as unknown, not as positive or negative evidence', async () => {
    const r = await tlsCase({ fail: new Error('TLS handshake timed out after 6000 ms') });
    const u = by(r.indicators, 'TLS_UNREACHABLE')[0]!;
    expect(u.polarity).toBe('unknown');
    expect(r.assessment.score).toBe(0);
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.nextSteps!.join(' ')).toMatch(/unknown/);
  });

  it('treats disagreeing verification results between connections as unknown and does not count transport', async () => {
    const r = await scenario(
      { url: 'https://app.example.org/' },
      site('example.org', { 'https://app.example.org/': { ...html(), tls: { authorized: false, error: 'CERT_HAS_EXPIRED', fingerprint256: null } } }, { ageDays: 3000 }),
    );
    expect(by(r.indicators, 'CORR_TLS_OBSERVATION_CONFLICT')[0]!.polarity).toBe('unknown');
    expect(r.assessment.positiveEvidence!.find((f) => f.family === 'transport')!.counted).toBe(false);
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.conflicts!.join(' ')).toMatch(/Transport security \(HTTPS\) not counted/);
  });
});

describe('redirect and collection failures', () => {
  it('7. redirect loops leave the upgrade unverified', async () => {
    const r = await scenario({ url: 'http://loop.example.org/' }, site('example.org', { 'http://loop.example.org/': { status: 302, headers: { location: 'https://loop.example.org/' } }, 'https://loop.example.org/': { status: 302, headers: { location: 'http://loop.example.org/' } } }));
    expect(by(r.indicators, 'REDIRECT_UNRESOLVED')).toHaveLength(1);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(0);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UNVERIFIED')).toHaveLength(1);
  });

  it('8. an HTTP link that upgrades onto an unrelated domain is not a same-site upgrade', async () => {
    const r = await scenario(
      { url: 'http://start.example.org/' },
      { ...site('example.org', { 'http://start.example.org/': { status: 301, headers: { location: 'https://landing.unrelated.example/' } }, 'https://landing.unrelated.example/': html() }) },
    );
    expect(by(r.indicators, 'REDIRECT_CROSS_DOMAIN')).toHaveLength(1);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(0);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UNVERIFIED')[0]!.description).toMatch(/different site/);
  });

  it('9. a DNS failure blocks a benign verdict and is named as a next step', async () => {
    const dns = { description: 'broken', resolve: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }); }, reverse: async () => [] };
    const r = await scenario({ url: 'https://app.example.org/' }, { ...site('example.org', { 'https://app.example.org/': html() }, { ageDays: 3000 }), dns });
    expect(r.analyzerRuns.find((x) => x.analyzer === 'dns')!.status).toBe('failed');
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.nextSteps!.join(' ')).toMatch(/dns collection gap/);
  });

  it('10. an RDAP failure blocks a benign verdict', async () => {
    const s = site('example.org', { 'https://app.example.org/': html() });
    const http = fakeHttp({ 'https://app.example.org/': html(), 'https://rdap.test/domain/example.org': { status: 503 } });
    const r = await scenario({ url: 'https://app.example.org/' }, { ...s, http });
    expect(r.analyzerRuns.find((x) => x.analyzer === 'rdap')!.status).toBe('failed');
    expect(r.assessment.verdict).toBe('inconclusive');
  });

  it('11. a timed-out scan is reported as incomplete, never as evidence', async () => {
    const http = fakeHttp({ 'http://slow.example.org/': new Error('request timed out after 6000 ms') });
    const r = await scenario({ url: 'http://slow.example.org/' }, { ...site('example.org', {}), http });
    expect(r.artifacts.redirects[0]!.status).toBe('failed');
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(0);
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UNVERIFIED')[0]!.description).toMatch(/timed out/);
    expect(r.assessment.verdict).toBe('inconclusive');
  });
});

describe('positive-evidence correlation and verdict policy', () => {
  it('12. surfaces conflicts and lets risk take precedence over positive evidence', async () => {
    const r = await scenario(
      { url: 'https://paypall.com/' },
      { dns: fakeDns({ 'paypall.com': { A: ['93.184.216.81'] } }), http: fakeHttp({ 'https://paypall.com/': html(), 'https://rdap.test/domain/paypall.com': rdapResponse(4000) }), tls: fakeTls() },
    );
    expect(r.assessment.verdict).toBe('suspicious');
    expect(r.assessment.conflicts!.join(' ')).toMatch(/coexists with risk findings: .*near-miss spelling of PayPal/);
  });

  it('13. correlated signals count once: certificate + upgrade, and SPF + DKIM + DMARC', () => {
    const mk = (code: string, category: Indicator['category']): Indicator => ({
      id: code, code, category, title: code, description: '', severity: 'info', confidence: 1, polarity: 'benign', evidence: 'e', source: 's', provenance: 'network', analyzer: 'a', timestamp: '',
    });
    const fams = groupPositiveEvidence([
      mk('TLS_VALID', 'TLS'),
      mk('TRANSPORT_HTTPS_UPGRADE', 'REDIRECT'),
      mk('EMAIL_SPF_PASS', 'EMAIL_AUTHENTICATION'),
      mk('EMAIL_DKIM_PASS', 'EMAIL_AUTHENTICATION'),
      mk('EMAIL_DMARC_PASS', 'EMAIL_AUTHENTICATION'),
    ]);
    expect(fams.map((f) => [f.family, f.indicatorIds.length, f.class])).toEqual([
      ['transport', 2, 'security_control'],
      ['sender_authentication', 3, 'security_control'],
    ]);
  });

  it('two security-control families without corroboration are not enough for benign', () => {
    // Attackers obtain certificates, HTTPS redirects and DMARC on their own domains for free.
    const mk = (code: string): Indicator => ({ id: code, code, category: 'TLS', title: code, description: '', severity: 'info', confidence: 1, polarity: 'benign', evidence: 'e', source: 's', provenance: 'network', analyzer: 'a', timestamp: '' });
    const fams = groupPositiveEvidence([mk('TLS_VALID'), mk('EMAIL_DMARC_PASS')]);
    expect(fams.every((f) => f.class === 'security_control')).toBe(true);
  });

  it('14. low risk with sufficient independent evidence (transport + registration maturity) is benign', async () => {
    const f = hustlanceLike('long-established.com', { ageDays: 3000 });
    const r = await scenario(f.input, f.services);
    expect(r.assessment.verdict).toBe('benign');
    expect(r.assessment.positiveEvidence!.map((x) => x.family).sort()).toEqual(['registration_maturity', 'transport']);
    expect(r.assessment.rationale.join(' ')).toMatch(/2 independent positive-evidence families/);
  });

  it('verified identity via the watchlist also corroborates', async () => {
    const f = hustlanceLike('studenthub.example');
    const r = await scenario(f.input, f.services, { brands: [brand('StudentHub', ['studenthub'], ['studenthub.example'])] });
    expect(r.assessment.verdict).toBe('benign');
    expect(r.assessment.positiveEvidence!.map((x) => x.family).sort()).toEqual(['identity', 'transport']);
  });

  it('15. low risk without sufficient independent evidence stays inconclusive', async () => {
    const f = hustlanceLike('young-site.com', { ageDays: 120 });
    const r = await scenario(f.input, f.services);
    expect(r.assessment.score).toBeLessThan(10);
    expect(r.assessment.verdict).toBe('inconclusive');
  });

  it('16. critical findings escalate regardless of positive evidence', async () => {
    const r = await scenario(
      { url: 'https://paypal.com.account-check.example/login' },
      {
        dns: fakeDns({ 'paypal.com.account-check.example': { A: ['93.184.216.82'] } }),
        http: fakeHttp({ 'https://paypal.com.account-check.example/login': html('<input type="password">'), 'https://rdap.test/domain/account-check.example': rdapResponse(4000) }),
        tls: fakeTls(),
      },
    );
    expect(by(r.indicators, 'TLS_VALID')).toHaveLength(1);
    expect(by(r.indicators, 'RDAP_ESTABLISHED')).toHaveLength(1);
    expect(r.assessment.verdict).toBe('high_risk');
    expect(r.assessment.rationale[0]).toMatch(/critical/);
  });

  it('17. high findings in two categories escalate to high risk', async () => {
    const r = await scenario(
      { url: 'https://paypa1.com/', message: '<a href="https://paypa1.com/">https://www.paypal.com/</a>' },
      { dns: fakeDns({ 'paypa1.com': { A: ['93.184.216.83'] } }), http: fakeHttp({ 'https://paypa1.com/': html(), 'https://rdap.test/domain/paypa1.com': rdapResponse(4000) }), tls: fakeTls() },
    );
    expect(r.assessment.verdict).toBe('high_risk');
    expect(r.assessment.rationale.join(' ')).toMatch(/independent categories/);
  });

  it('a medium risk finding prevents benign even when the score stays below 10', async () => {
    const f = hustlanceLike('old-ip-site.com', { ageDays: 3000 });
    const r = await scenario({ url: 'http://old-ip-site.com/?email=someone@corp.example' }, {
      ...f.services,
      http: fakeHttp({
        'http://old-ip-site.com/?email=someone@corp.example': { status: 301, headers: { location: 'https://old-ip-site.com/' } },
        'https://old-ip-site.com/': html(),
        'https://rdap.test/domain/old-ip-site.com': rdapResponse(3000),
      }),
    });
    expect(by(r.indicators, 'URL_RECIPIENT_EMAIL')[0]!.severity).toBe('medium');
    expect(r.assessment.score).toBeLessThan(10);
    expect(r.assessment.verdict).toBe('inconclusive');
  });
});

describe('18. Hustlance regression (supplied evidence)', () => {
  it('classifies by evidence: verified transport only → Inconclusive, with every observation preserved', async () => {
    const f = hustlanceLike();
    const r = await scenario(f.input, f.services);
    const codes = r.indicators.map((i) => i.code);

    // HTTP observation preserved, transport assessed once, calibrated residual for the plaintext first hop
    expect(by(r.indicators, 'URL_PLAINTEXT_HTTP')[0]).toMatchObject({ severity: 'info', polarity: 'neutral' });
    expect(by(r.indicators, 'TRANSPORT_HTTPS_UPGRADE')).toHaveLength(1);
    expect(by(r.indicators, 'TRANSPORT_HTTP_FIRST_REQUEST')).toHaveLength(1);
    expect(codes).not.toContain('TRANSPORT_HTTPS_UNVERIFIED');
    expect(r.artifacts.redirects[0]!.hops.map((h) => [h.statusCode, h.scheme])).toEqual([[301, 'http'], [200, 'https']]);
    expect(classifyHttpTransport(r.artifacts.redirects[0]).outcome).toBe('upgraded');

    // Final HTTPS response assessed separately: page and certificate
    expect(r.artifacts.redirects[0]!.page).toMatchObject({ hasPasswordField: false, formActions: [] });
    const tls = r.artifacts.tls.find((t) => t.host === 'hustlance.com')!;
    expect(tls).toMatchObject({ authorized: true, hostnameMatches: true });
    expect(tls.certificate!.subjectCN).toBe('food4fitness.com.au');
    expect(tls.certificate!.sans).toHaveLength(100);
    expect(codes).toEqual(expect.arrayContaining(['TLS_VALID', 'TLS_SAN_MATCH', 'TLS_SHARED_CERTIFICATE']));
    expect(codes).not.toContain('TLS_HOSTNAME_MISMATCH');

    // Infrastructure and registration are context, not positive evidence
    const providers = r.artifacts.dns.find((d) => d.name === 'hustlance.com')!.providers.map((p) => p.name);
    expect(providers).toEqual(expect.arrayContaining(['GoDaddy DNS', 'Firebase Hosting']));
    expect(by(r.indicators, 'RDAP_REGISTRATION_AGE')[0]).toMatchObject({ polarity: 'neutral' });
    expect(by(r.indicators, 'RDAP_REGISTRAR')[0]!.evidence).toContain('GoDaddy.com, LLC');

    // Correlated TLS attributes + upgrade = one family; no corroboration → Inconclusive
    const fams = r.assessment.positiveEvidence!;
    expect(fams).toHaveLength(1);
    expect(fams[0]).toMatchObject({ family: 'transport', class: 'security_control', counted: true });
    expect(fams[0]!.indicatorIds).toHaveLength(2);
    expect(r.assessment.score).toBe(1);
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.rationale.join(' ')).toMatch(/Only 1 independent positive-evidence family: Transport security/);
    expect(r.assessment.rationale.join(' ')).toMatch(/corroboration .* is required/);
    expect(r.assessment.nextSteps!.join(' ')).toMatch(/401 days/);
    expect(r.assessment.conflicts).toEqual([]);
  });

  it('equivalent evidence under another name gets the identical result (no allowlist)', async () => {
    const a = hustlanceLike();
    const b = hustlanceLike('gigsprout.com'); // same structure: one label, .com, no hyphens or digits
    const ra = await scenario(a.input, a.services);
    const rb = await scenario(b.input, b.services);
    expect([rb.assessment.verdict, rb.assessment.score]).toEqual([ra.assessment.verdict, ra.assessment.score]);
    expect(rb.indicators.map((i) => i.code).sort()).toEqual(ra.indicators.map((i) => i.code).sort());
  });
});

describe('analyst-facing report', () => {
  it('explains polarity, correlation, the verdict and how to resolve it — never as a probability', async () => {
    const { renderMarkdown } = await import('../../src/services/reportService.js');
    const f = hustlanceLike();
    const r = await scenario(f.input, f.services);
    const md = renderMarkdown({
      id: '00000000-0000-4000-8000-000000000000', title: 'hustlance.com', status: 'completed', verdict: r.assessment.verdict, score: r.assessment.score,
      indicatorCount: r.indicators.length, riskIndicatorCount: 1, inputTypes: ['url'], createdAt: '', completedAt: '', inputs: [],
      indicators: r.indicators, assessment: r.assessment, artifacts: r.artifacts, graph: r.graph, timeline: [], analyzerRuns: r.analyzerRuns, error: null,
    });
    expect(md).toContain('**Positive evidence (independent families):**');
    expect(md).toContain('Transport security (HTTPS)** (security control; counted once)');
    expect(md).toContain('**To resolve this result:**');
    expect(md).toContain('neutral (context only)');
    expect(md).toContain('not a probability');
    expect(md).not.toMatch(/\d+\s?% (chance|probability|likely)|score[^.\n]*\bis (a|the) probability/i);
  });
});
