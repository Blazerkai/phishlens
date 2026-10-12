import { describe, expect, it } from 'vitest';
import type { Indicator, OperatorVerification } from '@phishlens/shared';
import { fakeHttp } from '../fakes.js';
import { scenario } from '../scenario.js';
import { brand } from '../helpers.js';
import { hustlanceLike } from '../fixtures/hustlance.js';
import { createProviders } from '../../src/services/reputation/providers.js';
import { createReputationService, memoryCache } from '../../src/services/reputation/index.js';
import { REP_CFG, URLS, json, trancoRanks, vtDomain } from '../reputationFakes.js';

const by = (inds: Indicator[], code: string) => inds.filter((i) => i.code === code);

/** Reputation service backed by fake provider endpoints for one domain. */
function reputation(domain: string, r: { gsb?: unknown; urlhaus?: unknown; vt?: unknown; tranco?: unknown } & { fail?: boolean }) {
  const routes: Parameters<typeof fakeHttp>[0] = r.fail
    ? {}
    : {
        [URLS.gsb]: json(200, r.gsb ?? {}),
        [URLS.urlhaus]: json(200, r.urlhaus ?? { query_status: 'no_results' }),
        [URLS.vt(domain)]: json(200, r.vt ?? vtDomain(0)),
        [URLS.tranco(domain)]: json(200, r.tranco ?? { ranks: [] }),
      };
  return createReputationService({
    providers: createProviders({ ...REP_CFG, staleAfterDays: 7 }),
    http: fakeHttp(routes),
    cache: memoryCache(),
    timeoutMs: 1000,
    cacheTtlHours: 24,
    sleep: async () => {},
  });
}

function verification(domain: string, over: Partial<OperatorVerification> = {}): OperatorVerification {
  return {
    id: 1,
    domain,
    operatorName: 'Example Operator Ltd',
    method: 'legal_entity_registry',
    evidenceReference: 'Companies House 01234567, director contacted via registered office',
    verifiedBy: 'analyst@corp.example',
    verifiedAt: new Date(Date.now() - 86_400_000).toISOString(),
    expiresAt: new Date(Date.now() + 300 * 86_400_000).toISOString(),
    revokedAt: null,
    notes: null,
    ...over,
  };
}

async function run(domain: string, rep: ReturnType<typeof reputation> | undefined, opts: Parameters<typeof scenario>[2] = {}) {
  const f = hustlanceLike(domain);
  return scenario(f.input, { ...f.services, ...(rep ? { reputation: rep } : {}) }, opts);
}

describe('acceptance: legitimate vs unverified low-risk domains', () => {
  it('without reputation or identity, a low-risk domain stays Inconclusive and says what is missing', async () => {
    const r = await run('freelance-a.com', undefined);
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.analyzerRuns.find((x) => x.analyzer === 'reputation')!.status).toBe('unavailable');
    expect(r.assessment.nextSteps!.join(' ')).toMatch(/Reputation was not checked/);
  });

  it('clean results from every blocklist do NOT make it benign', async () => {
    const r = await run('freelance-b.com', reputation('freelance-b.com', {}));
    expect(by(r.indicators, 'REPUTATION_NO_LISTING')[0]).toMatchObject({ polarity: 'neutral' });
    expect(r.assessment.verdict).toBe('inconclusive');
  });

  it('sustained popularity corroborates transport security → Benign', async () => {
    const r = await run('popular-site.com', reputation('popular-site.com', { tranco: trancoRanks(4000) }));
    expect(r.assessment.positiveEvidence!.map((f) => f.family).sort()).toEqual(['reputation_popularity', 'transport']);
    expect(r.assessment.verdict).toBe('benign');
  });

  it('an independently verified operator corroborates transport security → Benign', async () => {
    const r = await run('verified-op.com', undefined, { identities: [verification('verified-op.com')] });
    expect(by(r.indicators, 'IDENTITY_VERIFIED')[0]).toMatchObject({ polarity: 'benign', provenance: 'user_input' });
    expect(r.assessment.verdict).toBe('benign');
  });

  it('Hustlance-equivalent evidence + verified operator is Benign; without it, Inconclusive (same general rule)', async () => {
    expect((await run('hustlance.com', undefined)).assessment.verdict).toBe('inconclusive');
    expect((await run('hustlance.com', undefined, { identities: [verification('hustlance.com')] })).assessment.verdict).toBe('benign');
  });
});

describe('identity workflow safeguards', () => {
  it('watchlist entry and analyst verification express one claim and count once', async () => {
    const r = await run('dual-claim.com', undefined, {
      identities: [verification('dual-claim.com')],
      brands: [brand('DualClaim', ['dualclaim'], ['dual-claim.com'])],
    });
    const identity = r.assessment.positiveEvidence!.filter((f) => f.family === 'identity');
    expect(identity).toHaveLength(1);
    expect(identity[0]!.indicatorIds).toHaveLength(2);
  });

  it('expired verifications are unknown and do not count', async () => {
    const r = await run('expired-op.com', undefined, { identities: [verification('expired-op.com', { expiresAt: new Date(Date.now() - 1000).toISOString() })] });
    expect(by(r.indicators, 'IDENTITY_VERIFICATION_EXPIRED')[0]!.polarity).toBe('unknown');
    expect(r.assessment.verdict).toBe('inconclusive');
  });

  it('revoked verifications are ignored entirely', async () => {
    const r = await run('revoked-op.com', undefined, { identities: [verification('revoked-op.com', { revokedAt: new Date().toISOString() })] });
    expect(r.indicators.filter((i) => i.category === 'IDENTITY')).toEqual([]);
    expect(r.assessment.verdict).toBe('inconclusive');
  });

  it('a verified domain that is only linked or redirected away from does not vouch for the destination', async () => {
    const f = hustlanceLike('landing-x.com');
    const r = await scenario(
      { url: 'http://landing-x.com/', message: 'See <a href="https://verified-elsewhere.com/">our partner</a>' },
      f.services,
      { identities: [verification('verified-elsewhere.com')] },
    );
    expect(by(r.indicators, 'IDENTITY_VERIFIED')).toHaveLength(0);
    expect(by(r.indicators, 'IDENTITY_VERIFIED_RELATED')[0]!.polarity).toBe('neutral');
    expect(r.assessment.verdict).toBe('inconclusive');
  });

  it('a verified operator never offsets a medium risk finding', async () => {
    const f = hustlanceLike('verified-but-odd.com');
    const r = await scenario({ url: 'http://verified-but-odd.com/?email=victim@corp.example' }, {
      ...f.services,
      http: fakeHttp({
        'http://verified-but-odd.com/?email=victim@corp.example': { status: 301, headers: { location: 'https://verified-but-odd.com/' } },
        'https://verified-but-odd.com/': { status: 200, headers: { 'content-type': 'text/html' }, body: '<title>x</title>' },
        'https://rdap.test/domain/verified-but-odd.com': json(200, { events: [] }),
      }),
    }, { identities: [verification('verified-but-odd.com')] });
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.rationale.join(' ')).toMatch(/medium severity present/);
  });
});

describe('malicious, conflicting and failing reputation', () => {
  it('a known-malicious listing makes the verdict at least Suspicious, even for a verified, popular domain', async () => {
    const d = 'listed-once.com';
    const r = await run(d, reputation(d, { gsb: { matches: [{ threatType: 'SOCIAL_ENGINEERING', threat: { url: `http://${d}/` } }] }, tranco: trancoRanks(4000) }), { identities: [verification(d)] });
    expect(by(r.indicators, 'REPUTATION_LISTED')[0]!.severity).toBe('high');
    expect(r.assessment.verdict).toBe('suspicious');
    const fams = r.assessment.positiveEvidence!;
    expect(fams.find((f) => f.family === 'reputation_popularity')!.counted).toBe(false);
    expect(fams.find((f) => f.family === 'identity')!.counted).toBe(false);
    expect(r.assessment.conflicts!.join(' ')).toMatch(/contradicted by a reputation listing/);
  });

  it('independent providers confirming a listing escalate to High risk (critical rule preserved)', async () => {
    const d = 'listed-twice.com';
    const r = await run(d, reputation(d, {
      gsb: { matches: [{ threatType: 'MALWARE', threat: { url: `http://${d}/` } }] },
      urlhaus: { query_status: 'ok', url_count: 1, urls: [{ url_status: 'online', date_added: '2026-10-10 08:00:00 UTC', threat: 'malware_download' }] },
    }));
    expect(by(r.indicators, 'REPUTATION_CORROBORATED_MALICIOUS')[0]!.severity).toBe('critical');
    expect(r.assessment.verdict).toBe('high_risk');
  });

  it('a VirusTotal minority detection is weak and does not by itself block corroborated Benign', async () => {
    const d = 'fp-report.com';
    const r = await run(d, reputation(d, { vt: vtDomain(1, ['OneVendor']), tranco: trancoRanks(4000) }));
    expect(by(r.indicators, 'REPUTATION_MINORITY_DETECTION')[0]!.severity).toBe('low');
    expect(r.assessment.verdict).toBe('benign');
  });

  it('every provider failing is reported as unknown, the verdict stays Inconclusive, and the gap is named', async () => {
    const r = await run('all-down.com', reputation('all-down.com', { fail: true }));
    expect(by(r.indicators, 'REPUTATION_UNKNOWN').length).toBe(4);
    expect(by(r.indicators, 'REPUTATION_UNKNOWN').every((i) => i.polarity === 'unknown')).toBe(true);
    expect(r.analyzerRuns.find((x) => x.analyzer === 'reputation')!.status).toBe('failed');
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.nextSteps!.join(' ')).toMatch(/Reputation was not checked/);
  });

  it('HSTS joins the transport family without adding an independent family', async () => {
    const f = hustlanceLike('hsts-site.com', { hsts: 'max-age=31556926' });
    const r = await scenario(f.input, f.services);
    expect(by(r.indicators, 'TRANSPORT_HSTS')).toHaveLength(1);
    const fams = r.assessment.positiveEvidence!;
    expect(fams.map((x) => x.family)).toEqual(['transport']);
    expect(fams[0]!.indicatorIds).toHaveLength(3);
    expect(r.assessment.verdict).toBe('inconclusive');
  });
});
