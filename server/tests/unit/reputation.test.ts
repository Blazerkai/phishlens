import { describe, expect, it } from 'vitest';
import {
  createProviders,
  parseSafeBrowsing,
  parseTranco,
  parseUrlhausHost,
  parseVirusTotalDomain,
  sourceKey,
  ProviderError,
} from '../../src/services/reputation/providers.js';
import { createReputationService, memoryCache } from '../../src/services/reputation/index.js';
import { reputationIndicators } from '../../src/analyzers/reputation/index.js';
import { hstsIndicators, parseHsts } from '../../src/analyzers/redirects/transport.js';
import { fakeHttp } from '../fakes.js';
import { NOW, REP_CFG, URLS, json, trancoRanks, vtDomain } from '../reputationFakes.js';
import type { ReputationObservation } from '@phishlens/shared';

describe('provider response parsers (documented shapes)', () => {
  it('Safe Browsing: empty object means no match; matches mean listed', () => {
    expect(parseSafeBrowsing({}).status).toBe('not_listed');
    const r = parseSafeBrowsing({ matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threatEntryType: 'URL', threat: { url: 'http://x.example/' }, cacheDuration: '300.000s' }] });
    expect(r).toMatchObject({ status: 'listed', underlyingSources: ['Google Safe Browsing'] });
    expect(() => parseSafeBrowsing('nope')).toThrow(ProviderError);
  });

  it('URLhaus: no_results, online listing, historical-only, and the documented "query_staus" spelling', () => {
    expect(parseUrlhausHost({ query_status: 'no_results' }, NOW).status).toBe('not_listed');
    const online = parseUrlhausHost(
      { query_staus: 'ok', url_count: '2', blacklists: { spamhaus_dbl: 'abused_legit_malware', surbl: 'not listed' }, urls: [{ url_status: 'online', date_added: '2026-10-10 08:00:00 UTC', threat: 'malware_download' }, { url_status: 'offline', date_added: '2026-09-01 08:00:00 UTC', threat: 'malware_download' }] },
      NOW,
    );
    expect(online).toMatchObject({ status: 'listed', underlyingSources: ['URLhaus', 'Spamhaus DBL'], dataDate: '2026-10-10T08:00:00.000Z' });
    expect(parseUrlhausHost({ query_status: 'ok', url_count: 1, urls: [{ url_status: 'offline', date_added: '2025-01-01 00:00:00 UTC' }] }, NOW).status).toBe('historical');
    expect(() => parseUrlhausHost({ query_status: 'invalid_host' }, NOW)).toThrow(/invalid_host/);
  });

  it('VirusTotal: majority listing, minority (false-positive pattern), none, malformed', () => {
    expect(parseVirusTotalDomain(vtDomain(7, ['Kaspersky', 'ESET', 'Fortinet', 'Sophos', 'BitDefender', 'G-Data', 'Avira'])).status).toBe('listed');
    const minority = parseVirusTotalDomain(vtDomain(2, ['OneVendor', 'OtherVendor']));
    expect(minority).toMatchObject({ status: 'minority', underlyingSources: ['OneVendor', 'OtherVendor'] });
    expect(parseVirusTotalDomain(vtDomain(0)).status).toBe('not_listed');
    expect(() => parseVirusTotalDomain({ data: {} })).toThrow(ProviderError);
  });

  it('Tranco: sustained rank is popular, sporadic is not, old list data is stale, unranked is not popular', () => {
    const opts = { rankThreshold: 100000, minDays: 25, staleAfterDays: 7, now: NOW };
    expect(parseTranco(trancoRanks(5000), opts).status).toBe('popular');
    expect(parseTranco(trancoRanks(5000, 10), opts).status).toBe('not_popular');
    expect(parseTranco(trancoRanks(500000), opts).status).toBe('not_popular');
    expect(parseTranco(trancoRanks(5000, 30, 20), opts).status).toBe('stale');
    expect(parseTranco({ ranks: [] }, opts).status).toBe('not_popular');
    expect(() => parseTranco({}, opts)).toThrow(ProviderError);
  });

  it('normalises source names for independence checks', () => {
    expect(sourceKey('Google Safebrowsing')).toBe(sourceKey('Google Safe Browsing'));
    expect(sourceKey('URLhaus')).toBe('urlhaus');
  });
});

function service(routes: Parameters<typeof fakeHttp>[0], cfg: Partial<typeof REP_CFG> = {}, cache = memoryCache(), now = () => NOW) {
  const http = fakeHttp(routes);
  return { svc: createReputationService({ providers: createProviders({ ...REP_CFG, ...cfg }), http, cache, timeoutMs: 1000, cacheTtlHours: 24, now, sleep: async () => {} }), http, cache };
}

describe('reputation service', () => {
  it('reports missing credentials as not configured and queries nothing', async () => {
    const { svc, http } = service({}, { gsbApiKey: undefined, urlhausAuthKey: undefined, virustotalApiKey: undefined, trancoEnabled: false });
    expect(svc.enabled).toBe(false);
    expect(svc.providers.every((p) => !p.configured)).toBe(true);
    expect(await svc.lookup([{ domain: 'a.example', urls: [] }])).toEqual([]);
    expect(http.calls).toEqual([]);
  });

  it('turns HTTP errors, malformed bodies and timeouts into error results, never clean ones', async () => {
    const { svc } = service(
      { [URLS.gsb]: { status: 500 }, [URLS.urlhaus]: { status: 200, body: 'not json' }, [URLS.vt('a.example')]: new Error('request timed out after 1000 ms') },
      { trancoEnabled: false },
    );
    const r = await svc.lookup([{ domain: 'a.example', urls: [] }]);
    expect(r.map((o) => [o.provider, o.status])).toEqual([['gsb', 'error'], ['urlhaus', 'error'], ['virustotal', 'error']]);
    expect(r.find((o) => o.provider === 'virustotal')!.summary).toMatch(/timed out/);
    // credentials never leak into results
    expect(JSON.stringify(r)).not.toMatch(/GSBKEY|UHKEY|VTKEY/);
  });

  it('caches successful results, and serves an expired entry only as stale when the live call fails', async () => {
    let now = NOW;
    const cache = memoryCache();
    const first = service({ [URLS.tranco('a.example')]: json(200, trancoRanks(1000)) }, { gsbApiKey: undefined, urlhausAuthKey: undefined, virustotalApiKey: undefined }, cache, () => now);
    expect((await first.svc.lookup([{ domain: 'a.example', urls: [] }]))[0]!.status).toBe('popular');

    now = new Date(NOW.getTime() + 3_600_000); // within TTL → cached, no call
    const second = service({}, { gsbApiKey: undefined, urlhausAuthKey: undefined, virustotalApiKey: undefined }, cache, () => now);
    const cached = (await second.svc.lookup([{ domain: 'a.example', urls: [] }]))[0]!;
    expect(cached).toMatchObject({ status: 'popular', cached: true });
    expect(second.http.calls).toEqual([]);

    now = new Date(NOW.getTime() + 48 * 3_600_000); // expired, provider down → stale, not popular
    const third = service({ [URLS.tranco('a.example')]: { status: 503 } }, { gsbApiKey: undefined, urlhausAuthKey: undefined, virustotalApiKey: undefined }, cache, () => now);
    const stale = (await third.svc.lookup([{ domain: 'a.example', urls: [] }]))[0]!;
    expect(stale).toMatchObject({ status: 'stale', cached: true });
    expect(stale.details.lastKnownStatus).toBe('popular');
  });

  it('applies documented quota spacing: a second VirusTotal call within 15 s is reported unavailable, not made', async () => {
    const { svc, http } = service(
      { [URLS.vt('a.example')]: json(200, vtDomain(0)), [URLS.vt('b.example')]: json(200, vtDomain(0)) },
      { gsbApiKey: undefined, urlhausAuthKey: undefined, trancoEnabled: false },
    );
    const r = await svc.lookup([{ domain: 'a.example', urls: [] }, { domain: 'b.example', urls: [] }]);
    expect(r.map((o) => o.status)).toEqual(['not_listed', 'unavailable']);
    expect(http.calls).toHaveLength(1);
  });
});

const obs = (provider: ReputationObservation['provider'], status: ReputationObservation['status'], underlyingSources: string[] = [], extra: Partial<ReputationObservation> = {}): ReputationObservation => ({
  provider,
  providerName: { gsb: 'Google Safe Browsing', urlhaus: 'URLhaus (abuse.ch)', virustotal: 'VirusTotal', tranco: 'Tranco popularity ranking' }[provider],
  subject: 'x.example',
  status,
  summary: status,
  underlyingSources,
  details: {},
  fetchedAt: NOW.toISOString(),
  dataDate: null,
  cached: false,
  reference: null,
  ...extra,
});
const codes = (o: ReputationObservation[]) => reputationIndicators(o).map((i) => `${i.code}:${i.severity}:${i.polarity ?? 'risk'}`);

describe('reputation indicators', () => {
  it('clean results are neutral, never positive', () => {
    expect(codes([obs('gsb', 'not_listed'), obs('urlhaus', 'not_listed'), obs('virustotal', 'not_listed')])).toEqual(['REPUTATION_NO_LISTING:info:neutral']);
  });

  it('a single listing is high; independent listings escalate to critical', () => {
    expect(codes([obs('gsb', 'listed', ['Google Safe Browsing'])])).toEqual(['REPUTATION_LISTED:high:risk']);
    expect(codes([obs('gsb', 'listed', ['Google Safe Browsing']), obs('urlhaus', 'listed', ['URLhaus'])])).toContain('REPUTATION_CORROBORATED_MALICIOUS:critical:risk');
  });

  it('does not double-count VirusTotal when its detections only repeat a direct provider', () => {
    const dup = [obs('gsb', 'listed', ['Google Safe Browsing']), obs('virustotal', 'listed', ['Google Safebrowsing'])];
    expect(codes(dup)).not.toContain('REPUTATION_CORROBORATED_MALICIOUS:critical:risk');
    const indep = [obs('gsb', 'listed', ['Google Safe Browsing']), obs('virustotal', 'listed', ['Google Safebrowsing', 'Kaspersky'])];
    expect(codes(indep)).toContain('REPUTATION_CORROBORATED_MALICIOUS:critical:risk');
  });

  it('minority detections (false-positive pattern) are low weight', () => {
    expect(codes([obs('virustotal', 'minority', ['OneVendor'])])).toEqual(['REPUTATION_MINORITY_DETECTION:low:risk']);
  });

  it('errors, unavailability and stale data are unknown; a stale listing stays visible as moderate risk', () => {
    expect(codes([obs('gsb', 'error'), obs('tranco', 'unavailable'), obs('tranco', 'stale', [], { details: { lastKnownStatus: 'popular' } })])).toEqual([
      'REPUTATION_UNKNOWN:info:unknown',
      'REPUTATION_UNKNOWN:info:unknown',
      'REPUTATION_UNKNOWN:info:unknown',
    ]);
    expect(codes([obs('gsb', 'stale', [], { details: { lastKnownStatus: 'listed' } })])).toEqual(['REPUTATION_LISTED_STALE:medium:risk']);
  });

  it('sustained popularity is positive corroboration', () => {
    expect(codes([obs('tranco', 'popular', ['Tranco'])])).toEqual(['REPUTATION_POPULAR:info:benign']);
  });
});

describe('HSTS', () => {
  it('parses RFC 6797 directives', () => {
    expect(parseHsts('max-age=31556926; includeSubDomains; preload')).toEqual({ maxAge: 31556926, includeSubDomains: true, preload: true });
    expect(parseHsts('max-age="600"')).toMatchObject({ maxAge: 600 });
    expect(parseHsts('includeSubDomains')).toBeNull();
    expect(parseHsts(null)).toBeNull();
  });

  it('credits HSTS only on a verified HTTPS response with max-age > 0', () => {
    const chain = (hsts: string, authorized = true) => ({
      startUrl: 'https://a.example/', status: 'completed' as const, redirectCount: 0, finalUrl: 'https://a.example/', inspectedAt: '',
      hops: [{ index: 0, url: 'https://a.example/', scheme: 'https', hostname: 'a.example', kind: 'final' as const, statusCode: 200, hsts, tls: { authorized, error: null, fingerprint256: null } }],
    });
    expect(hstsIndicators(chain('max-age=31536000')).map((i) => [i.code, i.polarity])).toEqual([['TRANSPORT_HSTS', 'benign']]);
    expect(hstsIndicators(chain('max-age=0')).map((i) => [i.code, i.polarity])).toEqual([['TRANSPORT_HSTS_DISABLED', 'neutral']]);
    expect(hstsIndicators(chain('max-age=31536000', false))).toEqual([]);
  });
});
