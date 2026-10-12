import type { ReputationObservation, ReputationProviderId, ReputationProviderInfo } from '@phishlens/shared';
import type { HttpService } from '../network/types.js';
import type { ReputationConfig } from '../../config/index.js';

/**
 * Reputation providers. Each wraps one documented API:
 *   Google Safe Browsing v4 Lookup – https://developers.google.com/safe-browsing/v4/lookup-api
 *   URLhaus host lookup            – https://urlhaus-api.abuse.ch/
 *   VirusTotal v3 domain object    – https://docs.virustotal.com/reference/domain-info
 *   Tranco rank lookup             – https://tranco-list.eu/api_documentation
 *
 * Parsers are pure functions of the documented response shapes. A response the
 * parser does not understand is an error, never a clean result.
 */

export interface LookupTarget {
  /** Registrable domain. */
  domain: string;
  /** Full URLs on that domain observed in the investigation (for URL-level APIs). */
  urls: string[];
}

export interface ProviderContext {
  http: HttpService;
  timeoutMs: number;
  now: () => Date;
}

export type ProviderResult = Omit<ReputationObservation, 'provider' | 'providerName' | 'subject' | 'fetchedAt' | 'cached'>;

export interface ReputationProvider {
  info: ReputationProviderInfo;
  /** Minimum spacing between calls, from the provider's documented quota. */
  minIntervalMs: number;
  lookup(target: LookupTarget, ctx: ProviderContext): Promise<ProviderResult>;
}

export class ProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProviderError';
  }
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

function parseJson(body: Buffer, provider: string): unknown {
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    throw new ProviderError(`${provider} returned a response that is not JSON`);
  }
}

async function call(ctx: ProviderContext, provider: string, url: string, init: { method?: 'GET' | 'POST'; headers?: Record<string, string>; body?: string }) {
  let res;
  try {
    res = await ctx.http.request(url, { timeoutMs: ctx.timeoutMs, maxBodyBytes: 2 * 1024 * 1024, readBody: true, ...init });
  } catch (err) {
    // Never echo the request URL: it may carry an API key.
    throw new ProviderError(`${provider} request failed: ${/timed out/i.test((err as Error).message) ? 'timed out' : 'network error'}`);
  }
  return res;
}

// ---------------------------------------------------------------------------
// Google Safe Browsing (v4 Lookup API)
// ---------------------------------------------------------------------------

export function parseSafeBrowsing(json: unknown): ProviderResult {
  if (!json || typeof json !== 'object') throw new ProviderError('Safe Browsing response has an unexpected shape');
  const matches = (json as { matches?: { threatType?: string; threat?: { url?: string }; cacheDuration?: string }[] }).matches;
  if (matches === undefined) {
    return { status: 'not_listed', summary: 'No match on the Safe Browsing lists queried', underlyingSources: [], details: {}, dataDate: null, reference: null };
  }
  if (!Array.isArray(matches)) throw new ProviderError('Safe Browsing "matches" is not a list');
  const types = [...new Set(matches.map((m) => m.threatType ?? 'UNKNOWN'))];
  return {
    status: 'listed',
    summary: `Safe Browsing match: ${types.join(', ')} for ${[...new Set(matches.map((m) => m.threat?.url ?? '?'))].slice(0, 3).join(', ')}`,
    underlyingSources: ['Google Safe Browsing'],
    details: { threatTypes: types.join(','), matches: matches.length },
    dataDate: null,
    reference: 'https://transparencyreport.google.com/safe-browsing/search',
  };
}

export function safeBrowsingProvider(apiKey: string | undefined): ReputationProvider {
  return {
    info: {
      id: 'gsb',
      name: 'Google Safe Browsing',
      kind: 'blocklist',
      configured: !!apiKey,
      requirement: 'GSB_API_KEY (Google Cloud API key, free)',
      terms: 'Non-commercial use only; commercial deployments must use Google Web Risk (paid). Looked-up URLs are sent to Google.',
    },
    minIntervalMs: 0,
    async lookup(t, ctx) {
      if (!apiKey) throw new ProviderError('not configured');
      const urls = [...new Set([...t.urls, `http://${t.domain}/`, `https://${t.domain}/`])].slice(0, 20);
      const body = JSON.stringify({
        client: { clientId: 'phishlens', clientVersion: '0.1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map((url) => ({ url })),
        },
      });
      const res = await call(ctx, 'Safe Browsing', `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      if (res.status !== 200) throw new ProviderError(`Safe Browsing returned HTTP ${res.status}`);
      return parseSafeBrowsing(parseJson(res.body, 'Safe Browsing'));
    },
  };
}

// ---------------------------------------------------------------------------
// URLhaus (abuse.ch) host lookup
// ---------------------------------------------------------------------------

interface UrlhausHost {
  query_status?: string;
  query_staus?: string; // the documented sample response uses this spelling
  urlhaus_reference?: string;
  firstseen?: string;
  url_count?: number | string;
  blacklists?: { spamhaus_dbl?: string; surbl?: string };
  urls?: { url_status?: string; date_added?: string; threat?: string }[];
}

export function parseUrlhausHost(json: unknown, now: Date): ProviderResult {
  const j = json as UrlhausHost;
  const status = j?.query_status ?? j?.query_staus;
  if (status === 'no_results') return { status: 'not_listed', summary: 'Host not present in URLhaus', underlyingSources: [], details: {}, dataDate: null, reference: null };
  if (status !== 'ok') throw new ProviderError(`URLhaus query_status "${status ?? 'missing'}"`);
  const urls = Array.isArray(j.urls) ? j.urls : [];
  const online = urls.filter((u) => u.url_status === 'online');
  const latest = urls.map((u) => (u.date_added ? Date.parse(u.date_added.replace(' UTC', 'Z').replace(' ', 'T')) : NaN)).filter((n) => !Number.isNaN(n)).sort((a, b) => b - a)[0];
  const sources = ['URLhaus'];
  const dbl = j.blacklists?.spamhaus_dbl;
  const surbl = j.blacklists?.surbl;
  if (dbl && dbl !== 'not listed') sources.push('Spamhaus DBL');
  if (surbl === 'listed') sources.push('SURBL');
  const details = {
    urlCount: Number(j.url_count ?? urls.length),
    online: online.length,
    firstSeen: j.firstseen ?? null,
    spamhausDbl: dbl ?? null,
    surbl: surbl ?? null,
    threats: [...new Set(urls.map((u) => u.threat).filter(Boolean))].join(',') || null,
  };
  const ageDays = latest ? Math.floor((now.getTime() - latest) / 86_400_000) : null;
  if (online.length > 0) {
    return {
      status: 'listed',
      summary: `URLhaus lists ${online.length} online malware URL(s) on this host${dbl && dbl !== 'not listed' ? `; Spamhaus DBL: ${dbl}` : ''}`,
      underlyingSources: sources,
      details,
      dataDate: latest ? new Date(latest).toISOString() : null,
      reference: j.urlhaus_reference ?? null,
    };
  }
  return {
    status: 'historical',
    summary: `URLhaus recorded ${details.urlCount} malware URL(s) on this host, none currently online${ageDays !== null ? ` (most recent added ${ageDays} days ago)` : ''}`,
    underlyingSources: sources,
    details,
    dataDate: latest ? new Date(latest).toISOString() : null,
    reference: j.urlhaus_reference ?? null,
  };
}

export function urlhausProvider(authKey: string | undefined): ReputationProvider {
  return {
    info: {
      id: 'urlhaus',
      name: 'URLhaus (abuse.ch)',
      kind: 'blocklist',
      configured: !!authKey,
      requirement: 'URLHAUS_AUTH_KEY (free abuse.ch account, auth.abuse.ch)',
      terms: 'Free; subject to abuse.ch terms. Domains looked up are sent to abuse.ch. URLhaus tracks malware distribution URLs, not all phishing.',
    },
    minIntervalMs: 0,
    async lookup(t, ctx) {
      if (!authKey) throw new ProviderError('not configured');
      const res = await call(ctx, 'URLhaus', 'https://urlhaus-api.abuse.ch/v1/host/', {
        method: 'POST',
        headers: { 'Auth-Key': authKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `host=${encodeURIComponent(t.domain)}`,
      });
      if (res.status === 401 || res.status === 403) throw new ProviderError('URLhaus rejected the Auth-Key');
      if (res.status !== 200) throw new ProviderError(`URLhaus returned HTTP ${res.status}`);
      return parseUrlhausHost(parseJson(res.body, 'URLhaus'), ctx.now());
    },
  };
}

// ---------------------------------------------------------------------------
// VirusTotal v3 domain object
// ---------------------------------------------------------------------------

/** Engines flagging below this count are reported as a minority detection. */
export const VT_LISTED_THRESHOLD = 5;

export function parseVirusTotalDomain(json: unknown): ProviderResult {
  const a = (json as { data?: { attributes?: Record<string, unknown> } })?.data?.attributes;
  if (!a || typeof a !== 'object') throw new ProviderError('VirusTotal response has no data.attributes');
  const stats = a.last_analysis_stats as Record<string, number> | undefined;
  if (!stats || typeof stats.malicious !== 'number') throw new ProviderError('VirusTotal response has no last_analysis_stats');
  const results = (a.last_analysis_results ?? {}) as Record<string, { category?: string; engine_name?: string }>;
  const flagged = Object.entries(results)
    .filter(([, r]) => r.category === 'malicious' || r.category === 'suspicious')
    .map(([k, r]) => r.engine_name ?? k);
  const malicious = stats.malicious;
  const suspicious = stats.suspicious ?? 0;
  const dataDate = typeof a.last_analysis_date === 'number' ? new Date(a.last_analysis_date * 1000).toISOString() : null;
  const details = { malicious, suspicious, harmless: stats.harmless ?? null, undetected: stats.undetected ?? null, reputation: typeof a.reputation === 'number' ? a.reputation : null };
  if (malicious >= VT_LISTED_THRESHOLD) {
    return { status: 'listed', summary: `${malicious} VirusTotal engines classify the domain as malicious`, underlyingSources: flagged, details, dataDate, reference: null };
  }
  if (malicious + suspicious > 0) {
    return {
      status: 'minority',
      summary: `${malicious} malicious / ${suspicious} suspicious verdict(s) out of the VirusTotal engines (${flagged.slice(0, 5).join(', ')})`,
      underlyingSources: flagged,
      details,
      dataDate,
      reference: null,
    };
  }
  return { status: 'not_listed', summary: 'No VirusTotal engine flags the domain in its last analysis', underlyingSources: [], details, dataDate, reference: null };
}

export function virusTotalProvider(apiKey: string | undefined): ReputationProvider {
  return {
    info: {
      id: 'virustotal',
      name: 'VirusTotal',
      kind: 'aggregator',
      configured: !!apiKey,
      requirement: 'VIRUSTOTAL_API_KEY (free public key: 4 requests/min, 500/day)',
      terms: 'The public API must not be used in commercial products or services. Queried indicators are added to the VirusTotal dataset and visible to its community.',
    },
    minIntervalMs: 15_000,
    async lookup(t, ctx) {
      if (!apiKey) throw new ProviderError('not configured');
      const res = await call(ctx, 'VirusTotal', `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(t.domain)}`, { headers: { 'x-apikey': apiKey } });
      if (res.status === 404) return { status: 'not_listed', summary: 'Domain unknown to VirusTotal', underlyingSources: [], details: {}, dataDate: null, reference: null };
      if (res.status === 401 || res.status === 403) throw new ProviderError('VirusTotal rejected the API key');
      if (res.status === 429) throw new ProviderError('VirusTotal quota exceeded');
      if (res.status !== 200) throw new ProviderError(`VirusTotal returned HTTP ${res.status}`);
      const r = parseVirusTotalDomain(parseJson(res.body, 'VirusTotal'));
      return { ...r, reference: `https://www.virustotal.com/gui/domain/${encodeURIComponent(t.domain)}` };
    },
  };
}

// ---------------------------------------------------------------------------
// Tranco popularity ranking
// ---------------------------------------------------------------------------

export function parseTranco(json: unknown, opts: { rankThreshold: number; minDays: number; staleAfterDays: number; now: Date }): ProviderResult {
  const ranks = (json as { ranks?: { date?: string; rank?: number }[] })?.ranks;
  if (!Array.isArray(ranks)) throw new ProviderError('Tranco response has no "ranks" list');
  const valid = ranks.filter((r) => typeof r.rank === 'number' && typeof r.date === 'string' && !Number.isNaN(Date.parse(r.date)));
  if (valid.length === 0) return { status: 'not_popular', summary: 'Not in the Tranco list during the last 30 days', underlyingSources: [], details: { daysRanked: 0 }, dataDate: null, reference: null };
  const latest = valid.reduce((a, b) => (Date.parse(b.date!) > Date.parse(a.date!) ? b : a));
  const within = valid.filter((r) => r.rank! <= opts.rankThreshold);
  const best = Math.min(...valid.map((r) => r.rank!));
  const details = { daysRanked: valid.length, daysWithinThreshold: within.length, rankThreshold: opts.rankThreshold, latestRank: latest.rank!, bestRank: best };
  const ageDays = Math.floor((opts.now.getTime() - Date.parse(latest.date!)) / 86_400_000);
  if (ageDays > opts.staleAfterDays) {
    return { status: 'stale', summary: `Latest Tranco data is ${ageDays} days old`, underlyingSources: ['Tranco'], details, dataDate: latest.date!, reference: null };
  }
  if (within.length >= opts.minDays) {
    return {
      status: 'popular',
      summary: `Ranked within the Tranco top ${opts.rankThreshold.toLocaleString('en-US')} on ${within.length} of the last ${valid.length} daily lists (latest rank ${latest.rank})`,
      underlyingSources: ['Tranco'],
      details,
      dataDate: latest.date!,
      reference: null,
    };
  }
  return {
    status: 'not_popular',
    summary: `Ranked within the top ${opts.rankThreshold.toLocaleString('en-US')} on ${within.length} of ${valid.length} daily lists (below the ${opts.minDays}-day requirement); latest rank ${latest.rank}`,
    underlyingSources: [],
    details,
    dataDate: latest.date!,
    reference: null,
  };
}

export function trancoProvider(cfg: Pick<ReputationConfig, 'trancoEnabled' | 'trancoRankThreshold' | 'trancoMinDays' | 'staleAfterDays'>): ReputationProvider {
  return {
    info: {
      id: 'tranco',
      name: 'Tranco popularity ranking',
      kind: 'popularity',
      configured: cfg.trancoEnabled,
      requirement: 'TRANCO_ENABLED=true (no key; 1 request/second)',
      terms: 'Free. Domains looked up are sent to tranco-list.eu. Popularity is not safety: popular sites can be compromised.',
    },
    minIntervalMs: 1_100,
    async lookup(t, ctx) {
      if (!cfg.trancoEnabled) throw new ProviderError('not configured');
      const res = await call(ctx, 'Tranco', `https://tranco-list.eu/api/ranks/domain/${encodeURIComponent(t.domain)}`, { headers: { Accept: 'application/json' } });
      if (res.status === 429) throw new ProviderError('Tranco rate limit exceeded');
      if (res.status !== 200) throw new ProviderError(`Tranco returned HTTP ${res.status}`);
      const r = parseTranco(parseJson(res.body, 'Tranco'), { rankThreshold: cfg.trancoRankThreshold, minDays: cfg.trancoMinDays, staleAfterDays: cfg.staleAfterDays, now: ctx.now() });
      return { ...r, reference: `https://tranco-list.eu/query?domain=${encodeURIComponent(t.domain)}` };
    },
  };
}

export function createProviders(cfg: ReputationConfig): ReputationProvider[] {
  return [safeBrowsingProvider(cfg.gsbApiKey), urlhausProvider(cfg.urlhausAuthKey), virusTotalProvider(cfg.virustotalApiKey), trancoProvider(cfg)];
}

/** Normalised source name for independence checks ("Google Safebrowsing" ≡ "Google Safe Browsing"). */
export function sourceKey(name: string): string {
  const n = norm(name);
  if (n.includes('safebrowsing')) return 'googlesafebrowsing';
  if (n.includes('urlhaus')) return 'urlhaus';
  if (n.includes('spamhaus')) return 'spamhaus';
  return n;
}

export type { ReputationProviderId };
