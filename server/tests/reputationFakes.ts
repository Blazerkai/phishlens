/** Fake provider endpoints and documented response shapes shared by reputation tests. */
// Relative to the real clock so fixtures never age (integration scenarios use real time).
export const NOW = new Date(Math.floor(Date.now() / 1000) * 1000);
const day = (offset: number) => new Date(NOW.getTime() - offset * 86_400_000).toISOString().slice(0, 10);

export const REP_CFG = {
  gsbApiKey: 'GSBKEY',
  urlhausAuthKey: 'UHKEY',
  virustotalApiKey: 'VTKEY',
  trancoEnabled: true,
  trancoRankThreshold: 100000,
  trancoMinDays: 25,
  timeoutMs: 1000,
  cacheTtlHours: 24,
  staleAfterDays: 7,
};

export const URLS = {
  gsb: 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=GSBKEY',
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/host/',
  vt: (d: string) => `https://www.virustotal.com/api/v3/domains/${d}`,
  tranco: (d: string) => `https://tranco-list.eu/api/ranks/domain/${d}`,
};
export const json = (status: number, body: unknown) => ({ status, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
export const trancoRanks = (rank: number, days = 30, latestOffset = 1) => ({ domain: 'x', ranks: Array.from({ length: days }, (_, i) => ({ date: day(i + latestOffset), rank })) });
export const vtDomain = (malicious: number, engines: string[] = []) => ({
  data: {
    type: 'domain',
    id: 'x',
    attributes: {
      last_analysis_date: Math.floor(NOW.getTime() / 1000) - 86400,
      last_analysis_stats: { harmless: 60, malicious, suspicious: 0, undetected: 20, timeout: 0 },
      last_analysis_results: Object.fromEntries(engines.map((e) => [e, { category: 'malicious', engine_name: e, method: 'blacklist', result: 'phishing' }])),
      reputation: 0,
    },
  },
});

