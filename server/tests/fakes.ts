import type { DnsRecordType, DnsService, HttpResponse, HttpService, TlsService } from '../src/services/network/types.js';

type Zone = Record<string, Partial<Record<DnsRecordType | 'PTR', string[] | 'NXDOMAIN' | 'TIMEOUT'>>>;

/** In-memory DNS used by tests. Unknown names → NXDOMAIN; known names without a type → ENODATA. */
export function fakeDns(zone: Zone): DnsService & { queries: string[] } {
  const queries: string[] = [];
  const fail = (code: string) => Object.assign(new Error(code), { code });
  return {
    description: 'fake resolver',
    queries,
    async resolve(name, type) {
      queries.push(`${type} ${name}`);
      const entry = zone[name];
      if (!entry) throw fail('ENOTFOUND');
      const v = entry[type];
      if (v === 'NXDOMAIN') throw fail('ENOTFOUND');
      if (v === 'TIMEOUT') throw fail('ETIMEOUT');
      if (!v) throw fail('ENODATA');
      return v;
    },
    async reverse(ip) {
      for (const e of Object.values(zone)) {
        const ptr = e.PTR;
        if (Array.isArray(ptr) && e.A?.includes?.(ip)) return ptr;
      }
      throw fail('ENOTFOUND');
    },
  };
}

export interface FakeRoute {
  status: number;
  headers?: Record<string, string>;
  body?: string;
  remoteAddress?: string;
  /** TLS verification of the serving connection; defaults to a verified certificate for https URLs. */
  tls?: { authorized: boolean; error: string | null; fingerprint256: string | null } | null;
}

/** Fake HTTP service; routes keyed by exact URL. Throws for unknown URLs. */
export function fakeHttp(routes: Record<string, FakeRoute | Error>): HttpService & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async request(url): Promise<HttpResponse> {
      calls.push(url);
      const r = routes[url];
      if (!r) throw new Error(`connect ECONNREFUSED (${url})`);
      if (r instanceof Error) throw r;
      return {
        status: r.status,
        headers: r.headers ?? {},
        body: Buffer.from(r.body ?? ''),
        bodyTruncated: false,
        remoteAddress: r.remoteAddress ?? '198.51.100.7',
        durationMs: 12,
        tls: r.tls !== undefined ? r.tls : url.startsWith('https:') ? { authorized: true, error: null, fingerprint256: 'FAKE:FP' } : null,
      };
    },
  };
}

export const noTls: TlsService = {
  async inspect() {
    throw new Error('TLS not available in this test');
  },
};
