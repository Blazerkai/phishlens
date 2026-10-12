import type { ReputationObservation, ReputationProviderInfo } from '@phishlens/shared';
import type { HttpService } from '../network/types.js';
import { ProviderError, type LookupTarget, type ProviderResult, type ReputationProvider } from './providers.js';

export interface ReputationCache {
  get(provider: string, subject: string): { result: ProviderResult; fetchedAt: string } | null;
  set(provider: string, subject: string, result: ProviderResult, fetchedAt: string): void;
}

export function memoryCache(): ReputationCache {
  const m = new Map<string, { result: ProviderResult; fetchedAt: string }>();
  return {
    get: (p, s) => m.get(`${p}|${s}`) ?? null,
    set: (p, s, result, fetchedAt) => void m.set(`${p}|${s}`, { result, fetchedAt }),
  };
}

export interface ReputationService {
  providers: ReputationProviderInfo[];
  /** True when at least one provider is configured. */
  enabled: boolean;
  lookup(targets: LookupTarget[]): Promise<ReputationObservation[]>;
}

/**
 * Runs every configured provider for every target.
 *  - Fresh cache entries (younger than the TTL) are reused and marked cached.
 *  - Only successful results are cached; errors are never cached.
 *  - If a live call fails and an expired entry exists, it is returned as "stale"
 *    (shown to the analyst, never counted as positive evidence).
 *  - Calls are spaced per provider according to its documented quota; a call that
 *    would have to wait longer than the timeout is reported as unavailable instead.
 */
export function createReputationService(opts: {
  providers: ReputationProvider[];
  http: HttpService;
  cache: ReputationCache;
  timeoutMs: number;
  cacheTtlHours: number;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
}): ReputationService {
  const now = opts.now ?? (() => new Date());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const active = opts.providers.filter((p) => p.info.configured);
  const nextAllowed = new Map<string, number>();
  const chains = new Map<string, Promise<unknown>>();

  const observe = (p: ReputationProvider, subject: string, r: ProviderResult, fetchedAt: string, cached: boolean): ReputationObservation => ({
    provider: p.info.id,
    providerName: p.info.name,
    subject,
    fetchedAt,
    cached,
    ...r,
  });
  const failure = (p: ReputationProvider, subject: string, status: 'error' | 'unavailable', reason: string): ReputationObservation =>
    observe(p, subject, { status, summary: reason, underlyingSources: [], details: {}, dataDate: null, reference: null }, now().toISOString(), false);

  async function one(p: ReputationProvider, t: LookupTarget): Promise<ReputationObservation> {
    const cached = opts.cache.get(p.info.id, t.domain);
    const ageH = cached ? (now().getTime() - Date.parse(cached.fetchedAt)) / 3_600_000 : Infinity;
    if (cached && ageH < opts.cacheTtlHours) return observe(p, t.domain, cached.result, cached.fetchedAt, true);

    const wait = (nextAllowed.get(p.info.id) ?? 0) - now().getTime();
    if (wait > opts.timeoutMs) {
      return staleOr(p, t, cached, `${p.info.name}: local rate limit for its quota; not queried`);
    }
    if (wait > 0) await sleep(wait);
    nextAllowed.set(p.info.id, now().getTime() + p.minIntervalMs);

    try {
      const r = await p.lookup(t, { http: opts.http, timeoutMs: opts.timeoutMs, now });
      const fetchedAt = now().toISOString();
      if (r.status !== 'stale') opts.cache.set(p.info.id, t.domain, r, fetchedAt);
      return observe(p, t.domain, r, fetchedAt, false);
    } catch (err) {
      const reason = err instanceof ProviderError ? err.message : `${p.info.name} failed unexpectedly`;
      return staleOr(p, t, cached, reason);
    }
  }

  function staleOr(p: ReputationProvider, t: LookupTarget, cached: { result: ProviderResult; fetchedAt: string } | null, reason: string): ReputationObservation {
    if (!cached) return failure(p, t.domain, /rate limit|quota/i.test(reason) ? 'unavailable' : 'error', reason);
    const ageH = Math.round((now().getTime() - Date.parse(cached.fetchedAt)) / 3_600_000);
    return observe(
      p,
      t.domain,
      {
        ...cached.result,
        status: 'stale',
        summary: `Live lookup failed (${reason}). Last known result, ${ageH} h old: ${cached.result.status} — ${cached.result.summary}`,
        details: { ...cached.result.details, lastKnownStatus: cached.result.status },
      },
      cached.fetchedAt,
      true,
    );
  }

  /** Serialise calls per provider so quota spacing holds across concurrent investigations. */
  function queued(p: ReputationProvider, t: LookupTarget): Promise<ReputationObservation> {
    const prev = chains.get(p.info.id) ?? Promise.resolve();
    const next = prev.then(() => one(p, t));
    chains.set(p.info.id, next.catch(() => undefined));
    return next;
  }

  return {
    providers: opts.providers.map((p) => p.info),
    enabled: active.length > 0,
    async lookup(targets) {
      const all = await Promise.all(active.flatMap((p) => targets.map((t) => queued(p, t))));
      return all;
    },
  };
}
