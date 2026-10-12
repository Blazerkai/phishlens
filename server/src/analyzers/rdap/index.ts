import { parse } from 'tldts';
import type { RdapAnalysis } from '@phishlens/shared';
import type { Analyzer, AnalyzerContext } from '../types.js';
import { networkTargets } from '../targets.js';
import { parseRdap, type RdapDomainResponse } from './parse.js';
import { rdapHeuristics } from './heuristics.js';
import { SsrfBlockedError } from '../../security/ssrf.js';

const MAX_RDAP_DOMAINS = 3;
const MAX_HOPS = 3;

/** ICANN registrable domains for targets; private-suffix platforms (github.io etc.) are excluded — their age says nothing about the tenant. */
export function rdapTargets(ctx: AnalyzerContext): string[] {
  const out = new Set<string>();
  for (const t of networkTargets(ctx)) {
    const p = parse(t.host, { allowPrivateDomains: true });
    if (p.isPrivate || !p.domain) continue;
    out.add(p.domain);
    if (out.size >= MAX_RDAP_DOMAINS) break;
  }
  return [...out];
}

async function fetchRdap(ctx: AnalyzerContext, domain: string): Promise<{ json: RdapDomainResponse; url: string }> {
  let url = `${ctx.settings.network.rdapBootstrapUrl.replace(/\/?$/, '/')}${encodeURIComponent(domain)}`;
  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    const res = await ctx.services.http.request(url, {
      timeoutMs: ctx.settings.network.requestTimeoutMs,
      maxBodyBytes: 512 * 1024,
      readBody: true,
    });
    if (res.status >= 300 && res.status < 400 && res.headers.location) {
      url = new URL(String(res.headers.location), url).href;
      continue;
    }
    if (res.status === 404) throw Object.assign(new Error('Registry has no RDAP record for this domain'), { notFound: true });
    if (res.status !== 200) throw new Error(`RDAP server returned HTTP ${res.status}`);
    return { json: JSON.parse(res.body.toString('utf8')) as RdapDomainResponse, url };
  }
  throw new Error('Too many RDAP redirects');
}

export const rdapAnalyzer: Analyzer = {
  id: 'rdap',
  label: 'Querying domain registration (RDAP)',
  dependsOn: ['domain'],
  applies: (ctx) => rdapTargets(ctx).length > 0,
  async run(ctx) {
    if (!ctx.settings.network.probesEnabled || !ctx.settings.network.rdapEnabled) {
      return {
        status: 'unavailable',
        reason: !ctx.settings.network.probesEnabled
          ? 'Network probing is disabled; registration data was not queried.'
          : 'RDAP lookups are disabled (RDAP_ENABLED=false). Domain age is unknown.',
      };
    }
    const results = await Promise.all(
      rdapTargets(ctx).map(async (domain): Promise<RdapAnalysis> => {
        const queriedAt = new Date().toISOString();
        try {
          const { json, url } = await fetchRdap(ctx, domain);
          return { domain, status: 'completed', source: `RDAP ${new URL(url).hostname}`, ...parseRdap(json), queriedAt };
        } catch (err) {
          if (err instanceof SsrfBlockedError) return { domain, status: 'blocked', source: 'RDAP', reason: err.message, queriedAt };
          return { domain, status: (err as { notFound?: boolean }).notFound ? 'completed' : 'failed', source: 'RDAP', reason: (err as Error).message, queriedAt };
        }
      }),
    );
    for (const r of results) {
      ctx.state.rdap.push(r);
      for (const d of rdapHeuristics(r)) ctx.emit(d);
    }
    const ok = results.filter((r) => r.status === 'completed' && r.registered);
    if (ok.length === 0) return { status: 'failed', reason: results.map((r) => `${r.domain}: ${r.reason ?? 'no registration date'}`).join('; ') };
    return { status: 'completed', detail: ok.map((r) => `${r.domain} registered ${r.registered?.slice(0, 10)} (${r.ageDays} days)`).join('; ') };
  },
};
