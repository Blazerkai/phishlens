import type { Analyzer, AnalyzerContext } from '../types.js';
import { followRedirects } from './follow.js';
import { redirectHeuristics } from './heuristics.js';
import { parseUrl } from '../url/parseUrl.js';
import { urlHeuristics } from '../url/heuristics.js';
import { parseDomain } from '../domain/parseDomain.js';
import { findBrandMatches } from '../domain/lookalike.js';
import { domainHeuristics } from '../domain/heuristics.js';
import { hstsIndicators, httpTransportIndicators } from './transport.js';

export function redirectTargets(ctx: AnalyzerContext): string[] {
  const out: string[] = [];
  for (const u of ctx.state.urls) {
    if (u.origin === 'input' && u.valid && (u.scheme === 'http' || u.scheme === 'https') && u.normalized) out.push(u.normalized);
  }
  const fromMessage = (ctx.state.message?.links ?? [])
    .map((l) => parseUrl(l.href, 'message'))
    .filter((u) => u.valid && (u.scheme === 'http' || u.scheme === 'https') && u.normalized && !out.includes(u.normalized))
    .map((u) => u.normalized!);
  out.push(...[...new Set(fromMessage)].slice(0, ctx.settings.network.maxMessageLinkProbes));
  return out;
}

export const redirectAnalyzer: Analyzer = {
  id: 'redirects',
  label: 'Inspecting redirects',
  dependsOn: ['url', 'message', 'domain'],
  applies: (ctx) => redirectTargets(ctx).length > 0,
  async run(ctx) {
    const n = ctx.settings.network;
    if (!n.probesEnabled) {
      return { status: 'unavailable', reason: 'Network probing is disabled (NETWORK_PROBES_ENABLED=false); links were not followed.' };
    }
    const chains = await Promise.all(
      redirectTargets(ctx).map((url) =>
        followRedirects(url, ctx.services.http, {
          maxRedirects: n.maxRedirects,
          timeoutMs: n.requestTimeoutMs,
          maxBodyBytes: n.maxBodyBytes,
          allowedPorts: n.allowedPorts,
        }),
      ),
    );

    const knownHosts = new Set(ctx.state.domains.map((d) => d.hostname));
    for (const chain of chains) {
      ctx.state.redirects.push(chain);
      for (const d of redirectHeuristics(chain, ctx.settings.lists)) ctx.emit(d);
      const origin = ctx.state.urls.find((u) => u.normalized === chain.startUrl && u.origin !== 'redirect');
      if (origin) for (const d of httpTransportIndicators(origin, chain)) ctx.emit(d);
      for (const d of hstsIndicators(chain)) ctx.emit(d);

      // The destination is a new URL/host the user never saw: assess it like any other.
      if (chain.finalUrl && chain.redirectCount > 0) {
        const fu = parseUrl(chain.finalUrl, 'redirect');
        if (fu.valid) {
          ctx.state.urls.push(fu);
          for (const d of urlHeuristics(fu, { brands: ctx.brands, lists: ctx.settings.lists })) ctx.emit(d);
          if (fu.hostname && !knownHosts.has(fu.hostname)) {
            knownHosts.add(fu.hostname);
            const dom = parseDomain(fu.hostname, ['redirect destination']);
            dom.brandMatches = findBrandMatches(dom, ctx.brands);
            ctx.state.domains.push(dom);
            for (const d of domainHeuristics(dom, ctx.settings.lists)) ctx.emit(d);
          }
        }
      }
    }

    const done = chains.filter((c) => c.status === 'completed');
    if (done.length === 0) {
      const allBlocked = chains.every((c) => c.status === 'blocked');
      return { status: allBlocked ? 'blocked' : 'failed', reason: chains.map((c) => `${c.startUrl}: ${c.reason ?? c.status}`).join('; ') };
    }
    return {
      status: 'completed',
      detail: chains.map((c) => `${c.redirectCount} redirect(s) → ${c.finalUrl ? new URL(c.finalUrl).hostname : 'n/a'}`).join('; '),
    };
  },
};
