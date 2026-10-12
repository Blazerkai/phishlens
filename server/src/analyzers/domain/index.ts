import type { Analyzer, AnalyzerContext } from '../types.js';
import { normalizeDomainInput, parseDomain } from './parseDomain.js';
import { findBrandMatches } from './lookalike.js';
import { domainHeuristics } from './heuristics.js';

/** Every hostname referenced anywhere in the evidence, with where it was seen. Order = priority. */
export function collectHosts(ctx: AnalyzerContext): Map<string, Set<string>> {
  const hosts = new Map<string, Set<string>>();
  const add = (host: string | null | undefined, source: string) => {
    if (!host) return;
    const h = normalizeDomainInput(host);
    if (!h) return;
    if (!hosts.has(h)) hosts.set(h, new Set());
    hosts.get(h)!.add(source);
  };
  if (ctx.input.domain) add(ctx.input.domain, 'submitted domain');
  for (const u of ctx.state.urls) if (u.valid && u.hostname) add(u.hostname, u.origin === 'input' ? 'submitted URL' : `${u.origin} URL`);
  const e = ctx.state.email;
  if (e) {
    add(e.from?.domain, 'From');
    for (const r of e.replyTo) add(r.domain, 'Reply-To');
    add(e.returnPath?.domain, 'Return-Path');
    add(e.sender?.domain, 'Sender');
  }
  if (ctx.state.emailAddress?.address.domain) add(ctx.state.emailAddress.address.domain, 'submitted email address');
  for (const l of ctx.state.message?.links ?? []) add(l.hrefHost, 'message link');
  return hosts;
}

export const domainAnalyzer: Analyzer = {
  id: 'domain',
  label: 'Parsing domain',
  dependsOn: ['url', 'email-headers', 'email-address', 'message'],
  applies: (ctx) => collectHosts(ctx).size > 0 || !!ctx.input.domain,
  async run(ctx) {
    if (ctx.input.domain && !normalizeDomainInput(ctx.input.domain)) {
      ctx.emit({
        code: 'DOMAIN_INVALID',
        category: 'DOMAIN',
        title: 'Submitted domain is not a valid hostname',
        description: 'The value does not conform to hostname syntax (RFC 1123), so no DNS or registration lookups were made for it.',
        severity: 'info',
        confidence: 1,
        evidence: ctx.input.domain,
        source: 'Submitted domain',
        provenance: 'user_input',
      });
    }
    const hosts = collectHosts(ctx);
    for (const [host, sources] of hosts) {
      const d = parseDomain(host, [...sources]);
      d.brandMatches = findBrandMatches(d, ctx.brands);
      ctx.state.domains.push(d);
      for (const draft of domainHeuristics(d, ctx.settings.lists)) ctx.emit(draft);
    }
    const lookalikes = ctx.state.domains.filter((d) => d.brandMatches.some((m) => m.technique !== 'official')).length;
    return {
      status: 'completed',
      detail: `${hosts.size} hostname(s) parsed${lookalikes ? `, ${lookalikes} brand lookalike match(es)` : ''}${ctx.brands.length === 0 ? '; brand watchlist is empty' : ''}`,
    };
  },
};
