import type { TlsAnalysis } from '@phishlens/shared';
import type { Analyzer, AnalyzerContext } from '../types.js';
import { normalizeCertificate, hostnameMatch } from './certificate.js';
import { tlsHeuristics } from './heuristics.js';
import { networkTargets } from '../targets.js';
import { SsrfBlockedError } from '../../security/ssrf.js';

const MAX_TLS_TARGETS = 4;

/** HTTPS endpoints worth inspecting: submitted URL/domain, final redirect destinations. */
export function tlsTargets(ctx: AnalyzerContext): { host: string; port: number }[] {
  const out = new Map<string, { host: string; port: number }>();
  const add = (host: string | undefined | null, port: number | null | undefined) => {
    if (!host || out.size >= MAX_TLS_TARGETS) return;
    const p = port ?? 443;
    out.set(`${host}:${p}`, { host, port: p });
  };
  for (const u of ctx.state.urls) if (u.origin === 'input' && u.valid && u.scheme === 'https') add(u.hostname, u.effectivePort);
  for (const r of ctx.state.redirects) {
    if (!r.finalUrl) continue;
    try {
      const f = new URL(r.finalUrl);
      if (f.protocol === 'https:') add(f.hostname.replace(/^\[|\]$/g, ''), f.port ? Number(f.port) : 443);
    } catch {
      /* ignore */
    }
  }
  if (ctx.input.domain) {
    const t = networkTargets(ctx).find((x) => x.roles.has('submitted-domain'));
    if (t) add(t.host, 443);
  }
  return [...out.values()];
}

export const tlsAnalyzer: Analyzer = {
  id: 'tls',
  label: 'Analyzing TLS',
  dependsOn: ['domain', 'redirects'],
  applies: (ctx) => tlsTargets(ctx).length > 0,
  async run(ctx) {
    if (!ctx.settings.network.probesEnabled) {
      return { status: 'unavailable', reason: 'Network probing is disabled (NETWORK_PROBES_ENABLED=false); certificates were not inspected.' };
    }
    const targets = tlsTargets(ctx);
    const results = await Promise.all(
      targets.map(async ({ host, port }): Promise<TlsAnalysis> => {
        const inspectedAt = new Date().toISOString();
        try {
          const r = await ctx.services.tls.inspect(host, port, ctx.settings.network.requestTimeoutMs);
          if (!r.certificate) return { host, port, status: 'failed', reason: 'Server presented no certificate', inspectedAt };
          const match = hostnameMatch(host, r.certificate);
          return {
            host,
            port,
            status: 'completed',
            remoteAddress: r.remoteAddress ?? undefined,
            protocol: r.protocol,
            cipher: r.cipher,
            authorized: r.authorized,
            authorizationError: r.authorizationError,
            hostnameMatches: match.matches,
            hostnameMismatchReason: match.reason,
            certificate: normalizeCertificate(r.certificate, new Date(inspectedAt)),
            chain: r.chain.map((c) => ({ subjectCN: c.subject?.CN ? String(c.subject.CN) : null, issuerCN: c.issuer?.CN ? String(c.issuer.CN) : null, validTo: new Date(c.valid_to).toISOString() })),
            inspectedAt,
          };
        } catch (err) {
          if (err instanceof SsrfBlockedError) return { host, port, status: 'blocked', reason: `Not contacted: ${err.message}`, inspectedAt };
          return { host, port, status: 'failed', reason: (err as Error).message, inspectedAt };
        }
      }),
    );
    for (const t of results) {
      ctx.state.tls.push(t);
      for (const d of tlsHeuristics(t)) ctx.emit(d);
    }
    const ok = results.filter((r) => r.status === 'completed');
    if (ok.length === 0) {
      return { status: results.every((r) => r.status === 'blocked') ? 'blocked' : 'failed', reason: results.map((r) => `${r.host}: ${r.reason}`).join('; ') };
    }
    return { status: 'completed', detail: ok.map((r) => `${r.host} — ${r.certificate?.issuerOrg ?? r.certificate?.issuerCN ?? 'unknown issuer'}, ${r.authorized && r.hostnameMatches ? 'valid' : 'problems found'}`).join('; ') };
  },
};
