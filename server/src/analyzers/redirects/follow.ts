import type { RedirectAnalysis, RedirectHop } from '@phishlens/shared';
import type { HttpService } from '../../services/network/types.js';
import { assertUrlAllowed, SsrfBlockedError } from '../../security/ssrf.js';
import { inspectHtml } from './page.js';

export interface FollowOptions {
  maxRedirects: number;
  timeoutMs: number;
  maxBodyBytes: number;
  allowedPorts: number[];
  /** Overall budget for the whole chain. */
  totalBudgetMs?: number;
}

function hostOf(u: string): { hostname: string; scheme: string } {
  try {
    const x = new URL(u);
    return { hostname: x.hostname.replace(/^\[|\]$/g, ''), scheme: x.protocol.replace(':', '') };
  } catch {
    return { hostname: '', scheme: '' };
  }
}

/**
 * Follows a redirect chain one request at a time. Every hop — including the
 * first — is validated against the SSRF policy before any connection, and the
 * HTTP service re-validates resolution and the connected peer.
 */
export async function followRedirects(startUrl: string, http: HttpService, o: FollowOptions): Promise<RedirectAnalysis> {
  const hops: RedirectHop[] = [];
  const visited = new Set<string>();
  const deadline = Date.now() + (o.totalBudgetMs ?? o.timeoutMs * (o.maxRedirects + 1));
  let current = startUrl;
  let page: RedirectAnalysis['page'];
  let status: RedirectAnalysis['status'] = 'completed';
  let reason: string | undefined;

  for (let i = 0; ; i++) {
    const { hostname, scheme } = hostOf(current);
    if (i > o.maxRedirects) {
      reason = `Stopped after the maximum of ${o.maxRedirects} redirects`;
      break;
    }
    if (visited.has(current)) {
      hops.push({ index: i, url: current, scheme, hostname, kind: 'error', error: 'Redirect loop detected' });
      reason = 'Redirect loop detected';
      break;
    }
    visited.add(current);

    try {
      assertUrlAllowed(current, { allowedPorts: o.allowedPorts });
    } catch (err) {
      if (!(err instanceof SsrfBlockedError)) throw err;
      hops.push({ index: i, url: current, scheme, hostname, kind: 'blocked', error: err.message });
      if (i === 0) status = 'blocked';
      reason = `Not followed: ${err.message}`;
      break;
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      reason = 'Overall time budget for the redirect chain was exhausted';
      break;
    }

    let res;
    try {
      res = await http.request(current, { timeoutMs: Math.min(o.timeoutMs, remaining), maxBodyBytes: o.maxBodyBytes, readBody: true });
    } catch (err) {
      const blocked = err instanceof SsrfBlockedError;
      hops.push({ index: i, url: current, scheme, hostname, kind: blocked ? 'blocked' : 'error', error: (err as Error).message });
      if (i === 0) status = blocked ? 'blocked' : 'failed';
      reason = blocked ? `Not followed: ${(err as Error).message}` : (err as Error).message;
      break;
    }

    const hop: RedirectHop = {
      index: i,
      url: current,
      scheme,
      hostname,
      statusCode: res.status,
      durationMs: res.durationMs,
      kind: 'final',
      ...(res.remoteAddress ? { remoteAddress: res.remoteAddress } : {}),
      ...(scheme === 'https' ? { tls: res.tls ?? null } : {}),
      hsts: (Array.isArray(res.headers['strict-transport-security']) ? res.headers['strict-transport-security'][0] : res.headers['strict-transport-security']) ?? null,
    };
    hops.push(hop);

    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      const loc = Array.isArray(location) ? location[0]! : location;
      hop.kind = 'http';
      hop.location = loc;
      try {
        current = new URL(loc, current).href;
      } catch {
        hop.error = 'Location header is not a valid URL';
        reason = hop.error;
        break;
      }
      continue;
    }

    const ct = String(res.headers['content-type'] ?? '') || null;
    if (ct && /html/i.test(ct) && res.body.length) {
      const obs = inspectHtml(res.body.toString('utf8'), ct, res.body.length);
      if (obs.metaRefresh && res.status < 400) {
        hop.kind = 'meta-refresh';
        hop.location = obs.metaRefresh;
        try {
          current = new URL(obs.metaRefresh, current).href;
          continue;
        } catch {
          hop.kind = 'final';
        }
      }
      const { metaRefresh: _m, ...pageObs } = obs;
      page = pageObs;
    } else {
      page = { contentType: ct, title: null, hasPasswordField: false, formActions: [], scriptRedirect: null, bytesInspected: res.body.length };
    }
    break;
  }

  const last = hops[hops.length - 1];
  // If the chain stopped on a redirect (limit reached), the next, unvisited URL is the furthest known destination.
  const finalUrl = last ? (last.kind === 'http' || last.kind === 'meta-refresh' ? current : last.url) : null;
  return {
    startUrl,
    status,
    ...(reason ? { reason } : {}),
    hops,
    finalUrl,
    redirectCount: hops.filter((h) => h.kind === 'http' || h.kind === 'meta-refresh').length,
    ...(page ? { page } : {}),
    inspectedAt: new Date().toISOString(),
  };
}
