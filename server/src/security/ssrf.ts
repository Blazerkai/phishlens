import dns from 'node:dns';
import type { LookupFunction } from 'node:net';
import { classifyIp, isIpLiteral } from './ip.js';

/**
 * SSRF guard for every outbound connection PhishLens makes.
 *
 * Defence in depth:
 *  1. URL policy: only http/https, only allow-listed ports, no internal hostnames.
 *  2. Resolution policy: every address a hostname resolves to must be public.
 *  3. Connection pinning: the socket connects to the exact address that was
 *     validated (via a custom `lookup`), so DNS rebinding between check and
 *     connect is not possible.
 *  4. Each redirect hop is re-validated from scratch by the caller.
 */

export class SsrfBlockedError extends Error {
  readonly code = 'SSRF_BLOCKED';
  constructor(
    message: string,
    readonly target: string,
  ) {
    super(message);
    this.name = 'SsrfBlockedError';
  }
}

const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.home.arpa', '.corp', '.localdomain'];
const BLOCKED_HOSTS = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback', 'metadata', 'metadata.google.internal']);

export interface UrlPolicy {
  allowedPorts: number[];
}

/** Returns a reason if the hostname itself (before resolution) must not be contacted. */
export function hostnamePolicyViolation(hostname: string): string | null {
  const h = hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!h) return 'empty hostname';
  if (BLOCKED_HOSTS.has(h)) return `hostname "${h}" refers to the local machine or internal metadata service`;
  if (BLOCKED_HOST_SUFFIXES.some((s) => h.endsWith(s))) return `hostname "${h}" uses an internal-only suffix`;
  if (isIpLiteral(h)) {
    const c = classifyIp(h);
    if (c.blocked) return `address ${h} is ${c.reason}`;
    return null;
  }
  if (!h.includes('.')) return `single-label hostname "${h}" would resolve against internal search domains`;
  return null;
}

/** Validates a URL before any connection is attempted. Throws SsrfBlockedError. */
export function assertUrlAllowed(rawUrl: string | URL, policy: UrlPolicy): URL {
  let url: URL;
  try {
    url = typeof rawUrl === 'string' ? new URL(rawUrl) : rawUrl;
  } catch {
    throw new SsrfBlockedError('URL could not be parsed', String(rawUrl));
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfBlockedError(`scheme "${url.protocol.replace(':', '')}" is not fetched (only http/https)`, url.href);
  }
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (!policy.allowedPorts.includes(port)) {
    throw new SsrfBlockedError(`port ${port} is not in the outbound allow-list (${policy.allowedPorts.join(', ')})`, url.href);
  }
  const violation = hostnamePolicyViolation(url.hostname);
  if (violation) throw new SsrfBlockedError(violation, url.href);
  return url;
}

export type ResolveAllFn = (hostname: string) => Promise<{ address: string; family: number }[]>;

export const systemResolveAll: ResolveAllFn = (hostname) =>
  new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => (err ? reject(err) : resolve(addresses)));
  });

/**
 * Resolves a hostname and returns its addresses only if *all* of them are public.
 * A hostname that resolves to a mix of public and private addresses is rejected:
 * an attacker controls which one a client would pick.
 */
export async function resolvePublicAddresses(
  hostname: string,
  resolveAll: ResolveAllFn = systemResolveAll,
): Promise<{ address: string; family: number }[]> {
  const h = hostname.replace(/^\[|\]$/g, '');
  const violation = hostnamePolicyViolation(h);
  if (violation) throw new SsrfBlockedError(violation, hostname);
  if (isIpLiteral(h)) return [{ address: h, family: h.includes(':') ? 6 : 4 }];

  const addresses = await resolveAll(h);
  if (addresses.length === 0) throw new SsrfBlockedError(`hostname "${h}" did not resolve`, hostname);
  for (const a of addresses) {
    const c = classifyIp(a.address);
    if (c.blocked) throw new SsrfBlockedError(`"${h}" resolves to ${a.address}, which is ${c.reason}`, hostname);
  }
  return addresses;
}

/**
 * A `lookup` implementation for http/https/tls that only ever yields validated
 * public addresses. The connection uses the address returned here, which pins
 * the socket to what was checked.
 */
export function createSafeLookup(
  resolveAll: ResolveAllFn = systemResolveAll,
  onResolved?: (address: string) => void,
): LookupFunction {
  return (hostname, options, callback) => {
    resolvePublicAddresses(hostname, resolveAll)
      .then((addresses) => {
        const wanted = typeof options === 'object' && options && 'family' in options ? options.family : 0;
        const pick = addresses.find((a) => !wanted || a.family === wanted) ?? addresses[0]!;
        onResolved?.(pick.address);
        if (typeof options === 'object' && options && 'all' in options && options.all) {
          (callback as unknown as (e: null, a: { address: string; family: number }[]) => void)(null, [pick]);
        } else {
          callback(null, pick.address, pick.family);
        }
      })
      .catch((err: Error) => callback(err as NodeJS.ErrnoException, '', 0));
  };
}
