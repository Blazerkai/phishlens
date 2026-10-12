import { domainToUnicode } from 'node:url';
import { parse as parseDomain } from 'tldts';
import type { UrlAnalysis } from '@phishlens/shared';
import { isIpLiteral } from '../../security/ip.js';
import { refang } from '../../lib/text.js';

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:/i;

/**
 * Parses a URL into its components without contacting it.
 * Uses the WHATWG URL parser (what browsers use), so the hostname we analyse is
 * the one a browser would actually connect to — e.g. `http://0x7f.1/` → 127.0.0.1
 * and `https://ex%61mple.com` → example.com.
 */
export function parseUrl(raw: string, origin: UrlAnalysis['origin'] = 'input'): UrlAnalysis {
  const input = raw.trim();
  const { value } = refang(input);
  let candidate = value;
  // Bare host/path (e.g. "example.com/login") is treated as http, as browsers do.
  if (!SCHEME_RE.test(candidate) || /^[^/:]+\.[^/:]+:\d+/.test(candidate)) {
    if (!/^(data|javascript|vbscript|file|blob):/i.test(candidate)) candidate = `http://${candidate}`;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { input, origin, valid: false, error: 'Not a parseable URL' };
  }

  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  if (!url.hostname) {
    return {
      input,
      origin,
      valid: true,
      scheme,
      hostname: '',
      path: url.pathname,
      query: [],
      fragment: '',
      normalized: url.href,
      isIp: false,
      registrableDomain: null,
      subdomain: null,
      publicSuffix: null,
    };
  }

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const isIp = isIpLiteral(hostname);
  const unicode = isIp ? hostname : domainToUnicode(hostname);
  const parsed = isIp ? null : parseDomain(hostname, { allowPrivateDomains: true });
  const defaultPort = scheme === 'https' ? 443 : scheme === 'http' ? 80 : null;

  return {
    input,
    origin,
    valid: true,
    scheme,
    hostname,
    ...(unicode && unicode !== hostname ? { hostnameUnicode: unicode } : {}),
    port: url.port ? Number(url.port) : null,
    effectivePort: url.port ? Number(url.port) : defaultPort,
    path: url.pathname,
    query: [...url.searchParams.entries()].map(([key, v]) => ({ key, value: v })),
    fragment: url.hash.replace(/^#/, ''),
    username: url.username ? decodeSafe(url.username) : '',
    hasPassword: url.password.length > 0,
    subdomain: parsed?.subdomain || null,
    registrableDomain: parsed?.domain ?? null,
    publicSuffix: parsed?.publicSuffix ?? null,
    isIp,
    normalized: url.href,
  };
}

export function decodeSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Finds http(s) URLs and bare www. hosts in free text. */
export function extractUrlsFromText(text: string): { url: string; index: number }[] {
  const out: { url: string; index: number }[] = [];
  const re = /\b(?:https?:\/\/|hxxps?:\/\/|www\.)(?:\[\.\]|\[:\]|[^\s<>"'`)\]}[])+/gi;
  for (const m of text.matchAll(re)) {
    const url = m[0].replace(/[.,;:!?]+$/, '');
    out.push({ url, index: m.index ?? 0 });
  }
  return out;
}
