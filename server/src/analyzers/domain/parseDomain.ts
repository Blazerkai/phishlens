import { domainToASCII, domainToUnicode } from 'node:url';
import { parse } from 'tldts';
import type { DomainAnalysis } from '@phishlens/shared';
import { isIpLiteral } from '../../security/ip.js';
import { refang } from '../../lib/text.js';
import { scriptsOf } from './confusables.js';

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;

/** Normalises user-supplied domain input (strips scheme/path, re-fangs, converts IDN to ASCII). */
export function normalizeDomainInput(raw: string): string | null {
  let v = refang(raw).value.toLowerCase();
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (v.includes('@')) v = v.slice(v.lastIndexOf('@') + 1);
  if (isIpLiteral(v)) return v.replace(/^\[|\]$/g, '');
  const ascii = domainToASCII(v);
  if (!ascii || !HOSTNAME_RE.test(ascii)) return null;
  return ascii;
}

export function parseDomain(hostname: string, sources: string[] = []): DomainAnalysis {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (isIpLiteral(host)) {
    return {
      hostname: host,
      hostnameUnicode: host,
      isIp: true,
      subdomain: null,
      registrableDomain: null,
      publicSuffix: null,
      tld: null,
      labels: [host],
      subdomainDepth: 0,
      isPunycode: false,
      isPrivateSuffix: false,
      scripts: [],
      sources,
      brandMatches: [],
    };
  }
  const p = parse(host, { allowPrivateDomains: true });
  const icann = parse(host);
  const unicode = domainToUnicode(host) || host;
  const labels = host.split('.');
  return {
    hostname: host,
    hostnameUnicode: unicode,
    isIp: false,
    subdomain: p.subdomain || null,
    registrableDomain: p.domain ?? null,
    publicSuffix: p.publicSuffix ?? null,
    tld: icann.publicSuffix?.split('.').pop() ?? labels[labels.length - 1] ?? null,
    labels,
    subdomainDepth: p.subdomain ? p.subdomain.split('.').length : 0,
    isPunycode: labels.some((l) => l.startsWith('xn--')),
    isPrivateSuffix: p.isPrivate === true,
    scripts: scriptsOf(unicode),
    sources,
    brandMatches: [],
  };
}
