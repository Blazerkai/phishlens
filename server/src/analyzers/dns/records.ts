import type { DmarcRecord, SpfRecord } from '@phishlens/shared';
import type { ReferenceLists } from '../../config/lists.js';

/** Parses SPF (RFC 7208) from a domain's TXT records. Returns every v=spf1 record found. */
export function parseSpfRecords(txt: string[]): SpfRecord[] {
  return txt
    .filter((t) => /^v=spf1(\s|$)/i.test(t.trim()))
    .map((raw) => {
      const terms = raw.trim().split(/\s+/).slice(1);
      const all = terms.find((t) => /^[+\-~?]?all$/i.test(t));
      return {
        raw,
        mechanisms: terms,
        allQualifier: all ? ((/^[+\-~?]/.test(all) ? all[0] : '+') as SpfRecord['allQualifier']) : null,
        includes: terms.filter((t) => /^[+\-~?]?include:/i.test(t)).map((t) => t.replace(/^[+\-~?]?include:/i, '')),
      };
    });
}

/** Parses a DMARC (RFC 7489) record from the TXT records at _dmarc.<domain>. */
export function parseDmarcRecord(txt: string[]): DmarcRecord | null {
  const raw = txt.find((t) => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
  if (!raw) return null;
  const tags = new Map<string, string>();
  for (const part of raw.split(';')) {
    const [k, ...v] = part.split('=');
    if (k && v.length) tags.set(k.trim().toLowerCase(), v.join('=').trim());
  }
  const pct = tags.has('pct') ? Number(tags.get('pct')) : null;
  return {
    raw,
    policy: tags.get('p')?.toLowerCase() ?? null,
    subdomainPolicy: tags.get('sp')?.toLowerCase() ?? null,
    pct: pct !== null && Number.isFinite(pct) ? pct : null,
    rua: (tags.get('rua') ?? '').split(',').map((s) => s.trim()).filter(Boolean),
  };
}

/** Matches hostnames (NS, MX, CNAME targets, PTR names) against the provider pattern list. */
export function identifyProviders(
  values: { role: 'dns' | 'mail' | 'hosting'; host: string; basis: string }[],
  lists: ReferenceLists,
): { role: 'dns' | 'mail' | 'hosting'; name: string; basis: string }[] {
  const out = new Map<string, { role: 'dns' | 'mail' | 'hosting'; name: string; basis: string }>();
  for (const v of values) {
    const host = v.host.replace(/\.$/, '').toLowerCase();
    const hit = lists.providerPatterns.find((p) => p.role === v.role && p.pattern.test(host));
    if (hit && !out.has(`${v.role}:${hit.name}`)) out.set(`${v.role}:${hit.name}`, { role: v.role, name: hit.name, basis: `${v.basis} ${host}` });
  }
  return [...out.values()];
}

/** Hosting platforms that publish a custom-domain verification TXT record. */
export function identifyTxtProviders(txt: string[], lists: ReferenceLists): { role: 'hosting'; name: string; basis: string }[] {
  const out = new Map<string, { role: 'hosting'; name: string; basis: string }>();
  for (const v of txt) {
    const hit = lists.txtProviderPatterns.find((p) => p.pattern.test(v.trim()));
    if (hit && !out.has(hit.name)) out.set(hit.name, { role: 'hosting', name: hit.name, basis: `TXT "${v.trim().slice(0, 80)}"` });
  }
  return [...out.values()];
}

/** MX values are stored as "<priority> <exchange>". A null MX (RFC 7505) is "0 .". */
export function isNullMx(mx: string[]): boolean {
  return mx.length === 1 && /^0\s+\.?$/.test(mx[0]!.trim());
}

export const PARKING_NS = /(sedoparking|parkingcrew|bodis|above\.com|parklogic|dan\.com|afternic|parked|domainnameshop|uniregistrymarket|hugedomains)/i;
