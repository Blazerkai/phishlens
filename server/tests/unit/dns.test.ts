import { describe, expect, it } from 'vitest';
import { identifyProviders, isNullMx, parseDmarcRecord, parseSpfRecords } from '../../src/analyzers/dns/records.js';
import { collectDns } from '../../src/analyzers/dns/index.js';
import { dnsHeuristics } from '../../src/analyzers/dns/heuristics.js';
import type { DnsAnalysis } from '@phishlens/shared';
import { fakeDns } from '../fakes.js';
import { codes, lists } from '../helpers.js';

describe('SPF record parsing', () => {
  it('parses mechanisms, includes and the all qualifier', () => {
    const [spf] = parseSpfRecords(['google-site-verification=xyz', 'v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:mailgun.org ~all']);
    expect(spf).toMatchObject({ allQualifier: '~', includes: ['_spf.google.com', 'mailgun.org'] });
    expect(spf!.mechanisms).toContain('ip4:192.0.2.0/24');
  });

  it('treats a bare "all" as +all', () => {
    expect(parseSpfRecords(['v=spf1 all'])[0]!.allQualifier).toBe('+');
  });

  it('handles records without an all mechanism and ignores non-SPF TXT', () => {
    expect(parseSpfRecords(['v=spf1 include:x.example'])[0]!.allQualifier).toBeNull();
    expect(parseSpfRecords(['v=spf10 nonsense', 'hello'])).toEqual([]);
  });
});

describe('DMARC record parsing', () => {
  it('parses policy, subdomain policy, pct and rua', () => {
    expect(parseDmarcRecord(['v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@x.example,mailto:b@x.example'])).toMatchObject({
      policy: 'reject',
      subdomainPolicy: 'quarantine',
      pct: 50,
      rua: ['mailto:a@x.example', 'mailto:b@x.example'],
    });
  });

  it('returns null when there is no DMARC record', () => {
    expect(parseDmarcRecord(['v=spf1 -all'])).toBeNull();
  });
});

describe('MX and providers', () => {
  it('recognises null MX', () => {
    expect(isNullMx(['0 .'])).toBe(true);
    expect(isNullMx(['10 mx.example.com'])).toBe(false);
  });

  it('identifies providers by role-specific patterns only', () => {
    const p = identifyProviders(
      [
        { role: 'dns', host: 'kim.ns.cloudflare.com.', basis: 'NS' },
        { role: 'mail', host: 'example-com.mail.protection.outlook.com', basis: 'MX' },
        { role: 'mail', host: 'ns1.google.com', basis: 'MX' },
      ],
      lists,
    ).map((x) => x.name);
    expect(p).toEqual(['Cloudflare DNS', 'Microsoft 365 (Exchange Online)', 'Google Workspace / Gmail']);
  });
});

const zone = {
  'corp.example': {
    A: ['93.184.216.10'],
    MX: ['10 corp-example.mail.protection.outlook.com'],
    NS: ['ns1.corp.example'],
    TXT: ['v=spf1 include:spf.protection.outlook.com -all'],
    PTR: ['web.hosting.example'],
  },
  '_dmarc.corp.example': { TXT: ['v=DMARC1; p=reject'] },
  'mail.corp.example': { A: ['93.184.216.11'] },
  'lazy.example': { A: ['93.184.216.20'], TXT: ['v=spf1 +all'] },
  'nomail.example': { A: ['93.184.216.21'], MX: ['0 .'], TXT: ['v=spf1 -all'] },
  'internal.example': { A: ['10.1.2.3'] },
};

async function collect(name: string, full = true): Promise<DnsAnalysis> {
  const c = await collectDns(fakeDns(zone), name, { full, orgDomain: name.split('.').slice(-2).join('.'), reverseLimit: 2 });
  return { ...c, providers: [] };
}

describe('DNS collection', () => {
  it('collects all record types and parses SPF/DMARC', async () => {
    const d = await collect('corp.example');
    expect(d.status).toBe('completed');
    expect(d.records.map((r) => [r.type, r.status])).toEqual([
      ['A', 'ok'], ['AAAA', 'nodata'], ['CNAME', 'nodata'], ['MX', 'ok'], ['NS', 'ok'], ['TXT', 'ok'], ['DMARC', 'ok'],
    ]);
    expect(d.spf?.allQualifier).toBe('-');
    expect(d.dmarc?.policy).toBe('reject');
    expect(d.reverse).toEqual([{ ip: '93.184.216.10', names: ['web.hosting.example'] }]);
  });

  it('falls back to the organisational domain for DMARC', async () => {
    const c = await collectDns(fakeDns(zone), 'mail.corp.example', { full: true, orgDomain: 'corp.example', reverseLimit: 0 });
    expect(c.dmarc?.policy).toBe('reject');
  });

  it('queries only address records for non-registrable names', async () => {
    const dns = fakeDns(zone);
    await collectDns(dns, 'mail.corp.example', { full: false, orgDomain: 'corp.example', reverseLimit: 0 });
    expect(dns.queries.sort()).toEqual(['A mail.corp.example', 'AAAA mail.corp.example', 'CNAME mail.corp.example']);
  });

  it('distinguishes NXDOMAIN from timeouts', async () => {
    const nx = await collect('missing.example');
    expect(nx.records.filter((r) => r.type !== 'DMARC').every((r) => r.status === 'nxdomain')).toBe(true);
    expect(nx.records.find((r) => r.type === 'DMARC')?.status).toBe('nodata');
    const c = await collectDns(fakeDns({ 'slow.example': { A: 'TIMEOUT', AAAA: 'TIMEOUT', CNAME: 'TIMEOUT' } }), 'slow.example', { full: false, orgDomain: null, reverseLimit: 0 });
    expect(c.status).toBe('failed');
    expect(c.records[0]!.status).toBe('timeout');
  });

  it('does not reverse-resolve non-public addresses', async () => {
    const d = await collect('internal.example', false);
    expect(d.reverse).toEqual([]);
  });
});

describe('DNS heuristics', () => {
  it('reports a well-configured sender domain as benign/neutral only', async () => {
    const out = dnsHeuristics(await collect('corp.example'), new Set(['sender']), true);
    expect(out.filter((i) => i.severity !== 'info')).toEqual([]);
    expect(out.find((i) => i.code === 'DNS_DMARC_ENFORCED')?.polarity).toBe('benign');
  });

  it('flags a sender domain that does not exist as medium, but a dead link host only as low', async () => {
    const nx = await collect('missing.example');
    expect(dnsHeuristics(nx, new Set(['sender']), true)[0]).toMatchObject({ code: 'DNS_SENDER_NXDOMAIN', severity: 'medium' });
    expect(dnsHeuristics(nx, new Set(['message-link']), false)[0]).toMatchObject({ code: 'DNS_NXDOMAIN', severity: 'low' });
  });

  it('flags +all SPF, missing DMARC and missing MX for a sender domain', async () => {
    expect(codes(dnsHeuristics(await collect('lazy.example'), new Set(['sender']), true))).toEqual(
      expect.arrayContaining(['DNS_SPF_PASS_ALL', 'DNS_NO_DMARC', 'DNS_SENDER_NO_MX']),
    );
  });

  it('flags null MX for a sender domain', async () => {
    expect(codes(dnsHeuristics(await collect('nomail.example'), new Set(['sender']), true))).toContain('DNS_SENDER_NULL_MX');
  });

  it('does not assess mail posture for a website-only domain', async () => {
    const out = dnsHeuristics(await collect('lazy.example'), new Set(['submitted-url']), false);
    expect(out).toEqual([]);
  });

  it('flags public names that resolve to private addresses', async () => {
    expect(codes(dnsHeuristics(await collect('internal.example', false), new Set(['message-link']), false))).toEqual(['DNS_NON_PUBLIC_ADDRESS']);
  });

  it('labels providers as neutral context', () => {
    const d: DnsAnalysis = { name: 'x.example', status: 'completed', resolver: 'r', records: [], spf: null, dmarc: null, reverse: [], providers: [{ role: 'dns', name: 'Cloudflare DNS', basis: 'NS a.ns.cloudflare.com' }], queriedAt: '' };
    expect(dnsHeuristics(d, new Set(['submitted-url']), false)).toMatchObject([{ code: 'DNS_PROVIDER_DNS', severity: 'info', polarity: 'neutral' }]);
  });
});
