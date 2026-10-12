import type { DnsAnalysis, DnsRecordSet } from '@phishlens/shared';
import type { Analyzer } from '../types.js';
import type { DnsRecordType, DnsService } from '../../services/network/types.js';
import { networkTargets, SENDER_ROLES, type TargetRole } from '../targets.js';
import { identifyProviders, identifyTxtProviders, parseDmarcRecord, parseSpfRecords } from './records.js';
import { dnsHeuristics } from './heuristics.js';
import { classifyIp } from '../../security/ip.js';

function errorStatus(err: unknown): DnsRecordSet['status'] {
  const code = (err as { code?: string })?.code;
  if (code === 'ENODATA' || code === 'ENONAME') return 'nodata';
  if (code === 'ENOTFOUND' || code === 'NXDOMAIN') return 'nxdomain';
  if (code === 'ETIMEOUT' || code === 'ETIMEDOUT') return 'timeout';
  return 'error';
}

export async function queryRecord(dns: DnsService, name: string, type: DnsRecordType, label: DnsRecordSet['type'] = type): Promise<DnsRecordSet> {
  try {
    const values = await dns.resolve(name, type);
    return { type: label, status: values.length ? 'ok' : 'nodata', values };
  } catch (err) {
    const status = errorStatus(err);
    return {
      type: label,
      status,
      values: [],
      ...(status === 'error' || status === 'timeout' ? { error: (err as Error).message } : {}),
    };
  }
}

/** Collects DNS records for one name. Full mail posture is collected for registrable/sender domains only. */
export async function collectDns(
  dns: DnsService,
  name: string,
  opts: { full: boolean; orgDomain: string | null; reverseLimit: number },
): Promise<Omit<DnsAnalysis, 'providers'>> {
  const types: DnsRecordType[] = opts.full ? ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'] : ['A', 'AAAA', 'CNAME'];
  const records = await Promise.all(types.map((t) => queryRecord(dns, name, t)));

  let spf = null;
  let dmarc = null;
  if (opts.full) {
    let dmarcSet = await queryRecord(dns, `_dmarc.${name}`, 'TXT', 'DMARC');
    // RFC 7489 §6.6.3: fall back to the organisational domain's policy.
    if (dmarcSet.status !== 'ok' && opts.orgDomain && opts.orgDomain !== name) {
      const org = await queryRecord(dns, `_dmarc.${opts.orgDomain}`, 'TXT', 'DMARC');
      if (org.status === 'ok') dmarcSet = { ...org, values: org.values.map((v) => v) };
    }
    // A missing _dmarc name (NXDOMAIN) simply means "no DMARC record"; it says nothing about the domain itself.
    if (dmarcSet.status === 'nxdomain') dmarcSet.status = 'nodata';
    dmarcSet.values = dmarcSet.values.filter((v) => /^v=DMARC1/i.test(v.trim()));
    if (dmarcSet.status === 'ok' && dmarcSet.values.length === 0) dmarcSet.status = 'nodata';
    records.push(dmarcSet);
    spf = parseSpfRecords(records.find((r) => r.type === 'TXT')?.values ?? [])[0] ?? null;
    dmarc = parseDmarcRecord(dmarcSet.values);
  }

  const ips = records
    .filter((r) => r.type === 'A' || r.type === 'AAAA')
    .flatMap((r) => r.values)
    .filter((ip) => !classifyIp(ip).blocked)
    .slice(0, opts.reverseLimit);
  const reverse = await Promise.all(
    ips.map(async (ip) => {
      try {
        return { ip, names: await dns.reverse(ip) };
      } catch {
        return { ip, names: [] };
      }
    }),
  );

  const anyAnswered = records.some((r) => r.status === 'ok' || r.status === 'nodata' || r.status === 'nxdomain');
  return {
    name,
    status: anyAnswered ? 'completed' : 'failed',
    ...(anyAnswered ? {} : { reason: records.find((r) => r.error)?.error ?? 'No DNS answers received' }),
    resolver: dns.description,
    records,
    spf,
    dmarc,
    reverse,
    queriedAt: new Date().toISOString(),
  };
}

export const dnsAnalyzer: Analyzer = {
  id: 'dns',
  label: 'Collecting DNS records',
  dependsOn: ['domain'],
  applies: (ctx) => networkTargets(ctx).length > 0,
  async run(ctx) {
    if (!ctx.settings.network.probesEnabled) {
      return { status: 'unavailable', reason: 'Network probing is disabled (NETWORK_PROBES_ENABLED=false); no DNS records were collected.' };
    }

    // Build the set of names to query: each target host plus its registrable domain.
    const names = new Map<string, { roles: Set<TargetRole>; full: boolean; isRegistrable: boolean; org: string | null }>();
    for (const t of networkTargets(ctx)) {
      const isSender = [...t.roles].some((r) => SENDER_ROLES.includes(r));
      const entry = names.get(t.host) ?? { roles: new Set<TargetRole>(), full: false, isRegistrable: t.host === t.registrableDomain, org: t.registrableDomain };
      t.roles.forEach((r) => entry.roles.add(r));
      entry.full ||= entry.isRegistrable || isSender;
      names.set(t.host, entry);
      if (t.registrableDomain && t.registrableDomain !== t.host) {
        const reg = names.get(t.registrableDomain) ?? { roles: new Set<TargetRole>(), full: true, isRegistrable: true, org: t.registrableDomain };
        t.roles.forEach((r) => reg.roles.add(r));
        names.set(t.registrableDomain, reg);
      }
    }
    const limited = [...names.entries()].slice(0, ctx.settings.network.maxTargets * 2);

    const results = await Promise.all(
      limited.map(async ([name, meta]) => {
        const collected = await collectDns(ctx.services.dns, name, { full: meta.full, orgDomain: meta.org, reverseLimit: 2 });
        const providerInputs = [
          ...(collected.records.find((r) => r.type === 'NS')?.values ?? []).map((h) => ({ role: 'dns' as const, host: h, basis: 'NS' })),
          ...(collected.records.find((r) => r.type === 'MX')?.values ?? []).map((v) => ({ role: 'mail' as const, host: v.split(' ')[1] ?? v, basis: 'MX' })),
          ...(collected.records.find((r) => r.type === 'CNAME')?.values ?? []).map((h) => ({ role: 'hosting' as const, host: h, basis: 'CNAME' })),
          ...collected.reverse.flatMap((r) => r.names.map((n) => ({ role: 'hosting' as const, host: n, basis: `PTR ${r.ip} →` }))),
        ];
        const analysis: DnsAnalysis = {
          ...collected,
          providers: [
            ...identifyProviders(providerInputs, ctx.settings.lists),
            ...identifyTxtProviders(collected.records.find((r) => r.type === 'TXT')?.values ?? [], ctx.settings.lists),
          ],
        };
        return { analysis, meta };
      }),
    );

    const targets = networkTargets(ctx);
    for (const { analysis, meta } of results) {
      ctx.state.dns.push(analysis);
      // Mail posture is assessed on the exact domain used in an address; its parent domain is context only.
      const usedAsSender = targets.some((t) => t.host === analysis.name && [...t.roles].some((r) => SENDER_ROLES.includes(r)));
      for (const d of dnsHeuristics(analysis, meta.roles, usedAsSender)) ctx.emit(d);
    }

    const failed = results.filter((r) => r.analysis.status === 'failed');
    if (failed.length === results.length) {
      return { status: 'failed', reason: `No DNS answers for ${failed.map((f) => f.analysis.name).join(', ')}: ${failed[0]?.analysis.reason ?? ''}` };
    }
    const recordCount = results.reduce((n, r) => n + r.analysis.records.reduce((m, s) => m + s.values.length, 0), 0);
    return { status: 'completed', detail: `${results.length} name(s) queried, ${recordCount} record(s) collected` };
  },
};
