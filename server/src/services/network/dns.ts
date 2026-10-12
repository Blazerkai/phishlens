import { promises as dnsPromises } from 'node:dns';
import type { DnsRecordType, DnsService } from './types.js';

function timeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      t = setTimeout(() => reject(Object.assign(new Error(`DNS query timed out after ${ms} ms`), { code: 'ETIMEOUT' })), ms);
    }),
  ]).finally(() => clearTimeout(t));
}

/** Live DNS resolver. Uses the system's configured servers unless DNS_SERVERS is set. */
export function createDnsService(opts: { timeoutMs: number; servers: string[] }): DnsService {
  const resolver = new dnsPromises.Resolver({ timeout: opts.timeoutMs, tries: 2 });
  if (opts.servers.length) resolver.setServers(opts.servers);
  const servers = resolver.getServers();
  const hardLimit = opts.timeoutMs * 2 + 500;

  return {
    description: `DNS resolver ${servers.join(', ') || 'system default'} (live query)`,
    async resolve(name: string, type: DnsRecordType): Promise<string[]> {
      switch (type) {
        case 'A':
          return timeout(resolver.resolve4(name), hardLimit);
        case 'AAAA':
          return timeout(resolver.resolve6(name), hardLimit);
        case 'CNAME':
          return timeout(resolver.resolveCname(name), hardLimit);
        case 'NS':
          return timeout(resolver.resolveNs(name), hardLimit);
        case 'MX':
          return (await timeout(resolver.resolveMx(name), hardLimit))
            .sort((a, b) => a.priority - b.priority)
            .map((m) => `${m.priority} ${m.exchange || '.'}`);
        case 'TXT':
          return (await timeout(resolver.resolveTxt(name), hardLimit)).map((chunks) => chunks.join(''));
      }
    },
    async reverse(ip: string): Promise<string[]> {
      return timeout(resolver.reverse(ip), hardLimit);
    },
  };
}
