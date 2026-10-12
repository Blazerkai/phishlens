import net from 'node:net';

/**
 * Classification of IP addresses that must never be reached by outbound probes.
 * Covers loopback, RFC1918 private space, CGNAT, link-local (incl. cloud metadata
 * at 169.254.169.254), multicast, reserved and documentation ranges, and the IPv6
 * equivalents, including IPv4 addresses embedded in IPv6 (mapped / NAT64 / 6to4).
 */

interface Range {
  cidr: string;
  prefix: number;
  reason: string;
}

const V4_RANGES: Range[] = [
  { cidr: '0.0.0.0', prefix: 8, reason: '"this network" (0.0.0.0/8)' },
  { cidr: '10.0.0.0', prefix: 8, reason: 'private network (10.0.0.0/8)' },
  { cidr: '100.64.0.0', prefix: 10, reason: 'carrier-grade NAT (100.64.0.0/10)' },
  { cidr: '127.0.0.0', prefix: 8, reason: 'loopback (127.0.0.0/8)' },
  { cidr: '169.254.0.0', prefix: 16, reason: 'link-local (169.254.0.0/16)' },
  { cidr: '172.16.0.0', prefix: 12, reason: 'private network (172.16.0.0/12)' },
  { cidr: '192.0.0.0', prefix: 24, reason: 'IETF protocol assignments (192.0.0.0/24)' },
  { cidr: '192.0.2.0', prefix: 24, reason: 'documentation (TEST-NET-1)' },
  { cidr: '192.88.99.0', prefix: 24, reason: '6to4 relay anycast (192.88.99.0/24)' },
  { cidr: '192.168.0.0', prefix: 16, reason: 'private network (192.168.0.0/16)' },
  { cidr: '198.18.0.0', prefix: 15, reason: 'benchmarking (198.18.0.0/15)' },
  { cidr: '198.51.100.0', prefix: 24, reason: 'documentation (TEST-NET-2)' },
  { cidr: '203.0.113.0', prefix: 24, reason: 'documentation (TEST-NET-3)' },
  { cidr: '224.0.0.0', prefix: 4, reason: 'multicast (224.0.0.0/4)' },
  { cidr: '240.0.0.0', prefix: 4, reason: 'reserved (240.0.0.0/4)' },
];

const V6_RANGES: Range[] = [
  { cidr: '::', prefix: 128, reason: 'unspecified address (::)' },
  { cidr: '::1', prefix: 128, reason: 'loopback (::1)' },
  { cidr: '100::', prefix: 64, reason: 'discard-only (100::/64)' },
  { cidr: '2001::', prefix: 32, reason: 'Teredo tunnelling (2001::/32)' },
  { cidr: '2001:db8::', prefix: 32, reason: 'documentation (2001:db8::/32)' },
  { cidr: 'fc00::', prefix: 7, reason: 'unique local address (fc00::/7)' },
  { cidr: 'fe80::', prefix: 10, reason: 'link-local (fe80::/10)' },
  { cidr: 'fec0::', prefix: 10, reason: 'site-local, deprecated (fec0::/10)' },
  { cidr: 'ff00::', prefix: 8, reason: 'multicast (ff00::/8)' },
];

const blockList = new net.BlockList();
for (const r of V4_RANGES) blockList.addSubnet(r.cidr, r.prefix, 'ipv4');
for (const r of V6_RANGES) blockList.addSubnet(r.cidr, r.prefix, 'ipv6');
blockList.addAddress('255.255.255.255', 'ipv4');

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inV4Range(ip: string, r: Range): boolean {
  const mask = r.prefix === 0 ? 0 : (~0 << (32 - r.prefix)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(r.cidr) & mask);
}

/** Expands an IPv6 address to 8 groups of 16-bit integers. */
export function expandIPv6(ip: string): number[] | null {
  if (!net.isIPv6(ip)) return null;
  let addr = ip.split('%')[0]!;
  // Trailing dotted-quad (e.g. ::ffff:1.2.3.4)
  const v4 = addr.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4) {
    const n = v4ToInt(v4[1]!);
    addr = addr.slice(0, -v4[1]!.length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [head, tail] = addr.split('::') as [string, string | undefined];
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = addr.includes('::') ? 8 - h.length - t.length : 0;
  const groups = [...h, ...Array(fill).fill('0'), ...t].map((g) => parseInt(g || '0', 16));
  return groups.length === 8 ? groups : null;
}

/** Returns an IPv4 address embedded in an IPv6 address via mapping, NAT64 or 6to4. */
export function embeddedIPv4(ip: string): string | null {
  const g = expandIPv6(ip);
  if (!g) return null;
  const toV4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  // ::ffff:a.b.c.d (IPv4-mapped) and ::a.b.c.d (IPv4-compatible, deprecated)
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0) && (g[6] !== 0 || g[7]! > 1)) {
    return toV4(g[6]!, g[7]!);
  }
  // 64:ff9b::/96 (NAT64 well-known prefix)
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return toV4(g[6]!, g[7]!);
  // 2002::/16 (6to4) embeds the IPv4 address in bits 16..47
  if (g[0] === 0x2002) return toV4(g[1]!, g[2]!);
  return null;
}

export interface IpClassification {
  ip: string;
  version: 4 | 6 | 0;
  blocked: boolean;
  reason: string | null;
}

export function classifyIp(ip: string): IpClassification {
  const bare = ip.replace(/^\[|\]$/g, '');
  const version = net.isIP(bare) as 0 | 4 | 6;
  if (version === 0) return { ip: bare, version: 0, blocked: true, reason: 'not a valid IP address' };

  if (version === 4) {
    const hit = V4_RANGES.find((r) => inV4Range(bare, r));
    if (hit) return { ip: bare, version, blocked: true, reason: hit.reason };
    if (bare === '255.255.255.255') return { ip: bare, version, blocked: true, reason: 'limited broadcast' };
    return { ip: bare, version, blocked: false, reason: null };
  }

  const embedded = embeddedIPv4(bare);
  if (embedded) {
    const inner = classifyIp(embedded);
    if (inner.blocked) return { ip: bare, version, blocked: true, reason: `embeds IPv4 ${embedded}: ${inner.reason}` };
  }
  if (blockList.check(bare, 'ipv6')) {
    const hit = V6_RANGES.find((r) => {
      const b = new net.BlockList();
      b.addSubnet(r.cidr, r.prefix, 'ipv6');
      return b.check(bare, 'ipv6');
    });
    return { ip: bare, version, blocked: true, reason: hit?.reason ?? 'reserved IPv6 range' };
  }
  return { ip: bare, version, blocked: false, reason: null };
}

export function isPublicIp(ip: string): boolean {
  return !classifyIp(ip).blocked;
}

export function isIpLiteral(host: string): boolean {
  return net.isIP(host.replace(/^\[|\]$/g, '')) !== 0;
}
