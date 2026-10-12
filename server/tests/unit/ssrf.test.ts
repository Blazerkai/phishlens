import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { classifyIp, embeddedIPv4, expandIPv6 } from '../../src/security/ip.js';
import { assertUrlAllowed, createSafeLookup, hostnamePolicyViolation, resolvePublicAddresses, SsrfBlockedError } from '../../src/security/ssrf.js';
import { createHttpService } from '../../src/services/network/http.js';
import { createTlsService } from '../../src/services/network/tls.js';

const policy = { allowedPorts: [80, 443, 8080, 8443] };

describe('IP classification', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['10.0.0.5', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'link-local'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['0.0.0.0', 'this network'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'reserved'],
    ['192.0.2.10', 'documentation'],
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fe80::1', 'link-local'],
    ['fc00::1', 'unique local'],
    ['fd12:3456::1', 'unique local'],
    ['ff02::1', 'multicast'],
    ['::ffff:127.0.0.1', 'embeds IPv4 127.0.0.1'],
    ['::ffff:7f00:1', 'embeds IPv4 127.0.0.1'],
    ['::ffff:169.254.169.254', 'link-local'],
    ['64:ff9b::a00:1', 'embeds IPv4 10.0.0.1'],
    ['2002:c0a8:0101::1', 'embeds IPv4 192.168.1.1'],
  ])('blocks %s (%s)', (ip, reason) => {
    const c = classifyIp(ip);
    expect(c.blocked).toBe(true);
    expect(c.reason).toContain(reason);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '172.15.255.255', '2606:4700:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8'])(
    'allows public address %s',
    (ip) => expect(classifyIp(ip).blocked).toBe(false),
  );

  it('rejects garbage', () => {
    expect(classifyIp('not-an-ip').blocked).toBe(true);
    expect(classifyIp('999.1.1.1').blocked).toBe(true);
  });

  it('expands IPv6 and extracts embedded IPv4', () => {
    expect(expandIPv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(embeddedIPv4('::ffff:10.1.2.3')).toBe('10.1.2.3');
    expect(embeddedIPv4('2606:4700::1111')).toBeNull();
  });
});

describe('URL / hostname policy', () => {
  it.each([
    ['http://localhost/', 'local machine'],
    ['http://LOCALHOST./', 'local machine'],
    ['http://foo.localhost/', 'internal-only suffix'],
    ['http://printer.local/', 'internal-only suffix'],
    ['http://metadata.google.internal/', 'metadata'],
    ['http://intranet/', 'single-label'],
    ['http://127.0.0.1/', 'loopback'],
    ['http://[::1]/', 'loopback'],
    ['http://169.254.169.254/latest/meta-data/', 'link-local'],
    ['http://2130706433/', 'loopback'], // decimal 127.0.0.1
    ['http://0x7f000001/', 'loopback'],
    ['http://0177.0.0.1/', 'loopback'],
    ['http://127.1/', 'loopback'],
    ['http://[::ffff:127.0.0.1]/', 'loopback'],
    ['http://10.0.0.1:8080/', 'private'],
    ['ftp://example.com/', 'scheme'],
    ['file:///etc/passwd', 'scheme'],
    ['gopher://example.com/', 'scheme'],
    ['http://example.com:22/', 'port 22'],
    ['http://example.com:6379/', 'port 6379'],
  ])('blocks %s', (url, reason) => {
    expect(() => assertUrlAllowed(url, policy)).toThrowError(SsrfBlockedError);
    try {
      assertUrlAllowed(url, policy);
    } catch (e) {
      expect((e as Error).message).toContain(reason);
    }
  });

  it.each(['https://example.com/', 'http://example.com:8080/x', 'https://93.184.216.34/'])('allows %s', (url) => {
    expect(() => assertUrlAllowed(url, policy)).not.toThrow();
  });

  it('flags hostnames before resolution', () => {
    expect(hostnamePolicyViolation('example.com')).toBeNull();
    expect(hostnamePolicyViolation('router.home.arpa')).toMatch(/internal/);
  });
});

describe('resolution policy', () => {
  it('rejects a hostname that resolves to a private address', async () => {
    await expect(resolvePublicAddresses('evil.example', async () => [{ address: '10.0.0.7', family: 4 }])).rejects.toThrow(/private network/);
  });

  it('rejects mixed public/private answers (rebinding / round-robin trick)', async () => {
    const resolveAll = async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ];
    await expect(resolvePublicAddresses('rebind.example', resolveAll)).rejects.toThrow(/loopback/);
  });

  it('rejects AAAA answers that embed private IPv4', async () => {
    await expect(resolvePublicAddresses('x.example', async () => [{ address: '::ffff:192.168.0.1', family: 6 }])).rejects.toThrow(SsrfBlockedError);
  });

  it('accepts all-public answers', async () => {
    const r = await resolvePublicAddresses('ok.example', async () => [{ address: '93.184.216.34', family: 4 }]);
    expect(r[0]!.address).toBe('93.184.216.34');
  });

  it('safe lookup returns the validated address, pinning the connection', async () => {
    const lookup = createSafeLookup(async () => [{ address: '93.184.216.34', family: 4 }]);
    const addr = await new Promise<string>((res, rej) => lookup('ok.example', {}, (err, a) => (err ? rej(err) : res(a as string))));
    expect(addr).toBe('93.184.216.34');
  });

  it('safe lookup refuses internal answers', async () => {
    const lookup = createSafeLookup(async () => [{ address: '169.254.169.254', family: 4 }]);
    await expect(new Promise((res, rej) => lookup('meta.example', {}, (err, a) => (err ? rej(err) : res(a))))).rejects.toThrow(SsrfBlockedError);
  });
});

describe('HTTP and TLS clients against a real local server', () => {
  let server: http.Server;
  let port: number;
  let hits = 0;
  beforeAll(async () => {
    server = http.createServer((_req, res) => {
      hits++;
      res.end('internal secret');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it('never connects to loopback, even with the port allow-listed', async () => {
    const svc = createHttpService({ allowedPorts: [port] });
    await expect(svc.request(`http://127.0.0.1:${port}/`, { timeoutMs: 1000, maxBodyBytes: 100, readBody: true })).rejects.toThrow(SsrfBlockedError);
    await expect(svc.request(`http://localhost:${port}/`, { timeoutMs: 1000, maxBodyBytes: 100, readBody: true })).rejects.toThrow(SsrfBlockedError);
    expect(hits).toBe(0);
  });

  it('never connects when a public-looking hostname resolves to loopback (DNS rebinding)', async () => {
    const svc = createHttpService({ allowedPorts: [port], resolveAll: async () => [{ address: '127.0.0.1', family: 4 }] });
    await expect(svc.request(`http://innocent.example:${port}/`, { timeoutMs: 1000, maxBodyBytes: 100, readBody: true })).rejects.toThrow(/loopback/);
    expect(hits).toBe(0);
  });

  it('TLS inspection refuses internal targets', async () => {
    const svc = createTlsService({ allowedPorts: [443, port], resolveAll: async () => [{ address: '127.0.0.1', family: 4 }] });
    await expect(svc.inspect('innocent.example', port, 1000)).rejects.toThrow(SsrfBlockedError);
    await expect(svc.inspect('example.com', 22, 1000)).rejects.toThrow(/allow-list/);
    expect(hits).toBe(0);
  });
});
