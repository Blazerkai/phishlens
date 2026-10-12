import { describe, expect, it } from 'vitest';
import { extractUrlsFromText, parseUrl } from '../../src/analyzers/url/parseUrl.js';

describe('parseUrl', () => {
  it('extracts every component of a full URL', () => {
    const u = parseUrl('https://user@login.secure.example.co.uk:8443/a/b.php?x=1&y=two#frag');
    expect(u).toMatchObject({
      valid: true,
      scheme: 'https',
      hostname: 'login.secure.example.co.uk',
      port: 8443,
      effectivePort: 8443,
      path: '/a/b.php',
      fragment: 'frag',
      username: 'user',
      subdomain: 'login.secure',
      registrableDomain: 'example.co.uk',
      publicSuffix: 'co.uk',
      isIp: false,
    });
    expect(u.query).toEqual([
      { key: 'x', value: '1' },
      { key: 'y', value: 'two' },
    ]);
  });

  it('uses the default port when none is given', () => {
    expect(parseUrl('https://example.com').effectivePort).toBe(443);
    expect(parseUrl('http://example.com').effectivePort).toBe(80);
    expect(parseUrl('https://example.com').port).toBeNull();
  });

  it('treats a bare host/path as http like a browser would', () => {
    const u = parseUrl('example.com/login');
    expect(u.scheme).toBe('http');
    expect(u.hostname).toBe('example.com');
    expect(u.path).toBe('/login');
  });

  it('re-fangs defanged indicators', () => {
    const u = parseUrl('hxxps://evil[.]example[.]com/path');
    expect(u.valid).toBe(true);
    expect(u.normalized).toBe('https://evil.example.com/path');
  });

  it('normalises obfuscated IPv4 notation the way browsers do', () => {
    expect(parseUrl('http://3232235777/').hostname).toBe('192.168.1.1');
    expect(parseUrl('http://0x7f.1/').hostname).toBe('127.0.0.1');
    expect(parseUrl('http://0x7f.1/').isIp).toBe(true);
  });

  it('handles IPv6 literals', () => {
    const u = parseUrl('http://[2606:4700::1111]/');
    expect(u.hostname).toBe('2606:4700::1111');
    expect(u.isIp).toBe(true);
    expect(u.registrableDomain).toBeNull();
  });

  it('decodes IDN to unicode for display but keeps the ASCII form for analysis', () => {
    const u = parseUrl('https://xn--pypal-4ve.com/');
    expect(u.hostname).toBe('xn--pypal-4ve.com');
    expect(u.hostnameUnicode).toBe('pаypal.com');
  });

  it('respects private public-suffix entries for registrable domain', () => {
    const u = parseUrl('https://login-portal.github.io/x');
    expect(u.registrableDomain).toBe('login-portal.github.io');
    expect(u.publicSuffix).toBe('github.io');
  });

  it('reports invalid input without throwing', () => {
    const u = parseUrl('http://exa mple.com');
    expect(u.valid).toBe(false);
    expect(u.error).toBeDefined();
  });

  it('keeps non-web schemes recognisable', () => {
    expect(parseUrl('javascript:alert(1)').scheme).toBe('javascript');
    expect(parseUrl('data:text/html;base64,PGgxPg==').scheme).toBe('data');
  });
});

describe('extractUrlsFromText', () => {
  it('finds http, https, defanged and www links and trims trailing punctuation', () => {
    const found = extractUrlsFromText('Visit https://a.example/x, or www.b.example. Also hxxp://c[.]example/y!').map((f) => f.url);
    expect(found).toEqual(['https://a.example/x', 'www.b.example', 'hxxp://c[.]example/y']);
  });
});
