import { describe, expect, it } from 'vitest';
import { followRedirects } from '../../src/analyzers/redirects/follow.js';
import { redirectHeuristics } from '../../src/analyzers/redirects/heuristics.js';
import { inspectHtml } from '../../src/analyzers/redirects/page.js';
import { fakeHttp } from '../fakes.js';
import { codes, lists } from '../helpers.js';

const opts = { maxRedirects: 5, timeoutMs: 1000, maxBodyBytes: 65536, allowedPorts: [80, 443, 8080, 8443] };
const redirect = (to: string, status = 302) => ({ status, headers: { location: to } });
const html = (body: string, status = 200) => ({ status, headers: { 'content-type': 'text/html; charset=utf-8' }, body });

describe('redirect following', () => {
  it('records each hop with status, host, scheme and location', async () => {
    const http = fakeHttp({
      'https://short.example/a': redirect('https://track.example/c?id=1', 301),
      'https://track.example/c?id=1': redirect('/landing'),
      'https://track.example/landing': html('<title>Welcome</title>'),
    });
    const r = await followRedirects('https://short.example/a', http, opts);
    expect(r.status).toBe('completed');
    expect(r.redirectCount).toBe(2);
    expect(r.finalUrl).toBe('https://track.example/landing');
    expect(r.hops.map((h) => [h.statusCode, h.hostname, h.scheme, h.kind])).toEqual([
      [301, 'short.example', 'https', 'http'],
      [302, 'track.example', 'https', 'http'],
      [200, 'track.example', 'https', 'final'],
    ]);
    expect(r.hops[1]!.location).toBe('/landing');
    expect(r.page?.title).toBe('Welcome');
  });

  it('enforces the maximum redirect count', async () => {
    const routes: Record<string, ReturnType<typeof redirect>> = {};
    for (let i = 0; i < 20; i++) routes[`https://hop.example/${i}`] = redirect(`https://hop.example/${i + 1}`);
    const http = fakeHttp(routes);
    const r = await followRedirects('https://hop.example/0', http, { ...opts, maxRedirects: 3 });
    expect(http.calls).toHaveLength(4);
    expect(r.reason).toMatch(/maximum of 3/);
    expect(r.finalUrl).toBe('https://hop.example/4');
  });

  it('detects loops', async () => {
    const http = fakeHttp({ 'https://a.example/': redirect('https://b.example/'), 'https://b.example/': redirect('https://a.example/') });
    const r = await followRedirects('https://a.example/', http, opts);
    expect(r.reason).toMatch(/loop/);
    expect(http.calls).toHaveLength(2);
  });

  it('refuses to follow a redirect into the internal network and never requests it', async () => {
    const http = fakeHttp({ 'https://public.example/': redirect('http://169.254.169.254/latest/meta-data/') });
    const r = await followRedirects('https://public.example/', http, opts);
    expect(http.calls).toEqual(['https://public.example/']);
    expect(r.hops[1]).toMatchObject({ kind: 'blocked', hostname: '169.254.169.254' });
    expect(codes(redirectHeuristics(r, lists))).toContain('REDIRECT_TO_INTERNAL');
  });

  it.each(['http://localhost/admin', 'http://127.0.0.1:8080/', 'http://[::1]/', 'http://10.0.0.1/', 'http://2130706433/', 'file:///etc/passwd'])(
    'blocks redirect to %s',
    async (target) => {
      const http = fakeHttp({ 'https://public.example/': redirect(target) });
      const r = await followRedirects('https://public.example/', http, opts);
      expect(http.calls).toHaveLength(1);
      expect(r.hops[r.hops.length - 1]!.kind).toBe('blocked');
    },
  );

  it('blocks an internal start URL without any request', async () => {
    const http = fakeHttp({});
    const r = await followRedirects('http://192.168.0.1/', http, opts);
    expect(r.status).toBe('blocked');
    expect(http.calls).toEqual([]);
  });

  it('follows meta refresh redirects', async () => {
    const http = fakeHttp({
      'https://a.example/': html('<meta http-equiv="refresh" content="0; url=https://b.example/next">'),
      'https://b.example/next': html('<p>done</p>'),
    });
    const r = await followRedirects('https://a.example/', http, opts);
    expect(r.hops[0]!.kind).toBe('meta-refresh');
    expect(r.finalUrl).toBe('https://b.example/next');
  });

  it('handles network errors safely', async () => {
    const http = fakeHttp({ 'https://a.example/': redirect('https://down.example/') });
    const r = await followRedirects('https://a.example/', http, opts);
    expect(r.status).toBe('completed');
    expect(r.hops[1]).toMatchObject({ kind: 'error' });
    const first = await followRedirects('https://down.example/', fakeHttp({}), opts);
    expect(first.status).toBe('failed');
  });
});

describe('redirect heuristics', () => {
  it('does not flag a short same-site redirect (http → https canonicalisation)', async () => {
    const http = fakeHttp({ 'http://example.com/': redirect('https://www.example.com/', 301), 'https://www.example.com/': html('ok') });
    expect(redirectHeuristics(await followRedirects('http://example.com/', http, opts), lists)).toEqual([]);
  });

  it('flags excessive, cross-domain, downgrading chains that land on an IP', async () => {
    const http = fakeHttp({
      'https://a.example/': redirect('https://b.example/'),
      'https://b.example/': redirect('https://c.example/'),
      'https://c.example/': redirect('https://d.example/'),
      'https://d.example/': redirect('http://93.184.216.34/x'),
      'http://93.184.216.34/x': html('<form action="https://collect.example/p"><input type="password" name="p"></form>'),
    });
    const out = redirectHeuristics(await followRedirects('https://a.example/', http, opts), lists);
    expect(codes(out)).toEqual(
      expect.arrayContaining(['REDIRECT_EXCESSIVE', 'REDIRECT_CROSS_DOMAIN', 'REDIRECT_HTTPS_DOWNGRADE', 'REDIRECT_TO_IP', 'PAGE_PASSWORD_FIELD', 'PAGE_FORM_OFFSITE']),
    );
    expect(out.find((i) => i.code === 'PAGE_FORM_OFFSITE')!.severity).toBe('medium');
  });

  it('treats shortener → destination as expected, not suspicious', async () => {
    const http = fakeHttp({ 'https://bit.ly/x': redirect('https://www.example.org/article', 301), 'https://www.example.org/article': html('ok') });
    const ind = redirectHeuristics(await followRedirects('https://bit.ly/x', http, opts), lists).find((i) => i.code === 'REDIRECT_CROSS_DOMAIN');
    expect(ind?.severity).toBe('info');
  });
});

describe('static page inspection', () => {
  it('extracts title, password fields, form actions and script redirects without executing anything', () => {
    const p = inspectHtml(
      `<html><head><title>Sign in &amp; verify</title></head><body>
       <form method="post" action="https://collector.example/gate.php"><input name="u"><input type = 'password' name="p"></form>
       <script>window.location.href = "https://next.example/";</script></body></html>`,
      'text/html',
      300,
    );
    expect(p).toMatchObject({ title: 'Sign in & verify', hasPasswordField: true, formActions: ['https://collector.example/gate.php'], scriptRedirect: 'https://next.example/' });
  });

  it('reports nothing for plain pages', () => {
    expect(inspectHtml('<p>Hello</p>', 'text/html', 12)).toMatchObject({ hasPasswordField: false, formActions: [], metaRefresh: null, scriptRedirect: null });
  });
});
