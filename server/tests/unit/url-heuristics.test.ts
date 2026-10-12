import { describe, expect, it } from 'vitest';
import { parseUrl } from '../../src/analyzers/url/parseUrl.js';
import { urlHeuristics } from '../../src/analyzers/url/heuristics.js';
import { brands, codes, lists } from '../helpers.js';

const run = (url: string) => urlHeuristics(parseUrl(url), { brands, lists });

describe('URL heuristics — benign cases', () => {
  it('does not flag a normal HTTPS login URL just because it contains "login"', () => {
    expect(run('https://login.microsoftonline.com/common/oauth2/authorize?client_id=abc')).toEqual([]);
  });

  it('does not flag "account", "verify" or "secure" words in a path', () => {
    expect(run('https://www.example.org/account/verify/secure')).toEqual([]);
  });

  it('does not flag a brand name in the path of the brand’s own domain', () => {
    expect(codes(run('https://www.paypal.com/paypal/signin'))).not.toContain('URL_BRAND_IN_PATH');
  });

  it('does not treat a normal query string as a redirect', () => {
    expect(run('https://shop.example.com/search?q=shoes&page=2')).toEqual([]);
  });
});

describe('URL heuristics — risk cases', () => {
  it('flags an IP address host with medium severity and a reason', () => {
    const [ind] = run('https://93.184.216.34/login');
    expect(ind).toMatchObject({ code: 'URL_IP_HOST', severity: 'medium' });
    expect(ind!.description).toMatch(/IP address/);
    expect(ind!.evidence).toBe('https://93.184.216.34/login');
  });

  it('explains URLs that point to reserved/internal addresses', () => {
    const ind = run('http://169.254.169.254/latest/meta-data/').find((i) => i.code === 'URL_NON_PUBLIC_ADDRESS');
    expect(ind?.description).toMatch(/link-local/);
    expect(codes(run('http://2130706433/'))).toEqual(expect.arrayContaining(['URL_NON_PUBLIC_ADDRESS', 'URL_OBFUSCATED_IP']));
  });

  it('flags obfuscated decimal IP notation as high severity', () => {
    const out = run('http://134744072/'); // 8.8.8.8
    expect(codes(out)).toContain('URL_OBFUSCATED_IP');
    expect(out.find((i) => i.code === 'URL_OBFUSCATED_IP')!.severity).toBe('high');
  });

  it('does not call a defanged IP "obfuscated"', () => {
    expect(codes(run('hxxp://93[.]184[.]216[.]34/'))).toContain('URL_IP_HOST');
    expect(codes(run('hxxp://93[.]184[.]216[.]34/'))).not.toContain('URL_OBFUSCATED_IP');
  });

  it('flags the userinfo trick when the username looks like a domain', () => {
    const out = run('https://www.paypal.com@evil.example/');
    const ind = out.find((i) => i.code === 'URL_USERINFO');
    expect(ind?.severity).toBe('high');
    expect(ind?.description).toContain('evil.example');
  });

  it('flags non-standard ports at low severity only', () => {
    const ind = run('https://example.com:8443/').find((i) => i.code === 'URL_NONSTANDARD_PORT');
    expect(ind?.severity).toBe('low');
  });

  it('records plaintext HTTP as a neutral observation (transport risk is assessed once, from the redirect outcome)', () => {
    expect(run('http://example.com/').map((i) => [i.code, i.severity, i.polarity])).toEqual([['URL_PLAINTEXT_HTTP', 'info', 'neutral']]);
  });

  it('flags javascript: and data: URLs', () => {
    expect(codes(run('javascript:alert(document.cookie)'))).toEqual(['URL_INLINE_CONTENT_SCHEME']);
    expect(codes(run('data:text/html;base64,PGZvcm0+'))).toEqual(['URL_INLINE_CONTENT_SCHEME']);
  });

  it('detects an embedded redirect to another domain', () => {
    const ind = run('https://www.google.com/url?q=https://evil.example/login').find((i) => i.code === 'URL_EMBEDDED_REDIRECT');
    expect(ind).toBeDefined();
    expect(ind!.evidence).toContain('evil.example');
  });

  it('does not flag a redirect parameter that stays on the same registrable domain', () => {
    expect(codes(run('https://accounts.example.com/login?next=https://www.example.com/home'))).not.toContain('URL_EMBEDDED_REDIRECT');
  });

  it('detects a recipient address in the query string, including base64', () => {
    expect(codes(run('https://x.example/p?email=jane.doe@corp.example'))).toContain('URL_RECIPIENT_EMAIL');
    const b64 = Buffer.from('jane.doe@corp.example').toString('base64');
    expect(codes(run(`https://x.example/p?u=${b64}`))).toContain('URL_RECIPIENT_EMAIL');
  });

  it('detects a recipient address hidden in the fragment', () => {
    const ind = run('https://x.example/p#jane@corp.example').find((i) => i.code === 'URL_RECIPIENT_EMAIL');
    expect(ind?.title).toMatch(/fragment/);
  });

  it('detects a brand domain placed in the path', () => {
    const ind = run('https://evil.example/www.paypal.com/signin').find((i) => i.code === 'URL_DOMAIN_IN_PATH');
    expect(ind?.title).toContain('PayPal');
  });

  it('detects double encoding', () => {
    expect(codes(run('https://x.example/a%252Fb'))).toContain('URL_DOUBLE_ENCODING');
  });

  it('detects executable downloads', () => {
    expect(codes(run('https://files.example/invoice.pdf.exe'))).toContain('URL_EXECUTABLE_DOWNLOAD');
    expect(codes(run('https://files.example/report.pdf'))).toEqual([]);
  });

  it('flags link shorteners as hiding the destination', () => {
    expect(codes(run('https://bit.ly/3abcdef'))).toContain('URL_SHORTENER');
  });

  it('flags percent-encoded hostnames', () => {
    expect(codes(run('https://pay%70al.example/'))).toContain('URL_ENCODED_HOSTNAME');
  });

  it('every indicator has evidence, a source and a reason', () => {
    for (const ind of run('http://user:pw@192.0.2.1:8080/www.paypal.com/x.exe?url=https://a.example&e=a@b.example')) {
      expect(ind.evidence.length).toBeGreaterThan(0);
      expect(ind.source.length).toBeGreaterThan(0);
      expect(ind.description.length).toBeGreaterThan(20);
      expect(ind.confidence).toBeGreaterThan(0);
      expect(ind.confidence).toBeLessThanOrEqual(1);
    }
  });
});
