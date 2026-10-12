import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { fakeDns, fakeHttp } from '../fakes.js';
import { fakeTls, rdapResponse, scenario } from '../scenario.js';

const fixture = (name: string) => fs.readFileSync(path.join(__dirname, '..', 'fixtures', name), 'utf8');

describe('end-to-end investigations (fake network)', () => {
  it('credential phishing on a brand lookalike → HIGH RISK with a critical correlation', async () => {
    const http = fakeHttp({
      'https://paypa1-secure.example/signin': { status: 302, headers: { location: 'https://paypa1-secure.example/auth/login.php' } },
      'https://paypa1-secure.example/auth/login.php': {
        status: 200,
        headers: { 'content-type': 'text/html' },
        body: '<title>Log in to your PayPal account</title><form action="https://collector.example/gate.php"><input type="password" name="pw"></form>',
      },
      'https://rdap.test/domain/paypa1-secure.example': rdapResponse(2),
    });
    const dns = fakeDns({ 'paypa1-secure.example': { A: ['93.184.216.50'], NS: ['a.ns.cloudflare.com'] } });
    const r = await scenario({ url: 'https://paypa1-secure.example/signin' }, { http, dns, tls: fakeTls({ issuedDaysAgo: 1 }) });

    expect(r.assessment.verdict).toBe('high_risk');
    expect(r.codes).toEqual(expect.arrayContaining(['LOOKALIKE_HOMOGLYPH', 'RDAP_NEWLY_REGISTERED', 'PAGE_PASSWORD_FIELD', 'PAGE_FORM_OFFSITE', 'CORR_LOOKALIKE_CREDENTIAL_HARVEST', 'CORR_NEW_DOMAIN_CREDENTIALS', 'TLS_VALID']));
    expect(r.indicators.find((i) => i.code === 'CORR_LOOKALIKE_CREDENTIAL_HARVEST')!.severity).toBe('critical');
    // Valid Let's Encrypt certificate does not reduce the risk
    expect(r.indicators.find((i) => i.code === 'TLS_VALID')!.polarity).toBe('benign');
    expect(r.artifacts.redirects[0]!.hops).toHaveLength(2);
  });

  it('authenticated newsletter with consistent links → BENIGN', async () => {
    const dns = fakeDns({
      'example.org': { A: ['93.184.216.34'], NS: ['a.iana-servers.net'] },
      'newsletter.example.org': { A: ['93.184.216.60'], MX: ['10 mx.newsletter.example.org'], TXT: ['v=spf1 include:_spf.esp.example -all'], NS: ['ns1.example.net'] },
      '_dmarc.newsletter.example.org': { TXT: ['v=DMARC1; p=reject'] },
      'mail.newsletter.example.org': { A: ['93.184.216.61'], MX: ['10 mx.newsletter.example.org'], TXT: ['v=spf1 ip4:198.2.128.10 -all'] },
      'www.newsletter.example.org': { A: ['93.184.216.60'] },
    });
    const http = fakeHttp({
      'https://www.newsletter.example.org/march': { status: 200, headers: { 'content-type': 'text/html' }, body: '<title>March</title>' },
      'https://rdap.test/domain/example.org': rdapResponse(4000),
    });
    const r = await scenario(
      { headers: fixture('legit-gmail.txt'), message: '<p>Hello! Read <a href="https://www.newsletter.example.org/march">this month’s update</a>.</p>' },
      { dns, http, tls: fakeTls() },
    );
    expect(r.indicators.filter((i) => i.polarity === 'risk' && i.severity !== 'info')).toEqual([]);
    expect(r.codes).toEqual(expect.arrayContaining(['EMAIL_DMARC_PASS', 'CORR_CONSISTENT_SENDER', 'RDAP_ESTABLISHED']));
    expect(r.assessment.verdict).toBe('benign');
  });

  it('spoofed brand with free-mail Reply-To → HIGH RISK', async () => {
    const r = await scenario(
      { headers: fixture('spoof-m365.txt'), message: 'Your PayPal account has been limited. Please verify your password within 24 hours.\n\nThe PayPal Team' },
      {},
      { probes: false },
    );
    expect(r.assessment.verdict).toBe('high_risk');
    expect(r.codes).toEqual(expect.arrayContaining(['EMAIL_DMARC_FAIL', 'EMAIL_REPLYTO_MISMATCH', 'CORR_SPOOFED_BRAND_DOMAIN', 'MESSAGE_SE_COMBINATION']));
  });

  it('business email compromise (display-name spoof + wire transfer + secrecy) → HIGH RISK', async () => {
    const r = await scenario(
      { headers: fixture('display-spoof.txt'), message: 'Are you at your desk? I need you to process a wire transfer today. Keep this confidential until the deal closes.' },
      {},
      { probes: false },
    );
    expect(r.codes).toContain('CORR_BEC_PATTERN');
    expect(r.assessment.verdict).toBe('high_risk');
  });

  it('a plain URL with probes disabled → INCONCLUSIVE with explicit unavailable collectors', async () => {
    const r = await scenario({ url: 'https://www.example.com/' }, {}, { probes: false });
    expect(r.assessment.verdict).toBe('inconclusive');
    expect(r.assessment.coverage.unavailable.map((u) => u.analyzer).sort()).toEqual(['dns', 'rdap', 'redirects', 'reputation', 'tls']);
    expect(r.artifacts.dns).toEqual([]); // nothing fabricated
    expect(r.artifacts.tls).toEqual([]);
    expect(r.events.filter((e) => e.status === 'unavailable').map((e) => e.stage).sort()).toEqual(['dns', 'rdap', 'redirects', 'reputation', 'tls']);
  });

  it('an analyzer crash is isolated and reported as failed', async () => {
    const dns = { description: 'broken', resolve: async () => { throw new TypeError('resolver exploded'); }, reverse: async () => [] };
    const r = await scenario({ domain: 'example.org' }, { dns, http: fakeHttp({}), tls: fakeTls() });
    const dnsRun = r.analyzerRuns.find((x) => x.analyzer === 'dns')!;
    expect(dnsRun.status).toBe('failed');
    expect(r.assessment.coverage.failed.map((f) => f.analyzer)).toContain('dns');
    expect(r.analyzerRuns.find((x) => x.analyzer === 'tls')!.status).toBe('completed');
  });

  it('only runs (and reports) the stages relevant to the input, in dependency order with real timestamps', async () => {
    const r = await scenario({ message: 'Hello, see you tomorrow.' }, {}, { probes: true });
    const started = r.events.filter((e) => e.status === 'started').map((e) => e.stage);
    expect(started).toEqual(['message', 'verdict']);
    const times = r.events.map((e) => new Date(e.timestamp).getTime());
    expect([...times].sort((a, b) => a - b)).toEqual(times);
  });

  it('builds an evidence graph whose node indicators reference real indicators', async () => {
    const r = await scenario({ headers: fixture('spoof-m365.txt'), url: 'https://paypal.com.account-check.example/x' }, {}, { probes: false });
    const ids = new Set(r.indicators.map((i) => i.id));
    const attached = r.graph.nodes.flatMap((n) => n.indicatorIds);
    expect(attached.length).toBe(r.indicators.length);
    expect(attached.every((id) => ids.has(id))).toBe(true);
    const types = new Set(r.graph.nodes.map((n) => n.type));
    expect([...types]).toEqual(expect.arrayContaining(['investigation', 'email', 'address', 'domain', 'mailserver', 'url']));
    for (const e of r.graph.edges) {
      expect(r.graph.nodes.some((n) => n.id === e.from)).toBe(true);
      expect(r.graph.nodes.some((n) => n.id === e.to)).toBe(true);
    }
    const lookalikeHost = r.graph.nodes.find((n) => n.id === 'host:paypal.com.account-check.example');
    expect(lookalikeHost?.risk).toBe('high');
  });
});
