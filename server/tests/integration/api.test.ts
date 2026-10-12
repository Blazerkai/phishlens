import fs from 'node:fs';
import path from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/index.js';
import { initDatabase } from '../../src/database/index.js';
import { InvestigationService } from '../../src/services/investigationService.js';
import { disabledSummarizer } from '../../src/services/ai/index.js';
import { createApp } from '../../src/app.js';
import { fakeDns, fakeHttp } from '../fakes.js';
import { fakeTls, rdapResponse } from '../scenario.js';

const fixture = (name: string) => fs.readFileSync(path.join(__dirname, '..', 'fixtures', name), 'utf8');

function setup(env: Record<string, string> = {}) {
  const config = loadConfig({ NODE_ENV: 'test', RDAP_BOOTSTRAP_URL: 'https://rdap.test/domain/', CORS_ORIGINS: 'http://localhost:5173', ...env });
  const { repo, db } = initDatabase(config);
  const services = {
    dns: fakeDns({ 'paypa1-secure.example': { A: ['93.184.216.50'] } }),
    http: fakeHttp({
      'https://paypa1-secure.example/login': { status: 200, headers: { 'content-type': 'text/html' }, body: '<title>Sign in</title><input type="password">' },
      'https://rdap.test/domain/paypa1-secure.example': rdapResponse(3),
    }),
    tls: fakeTls(),
  };
  const service = new InvestigationService({ config, repo, services });
  const app = createApp({ config, repo, service, ai: disabledSummarizer('disabled in tests') });
  return { app, repo, service, db, config };
}

async function createAndWait(ctx: ReturnType<typeof setup>, body: object) {
  const res = await request(ctx.app).post('/api/investigations').send(body).expect(202);
  await ctx.service.idle();
  return (await request(ctx.app).get(`/api/investigations/${res.body.id}`).expect(200)).body;
}

describe('POST /api/investigations validation', () => {
  const ctx = setup();
  it('rejects an empty submission', async () => {
    const r = await request(ctx.app).post('/api/investigations').send({}).expect(400);
    expect(r.body.error).toBe('validation_error');
  });
  it('rejects whitespace-only fields', async () => {
    await request(ctx.app).post('/api/investigations').send({ url: '   ' }).expect(400);
  });
  it('rejects unknown fields (strict schema)', async () => {
    await request(ctx.app).post('/api/investigations').send({ url: 'https://a.example', cmd: 'rm -rf /' }).expect(400);
  });
  it('rejects oversized fields', async () => {
    await request(ctx.app).post('/api/investigations').send({ url: `https://a.example/${'a'.repeat(5000)}` }).expect(400);
  });
  it('rejects malformed JSON without leaking internals', async () => {
    const r = await request(ctx.app).post('/api/investigations').set('Content-Type', 'application/json').send('{"url":').expect(400);
    expect(r.body).toEqual({ error: 'invalid_json', message: 'Request body is not valid JSON' });
  });
  it('rejects bodies over 1 MB', async () => {
    await request(ctx.app).post('/api/investigations').send({ message: 'x'.repeat(1_100_000) }).expect(413);
  });
  it('rejects non-UUID ids', async () => {
    await request(ctx.app).get('/api/investigations/../../etc/passwd').expect(404);
    await request(ctx.app).get('/api/investigations/1%20OR%201=1').expect(400);
  });
});

describe('investigation lifecycle', () => {
  it('runs the analysis, records a real timeline and does not retain raw content by default', async () => {
    const ctx = setup();
    const d = await createAndWait(ctx, { url: 'https://paypa1-secure.example/login', headers: fixture('spoof-m365.txt') });
    expect(d.status).toBe('completed');
    expect(d.verdict).toBe('high_risk');
    expect(d.indicatorCount).toBe(d.indicators.length);

    const stages = d.timeline.map((t: { stage: string; status: string }) => `${t.stage}:${t.status}`);
    expect(stages[0]).toBe('created:completed');
    expect(stages).toContain('url:started');
    expect(stages).toContain('email-headers:completed');
    expect(stages[stages.length - 1]).toBe('report:completed');
    const times = d.timeline.map((t: { timestamp: string }) => Date.parse(t.timestamp));
    expect([...times].sort((a, b) => a - b)).toEqual(times);

    const headers = d.inputs.find((i: { type: string }) => i.type === 'headers');
    expect(headers).toMatchObject({ value: null, retained: false });
    expect(headers.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(d.inputs.find((i: { type: string }) => i.type === 'url').value).toBe('https://paypa1-secure.example/login');
    const raw = ctx.db.prepare('SELECT value FROM inputs WHERE type = ?').get('headers') as { value: string | null };
    expect(raw.value).toBeNull();
  });

  it('retains raw content only when configured', async () => {
    const ctx = setup({ RETAIN_RAW_CONTENT: 'true' });
    const d = await createAndWait(ctx, { message: 'hello there' });
    expect(d.inputs[0]).toMatchObject({ type: 'message', value: 'hello there', retained: true });
  });

  it('persists normalised evidence tables', async () => {
    const ctx = setup();
    const d = await createAndWait(ctx, { url: 'https://paypa1-secure.example/login', headers: fixture('legit-gmail.txt') });
    const count = (t: string) => (ctx.db.prepare(`SELECT COUNT(*) AS n FROM ${t} WHERE investigation_id = ?`).get(d.id) as { n: number }).n;
    expect(count('indicators')).toBe(d.indicators.length);
    expect(count('dns_records')).toBeGreaterThan(0);
    expect(count('tls_certificates')).toBe(1);
    expect(count('redirects')).toBeGreaterThan(0);
    expect(count('email_headers')).toBe(1);
    expect(count('timeline_events')).toBe(d.timeline.length);
  });

  it('lists, filters, deletes (cascading) and reports 404 afterwards', async () => {
    const ctx = setup();
    const d = await createAndWait(ctx, { domain: 'example.org' });
    const list = await request(ctx.app).get('/api/investigations?limit=10').expect(200);
    expect(list.body.total).toBe(1);
    expect((await request(ctx.app).get('/api/investigations?verdict=benign').expect(200)).body.items.length).toBeLessThanOrEqual(1);
    await request(ctx.app).get('/api/investigations?verdict=evil').expect(400);
    await request(ctx.app).delete(`/api/investigations/${d.id}`).expect(204);
    await request(ctx.app).get(`/api/investigations/${d.id}`).expect(404);
    expect((ctx.db.prepare('SELECT COUNT(*) AS n FROM timeline_events').get() as { n: number }).n).toBe(0);
  });

  it('serves dashboard statistics', async () => {
    const ctx = setup();
    await createAndWait(ctx, { url: 'https://paypa1-secure.example/login' });
    await createAndWait(ctx, { message: 'See you at lunch.' });
    const r = await request(ctx.app).get('/api/dashboard').expect(200);
    expect(r.body.totals.total).toBe(2);
    expect(r.body.thisWeek).toBe(2);
    expect(r.body.recent).toHaveLength(2);
    expect(r.body.commonIndicators.length).toBeGreaterThan(0);
    expect(r.body.verdictByDay).toHaveLength(14);
  });
});

describe('reports', () => {
  it('exports md, html and json; HTML-escapes hostile evidence', async () => {
    const ctx = setup();
    const d = await createAndWait(ctx, { message: '<a href="https://evil.example/x">https://www.paypal.com/<script>alert(1)</script></a> verify your password immediately "><img src=x onerror=alert(2)>' });
    const html = await request(ctx.app).get(`/api/investigations/${d.id}/report?format=html`).expect(200);
    expect(html.headers['content-type']).toMatch(/text\/html/);
    expect(html.headers['content-security-policy']).toContain("default-src 'none'");
    expect(html.text).not.toMatch(/<script>alert/);
    expect(html.text).not.toMatch(/<img src=x/);
    for (const section of ['Executive summary', 'Risk assessment', 'Indicators', 'DNS information', 'TLS information', 'Redirect chain', 'Timeline', 'Limitations', d.id]) {
      expect(html.text).toContain(section);
    }
    const md = await request(ctx.app).get(`/api/investigations/${d.id}/report?format=md&download=1`).expect(200);
    expect(md.headers['content-disposition']).toMatch(/attachment; filename="phishlens-/);
    expect(md.text).toContain('# PhishLens Investigation Report');
    expect(md.text).toContain('## Limitations');
    const json = await request(ctx.app).get(`/api/investigations/${d.id}/report?format=json`).expect(200);
    expect(json.body.investigation.id).toBe(d.id);
  });

  it('AI summary reports an explicit unavailable state when disabled', async () => {
    const ctx = setup();
    const d = await createAndWait(ctx, { message: 'hello' });
    const r = await request(ctx.app).post(`/api/investigations/${d.id}/summary`).expect(200);
    expect(r.body).toMatchObject({ status: 'unavailable' });
  });
});

describe('brands API', () => {
  it('seeds, adds, validates and deletes brands', async () => {
    const ctx = setup();
    const seeded = (await request(ctx.app).get('/api/brands').expect(200)).body;
    expect(seeded.length).toBeGreaterThan(0);
    const created = await request(ctx.app).post('/api/brands').send({ name: 'Contoso', keywords: ['contoso'], officialDomains: ['contoso.com'] }).expect(201);
    await request(ctx.app).post('/api/brands').send({ name: 'contoso', keywords: ['contoso'], officialDomains: [] }).expect(409);
    await request(ctx.app).post('/api/brands').send({ name: 'Bad', keywords: ['a b'], officialDomains: [] }).expect(400);
    await request(ctx.app).post('/api/brands').send({ name: 'Bad2', keywords: ['bad2'], officialDomains: ['not a domain'] }).expect(400);
    await request(ctx.app).delete(`/api/brands/${created.body.id}`).expect(204);
  });
});

describe('HTTP hardening', () => {
  it('sets security headers and hides the framework', async () => {
    const ctx = setup();
    const r = await request(ctx.app).get('/api/health').expect(200);
    expect(r.headers['x-powered-by']).toBeUndefined();
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['x-frame-options']).toBe('DENY');
    expect(r.headers['content-security-policy']).toContain("default-src 'none'");
    expect(r.headers['cache-control']).toBe('no-store');
  });

  it('allows only configured CORS origins', async () => {
    const ctx = setup();
    const ok = await request(ctx.app).options('/api/investigations').set('Origin', 'http://localhost:5173').expect(204);
    expect(ok.headers['access-control-allow-origin']).toBe('http://localhost:5173');
    const bad = await request(ctx.app).options('/api/investigations').set('Origin', 'https://evil.example').expect(403);
    expect(bad.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('rate-limits investigation creation', async () => {
    const ctx = setup({ RATE_LIMIT_CREATE_MAX: '2' });
    await request(ctx.app).post('/api/investigations').send({ domain: 'a.example' }).expect(202);
    await request(ctx.app).post('/api/investigations').send({ domain: 'b.example' }).expect(202);
    const r = await request(ctx.app).post('/api/investigations').send({ domain: 'c.example' }).expect(429);
    expect(r.headers['retry-after']).toBeDefined();
    await ctx.service.idle();
  });

  it('returns JSON 404 for unknown API routes', async () => {
    const ctx = setup();
    expect((await request(ctx.app).get('/api/nope').expect(404)).body.error).toBe('not_found');
  });
});

describe('retention', () => {
  it('purges investigations older than the retention window', async () => {
    const ctx = setup();
    const d = await createAndWait(ctx, { domain: 'old.example' });
    ctx.db.prepare('UPDATE investigations SET created_at = ? WHERE id = ?').run('2020-01-01T00:00:00.000Z', d.id);
    expect(ctx.repo.purgeOlderThan(30)).toBe(1);
    expect(ctx.repo.getDetail(d.id)).toBeNull();
  });

  it('marks investigations interrupted by a restart as failed', () => {
    const ctx = setup();
    ctx.repo.createInvestigation({ id: '00000000-0000-4000-8000-000000000001', title: 't', inputTypes: ['url'], inputs: [], createdAt: new Date().toISOString() });
    expect(ctx.repo.failInterrupted()).toBe(1);
    expect(ctx.repo.getDetail('00000000-0000-4000-8000-000000000001')!.status).toBe('failed');
  });
});

describe('operator identity API', () => {
  const valid = { domain: 'https://www.Contoso-Shop.com/login', operatorName: 'Contoso Retail Ltd', method: 'legal_entity_registry', evidenceReference: 'Companies House 09876543; confirmed by phone via registered office', verifiedBy: 'analyst@corp.example' };

  it('records a verification against the registrable domain with an expiry', async () => {
    const ctx = setup();
    const r = await request(ctx.app).post('/api/identity').send(valid).expect(201);
    expect(r.body).toMatchObject({ domain: 'contoso-shop.com', operatorName: 'Contoso Retail Ltd', revokedAt: null });
    expect(Date.parse(r.body.expiresAt) - Date.parse(r.body.verifiedAt)).toBe(365 * 86_400_000);
  });

  it('rejects DNS ownership as a verification method, with an explanation', async () => {
    const ctx = setup();
    const r = await request(ctx.app).post('/api/identity').send({ ...valid, method: 'dns_ownership' }).expect(400);
    expect(JSON.stringify(r.body.issues)).toMatch(/DNS or website control alone does not establish/);
  });

  it('requires supporting evidence, a verifier, a real domain and an expiry of at most two years', async () => {
    const ctx = setup();
    await request(ctx.app).post('/api/identity').send({ ...valid, evidenceReference: 'trust me' }).expect(400);
    await request(ctx.app).post('/api/identity').send({ ...valid, verifiedBy: undefined }).expect(400);
    await request(ctx.app).post('/api/identity').send({ ...valid, domain: '203.0.113.5' }).expect(400);
    await request(ctx.app).post('/api/identity').send({ ...valid, validDays: 3650 }).expect(400);
  });

  it('revokes instead of deleting, and revoked records drop out of the active list', async () => {
    const ctx = setup();
    const { body } = await request(ctx.app).post('/api/identity').send(valid).expect(201);
    await request(ctx.app).post(`/api/identity/${body.id}/revoke`).expect(204);
    await request(ctx.app).post(`/api/identity/${body.id}/revoke`).expect(404);
    expect((await request(ctx.app).get('/api/identity').expect(200)).body).toEqual([]);
    expect((await request(ctx.app).get('/api/identity?includeRevoked=1').expect(200)).body[0].revokedAt).not.toBeNull();
  });

  it('applies an active verification to new investigations of that domain', async () => {
    const ctx = setup();
    await request(ctx.app).post('/api/identity').send({ ...valid, domain: 'paypa1-secure.example' }).expect(201);
    const d = await createAndWait(ctx, { url: 'https://paypa1-secure.example/login' });
    // Identity is recorded but the lookalike still escalates: identity never offsets risk.
    expect(d.indicators.some((i: { code: string }) => i.code === 'IDENTITY_VERIFIED')).toBe(true);
    expect(['suspicious', 'high_risk']).toContain(d.verdict);
  });

  it('exposes reputation provider status without credentials', async () => {
    const ctx = setup({ VIRUSTOTAL_API_KEY: 'secret-vt-key' });
    const r = await request(ctx.app).get('/api/settings').expect(200);
    expect(JSON.stringify(r.body)).not.toContain('secret-vt-key');
  });
});
