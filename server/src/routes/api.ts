import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { VERDICTS, VERIFICATION_METHODS } from '@phishlens/shared';
import { registrableOf } from '../engine/signals.js';
import { isIpLiteral } from '../security/ip.js';
import type { AppContext } from '../app.js';
import { InvestigationInputSchema } from '../engine/input.js';
import { renderHtml, renderJson, renderMarkdown } from '../services/reportService.js';
import { normalizeDomainInput } from '../analyzers/domain/parseDomain.js';
import { rateLimit } from '../security/rateLimit.js';

const IdParam = z.object({ id: z.uuid() });
const ListQuery = z.object({
  verdict: z.enum(VERDICTS).optional(),
  status: z.enum(['queued', 'running', 'completed', 'failed']).optional(),
  q: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(1_000_000).optional(),
});
const ReportQuery = z.object({ format: z.enum(['md', 'html', 'json']).default('html'), download: z.enum(['1', '0']).optional() });
const BrandBody = z
  .object({
    name: z.string().trim().min(1).max(80),
    keywords: z.array(z.string().trim().toLowerCase().regex(/^[a-z0-9-]{3,40}$/, 'keywords are 3–40 chars: a-z, 0-9, hyphen')).min(1).max(20),
    officialDomains: z.array(z.string().trim().toLowerCase().max(253)).max(50),
  })
  .strict();

const VerificationBody = z
  .object({
    domain: z.string().trim().min(3).max(253),
    operatorName: z.string().trim().min(2).max(200),
    method: z.enum(VERIFICATION_METHODS, {
      error: `method must be one of ${VERIFICATION_METHODS.join(', ')}. DNS or website control alone does not establish who operates a domain.`,
    }),
    evidenceReference: z.string().trim().min(20, 'evidenceReference must describe the supporting evidence (e.g. registry name and ID, ticket or document reference)').max(1000),
    verifiedBy: z.string().trim().min(2).max(120),
    validDays: z.coerce.number().int().min(1).max(730).default(365),
    notes: z.string().trim().max(2000).optional(),
  })
  .strict();

type Handler = (req: Request, res: Response) => unknown;
const wrap = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => Promise.resolve(fn(req, res)).catch(next);

export function apiRouter(ctx: AppContext): Router {
  const r = Router();
  const { repo, service, config } = ctx;

  r.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: config.version, queue: service.queueSize() });
  });

  r.get('/settings', (_req, res) => {
    res.json({
      networkProbesEnabled: config.network.probesEnabled,
      rdapEnabled: config.network.rdapEnabled,
      retainRawContent: config.retention.retainRawContent,
      retentionDays: config.retention.days,
      maxRedirects: config.network.maxRedirects,
      requestTimeoutMs: config.network.requestTimeoutMs,
      allowedPorts: config.network.allowedPorts,
      aiSummaryAvailable: ctx.ai.available,
      aiProvider: ctx.ai.available ? ctx.ai.provider : null,
      version: config.version,
      reputationProviders: ctx.reputationProviders ?? [],
    });
  });

  r.get('/dashboard', (_req, res) => {
    res.json(repo.dashboard());
  });

  r.post(
    '/investigations',
    rateLimit({ windowMs: config.rateLimit.windowMs, max: config.rateLimit.createMax, name: 'create' }),
    wrap((req, res) => {
      const input = InvestigationInputSchema.parse(req.body);
      const { id } = service.create(input);
      res.status(202).location(`/api/investigations/${id}`).json({ id });
    }),
  );

  r.get(
    '/investigations',
    wrap((req, res) => {
      res.json(repo.list(ListQuery.parse(req.query)));
    }),
  );

  r.get(
    '/investigations/:id',
    wrap((req, res) => {
      const { id } = IdParam.parse(req.params);
      const d = repo.getDetail(id);
      if (!d) return res.status(404).json({ error: 'not_found', message: 'Investigation not found' });
      res.json({ ...d, aiSummary: repo.getAiSummary(id), related: repo.related(id) });
    }),
  );

  r.delete(
    '/investigations/:id',
    wrap((req, res) => {
      const { id } = IdParam.parse(req.params);
      if (!repo.deleteInvestigation(id)) return res.status(404).json({ error: 'not_found', message: 'Investigation not found' });
      res.status(204).end();
    }),
  );

  r.get(
    '/investigations/:id/report',
    wrap((req, res) => {
      const { id } = IdParam.parse(req.params);
      const { format, download } = ReportQuery.parse(req.query);
      const d = repo.getDetail(id);
      if (!d) return res.status(404).json({ error: 'not_found', message: 'Investigation not found' });
      const name = `phishlens-${id.slice(0, 8)}`;
      if (download === '1') res.setHeader('Content-Disposition', `attachment; filename="${name}.${format}"`);
      if (format === 'md') return res.type('text/markdown; charset=utf-8').send(renderMarkdown(d));
      if (format === 'json') return res.type('application/json').send(renderJson(d));
      // The HTML report is a standalone document with its own restrictive CSP.
      res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
      return res.type('text/html; charset=utf-8').send(renderHtml(d));
    }),
  );

  r.post(
    '/investigations/:id/summary',
    rateLimit({ windowMs: config.rateLimit.windowMs, max: config.rateLimit.createMax, name: 'ai-summary' }),
    wrap(async (req, res) => {
      const { id } = IdParam.parse(req.params);
      const d = repo.getDetail(id);
      if (!d) return res.status(404).json({ error: 'not_found', message: 'Investigation not found' });
      if (d.status !== 'completed') return res.status(409).json({ error: 'not_ready', message: 'Investigation has not completed' });
      const summary = await ctx.ai.summarize(d);
      if (summary.status === 'completed') repo.saveAiSummary(id, summary);
      res.json(summary);
    }),
  );

  // -- operator identity verifications ----------------------------------------
  r.get('/identity', (req, res) => {
    res.json(repo.listVerifications({ includeRevoked: req.query.includeRevoked === '1' }));
  });

  r.post(
    '/identity',
    wrap((req, res) => {
      const body = VerificationBody.parse(req.body);
      const host = normalizeDomainInput(body.domain);
      const domain = host ? registrableOf(host) : null;
      if (!domain || isIpLiteral(domain)) {
        return res.status(400).json({ error: 'validation_error', message: 'domain must be a valid domain name' });
      }
      const verifiedAt = new Date();
      res.status(201).json(
        repo.addVerification({
          domain,
          operatorName: body.operatorName,
          method: body.method,
          evidenceReference: body.evidenceReference,
          verifiedBy: body.verifiedBy,
          verifiedAt: verifiedAt.toISOString(),
          expiresAt: new Date(verifiedAt.getTime() + body.validDays * 86_400_000).toISOString(),
          notes: body.notes ?? null,
        }),
      );
    }),
  );

  r.post(
    '/identity/:id/revoke',
    wrap((req, res) => {
      const id = z.coerce.number().int().positive().parse(req.params.id);
      if (!repo.revokeVerification(id)) return res.status(404).json({ error: 'not_found', message: 'Active verification not found' });
      res.status(204).end();
    }),
  );

  r.get('/brands', (_req, res) => {
    res.json(repo.listBrands());
  });

  r.post(
    '/brands',
    wrap((req, res) => {
      const body = BrandBody.parse(req.body);
      const domains = body.officialDomains.map((d) => normalizeDomainInput(d));
      if (domains.some((d) => !d)) return res.status(400).json({ error: 'validation_error', message: 'One or more official domains are not valid hostnames' });
      if (repo.listBrands().some((b) => b.name.toLowerCase() === body.name.toLowerCase())) {
        return res.status(409).json({ error: 'conflict', message: 'A brand with this name already exists' });
      }
      res.status(201).json(repo.addBrand({ name: body.name, keywords: [...new Set(body.keywords)], officialDomains: [...new Set(domains as string[])] }));
    }),
  );

  r.delete(
    '/brands/:id',
    wrap((req, res) => {
      const id = z.coerce.number().int().positive().parse(req.params.id);
      if (!repo.deleteBrand(id)) return res.status(404).json({ error: 'not_found', message: 'Brand not found' });
      res.status(204).end();
    }),
  );

  return r;
}
