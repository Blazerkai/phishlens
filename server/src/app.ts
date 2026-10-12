import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type NextFunction, type Request, type Response } from 'express';
import { ZodError } from 'zod';
import type { AppConfig } from './config/index.js';
import type { Repository } from './database/repository.js';
import type { InvestigationService } from './services/investigationService.js';
import type { AiSummarizer } from './services/ai/index.js';
import type { ReputationProviderInfo } from '@phishlens/shared';
import { apiRouter } from './routes/api.js';
import { cors, securityHeaders } from './security/headers.js';
import { rateLimit } from './security/rateLimit.js';
import { logger } from './lib/logger.js';

export interface AppContext {
  config: AppConfig;
  repo: Repository;
  service: InvestigationService;
  ai: AiSummarizer;
  reputationProviders?: ReputationProviderInfo[];
}

export function createApp(ctx: AppContext) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.config.trustProxy ? 1 : false);
  app.set('query parser', 'simple');

  app.use(securityHeaders);
  app.use('/api', cors(ctx.config.corsOrigins));
  app.use('/api', rateLimit({ windowMs: ctx.config.rateLimit.windowMs, max: ctx.config.rateLimit.max, name: 'api' }));
  app.use('/api', express.json({ limit: '1mb', strict: true }));
  app.use('/api', apiRouter(ctx));
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'not_found', message: 'Unknown API route' });
  });

  // Production: serve the built SPA from client/dist.
  const clientDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../client/dist');
  if (ctx.config.env === 'production' && fs.existsSync(clientDist)) {
    app.use(express.static(clientDist, { index: false, maxAge: '1h' }));
    app.get(/^(?!\/api\/).*/, (_req, res) => res.sendFile(path.join(clientDist, 'index.html')));
  }

  // Errors: validation problems are reported precisely; everything else is generic.
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof ZodError) {
      res.status(400).json({
        error: 'validation_error',
        message: 'Request validation failed',
        issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      });
      return;
    }
    const e = err as { type?: string; status?: number; message?: string };
    if (e?.type === 'entity.too.large') {
      res.status(413).json({ error: 'payload_too_large', message: 'Request body exceeds 1 MB' });
      return;
    }
    if (e?.type === 'entity.parse.failed') {
      res.status(400).json({ error: 'invalid_json', message: 'Request body is not valid JSON' });
      return;
    }
    logger.error('unhandled error', { path: req.path, method: req.method, error: e?.message });
    res.status(500).json({ error: 'internal_error', message: 'An internal error occurred' });
  });

  return app;
}
