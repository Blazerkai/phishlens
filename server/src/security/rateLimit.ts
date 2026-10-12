import type { NextFunction, Request, Response } from 'express';

/**
 * Fixed-window, in-memory rate limiter keyed by client IP. Adequate for a
 * single-instance tool; put a shared limiter in front for multi-instance deploys.
 */
export function rateLimit(opts: { windowMs: number; max: number; name: string; now?: () => number }) {
  const now = opts.now ?? Date.now;
  const hits = new Map<string, { count: number; resetAt: number }>();
  let lastSweep = now();

  return (req: Request, res: Response, next: NextFunction) => {
    const t = now();
    if (t - lastSweep > opts.windowMs) {
      for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
      lastSweep = t;
    }
    const key = req.ip ?? 'unknown';
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= t) {
      entry = { count: 0, resetAt: t + opts.windowMs };
      hits.set(key, entry);
    }
    entry.count++;
    const remaining = Math.max(0, opts.max - entry.count);
    res.setHeader('RateLimit-Policy', `${opts.max};w=${Math.round(opts.windowMs / 1000)};name="${opts.name}"`);
    res.setHeader('RateLimit', `limit=${opts.max}, remaining=${remaining}, reset=${Math.ceil((entry.resetAt - t) / 1000)}`);
    if (entry.count > opts.max) {
      res.setHeader('Retry-After', String(Math.ceil((entry.resetAt - t) / 1000)));
      res.status(429).json({ error: 'rate_limited', message: 'Too many requests. Try again later.' });
      return;
    }
    next();
  };
}
