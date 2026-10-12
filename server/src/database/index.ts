import fs from 'node:fs';
import { z } from 'zod';
import type { AppConfig } from '../config/index.js';
import { openDatabase, type DB } from './db.js';
import { Repository } from './repository.js';

const BrandSeedSchema = z.object({
  brands: z.array(
    z.object({
      name: z.string().min(1).max(80),
      keywords: z.array(z.string().min(3).max(40)).min(1),
      officialDomains: z.array(z.string().min(3).max(253)),
    }),
  ),
});

export function seedBrands(repo: Repository, file: string): number {
  if (!fs.existsSync(file)) return 0;
  const parsed = BrandSeedSchema.parse(JSON.parse(fs.readFileSync(file, 'utf8')));
  for (const b of parsed.brands) {
    repo.addBrand({
      name: b.name,
      keywords: b.keywords.map((k) => k.toLowerCase()),
      officialDomains: b.officialDomains.map((d) => d.toLowerCase()),
    });
  }
  return parsed.brands.length;
}

export function initDatabase(config: Pick<AppConfig, 'databasePath' | 'brandsSeedFile'>, opts: { seed?: boolean } = {}) {
  const db: DB = openDatabase(config.databasePath);
  const repo = new Repository(db);
  const isFresh = (db.prepare('SELECT COUNT(*) AS n FROM schema_migrations').get() as { n: number }).n > 0 &&
    !(db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'phishlens_meta'").get());
  if (isFresh) {
    db.exec(`CREATE TABLE IF NOT EXISTS phishlens_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
    if (opts.seed !== false) seedBrands(repo, config.brandsSeedFile);
    db.prepare("INSERT INTO phishlens_meta (key, value) VALUES ('initialized_at', ?)").run(new Date().toISOString());
  }
  return { db, repo };
}

export { Repository, type DB };
