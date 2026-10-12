import { loadConfig } from '../config/index.js';
import { initDatabase } from './index.js';

const config = loadConfig();
const { db, repo } = initDatabase(config);
const versions = (db.prepare('SELECT version, name, applied_at FROM schema_migrations ORDER BY version').all() as {
  version: number;
  name: string;
  applied_at: string;
}[]);
console.log(`Database: ${config.databasePath}`);
for (const v of versions) console.log(`  migration ${v.version} ${v.name} (applied ${v.applied_at})`);
console.log(`  brands configured: ${repo.brandCount()}`);
db.close();
