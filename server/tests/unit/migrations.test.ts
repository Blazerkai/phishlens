import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { migrate } from '../../src/database/db.js';
import { migrations } from '../../src/database/migrations/index.js';

describe('migration 2 (unknown polarity)', () => {
  it('upgrades a populated v1 database without losing indicators and accepts "unknown"', () => {
    const db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    db.exec('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)');
    db.exec(migrations[0]!.sql);
    db.prepare("INSERT INTO schema_migrations VALUES (1, 'initial_schema', 'x')").run();
    db.prepare("INSERT INTO investigations (id, title, status, input_types, created_at) VALUES ('i1', 't', 'completed', '[]', 'x')").run();
    const ins = "INSERT INTO indicators VALUES ('a', 'i1', 'C', 'DNS', 't', 'd', 'low', 0.5, ?, 'e', 's', 'network', 'dns', NULL, 'x')";
    db.prepare(ins).run('risk');
    expect(() => db.prepare(ins.replace("'a'", "'b'")).run('unknown')).toThrow(/CHECK/);

    expect(migrate(db)).toEqual([2, 3]);
    expect(db.prepare('SELECT id, polarity FROM indicators').all()).toEqual([{ id: 'a', polarity: 'risk' }]);
    db.prepare(ins.replace("'a'", "'b'")).run('unknown');
    db.prepare("DELETE FROM investigations WHERE id = 'i1'").run();
    expect((db.prepare('SELECT COUNT(*) AS n FROM indicators').get() as { n: number }).n).toBe(0); // cascade preserved
  });
});
