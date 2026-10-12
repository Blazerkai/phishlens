import { describe, expect, it } from 'vitest';
import { parseRdap } from '../../src/analyzers/rdap/parse.js';
import { rdapHeuristics } from '../../src/analyzers/rdap/heuristics.js';

const NOW = new Date('2026-06-01T00:00:00Z');
const sample = (registered: string) => ({
  objectClassName: 'domain',
  ldhName: 'EXAMPLE.COM',
  status: ['client transfer prohibited'],
  events: [
    { eventAction: 'registration', eventDate: registered },
    { eventAction: 'expiration', eventDate: '2027-01-01T00:00:00Z' },
  ],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]] as never }],
});

describe('RDAP', () => {
  it('extracts registration date, age and registrar', () => {
    expect(parseRdap(sample('2026-05-29T00:00:00Z'), NOW)).toMatchObject({ registered: '2026-05-29T00:00:00Z', ageDays: 3, registrar: 'Example Registrar, Inc.' });
  });

  it('flags very new domains as high and young domains as medium', () => {
    const base = { domain: 'x.example', status: 'completed' as const, source: 'RDAP test', queriedAt: NOW.toISOString() };
    expect(rdapHeuristics({ ...base, ...parseRdap(sample('2026-05-29T00:00:00Z'), NOW) })[0]).toMatchObject({ code: 'RDAP_NEWLY_REGISTERED', severity: 'high', provenance: 'external' });
    expect(rdapHeuristics({ ...base, ...parseRdap(sample('2026-05-10T00:00:00Z'), NOW) })[0]).toMatchObject({ code: 'RDAP_NEWLY_REGISTERED', severity: 'medium' });
    expect(rdapHeuristics({ ...base, ...parseRdap(sample('2010-01-01T00:00:00Z'), NOW) })[0]).toMatchObject({ code: 'RDAP_ESTABLISHED', polarity: 'benign' });
  });

  it('emits nothing for failed lookups', () => {
    expect(rdapHeuristics({ domain: 'x.example', status: 'failed', source: 'RDAP', reason: 'timeout', queriedAt: '' })).toEqual([]);
  });
});
