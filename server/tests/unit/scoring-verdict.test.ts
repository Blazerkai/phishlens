import { describe, expect, it } from 'vitest';
import type { AnalyzerRun, Indicator, Severity } from '@phishlens/shared';
import { scoreIndicators, SEVERITY_POINTS } from '../../src/engine/scoring/index.js';
import { assessRisk, THRESHOLDS } from '../../src/engine/verdict/index.js';
import { emptyArtifacts, validateAnalyzerGraph } from '../../src/engine/pipeline.js';
import { IndicatorCollector } from '../../src/engine/indicators/index.js';

let n = 0;
function ind(severity: Severity, opts: Partial<Indicator> = {}): Indicator {
  n++;
  return {
    id: `i${n}`,
    code: opts.code ?? `CODE_${n}`,
    category: opts.category ?? 'URL_STRUCTURE',
    title: opts.title ?? `Indicator ${n}`,
    description: 'reason',
    severity,
    confidence: opts.confidence ?? 1,
    polarity: opts.polarity ?? (severity === 'info' ? 'neutral' : 'risk'),
    evidence: 'evidence',
    source: 'test',
    provenance: 'analysis',
    analyzer: 'test',
    timestamp: new Date().toISOString(),
  };
}
const run = (analyzer: string, status: AnalyzerRun['status'] = 'completed', reason?: string): AnalyzerRun => ({
  analyzer, label: analyzer, status, ...(reason ? { reason } : {}), startedAt: '', finishedAt: '', durationMs: 1,
});

describe('risk scoring', () => {
  it('multiplies severity points by confidence', () => {
    expect(scoreIndicators([ind('high', { confidence: 0.5 })]).score).toBe(SEVERITY_POINTS.high * 0.5);
  });

  it('ignores info, benign and neutral indicators', () => {
    expect(scoreIndicators([ind('info'), ind('low', { polarity: 'benign' }), ind('medium', { polarity: 'neutral' })]).score).toBe(0);
  });

  it('applies diminishing returns within one category but not across categories', () => {
    const same = scoreIndicators([ind('medium'), ind('medium'), ind('medium')]).score;
    const spread = scoreIndicators([ind('medium', { category: 'DNS' }), ind('medium', { category: 'TLS' }), ind('medium', { category: 'LINK' })]).score;
    expect(same).toBe(Math.round(15 + 7.5 + 3.75));
    expect(spread).toBe(45);
  });

  it('caps at 100 and lists contributions highest first', () => {
    const r = scoreIndicators(['URL_STRUCTURE', 'DNS', 'TLS', 'LINK', 'SENDER'].map((c) => ind('critical', { category: c as Indicator['category'] })));
    expect(r.score).toBe(100);
    expect(r.contributions[0]!.points).toBeGreaterThanOrEqual(r.contributions[r.contributions.length - 1]!.points);
  });
});

describe('verdict rules', () => {
  const runs = [run('dns'), run('tls'), run('redirects'), run('rdap')];

  it('HIGH RISK on a confident critical finding', () => {
    expect(assessRisk([ind('critical', { confidence: 0.85 })], runs, emptyArtifacts()).verdict).toBe('high_risk');
  });

  it('HIGH RISK on high findings in two independent categories', () => {
    const a = assessRisk([ind('high', { category: 'EMAIL_AUTHENTICATION', confidence: 0.7 }), ind('high', { category: 'SENDER', confidence: 0.75 })], runs, emptyArtifacts());
    expect(a.verdict).toBe('high_risk');
    expect(a.rationale.join(' ')).toMatch(/2 independent categories/);
  });

  it('SUSPICIOUS on a single high finding', () => {
    expect(assessRisk([ind('high', { confidence: 0.7 })], runs, emptyArtifacts()).verdict).toBe('suspicious');
  });

  it('SUSPICIOUS when weak findings accumulate past the threshold', () => {
    const inds = ['DNS', 'TLS', 'LINK'].map((c) => ind('medium', { category: c as Indicator['category'], confidence: 0.6 }));
    const a = assessRisk(inds, runs, emptyArtifacts());
    expect(a.score).toBeGreaterThanOrEqual(THRESHOLDS.suspicious);
    expect(a.verdict).toBe('suspicious');
  });

  it('BENIGN requires two independent families including corroboration, and full collection', () => {
    const tls = ind('info', { code: 'TLS_VALID', polarity: 'benign', category: 'TLS' });
    const upgrade = ind('info', { code: 'TRANSPORT_HTTPS_UPGRADE', polarity: 'benign', category: 'REDIRECT' });
    const aged = { ...ind('info', { code: 'RDAP_ESTABLISHED', polarity: 'benign', category: 'DOMAIN_REGISTRATION' }), subject: 'rdap:example.org' };
    const art = { ...emptyArtifacts(), domains: [{ hostname: 'example.org', sources: ['submitted domain'] } as never] };
    expect(assessRisk([tls, aged], runs, art).verdict).toBe('benign');
    // corroboration about a domain that is not the investigated subject does not count
    expect(assessRisk([tls, { ...aged, subject: 'rdap:elsewhere.example' }], runs, art).verdict).toBe('inconclusive');
    // two indicators, one family → not enough
    expect(assessRisk([tls, upgrade], runs, emptyArtifacts()).verdict).toBe('inconclusive');
    const gap = assessRisk([tls, aged], [...runs.slice(1), run('dns', 'unavailable', 'disabled')], art);
    expect(gap.verdict).toBe('inconclusive');
    expect(gap.rationale.join(' ')).toMatch(/unavailable or failed/);
  });

  it('benign signals never cancel risk', () => {
    const a = assessRisk([ind('high', { confidence: 0.7 }), ...Array.from({ length: 10 }, () => ind('info', { polarity: 'benign' }))], runs, emptyArtifacts());
    expect(a.verdict).toBe('suspicious');
  });

  it('INCONCLUSIVE with no evidence at all', () => {
    const a = assessRisk([], [], emptyArtifacts());
    expect(a.verdict).toBe('inconclusive');
    expect(a.summary).toMatch(/Inconclusive/);
  });

  it('explains itself: summary, rationale, method and limitations', () => {
    const a = assessRisk([ind('high', { title: 'DMARC alignment failed', confidence: 0.7 })], [run('rdap', 'unavailable', 'RDAP disabled')], emptyArtifacts(), { brandCount: 0 });
    expect(a.summary).toContain('DMARC alignment failed');
    expect(a.method).toMatch(/not a probability/);
    expect(a.limitations.join(' ')).toMatch(/not a statistically calibrated probability/);
    expect(a.limitations.join(' ')).toMatch(/watchlist is empty/);
    expect(a.limitations).toContain('rdap: RDAP disabled');
    expect(a.coverage.unavailable).toEqual([{ analyzer: 'rdap', reason: 'RDAP disabled' }]);
  });
});

describe('indicator model invariants', () => {
  it('rejects indicators without evidence or source', () => {
    const c = new IndicatorCollector();
    const base = { code: 'X', category: 'DNS' as const, title: 't', description: 'd', severity: 'low' as const, confidence: 0.5, provenance: 'analysis' as const };
    expect(() => c.add({ ...base, evidence: ' ', source: 's' }, 'a')).toThrow(/no evidence/);
    expect(() => c.add({ ...base, evidence: 'e', source: '' }, 'a')).toThrow(/no source/);
  });

  it('clamps confidence, defaults polarity, deduplicates and stamps time and id', () => {
    const c = new IndicatorCollector(() => new Date('2026-01-01T00:00:00Z'));
    const d = { code: 'X', category: 'DNS' as const, title: 't', description: 'd', severity: 'info' as const, confidence: 3, evidence: 'e', source: 's', provenance: 'analysis' as const };
    const a = c.add(d, 'dns')!;
    expect(c.add(d, 'dns')).toBeNull();
    expect(a).toMatchObject({ confidence: 1, polarity: 'neutral', analyzer: 'dns', timestamp: '2026-01-01T00:00:00.000Z' });
    expect(a.id).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('analyzer graph validation', () => {
  const a = (id: string, dependsOn: string[] = []) => ({ id, label: id, dependsOn, applies: () => true, run: async () => ({ status: 'completed' as const }) });
  it('rejects cycles, unknown dependencies and duplicates', () => {
    expect(() => validateAnalyzerGraph([a('x', ['y']), a('y', ['x'])])).toThrow(/cycle/);
    expect(() => validateAnalyzerGraph([a('x', ['nope'])])).toThrow(/unknown/);
    expect(() => validateAnalyzerGraph([a('x'), a('x')])).toThrow(/Duplicate/);
    expect(() => validateAnalyzerGraph([a('x'), a('y', ['x'])])).not.toThrow();
  });
});
