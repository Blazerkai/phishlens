import { randomUUID } from 'node:crypto';
import type { Indicator, IndicatorCategory, Polarity, Provenance, Severity } from '@phishlens/shared';
import { truncate } from '../../lib/text.js';

export interface IndicatorDraft {
  code: string;
  category: IndicatorCategory;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  polarity?: Polarity;
  evidence: string;
  source: string;
  provenance: Provenance;
  subject?: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function maxSeverity(values: Severity[]): Severity | null {
  if (values.length === 0) return null;
  return values.reduce((a, b) => (SEVERITY_ORDER[b] > SEVERITY_ORDER[a] ? b : a));
}

/**
 * Collects indicators for one investigation. Enforces the evidence-model
 * invariants: every indicator has non-empty evidence and a source, confidence is
 * clamped to [0,1], and exact duplicates (same rule, subject and evidence) are dropped.
 */
export class IndicatorCollector {
  private readonly items: Indicator[] = [];
  private readonly seen = new Set<string>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  add(draft: IndicatorDraft, analyzer: string): Indicator | null {
    if (!draft.evidence?.trim()) throw new Error(`Indicator ${draft.code} has no evidence`);
    if (!draft.source?.trim()) throw new Error(`Indicator ${draft.code} has no source`);
    const evidence = truncate(draft.evidence, 500);
    const key = `${draft.code}|${draft.subject ?? ''}|${evidence}`;
    if (this.seen.has(key)) return null;
    this.seen.add(key);
    const indicator: Indicator = {
      id: randomUUID(),
      code: draft.code,
      category: draft.category,
      title: draft.title,
      description: draft.description,
      severity: draft.severity,
      confidence: Math.round(Math.min(1, Math.max(0, draft.confidence)) * 100) / 100,
      polarity: draft.polarity ?? (draft.severity === 'info' ? 'neutral' : 'risk'),
      evidence,
      source: draft.source,
      provenance: draft.provenance,
      analyzer,
      ...(draft.subject ? { subject: draft.subject } : {}),
      timestamp: this.now().toISOString(),
    };
    this.items.push(indicator);
    return indicator;
  }

  list(): Indicator[] {
    return [...this.items];
  }

  has(code: string): boolean {
    return this.items.some((i) => i.code === code);
  }

  byCode(code: string): Indicator[] {
    return this.items.filter((i) => i.code === code);
  }
}
