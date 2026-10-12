import type { AssessmentContribution, Indicator, Severity } from '@phishlens/shared';

/**
 * Heuristic risk score.
 *
 *   points(indicator) = SEVERITY_POINTS[severity] × confidence
 *
 * Within one category, contributions diminish (1, 0.5, 0.25, …) so that ten
 * variations of the same observation cannot outweigh independent evidence from
 * different sources. The total is capped at 100.
 *
 * Only `risk` indicators contribute. Benign signals do not subtract points: an
 * attacker can make a phishing message pass DMARC for a domain they own, so
 * positive evidence must not cancel negative evidence. Benign signals are used
 * by the verdict rules instead (to allow a BENIGN verdict when risk is low).
 *
 * The weights are expert-set, not statistically calibrated. The score ranks and
 * summarises evidence; it is not a probability of phishing.
 */
export const SEVERITY_POINTS: Record<Severity, number> = { info: 0, low: 6, medium: 15, high: 30, critical: 50 };
export const CATEGORY_DECAY = [1, 0.5, 0.25, 0.125];
export const SCORE_METHOD =
  'Score = Σ severity points × rule confidence (low 6, medium 15, high 30, critical 50), with diminishing contributions within each category (×1, ×0.5, ×0.25, ×0.125), capped at 100. Benign signals do not subtract. Weights are expert-set and uncalibrated: the score summarises evidence and is not a probability.';

export function scoreIndicators(indicators: Indicator[]): { score: number; contributions: AssessmentContribution[] } {
  const risk = indicators
    .filter((i) => i.polarity === 'risk' && SEVERITY_POINTS[i.severity] > 0)
    .map((i) => ({ i, raw: SEVERITY_POINTS[i.severity] * i.confidence }))
    .sort((a, b) => b.raw - a.raw);

  const perCategory = new Map<string, number>();
  const contributions: AssessmentContribution[] = [];
  for (const { i, raw } of risk) {
    const n = perCategory.get(i.category) ?? 0;
    perCategory.set(i.category, n + 1);
    const factor = CATEGORY_DECAY[n] ?? 0;
    const points = Math.round(raw * factor * 10) / 10;
    contributions.push({ indicatorId: i.id, code: i.code, title: i.title, category: i.category, severity: i.severity, confidence: i.confidence, points });
  }
  contributions.sort((a, b) => b.points - a.points);
  const score = Math.min(100, Math.round(contributions.reduce((s, c) => s + c.points, 0)));
  return { score, contributions };
}
