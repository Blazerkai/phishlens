import type { AnalyzerRun, Indicator, InvestigationArtifacts, RiskAssessment, Verdict } from '@phishlens/shared';
import { SCORE_METHOD, scoreIndicators } from '../scoring/index.js';
import { groupPositiveEvidence } from '../signals.js';

export const THRESHOLDS = {
  /** Score at or above which the verdict is HIGH RISK. */
  highRisk: 60,
  /** Score at or above which the verdict is at least SUSPICIOUS. */
  suspicious: 25,
  /** Score below which a BENIGN verdict is possible (given enough benign evidence). */
  benignMax: 10,
  /** Independent positive-evidence families required for a BENIGN verdict (at least one must be corroboration). */
  benignSignals: 2,
};

const LABEL: Record<Verdict, string> = { benign: 'Benign', suspicious: 'Suspicious', high_risk: 'High risk', inconclusive: 'Inconclusive' };

/** Analyzers whose failure removes evidence that could otherwise establish legitimacy. */
const COLLECTORS = ['dns', 'tls', 'redirects', 'rdap'];

/**
 * Turns indicators into an explainable verdict. Rules, in order:
 *  1. HIGH RISK  – any critical finding (confidence ≥ 0.7), or two independent high findings, or score ≥ 60
 *  2. SUSPICIOUS – any high finding (confidence ≥ 0.6), or score ≥ 25
 *  3. BENIGN     – score < 10, no risk finding of medium severity or above, at least two independent
 *                  positive-evidence families of which at least one is corroboration (identity or
 *                  registration maturity), no contradicted family, and no collector failed
 *  4. INCONCLUSIVE otherwise: weak, insufficient or conflicting evidence
 *
 * Positive evidence never offsets risk: it is only consulted once rules 1 and 2 have not fired.
 */
export function assessRisk(
  indicators: Indicator[],
  runs: AnalyzerRun[],
  artifacts: InvestigationArtifacts,
  opts: { brandCount?: number } = {},
): RiskAssessment {
  const { score, contributions } = scoreIndicators(indicators);
  const risk = indicators.filter((i) => i.polarity === 'risk');
  const benign = indicators.filter((i) => i.polarity === 'benign');
  const critical = risk.filter((i) => i.severity === 'critical' && i.confidence >= 0.7);
  const high = risk.filter((i) => i.severity === 'high' && i.confidence >= 0.6);
  const highCategories = new Set(high.map((i) => i.category));

  const completed = runs.filter((r) => r.status === 'completed').map((r) => r.analyzer);
  const unavailable = runs.filter((r) => r.status === 'unavailable' || r.status === 'blocked' || r.status === 'skipped').map((r) => ({ analyzer: r.analyzer, reason: r.reason ?? r.status }));
  const failed = runs.filter((r) => r.status === 'failed').map((r) => ({ analyzer: r.analyzer, reason: r.reason ?? 'failed' }));
  const collectorGap = [...unavailable, ...failed].some((r) => COLLECTORS.includes(r.analyzer));

  const positiveEvidence = groupPositiveEvidence(indicators, artifacts);
  const counted = positiveEvidence.filter((f) => f.counted);
  const corroborating = counted.filter((f) => f.class === 'corroboration');
  const notableRisk = risk.filter((i) => i.severity === 'medium' || i.severity === 'high' || i.severity === 'critical');
  const familyText = (fs: typeof positiveEvidence) => fs.map((f) => `${f.label} (${f.titles.join('; ')})`).join(' + ');

  const conflicts: string[] = [];
  for (const f of positiveEvidence.filter((x) => !x.counted)) conflicts.push(`${f.label} not counted — ${f.reason}`);
  if (positiveEvidence.length && notableRisk.length) {
    conflicts.push(
      `Positive evidence (${positiveEvidence.map((f) => f.label).join(', ')}) coexists with risk findings: ${notableRisk
        .slice(0, 4)
        .map((i) => `${i.title} [${i.severity}]`)
        .join('; ')}. Risk findings take precedence.`,
    );
  }
  const unknowns = indicators.filter((i) => i.polarity === 'unknown');

  let verdict: Verdict;
  const rationale: string[] = [];
  if (critical.length || highCategories.size >= 2 || score >= THRESHOLDS.highRisk) {
    verdict = 'high_risk';
    if (critical.length) rationale.push(`${critical.length} critical finding(s): ${critical.map((i) => i.title).join('; ')}`);
    if (highCategories.size >= 2) rationale.push(`High-severity findings in ${highCategories.size} independent categories (${[...highCategories].join(', ')})`);
    if (score >= THRESHOLDS.highRisk) rationale.push(`Risk score ${score} ≥ ${THRESHOLDS.highRisk}`);
  } else if (high.length || score >= THRESHOLDS.suspicious) {
    verdict = 'suspicious';
    if (high.length) rationale.push(`High-severity finding: ${high[0]!.title}`);
    if (score >= THRESHOLDS.suspicious) rationale.push(`Risk score ${score} ≥ ${THRESHOLDS.suspicious}`);
  } else if (
    score < THRESHOLDS.benignMax &&
    notableRisk.length === 0 &&
    counted.length >= THRESHOLDS.benignSignals &&
    corroborating.length >= 1 &&
    !positiveEvidence.some((f) => !f.counted) &&
    !collectorGap
  ) {
    verdict = 'benign';
    rationale.push(`Risk score ${score} < ${THRESHOLDS.benignMax} and no risk finding of medium severity or above`);
    rationale.push(`${counted.length} independent positive-evidence families: ${familyText(counted)}`);
    rationale.push('No collection gaps or contradicted evidence');
  } else {
    verdict = 'inconclusive';
    if (score >= THRESHOLDS.benignMax) rationale.push(`Risk score ${score} is between ${THRESHOLDS.benignMax} and ${THRESHOLDS.suspicious}: weak signals only`);
    if (notableRisk.length) rationale.push(`Risk finding(s) of medium severity present (${notableRisk.map((i) => i.title).join('; ')}), so positive evidence cannot establish a benign verdict`);
    if (counted.length < THRESHOLDS.benignSignals) {
      rationale.push(
        counted.length
          ? `Only ${counted.length} independent positive-evidence family: ${familyText(counted)}. At least ${THRESHOLDS.benignSignals} are required`
          : `No verified positive evidence; at least ${THRESHOLDS.benignSignals} independent families are required`,
      );
    }
    if (counted.length && corroborating.length === 0) {
      rationale.push('All positive evidence is operator-controlled security hygiene, which attackers can also obtain; corroboration (verified identity or registration maturity) is required');
    }
    if (positiveEvidence.some((f) => !f.counted)) rationale.push('Some positive evidence is contradicted by other observations');
    if (collectorGap) rationale.push('Some evidence collectors were unavailable or failed, so legitimacy could not be established');
  }

  const nextSteps: string[] = [];
  if (verdict === 'inconclusive') {
    const has = (fam: string) => counted.some((f) => f.family === fam);
    if (!has('identity')) nextSteps.push('Establish who operates the domain through an independent channel (legal-entity registry, direct contact via a known channel, existing business relationship) and record it under Settings → Verified operators, or add a known organisation to the brand watchlist. DNS control alone does not qualify.');
    if (!has('registration_maturity')) {
      const rd = artifacts.rdap.find((r) => r.status === 'completed' && r.ageDays !== null && r.ageDays !== undefined);
      nextSteps.push(rd ? `Registration age (${rd.ageDays} days for ${rd.domain}) is below the two-year corroboration threshold; weigh other context accordingly.` : 'Domain registration data was not obtained; enable RDAP or check the registry manually.');
    }
    if (!has('transport') && artifacts.urls.some((u) => u.origin === 'input')) nextSteps.push('Transport security was not verified; re-run with network probes enabled or inspect the site’s certificate manually.');
    if (!artifacts.email && artifacts.urls.some((u) => u.origin === 'input')) nextSteps.push('If this link arrived by email, submit the full headers and message so sender authentication and social-engineering content can be assessed.');
    for (const u of [...unavailable, ...failed].filter((x) => COLLECTORS.includes(x.analyzer))) nextSteps.push(`Resolve the ${u.analyzer} collection gap (${u.reason}) and re-run.`);
    const rep = runs.find((r) => r.analyzer === 'reputation');
    if (rep && rep.status !== 'completed') nextSteps.push(`Reputation was not checked (${rep.reason ?? rep.status}). Configure a provider in the environment to add listing checks and popularity corroboration.`);
    if (unknowns.length) nextSteps.push(`Resolve ${unknowns.length} observation(s) recorded as unknown: ${unknowns.map((i) => i.title).join('; ')}.`);
  }

  const top = contributions.slice(0, 6);
  const summary =
    verdict === 'benign'
      ? `Benign. No risk finding of medium severity or above, and ${counted.length} independent families of positive evidence agree: ${counted.map((f) => f.label).join(', ')}.`
      : verdict === 'inconclusive'
        ? `Inconclusive. ${risk.length ? `${risk.length} weak risk indicator(s)` : 'No risk indicators'}; positive evidence ${counted.length ? `covers ${counted.map((f) => f.label.toLowerCase()).join(' and ')} only` : 'was not verified'}, which is not enough to establish legitimacy. See the suggested next steps.`
        : `${LABEL[verdict]}. ${risk.length} risk indicator(s), led by: ${top.slice(0, 3).map((c) => c.title).join('; ')}.`;

  const limitations = [
    'The risk score is an expert-weighted sum of heuristics, not a statistically calibrated probability of phishing.',
    'Absence of indicators is not proof of legitimacy; targeted attacks can avoid every heuristic.',
    'Pages are inspected statically: scripts are not executed and sub-resources are not loaded, so script-driven redirects and content are not observed.',
    'Network observations reflect what PhishLens saw at the time of analysis from its own network location; phishing infrastructure often serves different content per visitor (cloaking) and changes quickly.',
    'No third-party reputation or threat-intelligence feeds are consulted.',
  ];
  if (artifacts.email) limitations.push('Only the top-most Authentication-Results header is trusted; header fields below it can be forged by the sender.');
  if ((opts.brandCount ?? 0) === 0) limitations.push('The brand watchlist is empty, so brand impersonation and lookalike checks did not run.');
  else limitations.push(`Lookalike detection only covers the ${opts.brandCount} brand(s) in the watchlist.`);
  for (const u of unavailable) limitations.push(`${u.analyzer}: ${u.reason}`);
  for (const f of failed) limitations.push(`${f.analyzer} failed: ${f.reason}`);

  return {
    verdict,
    score,
    summary,
    rationale,
    contributions,
    benignSignals: benign.map((b) => ({ indicatorId: b.id, title: b.title })),
    positiveEvidence,
    conflicts,
    nextSteps,
    coverage: { completed, unavailable, failed },
    limitations,
    method: SCORE_METHOD,
  };
}
