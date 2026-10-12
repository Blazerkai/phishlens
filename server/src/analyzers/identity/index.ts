import type { OperatorVerification } from '@phishlens/shared';
import type { Analyzer } from '../types.js';
import { subject } from '../../engine/subjects.js';
import { primaryDomains, registrableOf } from '../../engine/signals.js';

const METHOD_LABEL: Record<OperatorVerification['method'], string> = {
  legal_entity_registry: 'legal-entity registry record',
  direct_contact: 'direct contact through an independently sourced channel',
  contractual_relationship: 'existing contractual or business relationship',
  official_publication: 'official publication by the operator (e.g. annual report, regulator filing)',
  other: 'other documented method',
};

export function isActive(v: OperatorVerification, now: Date): boolean {
  return !v.revokedAt && Date.parse(v.expiresAt) > now.getTime();
}

/**
 * Applies analyst-recorded operator verifications. A verification establishes
 * *who* operates a domain — it does not vouch for the site's current conduct,
 * and it never offsets risk findings. It only counts for the investigation's
 * primary subject (submitted domain, final destination of the submitted URL,
 * sender domain), so a verified domain merely linked from a message adds nothing.
 */
export const identityAnalyzer: Analyzer = {
  id: 'identity',
  label: 'Checking recorded operator identity',
  dependsOn: ['domain', 'redirects'],
  applies: (ctx) => ctx.identities.length > 0 && ctx.state.domains.length > 0,
  async run(ctx) {
    const now = new Date();
    const primary = primaryDomains(ctx.state);
    const seen = new Set(ctx.state.domains.map((d) => registrableOf(d.hostname)).filter((d): d is string => !!d));
    let applied = 0;
    for (const v of ctx.identities) {
      if (!seen.has(v.domain) && !primary.has(v.domain)) continue;
      const base = { subject: subject.domain(v.domain), category: 'IDENTITY' as const, provenance: 'user_input' as const, source: `Analyst verification by ${v.verifiedBy} (${v.verifiedAt.slice(0, 10)})` };
      const evidence = `${v.domain} → ${v.operatorName} · ${METHOD_LABEL[v.method]} · reference: ${v.evidenceReference} · expires ${v.expiresAt.slice(0, 10)}`;
      if (v.revokedAt) continue;
      if (!isActive(v, now)) {
        ctx.emit({ ...base, code: 'IDENTITY_VERIFICATION_EXPIRED', title: `Operator verification for ${v.domain} has expired`, description: 'An expired verification is not counted. Re-verify the operator to restore it.', severity: 'info', confidence: 1, polarity: 'unknown', evidence });
        continue;
      }
      if (!primary.has(v.domain)) {
        ctx.emit({ ...base, code: 'IDENTITY_VERIFIED_RELATED', title: `Verified operator for related domain ${v.domain}`, description: 'This domain appears in the evidence but is not the investigated destination, so its verified identity does not vouch for the investigation.', severity: 'info', confidence: 1, polarity: 'neutral', evidence });
        continue;
      }
      applied++;
      ctx.emit({
        ...base,
        code: 'IDENTITY_VERIFIED',
        title: `Operator independently verified: ${v.operatorName}`,
        description:
          'An analyst recorded that the operator of this domain was identified through an independent channel (not DNS control alone). This establishes who runs the site, not that its current content is safe; risk findings still take precedence.',
        severity: 'info',
        confidence: 0.8,
        polarity: 'benign',
        evidence,
      });
    }
    return { status: 'completed', detail: applied ? `${applied} active operator verification(s) apply` : 'No active verification applies to the investigated destination' };
  },
};
