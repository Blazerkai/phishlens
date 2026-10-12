import { domainToUnicode } from 'node:url';
import { parse } from 'tldts';
import type { Brand, BrandMatch, DomainAnalysis } from '@phishlens/shared';
import { editDistance } from '../../lib/text.js';
import { skeleton } from './confusables.js';

/**
 * Brand-lookalike HEURISTIC.
 *
 * Compares a hostname against an optional, user-configured brand watchlist.
 * It does not know every brand in the world and does not try to: it answers
 * "does this host imitate one of the organisations *we* care about?".
 *
 * Techniques, strongest first:
 *  official-domain-as-subdomain  paypal.com.account-check.net
 *  homoglyph                     pаypal.com (Cyrillic а), paypa1.com
 *  typosquat                     paypall.com, paypla.com (edit distance 1–2)
 *  tld-swap                      paypal.co (same label, other suffix)
 *  keyword                       paypal-secure-login.com, paypal.evil.net
 */

export function isOfficialDomain(brand: Brand, registrable: string | null): boolean {
  if (!registrable) return false;
  return brand.officialDomains.some((d) => registrable === d || registrable.endsWith(`.${d}`));
}

function labelOf(registrable: string): string {
  return parse(registrable, { allowPrivateDomains: true }).domainWithoutSuffix ?? registrable.split('.')[0] ?? registrable;
}

export function findBrandMatches(d: DomainAnalysis, brands: Brand[]): BrandMatch[] {
  if (d.isIp || !d.registrableDomain) return [];
  const matches: BrandMatch[] = [];
  const registrable = d.registrableDomain;
  const regLabel = labelOf(registrable);
  const regLabelUnicode = domainToUnicode(regLabel) || regLabel;
  const regTokens = regLabelUnicode.split('-').filter(Boolean);
  const subLabels = (d.subdomain ?? '').split('.').filter(Boolean);

  for (const brand of brands) {
    if (isOfficialDomain(brand, registrable)) {
      matches.push({ brand: brand.name, technique: 'official', detail: `${registrable} is a configured official domain of ${brand.name}` });
      continue;
    }

    // Official domain used as a subdomain prefix: paypal.com.example.net
    const sub = d.subdomain ?? '';
    const offAsSub = brand.officialDomains.find((od) => sub === od || sub.endsWith(`.${od}`) || sub.includes(`${od}.`) || sub.startsWith(`${od}-`));
    if (offAsSub) {
      matches.push({
        brand: brand.name,
        technique: 'official-domain-as-subdomain',
        detail: `"${offAsSub}" appears inside the subdomain "${sub}", but the registered domain is ${registrable}`,
      });
      continue;
    }

    let matched: BrandMatch | null = null;
    for (const kw of brand.keywords) {
      const kwSkel = skeleton(kw);
      const candidates = [regLabelUnicode, regLabelUnicode.replace(/-/g, ''), ...regTokens];

      // Exact label on a different suffix
      if (regLabel === kw) {
        matched = { brand: brand.name, technique: 'tld-swap', detail: `"${registrable}" uses the ${brand.name} name on a suffix not listed as official` };
        break;
      }
      // Homoglyph / character substitution
      const homo = candidates.find((c) => c !== kw && skeleton(c) === kwSkel);
      if (homo) {
        matched = { brand: brand.name, technique: 'homoglyph', detail: `"${homo}" renders like "${kw}" (confusable characters)` };
        break;
      }
      // Typosquat (only for keywords long enough to avoid noise)
      if (kw.length >= 5) {
        const maxDist = kw.length >= 8 ? 2 : 1;
        const typo = candidates.find((c) => c !== kw && /^[a-z0-9]+$/.test(c) && Math.abs(c.length - kw.length) <= maxDist && editDistance(c, kw) <= maxDist);
        if (typo) {
          matched = { brand: brand.name, technique: 'typosquat', detail: `"${typo}" is ${editDistance(typo, kw)} edit(s) away from "${kw}"` };
          break;
        }
      }
      // Keyword as a token of the registered label, or embedded in a longer label
      if (regTokens.includes(kw) || (kw.length >= 6 && regLabel.includes(kw))) {
        matched = { brand: brand.name, technique: 'keyword', detail: `"${kw}" is part of the registered domain ${registrable}, which is not a configured official domain` };
        break;
      }
      // Keyword as a subdomain label: paypal.secure-check.net
      if (subLabels.some((l) => l === kw || l.split('-').includes(kw))) {
        matched = { brand: brand.name, technique: 'keyword', detail: `"${kw}" appears as a subdomain of ${registrable}, which is not a configured official domain` };
        break;
      }
    }
    if (matched) matches.push(matched);
  }
  return matches;
}
