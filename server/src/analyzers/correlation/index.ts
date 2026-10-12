import { parse } from 'tldts';
import type { Indicator } from '@phishlens/shared';
import type { Analyzer, AnalyzerContext } from '../types.js';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { isOfficialDomain } from '../domain/lookalike.js';
import { orgDomain } from '../email/parseHeaders.js';
import { subject } from '../../engine/subjects.js';
import { isIpLiteral } from '../../security/ip.js';
import { httpTransportIndicators } from '../redirects/transport.js';

const reg = (host: string | null | undefined) => (!host ? null : isIpLiteral(host) ? host : parse(host, { allowPrivateDomains: true }).domain ?? host);

const STRONG_LOOKALIKE = ['LOOKALIKE_HOMOGLYPH', 'LOOKALIKE_TYPOSQUAT', 'LOOKALIKE_OFFICIAL_AS_SUBDOMAIN', 'DOMAIN_MIXED_SCRIPT_IDN'];
const WEAK_LOOKALIKE = ['LOOKALIKE_BRAND_KEYWORD', 'LOOKALIKE_TLD_SWAP'];
const CREDENTIAL = ['MESSAGE_CREDENTIAL_REQUEST', 'MESSAGE_CREDENTIAL_ACCOUNT_VERIFY'];
const PAYMENT = ['MESSAGE_PAYMENT_GIFT_CARDS', 'MESSAGE_PAYMENT_BANK_CHANGE', 'MESSAGE_PAYMENT_TRANSFER', 'MESSAGE_PAYMENT_CRYPTO'];

function cite(inds: Indicator[]): string {
  return inds.map((i) => `[${i.code}] ${i.title}`).join(' + ');
}

/**
 * Correlation rules: findings that are individually weak but meaningful together.
 * Every correlation cites the indicators it combines, so the chain of reasoning
 * stays traceable to observable evidence.
 */
export function correlate(ctx: AnalyzerContext): IndicatorDraft[] {
  const all = ctx.indicators.list();
  const find = (codes: string[]) => all.filter((i) => codes.includes(i.code));
  const out: IndicatorDraft[] = [];
  const base = { source: 'Correlation of findings', provenance: 'analysis' as const, category: 'CORRELATION' as const };

  const email = ctx.state.email;
  const senderDomain = email?.from?.domain ?? ctx.state.emailAddress?.address.domain ?? null;
  const senderOrg = orgDomain(senderDomain);
  const links = ctx.state.message?.links ?? [];
  const linkDomains = [...new Set(links.map((l) => reg(l.hrefHost)).filter((d): d is string => !!d))];
  const credential = find(CREDENTIAL);
  const passwordPages = find(['PAGE_PASSWORD_FIELD']);
  const payment = find(PAYMENT);

  // 1. Credential request + link to a domain unrelated to the sender
  if (credential.length && senderOrg && linkDomains.length) {
    const foreign = linkDomains.filter((d) => d !== senderOrg && !ctx.brands.some((b) => isOfficialDomain(b, d) && isOfficialDomain(b, senderOrg)));
    if (foreign.length) {
      out.push({
        ...base,
        code: 'CORR_CREDENTIAL_LINK_OFFSITE',
        title: 'Credential request links away from the sender’s domain',
        description: `The message asks for credentials and links to ${foreign.join(', ')}, which is not the sender’s domain (${senderOrg}). Legitimate account notices send you to the organisation’s own domain.`,
        severity: 'high',
        confidence: 0.7,
        evidence: `${cite(credential.slice(0, 1))} · sender ${senderOrg} · link domain(s) ${foreign.join(', ')}`,
        subject: subject.message(),
      });
    }
  }

  // 2. Lookalike domain where credentials are requested or collected
  const strong = find(STRONG_LOOKALIKE);
  const weak = find(WEAK_LOOKALIKE);
  const lookalikes = [...strong, ...weak];
  if (lookalikes.length && (credential.length || passwordPages.length)) {
    const isStrong = strong.length > 0;
    const asks = [...passwordPages, ...credential];
    out.push({
      ...base,
      code: 'CORR_LOOKALIKE_CREDENTIAL_HARVEST',
      title: isStrong ? 'Credentials requested on a domain imitating a brand' : 'Credentials requested on a domain using a brand name',
      description: isStrong
        ? 'A domain built to look like a known brand (homoglyph, typo or brand-as-subdomain) is combined with a password prompt or credential request. This combination is the defining pattern of credential phishing.'
        : 'A domain that uses a brand name it does not own is combined with a password prompt or credential request.',
      severity: isStrong ? 'critical' : 'high',
      confidence: isStrong ? 0.85 : 0.65,
      evidence: `${cite([(isStrong ? strong : weak)[0]!])} (${(isStrong ? strong : weak)[0]!.evidence.slice(0, 120)}) + ${cite(asks.slice(0, 1))}`,
      ...((isStrong ? strong : weak)[0]!.subject ? { subject: (isStrong ? strong : weak)[0]!.subject } : {}),
    });
  }

  // 3. Newly registered domain + credential collection
  const young = find(['RDAP_NEWLY_REGISTERED']);
  if (young.length && (credential.length || passwordPages.length)) {
    out.push({
      ...base,
      code: 'CORR_NEW_DOMAIN_CREDENTIALS',
      title: 'Newly registered domain collects credentials',
      description: 'A domain registered within the last month is asking for credentials. Established services do not move sign-in to brand-new domains.',
      severity: 'high',
      confidence: 0.7,
      evidence: `${cite(young.slice(0, 1))} (${young[0]!.evidence}) + ${cite([...passwordPages, ...credential].slice(0, 1))}`,
      ...(young[0]!.subject ? { subject: young[0]!.subject } : {}),
    });
  }

  // 4. Message claims a brand, sender is not that brand
  const displayBrand = find(['EMAIL_DISPLAY_NAME_BRAND']);
  for (const name of ctx.state.message?.claimedBrands ?? []) {
    const brand = ctx.brands.find((b) => b.name === name);
    if (!brand || !senderOrg || isOfficialDomain(brand, senderOrg)) continue;
    if (displayBrand.some((i) => i.title.includes(brand.name))) continue;
    const offBrandLinks = linkDomains.filter((d) => !isOfficialDomain(brand, d));
    out.push({
      ...base,
      code: 'CORR_BRAND_CLAIM_SENDER_MISMATCH',
      title: `Message speaks for ${brand.name}, sender domain is ${senderOrg}`,
      description: `The text presents itself as ${brand.name}, but the sender domain is not one of ${brand.name}'s configured official domains${offBrandLinks.length ? ` and its links lead to ${offBrandLinks.join(', ')}` : ''}. (Brand heuristic.)`,
      severity: offBrandLinks.length ? 'high' : 'medium',
      confidence: offBrandLinks.length ? 0.7 : 0.5,
      evidence: `${cite(find(['MESSAGE_BRAND_CLAIM']).slice(0, 1))} · sender ${senderDomain}`,
      subject: subject.message(),
    });
  }

  // 5. Business email compromise structure
  const identity = find(['EMAIL_REPLYTO_MISMATCH', 'EMAIL_DISPLAY_NAME_SPOOF']);
  const becAsk = [...payment, ...find(['MESSAGE_SECRECY'])];
  if (identity.length && becAsk.length) {
    out.push({
      ...base,
      code: 'CORR_BEC_PATTERN',
      title: 'Business email compromise pattern',
      description: 'A misleading sender identity (diverted replies or a spoofed display name) is combined with a payment or secrecy request. This is the structure of invoice, payroll and CEO-fraud scams; verify the request through a known channel.',
      severity: 'high',
      confidence: 0.75,
      evidence: `${cite(identity.slice(0, 1))} + ${cite(becAsk.slice(0, 2))}`,
      subject: subject.email(),
    });
  }

  // 6. Official brand domain in From, but DMARC fails → direct spoofing
  const dmarcFail = find(['EMAIL_DMARC_FAIL']);
  if (dmarcFail.length && senderOrg) {
    const spoofed = ctx.brands.find((b) => isOfficialDomain(b, senderOrg));
    if (spoofed) {
      out.push({
        ...base,
        code: 'CORR_SPOOFED_BRAND_DOMAIN',
        title: `Message forges ${spoofed.name}'s own domain`,
        description: `The From address uses ${senderOrg}, an official ${spoofed.name} domain, but the message fails that domain's DMARC check. Mail genuinely sent by ${spoofed.name} passes DMARC.`,
        severity: 'high',
        confidence: 0.8,
        evidence: `${cite(dmarcFail)} · From ${email?.from?.address}`,
        subject: subject.email(),
      });
    }
  }

  // 7. Authentication failure combined with a request
  if (dmarcFail.length && (credential.length || payment.length) && !out.some((o) => o.code === 'CORR_SPOOFED_BRAND_DOMAIN')) {
    out.push({
      ...base,
      code: 'CORR_UNAUTHENTICATED_REQUEST',
      title: 'Unauthenticated message makes a sensitive request',
      description: 'The message fails DMARC for its From domain and asks for credentials or money. Even if the failure has a benign cause such as forwarding, the request cannot be attributed to the sender it claims.',
      severity: 'medium',
      confidence: 0.6,
      evidence: `${cite(dmarcFail)} + ${cite([...credential, ...payment].slice(0, 1))}`,
      subject: subject.email(),
    });
  }

  // 8. Free-mail sender claiming to be an organisation
  const freemailSender = !!senderDomain && ctx.settings.lists.freemailDomains.includes(senderDomain);
  const orgClaims = find(['MESSAGE_IMPERSONATION_DEPARTMENT', 'MESSAGE_BRAND_CLAIM']);
  if (freemailSender && orgClaims.length && !displayBrand.length) {
    out.push({
      ...base,
      code: 'CORR_FREEMAIL_ORG_CLAIM',
      title: 'Organisational claim from a consumer mailbox',
      description: `The message claims to come from a department or company but was sent from ${senderDomain}, where anyone can register an address.`,
      severity: 'medium',
      confidence: 0.6,
      evidence: `${cite(orgClaims.slice(0, 1))} · sender ${senderDomain}`,
      subject: subject.message(),
    });
  }

  // Benign corroboration: authenticated sender whose links stay within its own organisation.
  const dmarcPass = find(['EMAIL_DMARC_PASS']);
  if (dmarcPass.length && senderOrg && lookalikes.length === 0 && linkDomains.length > 0 && linkDomains.every((d) => d === senderOrg)) {
    out.push({
      ...base,
      code: 'CORR_CONSISTENT_SENDER',
      title: 'Authenticated sender; links stay within its domain',
      description: 'The From domain passed DMARC and every link points to that same organisation. This is consistent with legitimate mail from that domain; it does not vouch for the domain itself.',
      severity: 'info',
      confidence: 0.6,
      polarity: 'benign',
      evidence: `${cite(dmarcPass)} · links: ${linkDomains.join(', ')}`,
      subject: subject.email(),
    });
  }

  // HTTP links whose redirect chain was never inspected (probes disabled, beyond the probe cap, failed before a chain existed).
  for (const u of ctx.state.urls) {
    if (u.origin === 'redirect' || u.scheme !== 'http' || !u.normalized) continue;
    if (ctx.state.redirects.some((r) => r.startUrl === u.normalized)) continue;
    out.push(...httpTransportIndicators(u, undefined));
  }

  // The same endpoint verified differently on two connections: the observation is unreliable, not positive.
  for (const t of ctx.state.tls) {
    if (t.status !== 'completed' || t.authorized === undefined) continue;
    const hop = ctx.state.redirects.flatMap((r) => r.hops).find((h) => h.hostname === t.host && h.tls);
    if (hop?.tls && hop.tls.authorized !== (t.authorized && t.hostnameMatches === true)) {
      out.push({
        ...base,
        code: 'CORR_TLS_OBSERVATION_CONFLICT',
        title: `Certificate verification for ${t.host} disagrees between connections`,
        description:
          'The dedicated TLS handshake and the HTTP request that served the page reached different verification results. Possible causes: multiple servers behind one name, ' +
          'per-visitor responses, or interception. Transport evidence for this host is treated as unknown rather than positive.',
        severity: 'info',
        confidence: 1,
        polarity: 'unknown',
        evidence: `handshake: ${t.authorized && t.hostnameMatches ? 'verified' : `failed (${t.authorizationError ?? 'hostname mismatch'})`} · page connection: ${hop.tls.authorized ? 'verified' : `failed (${hop.tls.error ?? 'unknown'})`}`,
        subject: subject.certificate(t.host, t.port),
      });
    }
  }

  return out;
}

export const correlationAnalyzer: Analyzer = {
  id: 'correlation',
  label: 'Correlating evidence',
  dependsOn: ['url', 'domain', 'dns', 'tls', 'redirects', 'rdap', 'reputation', 'identity', 'email-headers', 'email-address', 'message'],
  applies: (ctx) => ctx.indicators.list().some((i) => i.polarity !== 'neutral') || ctx.state.urls.some((u) => u.scheme === 'http' && u.origin !== 'redirect'),
  async run(ctx) {
    const found = correlate(ctx);
    for (const d of found) ctx.emit(d);
    return { status: 'completed', detail: found.length ? `${found.length} correlation(s): ${found.map((f) => f.code).join(', ')}` : 'No cross-evidence correlations' };
  },
};
