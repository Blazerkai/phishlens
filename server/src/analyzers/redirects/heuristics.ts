import { parse } from 'tldts';
import type { RedirectAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import type { ReferenceLists } from '../../config/lists.js';
import { subject } from '../../engine/subjects.js';
import { isIpLiteral } from '../../security/ip.js';

const registrable = (host: string) => (isIpLiteral(host) ? host : parse(host, { allowPrivateDomains: true }).domain ?? host);

export function redirectHeuristics(r: RedirectAnalysis, lists: ReferenceLists): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const first = r.hops[0];
  if (!first) return out;
  const last = r.hops[r.hops.length - 1]!;
  const base = { source: `HTTP redirect inspection of ${r.startUrl}`, provenance: 'network' as const };
  const chainText = r.hops.map((h) => `${h.statusCode ?? h.kind} ${h.hostname}`).join(' → ');

  if (r.redirectCount >= 4) {
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, r.hops.length - 1),
      code: 'REDIRECT_EXCESSIVE',
      category: 'REDIRECT',
      title: `Excessive redirects (${r.redirectCount})`,
      description: 'Long chains are used to pass a link through reputable or tracking domains before the real destination and to frustrate automated analysis. Marketing trackers also chain several hops.',
      severity: 'medium',
      confidence: 0.45,
      evidence: chainText,
    });
  }

  const startDomain = registrable(first.hostname);
  const endHost = r.finalUrl ? (() => { try { return new URL(r.finalUrl).hostname.replace(/^\[|\]$/g, ''); } catch { return ''; } })() : '';
  const endDomain = endHost ? registrable(endHost) : '';
  if (r.redirectCount > 0 && endDomain && startDomain !== endDomain) {
    const fromShortener = lists.urlShorteners.includes(startDomain);
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, r.hops.length - 1),
      code: 'REDIRECT_CROSS_DOMAIN',
      category: 'REDIRECT',
      title: `Link leads to a different domain (${endDomain})`,
      description: fromShortener
        ? `The shortener resolves to ${endHost}. The destination, not the shortener, is what should be assessed.`
        : `The link displays ${startDomain} but ends at ${endHost}. The user's trust in the first domain is transferred to a site they never chose.`,
      severity: fromShortener ? 'info' : 'low',
      confidence: fromShortener ? 1 : 0.4,
      evidence: `${r.startUrl} → ${r.finalUrl}`,
    });
  }

  const downgrade = r.hops.findIndex((h, i) => i > 0 && h.scheme === 'http' && r.hops[i - 1]!.scheme === 'https');
  if (downgrade > 0) {
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, downgrade),
      code: 'REDIRECT_HTTPS_DOWNGRADE',
      category: 'REDIRECT',
      title: 'Redirect downgrades HTTPS to HTTP',
      description: 'The chain moves from an encrypted to an unencrypted connection. Legitimate sites redirect the other way.',
      severity: 'medium',
      confidence: 0.5,
      evidence: `${r.hops[downgrade - 1]!.url} → ${r.hops[downgrade]!.url}`,
    });
  }

  const ipHop = r.hops.find((h, i) => i > 0 && isIpLiteral(h.hostname));
  if (ipHop) {
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, ipHop.index),
      code: 'REDIRECT_TO_IP',
      category: 'REDIRECT',
      title: 'Redirect lands on a raw IP address',
      description: 'A domain-based link forwards to a bare IP address, bypassing domain reputation. Rare for legitimate services.',
      severity: 'medium',
      confidence: 0.55,
      evidence: ipHop.url,
    });
  }

  const blocked = r.hops.find((h) => h.kind === 'blocked');
  if (blocked && blocked.index > 0) {
    const internal = /private|loopback|link-local|internal|local machine|not a public|reserved|unique local|metadata/i.test(blocked.error ?? '');
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, blocked.index),
      code: internal ? 'REDIRECT_TO_INTERNAL' : 'REDIRECT_NOT_FOLLOWED',
      category: 'REDIRECT',
      title: internal ? 'Redirect points to a non-public network address' : 'Redirect destination not followed by policy',
      description: internal
        ? 'A public link redirects towards an internal, loopback or link-local destination. PhishLens refused to follow it. Public services have no reason to do this; it can indicate an attempt to reach internal systems.'
        : 'The next hop is outside the outbound policy (scheme or port), so it was recorded but not requested.',
      severity: internal ? 'medium' : 'info',
      confidence: internal ? 0.5 : 1,
      evidence: `${blocked.url} — ${blocked.error}`,
    });
  }

  const meta = r.hops.find((h) => h.kind === 'meta-refresh');
  if (meta) {
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, meta.index),
      code: 'REDIRECT_META_REFRESH',
      category: 'REDIRECT',
      title: 'Client-side (meta refresh) redirect',
      description: 'The page forwards the browser using an HTML meta refresh instead of an HTTP redirect, which hides the destination from tools that only read HTTP headers.',
      severity: 'low',
      confidence: 0.35,
      evidence: `${meta.url} → ${meta.location}`,
    });
  }

  if (r.reason && /loop|maximum/i.test(r.reason)) {
    out.push({
      ...base,
      code: 'REDIRECT_UNRESOLVED',
      category: 'REDIRECT',
      title: 'Redirect chain did not terminate',
      description: `${r.reason}. Cloaking setups sometimes loop or bounce automated clients; misconfigured sites also loop.`,
      severity: 'low',
      confidence: 0.3,
      evidence: chainText,
    });
  }

  if (last.kind === 'final' && last.statusCode && last.statusCode >= 400) {
    out.push({
      ...base,
      subject: subject.redirect(r.startUrl, last.index),
      code: 'REDIRECT_FINAL_ERROR',
      category: 'REDIRECT',
      title: `Destination returned HTTP ${last.statusCode}`,
      description: 'The final page returned an error. Phishing pages are often taken down quickly, and some kits return errors to non-browser clients (cloaking). Observation only.',
      severity: 'info',
      confidence: 1,
      evidence: `${last.url} → HTTP ${last.statusCode}`,
    });
  }

  // --- Static page observations ----------------------------------------------
  const p = r.page;
  if (p && last.kind === 'final') {
    const pageSubject = subject.redirect(r.startUrl, last.index);
    const finalDomain = registrable(last.hostname);
    const offsite = p.formActions
      .map((a) => { try { return new URL(a, last.url); } catch { return null; } })
      .filter((u): u is URL => !!u && /^https?:$/.test(u.protocol) && registrable(u.hostname.replace(/^\[|\]$/g, '')) !== finalDomain);
    if (p.hasPasswordField) {
      out.push({
        ...base,
        subject: pageSubject,
        code: 'PAGE_PASSWORD_FIELD',
        category: 'PAGE_CONTENT',
        title: 'Destination page contains a password field',
        description: 'The page collects a password. Normal for genuine sign-in pages; decisive only together with who operates the domain (see lookalike, registration age and correlation findings).',
        severity: 'info',
        confidence: 1,
        polarity: 'neutral',
        evidence: `${last.url}${p.title ? ` — title "${p.title}"` : ''}`,
      });
    }
    if (offsite.length) {
      out.push({
        ...base,
        subject: pageSubject,
        code: 'PAGE_FORM_OFFSITE',
        category: 'PAGE_CONTENT',
        title: `Form submits to another domain (${offsite[0]!.hostname})`,
        description: p.hasPasswordField
          ? 'A page with a password field sends the form to a different domain than the one shown in the address bar. Single sign-on can do this legitimately; credential-harvesting kits commonly post to a separate collection server.'
          : 'A form on the page posts to a different domain. Common for newsletters and payments; noted because it moves submitted data off-site.',
        severity: p.hasPasswordField ? 'medium' : 'low',
        confidence: p.hasPasswordField ? 0.6 : 0.3,
        evidence: `${last.hostname} → form action ${offsite[0]!.href.slice(0, 150)}`,
      });
    }
    if (p.scriptRedirect) {
      out.push({
        ...base,
        subject: pageSubject,
        code: 'PAGE_SCRIPT_REDIRECT',
        category: 'PAGE_CONTENT',
        title: 'Page contains a script-based redirect (not followed)',
        description: 'Inline script assigns a new location. PhishLens does not execute scripts, so the browser may end up somewhere this report does not show.',
        severity: 'low',
        confidence: 0.3,
        evidence: `${last.url} → ${p.scriptRedirect.slice(0, 150)}`,
      });
    }
  }
  return out;
}
