import type { Brand, EmailHeaderAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import type { ReferenceLists } from '../../config/lists.js';
import { subject } from '../../engine/subjects.js';
import { orgDomain } from './parseHeaders.js';
import { isOfficialDomain } from '../domain/lookalike.js';

const AUTH = 'Authentication-Results';

/**
 * Email header indicators. Authentication failures are explained, not treated as
 * verdicts: forwarding, mailing lists and misconfiguration break SPF/DKIM/DMARC
 * for legitimate mail every day, and attackers routinely pass all three for
 * domains they own.
 */
export function emailHeuristics(e: EmailHeaderAnalysis, opts: { brands: Brand[]; lists: ReferenceLists }): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const base = { provenance: 'user_input' as const, subject: subject.email() };
  const s = e.summary;
  const fromDomain = e.from?.domain ?? null;
  const fromOrg = orgDomain(fromDomain);
  const trusted = e.authenticationResults[0];
  const authSource = trusted ? `${AUTH} (${trusted.authservId ?? 'receiving system'})` : e.receivedSpf ? 'Received-SPF' : AUTH;
  const resultRaw = (method: string) => trusted?.results.find((r) => r.method === method)?.raw ?? '';

  // --- Authentication ---------------------------------------------------------
  if (!trusted && !e.receivedSpf) {
    out.push({
      ...base,
      code: 'EMAIL_NO_AUTH_RESULTS',
      category: 'EMAIL_AUTHENTICATION',
      title: 'No authentication results in the headers',
      description:
        'There is no Authentication-Results or Received-SPF header, so SPF, DKIM and DMARC outcomes are unknown. The headers may be incomplete (copied from a client that hides them) or the receiving system did not record them.',
      severity: 'info',
      confidence: 1,
      evidence: `${e.headerCount} header fields parsed; none are authentication results`,
      source: 'Email headers',
    });
  }

  if (e.authenticationResults.length > 1) {
    const ids = [...new Set(e.authenticationResults.map((a) => a.authservId ?? '(none)'))];
    if (ids.length > 1) {
      out.push({
        ...base,
        code: 'EMAIL_MULTIPLE_AUTHSERV',
        category: 'EMAIL_AUTHENTICATION',
        title: `Authentication-Results from ${ids.length} different systems`,
        description:
          'Only the top-most header, added by the final receiving system, is used for this assessment. Lower headers may come from intermediate relays or could have been inserted by the sender, so they are not trusted.',
        severity: 'info',
        confidence: 1,
        evidence: ids.join(', '),
        source: AUTH,
      });
    }
  }

  // SPF
  if (s.spf !== 'absent') {
    const spfEvidence = resultRaw('spf') || e.receivedSpf?.raw || `spf=${s.spf}`;
    if (s.spf === 'fail') {
      out.push({
        ...base,
        code: 'EMAIL_SPF_FAIL',
        category: 'EMAIL_AUTHENTICATION',
        title: 'SPF fail',
        description: `The sending server is not authorised by the SPF policy of ${s.spfDomain ?? 'the envelope domain'}. Either the envelope sender was spoofed or the message was forwarded by a server the domain did not list.`,
        severity: 'medium',
        confidence: 0.55,
        evidence: spfEvidence,
        source: authSource,
      });
    } else if (s.spf === 'softfail') {
      out.push({
        ...base,
        code: 'EMAIL_SPF_SOFTFAIL',
        category: 'EMAIL_AUTHENTICATION',
        title: 'SPF softfail',
        description: `The envelope domain ${s.spfDomain ?? ''} indicates this server is probably not authorised ("~all"), but asks receivers not to reject outright. Common with forwarding.`,
        severity: 'low',
        confidence: 0.4,
        evidence: spfEvidence,
        source: authSource,
      });
    } else if (s.spf === 'neutral' || s.spf === 'none') {
      out.push({
        ...base,
        code: 'EMAIL_SPF_NO_ASSERTION',
        category: 'EMAIL_AUTHENTICATION',
        title: `SPF ${s.spf}`,
        description: 'The envelope domain makes no assertion about this server, so SPF provides no assurance either way.',
        severity: 'low',
        confidence: 0.3,
        evidence: spfEvidence,
        source: authSource,
      });
    } else if (s.spf === 'temperror' || s.spf === 'permerror') {
      out.push({
        ...base,
        code: 'EMAIL_SPF_ERROR',
        category: 'EMAIL_AUTHENTICATION',
        title: `SPF ${s.spf}`,
        description: 'SPF could not be evaluated (DNS error or invalid record). No conclusion can be drawn from SPF.',
        severity: 'info',
        confidence: 1,
        evidence: spfEvidence,
        source: authSource,
      });
    } else if (s.spf === 'pass') {
      out.push({
        ...base,
        code: 'EMAIL_SPF_PASS',
        category: 'EMAIL_AUTHENTICATION',
        title: s.spfAligned ? 'SPF pass (aligned with From domain)' : `SPF pass for ${s.spfDomain ?? 'envelope domain'}`,
        description: s.spfAligned
          ? 'The sending server is authorised by the From domain’s organisation.'
          : `The server is authorised to send for ${s.spfDomain ?? 'the envelope domain'}, which is not the visible From domain. SPF pass alone only proves the envelope domain’s owner allowed this server — attackers pass SPF for domains they control.`,
        severity: 'info',
        confidence: s.spfAligned ? 0.5 : 1,
        polarity: s.spfAligned ? 'benign' : 'neutral',
        evidence: spfEvidence,
        source: authSource,
      });
    }
  }

  // DKIM
  if (s.dkim !== 'absent' && s.dkim !== 'unknown') {
    const dkimEvidence = trusted?.results.filter((r) => r.method === 'dkim').map((r) => r.raw).join(' | ') || `dkim=${s.dkim}`;
    if (s.dkim === 'pass') {
      out.push({
        ...base,
        code: 'EMAIL_DKIM_PASS',
        category: 'EMAIL_AUTHENTICATION',
        title: s.dkimAligned ? 'DKIM pass (aligned with From domain)' : `DKIM pass for ${s.dkimDomains.join(', ') || 'signing domain'}`,
        description: s.dkimAligned
          ? 'A valid signature from the From domain’s organisation shows the message was sent with that domain’s keys and not modified.'
          : 'The signature is valid but belongs to a different domain than the visible From address (often an email service provider). It proves who signed, not who the From address claims.',
        severity: 'info',
        confidence: s.dkimAligned ? 0.6 : 1,
        polarity: s.dkimAligned ? 'benign' : 'neutral',
        evidence: dkimEvidence,
        source: authSource,
      });
    } else if (s.dkim === 'fail') {
      out.push({
        ...base,
        code: 'EMAIL_DKIM_FAIL',
        category: 'EMAIL_AUTHENTICATION',
        title: 'DKIM fail',
        description: 'A DKIM signature did not verify: the message was modified after signing (mailing lists and security gateways do this) or the signature was forged.',
        severity: 'medium',
        confidence: 0.45,
        evidence: dkimEvidence,
        source: authSource,
      });
    } else if (s.dkim === 'none') {
      out.push({
        ...base,
        code: 'EMAIL_DKIM_NONE',
        category: 'EMAIL_AUTHENTICATION',
        title: 'Message is not DKIM-signed',
        description: 'No DKIM signature was evaluated. Most large senders sign their mail; unsigned mail relies on SPF alone for DMARC.',
        severity: 'low',
        confidence: 0.3,
        evidence: dkimEvidence,
        source: authSource,
      });
    }
  }

  // DMARC
  if (s.dmarc === 'fail') {
    out.push({
      ...base,
      code: 'EMAIL_DMARC_FAIL',
      category: 'EMAIL_AUTHENTICATION',
      title: 'DMARC alignment failed',
      description:
        `Neither SPF nor DKIM produced a pass aligned with the visible From domain (${fromDomain ?? 'unknown'})${s.dmarcPolicy ? `, whose published policy is p=${s.dmarcPolicy}` : ''}. ` +
        'This is the strongest header-level sign that the From address is not authentic. Forwarding and mailing lists can also cause DMARC failures for legitimate mail.',
      severity: 'high',
      confidence: 0.7,
      evidence: resultRaw('dmarc') || 'dmarc=fail',
      source: authSource,
    });
  } else if (s.dmarc === 'pass') {
    out.push({
      ...base,
      code: 'EMAIL_DMARC_PASS',
      category: 'EMAIL_AUTHENTICATION',
      title: `DMARC pass for ${fromDomain ?? 'From domain'}`,
      description: 'The message is authenticated as coming from the domain in the From header. This confirms the domain, not its trustworthiness: check that the domain itself is the one expected (lookalike findings).',
      severity: 'info',
      confidence: 0.6,
      polarity: 'benign',
      evidence: resultRaw('dmarc') || 'dmarc=pass',
      source: authSource,
    });
  } else if (s.dmarc === 'none' || (s.dmarc === 'absent' && trusted)) {
    out.push({
      ...base,
      code: 'EMAIL_DMARC_NONE',
      category: 'EMAIL_AUTHENTICATION',
      title: 'No DMARC evaluation for the From domain',
      description: 'The From domain publishes no DMARC policy (or none was evaluated), so receivers had no owner instruction for unauthenticated mail claiming this domain.',
      severity: 'low',
      confidence: 0.3,
      evidence: resultRaw('dmarc') || `${authSource}: no dmarc result`,
      source: authSource,
    });
  }

  // --- Sender identity ---------------------------------------------------------
  const from = e.from;
  if (!from?.address) {
    out.push({
      ...base,
      code: 'EMAIL_FROM_MISSING',
      category: 'EMAIL_HEADER',
      title: 'No parseable From address',
      description: 'RFC 5322 requires a From header with a mailbox. Its absence or malformation indicates hand-crafted or broken mail.',
      severity: 'low',
      confidence: 0.5,
      evidence: e.from?.raw ?? 'From header absent',
      source: 'From',
    });
  }

  for (const r of e.replyTo) {
    if (!r.address || !from?.address) continue;
    const rOrg = orgDomain(r.domain);
    if (rOrg && fromOrg && rOrg !== fromOrg) {
      const free = opts.lists.freemailDomains.includes(r.domain ?? '') && !opts.lists.freemailDomains.includes(fromDomain ?? '');
      out.push({
        ...base,
        code: 'EMAIL_REPLYTO_MISMATCH',
        category: 'SENDER',
        title: free ? 'Reply-To diverts replies to a free mailbox' : 'From/Reply-To mismatch',
        description: free
          ? `The message appears to come from ${fromDomain}, but replies go to a consumer mailbox at ${r.domain}. This is characteristic of business email compromise and advance-fee fraud, where the attacker needs your reply.`
          : `Replies go to ${r.domain}, a different organisation than the visible sender ${fromDomain}. Marketing platforms and ticketing systems do this legitimately; fraud uses it to receive replies the real sender never sees.`,
        severity: 'medium',
        confidence: free ? 0.65 : 0.5,
        evidence: `From: ${from.address} · Reply-To: ${r.address}`,
        source: 'From, Reply-To',
        subject: subject.address(r.address),
      });
    } else if (r.address !== from.address) {
      out.push({
        ...base,
        code: 'EMAIL_REPLYTO_DIFFERENT_MAILBOX',
        category: 'SENDER',
        title: 'Reply-To is a different mailbox in the same organisation',
        description: 'Context only: common for no-reply senders that route replies to a support mailbox.',
        severity: 'info',
        confidence: 1,
        evidence: `From: ${from.address} · Reply-To: ${r.address}`,
        source: 'From, Reply-To',
      });
    }
  }

  const rp = e.returnPath;
  if (rp?.domain && fromOrg && orgDomain(rp.domain) !== fromOrg) {
    const dmarcPassed = s.dmarc === 'pass';
    out.push({
      ...base,
      code: 'EMAIL_RETURNPATH_MISMATCH',
      category: 'SENDER',
      title: 'From vs Return-Path mismatch',
      description: dmarcPassed
        ? `The envelope sender (${rp.domain}) differs from the From domain, which is normal for email service providers handling bounces. DMARC still passed via DKIM, so this is context only.`
        : `The envelope sender (${rp.domain}) belongs to a different organisation than the From domain (${fromDomain}). Bulk senders do this routinely; together with a DMARC failure it means nothing ties the message to the visible sender.`,
      severity: dmarcPassed ? 'info' : 'low',
      confidence: dmarcPassed ? 1 : 0.35,
      evidence: `From: ${from?.address} · Return-Path: ${rp.address ?? rp.domain}`,
      source: 'From, Return-Path',
    });
  }

  if (from?.displayName) {
    const shown = from.displayName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i)?.[0]?.toLowerCase();
    if (shown && from.address && shown !== from.address && orgDomain(shown.split('@')[1]) !== fromOrg) {
      out.push({
        ...base,
        code: 'EMAIL_DISPLAY_NAME_SPOOF',
        category: 'SENDER',
        title: 'Display name shows a different email address',
        description: `Mail clients often show only the display name, so the recipient sees "${shown}" while the message actually comes from ${from.address}. There is no legitimate reason to put another organisation’s address in a display name.`,
        severity: 'high',
        confidence: 0.75,
        evidence: from.raw,
        source: 'From',
        subject: subject.address(from.address),
      });
    }
    const name = from.displayName.toLowerCase();
    for (const b of opts.brands) {
      if (isOfficialDomain(b, fromOrg)) continue;
      const kw = b.keywords.find((k) => new RegExp(`(^|[^a-z0-9])${k}([^a-z0-9]|$)`).test(name));
      if (!kw || !from.address) continue;
      const free = opts.lists.freemailDomains.includes(fromDomain ?? '');
      out.push({
        ...base,
        code: 'EMAIL_DISPLAY_NAME_BRAND',
        category: 'SENDER',
        title: `Display name claims ${b.name}, sending domain is not ${b.name}'s`,
        description: free
          ? `The sender presents as ${b.name} but uses a consumer mailbox (${fromDomain}). Organisations do not send official notices from free webmail. (Brand heuristic.)`
          : `The sender presents as ${b.name}, but ${fromDomain} is not among ${b.name}'s configured official domains. Partners and resellers may legitimately mention the brand. (Brand heuristic.)`,
        severity: free ? 'high' : 'medium',
        confidence: free ? 0.7 : 0.5,
        evidence: from.raw,
        source: 'From',
        subject: subject.address(from.address),
      });
      break;
    }
  }

  // --- Structure and Received chain ---------------------------------------------
  const missing = [!e.date && 'Date', !e.messageId && 'Message-ID'].filter(Boolean) as string[];
  if (missing.length && e.headerCount > 3) {
    out.push({
      ...base,
      code: 'EMAIL_MISSING_HEADERS',
      category: 'EMAIL_HEADER',
      title: `Missing ${missing.join(' and ')} header`,
      description: 'Standards-compliant mail software always sets Date and almost always Message-ID. Their absence suggests hand-crafted mail or incomplete pasted headers.',
      severity: 'low',
      confidence: 0.3,
      evidence: `${missing.join(', ')} not present among ${e.headerCount} headers`,
      source: 'Email headers',
    });
  }

  if (e.received.length === 0 && e.headerCount > 3) {
    out.push({
      ...base,
      code: 'EMAIL_NO_RECEIVED',
      category: 'EMAIL_HEADER',
      title: 'No Received headers',
      description: 'Every hop adds a Received header, so delivered mail always has at least one. The pasted headers are likely incomplete; the delivery path cannot be assessed.',
      severity: 'info',
      confidence: 1,
      evidence: `${e.headerCount} headers, 0 Received`,
      source: 'Received',
    });
  }

  const backwards = e.received.find((h) => h.delaySeconds !== null && h.delaySeconds < -300);
  if (backwards) {
    out.push({
      ...base,
      code: 'EMAIL_RECEIVED_TIME_REVERSAL',
      category: 'EMAIL_HEADER',
      title: 'Received timestamps go backwards',
      description: `Hop ${backwards.index + 1} is stamped ${Math.round(-backwards.delaySeconds! / 60)} minutes before the previous hop. Clock skew on a relay is the usual cause; fabricated lower Received headers (added by the sender to fake a route) are another.`,
      severity: 'low',
      confidence: 0.35,
      evidence: backwards.raw.slice(0, 250),
      source: 'Received',
      subject: subject.mailserver(backwards.index),
    });
  }

  const slow = e.received.find((h) => h.delaySeconds !== null && h.delaySeconds > 86_400);
  if (slow) {
    out.push({
      ...base,
      code: 'EMAIL_RECEIVED_DELAY',
      category: 'EMAIL_HEADER',
      title: `Delivery delay of ${Math.round(slow.delaySeconds! / 3600)} hours between hops`,
      description: 'Context only: long delays come from queueing, greylisting or retries.',
      severity: 'info',
      confidence: 1,
      evidence: slow.raw.slice(0, 250),
      source: 'Received',
      subject: subject.mailserver(slow.index),
    });
  }

  const firstStamp = e.received.find((h) => h.timestamp)?.timestamp;
  if (e.date && firstStamp) {
    const d = new Date(e.date);
    if (!Number.isNaN(d.getTime())) {
      const diffH = (new Date(firstStamp).getTime() - d.getTime()) / 3_600_000;
      if (Math.abs(diffH) > 24) {
        out.push({
          ...base,
          code: 'EMAIL_DATE_INCONSISTENT',
          category: 'EMAIL_HEADER',
          title: `Date header is ${Math.round(Math.abs(diffH))} hours ${diffH > 0 ? 'before' : 'after'} the first relay`,
          description: 'The Date header is set by the sender and can be arbitrary. A large gap to the first server timestamp suggests a wrong clock, a delayed queue, or a backdated message.',
          severity: 'low',
          confidence: 0.3,
          evidence: `Date: ${e.date} · first Received: ${firstStamp}`,
          source: 'Date, Received',
        });
      }
    }
  }

  const origin = e.received.find((h) => h.fromIp && !h.ipIsPrivate);
  if (origin?.from && origin.fromRdns && orgDomain(origin.from) !== orgDomain(origin.fromRdns) && /\./.test(origin.from)) {
    out.push({
      ...base,
      code: 'EMAIL_HELO_RDNS_MISMATCH',
      category: 'EMAIL_HEADER',
      title: 'Sending host name does not match its reverse DNS',
      description: 'The name the sending server announced (HELO) belongs to a different domain than the reverse DNS of its IP. Common for legitimate cloud mail; recorded as context.',
      severity: 'info',
      confidence: 1,
      evidence: `HELO ${origin.from} · rDNS ${origin.fromRdns} [${origin.fromIp}]`,
      source: 'Received',
      subject: subject.mailserver(origin.index),
    });
  }

  return out;
}
