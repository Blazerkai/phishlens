import type { Analyzer } from '../types.js';
import { parseAddress, parseEmailHeaders } from './parseHeaders.js';
import { emailHeuristics } from './heuristics.js';
import { isOfficialDomain } from '../domain/lookalike.js';
import { orgDomain } from './parseHeaders.js';
import { subject } from '../../engine/subjects.js';

export const emailHeaderAnalyzer: Analyzer = {
  id: 'email-headers',
  label: 'Checking email authentication',
  dependsOn: [],
  applies: (ctx) => !!ctx.input.headers,
  async run(ctx) {
    const e = parseEmailHeaders(ctx.input.headers!);
    if (e.headerCount === 0) {
      ctx.emit({
        code: 'EMAIL_HEADERS_UNPARSEABLE',
        category: 'EMAIL_HEADER',
        title: 'No header fields found',
        description: 'The submitted text contains no "Name: value" header fields, so no header analysis was possible.',
        severity: 'info',
        confidence: 1,
        evidence: `${ctx.input.headers!.length} characters submitted`,
        source: 'Email headers',
        provenance: 'user_input',
      });
      return { status: 'completed', detail: 'No header fields found' };
    }
    ctx.state.email = e;
    for (const d of emailHeuristics(e, { brands: ctx.brands, lists: ctx.settings.lists })) ctx.emit(d);
    const s = e.summary;
    return {
      status: 'completed',
      detail: `${e.headerCount} headers, ${e.received.length} Received hop(s) · SPF ${s.spf} · DKIM ${s.dkim} · DMARC ${s.dmarc}`,
    };
  },
};

const ROLE_LOCALPARTS = /^(admin|administrator|support|help|helpdesk|security|secure|billing|accounts?|noreply|no-reply|donotreply|service|services|info|team|it|hr|payroll|finance|verify|verification|alert|alerts|notification|notifications)$/i;

export const emailAddressAnalyzer: Analyzer = {
  id: 'email-address',
  label: 'Analyzing email address',
  dependsOn: [],
  applies: (ctx) => !!ctx.input.email,
  async run(ctx) {
    const a = parseAddress(ctx.input.email!);
    const valid = !!a.address && !!a.domain;
    const freemail = !!a.domain && ctx.settings.lists.freemailDomains.includes(a.domain);
    const roleAccount = !!a.localPart && ROLE_LOCALPARTS.test(a.localPart);
    ctx.state.emailAddress = { address: a, valid, freemail, roleAccount };
    const base = { source: 'Submitted email address', provenance: 'user_input' as const, ...(a.address ? { subject: subject.address(a.address) } : {}) };

    if (!valid) {
      ctx.emit({ ...base, code: 'EMAIL_ADDRESS_INVALID', category: 'SENDER', title: 'Not a valid email address', description: 'The value does not have the form local-part@domain, so no sender analysis was possible.', severity: 'info', confidence: 1, evidence: ctx.input.email! });
      return { status: 'completed', detail: 'Invalid address' };
    }
    if (freemail) {
      ctx.emit({
        ...base,
        code: 'EMAIL_ADDRESS_FREEMAIL',
        category: 'SENDER',
        title: `Consumer mailbox provider (${a.domain})`,
        description: 'Anyone can create an address here at no cost. Context only; it matters when the sender claims to represent an organisation.',
        severity: 'info',
        confidence: 1,
        evidence: a.address!,
      });
    }
    const lp = (a.localPart ?? '').toLowerCase();
    for (const b of ctx.brands) {
      if (isOfficialDomain(b, orgDomain(a.domain))) continue;
      const kw = b.keywords.find((k) => lp.split(/[^a-z0-9]+/).includes(k) || (k.length >= 6 && lp.includes(k)));
      if (kw) {
        ctx.emit({
          ...base,
          code: 'EMAIL_ADDRESS_BRAND_LOCALPART',
          category: 'SENDER',
          title: `Mailbox name invokes ${b.name} on an unrelated domain`,
          description: `"${a.localPart}" suggests ${b.name}, but ${a.domain} is not one of its configured official domains${freemail ? ' and is a consumer mailbox provider' : ''}. (Brand heuristic.)`,
          severity: freemail ? 'high' : 'medium',
          confidence: freemail ? 0.7 : 0.5,
          evidence: a.address!,
        });
        break;
      }
    }
    return { status: 'completed', detail: `${a.address}${freemail ? ' (consumer mailbox provider)' : ''}${roleAccount ? ' (role mailbox)' : ''}` };
  },
};
