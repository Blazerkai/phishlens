import { parse as parseDomain } from 'tldts';
import type {
  AuthenticationResultsHeader,
  AuthMethodResult,
  AuthResultValue,
  DkimSignature,
  EmailAddress,
  EmailHeaderAnalysis,
  ReceivedHop,
} from '@phishlens/shared';
import { classifyIp } from '../../security/ip.js';

export interface RawHeader {
  name: string;
  value: string;
}

// ---------------------------------------------------------------------------
// Header block
// ---------------------------------------------------------------------------

/**
 * Splits a raw header block into fields (RFC 5322 §2.2): unfolds continuation
 * lines and stops at the first empty line (start of body). Order is preserved,
 * top to bottom, which matters for Received and Authentication-Results.
 */
export function splitHeaders(raw: string): RawHeader[] {
  const lines = raw.replace(/\r\n?/g, '\n').replace(/^\s*\n/, '').split('\n');
  const out: RawHeader[] = [];
  for (const line of lines) {
    if (line.trim() === '') {
      if (out.length) break; // end of header section
      continue;
    }
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1]!.value += ` ${line.trim()}`;
      continue;
    }
    const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
    if (m) out.push({ name: m[1]!, value: m[2]!.trim() });
  }
  return out;
}

export function headerValues(headers: RawHeader[], name: string): string[] {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n).map((h) => h.value);
}

/** Decodes RFC 2047 encoded-words (=?charset?B|Q?...?=). Unknown charsets fall back to latin1/utf8. */
export function decodeEncodedWords(value: string): string {
  return value
    .replace(/\?=\s+=\?/g, '?==?') // whitespace between adjacent encoded words is ignored
    .replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (_, charset: string, enc: string, text: string) => {
      try {
        const bytes =
          enc.toUpperCase() === 'B'
            ? Buffer.from(text, 'base64')
            : Buffer.from(
                text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16))),
                'latin1',
              );
        const cs = charset.toLowerCase().split('*')[0]!;
        const decoder = new TextDecoder(['utf-8', 'utf8'].includes(cs) ? 'utf-8' : cs, { fatal: false });
        return decoder.decode(bytes);
      } catch {
        return text;
      }
    });
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/** Splits on a delimiter that is not inside quotes, angle brackets or comments. */
export function splitOutside(value: string, delimiter: string): string[] {
  const parts: string[] = [];
  let buf = '';
  let quote = false;
  let angle = 0;
  let paren = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === '\\' && quote) {
      buf += c + (value[i + 1] ?? '');
      i++;
      continue;
    }
    if (c === '"' && paren === 0) quote = !quote;
    else if (!quote && c === '(') paren++;
    else if (!quote && c === ')' && paren > 0) paren--;
    else if (!quote && paren === 0 && c === '<') angle++;
    else if (!quote && paren === 0 && c === '>' && angle > 0) angle--;
    if (c === delimiter && !quote && angle === 0 && paren === 0) {
      parts.push(buf);
      buf = '';
      continue;
    }
    buf += c;
  }
  if (buf.trim()) parts.push(buf);
  return parts.map((p) => p.trim()).filter(Boolean);
}

const ADDR_RE = /^[^\s@<>()",;:]+@[^\s@<>()",;:]+\.[^\s@<>()",;:]+$/;

export function parseAddress(raw: string): EmailAddress {
  const value = decodeEncodedWords(raw.trim());
  let display: string | null = null;
  let addr: string | null = null;
  const angle = value.match(/^(.*)<([^<>]*)>\s*(\(.*\))?$/s);
  if (angle) {
    display = angle[1]!.trim().replace(/^"(.*)"$/s, '$1').replace(/\\(.)/g, '$1').trim() || null;
    addr = angle[2]!.trim() || null;
  } else {
    // bare address, possibly with a trailing (comment) used as display name
    const m = value.match(/^([^\s()]+)\s*(?:\((.*)\))?$/s);
    addr = m?.[1] ?? value;
    display = m?.[2]?.trim() || null;
  }
  if (addr && !ADDR_RE.test(addr)) addr = addr.includes('@') ? addr : null;
  const at = addr ? addr.lastIndexOf('@') : -1;
  return {
    raw: raw.trim(),
    displayName: display,
    address: addr ? addr.toLowerCase() : null,
    localPart: addr && at > 0 ? addr.slice(0, at) : null,
    domain: addr && at > 0 ? addr.slice(at + 1).toLowerCase().replace(/\.$/, '') : null,
  };
}

export function parseAddressList(value: string | undefined): EmailAddress[] {
  if (!value) return [];
  // Strip group syntax "Group: a@x, b@y;"
  const v = value.replace(/^[^:<>"@]+:\s*(.*);\s*$/s, '$1');
  return splitOutside(v, ',').map(parseAddress).filter((a) => a.address || a.displayName);
}

// ---------------------------------------------------------------------------
// Received
// ---------------------------------------------------------------------------

const IP_IN_BRACKETS = /\[(?:IPv6:)?([0-9a-fA-F:.]+)\]/;
const BARE_IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;

/** Parses one Received header (RFC 5321 §4.4 trace field). Tolerant of vendor variations. */
export function parseReceived(raw: string, index = 0): ReceivedHop {
  const semi = raw.lastIndexOf(';');
  const clauses = semi >= 0 ? raw.slice(0, semi) : raw;
  const dateStr = semi >= 0 ? raw.slice(semi + 1).trim() : null;
  const clause = (kw: string) => {
    const m = clauses.match(new RegExp(`(?:^|\\s)${kw}\\s+([^\\s;]+)`, 'i'));
    return m?.[1]?.replace(/[()]/g, '') ?? null;
  };
  // "from" clause including its parenthesised TCP-info comment: from helo (rdns [ip])
  const fromPart = clauses.match(/(?:^|\s)from\s+(.+?)(?=\s+by\s|\s+via\s|\s+with\s|\s+id\s|\s+for\s|$)/is)?.[1] ?? '';
  const fromHelo = fromPart.match(/^([^\s(]+)/)?.[1] ?? null;
  const comment = fromPart.match(/\(([^)]*)\)/)?.[1] ?? '';
  const ip = comment.match(IP_IN_BRACKETS)?.[1] ?? fromPart.match(IP_IN_BRACKETS)?.[1] ?? comment.match(BARE_IPV4)?.[1] ?? null;
  const rdns = comment.match(/^\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b/i)?.[1] ?? null;
  const parsedDate = dateStr ? new Date(dateStr.replace(/\s*\([^)]*\)\s*$/, '')) : null;
  const timestamp = parsedDate && !Number.isNaN(parsedDate.getTime()) ? parsedDate.toISOString() : null;

  return {
    index,
    raw,
    from: fromHelo,
    fromRdns: rdns,
    fromIp: ip,
    by: clause('by'),
    with: clause('with'),
    id: clause('id'),
    for: clause('for')?.replace(/[<>]/g, '') ?? null,
    date: dateStr,
    timestamp,
    delaySeconds: null,
    ipIsPrivate: ip ? classifyIp(ip).blocked : null,
  };
}

/** Received headers are prepended by each hop; the bottom one is the earliest. Returns them oldest → newest. */
export function parseReceivedChain(values: string[]): ReceivedHop[] {
  const hops = [...values].reverse().map((v, i) => parseReceived(v, i));
  for (let i = 1; i < hops.length; i++) {
    const prev = hops[i - 1]!.timestamp;
    const cur = hops[i]!.timestamp;
    if (prev && cur) hops[i]!.delaySeconds = Math.round((new Date(cur).getTime() - new Date(prev).getTime()) / 1000);
  }
  return hops;
}

// ---------------------------------------------------------------------------
// Authentication-Results (RFC 8601)
// ---------------------------------------------------------------------------

const RESULT_VALUES: AuthResultValue[] = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy', 'bestguesspass'];

function normalizeResult(v: string): AuthResultValue {
  const r = v.toLowerCase();
  if (r === 'hardfail') return 'fail';
  return (RESULT_VALUES as string[]).includes(r) ? (r as AuthResultValue) : 'unknown';
}

function stripComments(s: string): { text: string; comments: string[] } {
  const comments: string[] = [];
  let text = '';
  let depth = 0;
  let quote = false;
  let cur = '';
  for (const c of s) {
    if (c === '"' && depth === 0) quote = !quote;
    if (!quote && c === '(') {
      if (depth === 0) cur = '';
      else cur += c;
      depth++;
      continue;
    }
    if (!quote && c === ')' && depth > 0) {
      depth--;
      if (depth === 0) comments.push(cur.trim());
      else cur += c;
      continue;
    }
    if (depth > 0) cur += c;
    else text += c;
  }
  return { text, comments };
}

export function parseAuthenticationResults(raw: string): AuthenticationResultsHeader {
  // ARC-Authentication-Results starts with "i=N;"
  const value = raw.replace(/^\s*i\s*=\s*\d+\s*;\s*/i, '');
  const parts = splitOutside(value, ';');
  const head = stripComments(parts[0] ?? '').text.trim();
  const authservId = head && !/=/.test(head.split(/\s+/)[0] ?? '') ? head.split(/\s+/)[0]! : null;
  const resinfos = authservId ? parts.slice(1) : parts;

  const results: AuthMethodResult[] = [];
  for (const part of resinfos) {
    const { text, comments } = stripComments(part);
    const m = text.trim().match(/^([a-z0-9-]+)(?:\/\d+)?\s*=\s*([a-z]+)\b(.*)$/is);
    if (!m) continue;
    const methodName = m[1]!.toLowerCase();
    const method: AuthMethodResult['method'] = methodName === 'spf' || methodName === 'dkim' || methodName === 'dmarc' || methodName === 'arc' ? methodName : 'other';
    const properties: Record<string, string> = {};
    let reason: string | null = null;
    const rest = m[3] ?? '';
    for (const pm of rest.matchAll(/([a-z0-9_.-]+)\s*=\s*("([^"]*)"|[^\s;]+)/gi)) {
      const key = pm[1]!.toLowerCase();
      const val = pm[3] ?? pm[2]!;
      if (key === 'reason') reason = val;
      else properties[key] = val;
    }
    // Policy details commonly appear in a comment, e.g. dmarc=fail (p=REJECT sp=NONE dis=QUARANTINE)
    for (const c of comments) {
      for (const pm of c.matchAll(/\b(p|sp|dis|pct|policy)\s*=\s*([a-z0-9]+)/gi)) {
        const key = `comment.${pm[1]!.toLowerCase()}`;
        if (!properties[key]) properties[key] = pm[2]!.toLowerCase();
      }
    }
    results.push({ method, result: normalizeResult(m[2]!), reason: reason ?? (comments.join('; ') || null), properties, raw: part.trim() });
  }
  return { authservId, results, raw };
}

export function parseDkimSignature(raw: string): DkimSignature {
  const tags = new Map<string, string>();
  for (const part of raw.split(';')) {
    const [k, ...v] = part.split('=');
    if (k && v.length) tags.set(k.trim().toLowerCase(), v.join('=').replace(/\s+/g, ''));
  }
  return {
    domain: tags.get('d')?.toLowerCase() ?? null,
    selector: tags.get('s') ?? null,
    algorithm: tags.get('a') ?? null,
    signedHeaders: (tags.get('h') ?? '').split(':').map((h) => h.trim().toLowerCase()).filter(Boolean),
    raw: raw.length > 300 ? `${raw.slice(0, 300)}…` : raw,
  };
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

export function orgDomain(domain: string | null | undefined): string | null {
  if (!domain) return null;
  return parseDomain(domain).domain ?? domain;
}

function domainOfProperty(v: string | undefined): string | null {
  if (!v) return null;
  const s = v.replace(/^<|>$/g, '');
  return (s.includes('@') ? s.slice(s.lastIndexOf('@') + 1) : s).toLowerCase() || null;
}

export function parseEmailHeaders(raw: string): EmailHeaderAnalysis {
  const headers = splitHeaders(raw);
  const one = (name: string) => headerValues(headers, name)[0];

  const from = parseAddressList(one('from'))[0] ?? null;
  const returnPathRaw = one('return-path');
  const returnPath = returnPathRaw ? parseAddress(returnPathRaw.replace(/^<\s*>$/, '')) : null;
  const authResults = headerValues(headers, 'authentication-results').map(parseAuthenticationResults);
  const receivedSpfRaw = one('received-spf');
  const receivedSpf = receivedSpfRaw ? { result: normalizeResult(receivedSpfRaw.split(/[\s(;]/)[0] ?? ''), raw: receivedSpfRaw } : null;
  const dkimSignatures = headerValues(headers, 'dkim-signature').map(parseDkimSignature);
  const messageId = one('message-id')?.trim() ?? null;

  // The top-most Authentication-Results header is added by the receiving system and is the one to trust.
  const trusted = authResults[0];
  const pick = (method: 'spf' | 'dkim' | 'dmarc') => trusted?.results.filter((r) => r.method === method) ?? [];
  const spfR = pick('spf')[0];
  const dkimRs = pick('dkim');
  const dmarcR = pick('dmarc')[0];
  const dkimPass = dkimRs.filter((r) => r.result === 'pass');
  const fromOrg = orgDomain(from?.domain);

  const spfDomain = domainOfProperty(spfR?.properties['smtp.mailfrom']) ?? domainOfProperty(spfR?.properties['smtp.helo']) ?? returnPath?.domain ?? null;
  const dkimDomains = (dkimPass.length ? dkimPass : dkimRs)
    .map((r) => domainOfProperty(r.properties['header.d'] ?? r.properties['header.i']))
    .filter((d): d is string => !!d);
  const dkimDomainsFinal = dkimDomains.length ? dkimDomains : dkimSignatures.map((s) => s.domain).filter((d): d is string => !!d);
  const spfResult = spfR?.result ?? receivedSpf?.result ?? 'absent';

  return {
    headerCount: headers.length,
    from,
    to: parseAddressList(one('to')),
    cc: parseAddressList(one('cc')),
    replyTo: parseAddressList(one('reply-to')),
    returnPath: returnPath && (returnPath.address || returnPath.domain) ? returnPath : null,
    sender: one('sender') ? parseAddress(one('sender')!) : null,
    subject: one('subject') !== undefined ? decodeEncodedWords(one('subject')!) : null,
    date: one('date') ?? null,
    messageId,
    messageIdDomain: messageId?.match(/@([^>\s]+)>?$/)?.[1]?.toLowerCase() ?? null,
    xMailer: one('x-mailer') ?? one('user-agent') ?? null,
    received: parseReceivedChain(headerValues(headers, 'received')),
    authenticationResults: authResults,
    receivedSpf,
    dkimSignatures,
    summary: {
      spf: spfResult,
      dkim: dkimPass.length ? 'pass' : dkimRs[0]?.result ?? (dkimSignatures.length && !trusted ? 'unknown' : 'absent'),
      dmarc: dmarcR?.result ?? 'absent',
      spfDomain,
      dkimDomains: [...new Set(dkimDomainsFinal)],
      dmarcPolicy: dmarcR?.properties['policy.published-domain-policy'] ?? dmarcR?.properties['comment.p'] ?? dmarcR?.properties['comment.policy'] ?? null,
      spfAligned: fromOrg && spfDomain ? orgDomain(spfDomain) === fromOrg : null,
      dkimAligned: fromOrg && dkimPass.length ? dkimPass.some((r) => orgDomain(domainOfProperty(r.properties['header.d'] ?? r.properties['header.i'])) === fromOrg) : fromOrg && dkimRs.length ? false : null,
    },
  };
}
