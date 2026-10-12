import { parse as parseDomain } from 'tldts';
import type { Brand, UrlAnalysis } from '@phishlens/shared';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import type { ReferenceLists } from '../../config/lists.js';
import { subject } from '../../engine/subjects.js';
import { decodeSafe, parseUrl } from './parseUrl.js';
import { refang } from '../../lib/text.js';
import { classifyIp } from '../../security/ip.js';

const EXECUTABLE_EXT = /\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|msix|jar|apk|lnk|iso|img|vhd|vhdx|dll|cpl)$/i;
const ARCHIVE_EXT = /\.(zip|rar|7z|tar|gz|cab|ace|arj)$/i;
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
const BASE64_RE = /^[A-Za-z0-9+/_-]{12,}={0,2}$/;

function sourceFor(u: UrlAnalysis): string {
  switch (u.origin) {
    case 'input': return 'Submitted URL';
    case 'message': return 'Link in submitted message';
    case 'redirect': return 'Redirect destination';
    case 'email': return 'URL in email headers';
  }
}

function tryBase64(value: string): string | null {
  if (!BASE64_RE.test(value)) return null;
  try {
    const decoded = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return /^[\x20-\x7e]+$/.test(decoded) ? decoded : null;
  } catch {
    return null;
  }
}

/** The authority section exactly as written in the original input, before browser normalisation. */
function rawAuthority(input: string): string | null {
  const m = input.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
  if (!m) return null;
  const auth = m[1]!;
  return auth.includes('@') ? auth.slice(auth.lastIndexOf('@') + 1) : auth;
}

function isOfficialFor(brand: Brand, registrable: string | null | undefined): boolean {
  return !!registrable && brand.officialDomains.some((d) => registrable === d || registrable.endsWith(`.${d}`));
}

/**
 * Structural URL heuristics. Pure function: no network access.
 * Hostname-level checks (IDN, subdomain depth, lookalikes) live in the domain analyzer
 * so each host is assessed once regardless of how many URLs reference it.
 */
export function urlHeuristics(u: UrlAnalysis, opts: { brands: Brand[]; lists: ReferenceLists }): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const src = sourceFor(u);
  const subj = u.normalized ? subject.url(u.normalized) : undefined;
  const base = { source: src, provenance: (u.origin === 'redirect' ? 'network' : 'user_input') as IndicatorDraft['provenance'], ...(subj ? { subject: subj } : {}) };

  if (!u.valid) {
    out.push({
      ...base,
      code: 'URL_UNPARSEABLE',
      category: 'URL_STRUCTURE',
      title: 'URL could not be parsed',
      description: 'The value is not a valid URL by the WHATWG URL standard used by browsers; no further URL analysis was possible.',
      severity: 'info',
      confidence: 1,
      evidence: u.input,
    });
    return out;
  }

  const scheme = u.scheme ?? '';
  if (scheme === 'data' || scheme === 'javascript' || scheme === 'vbscript') {
    out.push({
      ...base,
      code: 'URL_INLINE_CONTENT_SCHEME',
      category: 'URL_STRUCTURE',
      title: `${scheme}: URL carries inline content`,
      description:
        `A ${scheme}: URL embeds content or script directly instead of pointing to a server. Browsers block most top-level ` +
        'navigations to these, so legitimate senders rarely use them in links; they have been used to render credential forms without hosting a site.',
      severity: 'high',
      confidence: 0.8,
      evidence: u.input.slice(0, 200),
    });
    return out;
  }
  if (scheme !== 'http' && scheme !== 'https') {
    out.push({
      ...base,
      code: 'URL_NON_WEB_SCHEME',
      category: 'URL_STRUCTURE',
      title: `Non-web URL scheme: ${scheme}`,
      description: 'The link does not open a web page. Recorded for context; the scheme alone is not a risk signal.',
      severity: 'info',
      confidence: 1,
      evidence: u.input,
    });
    return out;
  }

  const host = u.hostname ?? '';
  const refanged = refang(u.input).value;
  const authority = rawAuthority(refanged);

  if (scheme === 'http' && !u.isIp) {
    out.push({
      ...base,
      code: 'URL_PLAINTEXT_HTTP',
      category: 'URL_STRUCTURE',
      title: 'Original URL uses HTTP',
      description:
        'The URL as written starts with http://. Whether that matters depends on what the server does with it — an immediate upgrade to HTTPS, ' +
        'or content served in plaintext — which is assessed separately as a single transport finding (TRANSPORT_*), so it is not counted twice.',
      severity: 'info',
      confidence: 1,
      polarity: 'neutral',
      evidence: u.normalized ?? u.input,
    });
  }

  const reserved = u.isIp ? classifyIp(host) : null;
  if (reserved?.blocked) {
    out.push({
      ...base,
      code: 'URL_NON_PUBLIC_ADDRESS',
      category: 'URL_STRUCTURE',
      title: 'URL points to a non-public network address',
      description: `${host} is ${reserved.reason}. It cannot be a public website; in a message it would make the recipient's browser contact their own device or local network (e.g. routers or cloud metadata services). PhishLens does not connect to it.`,
      severity: 'medium',
      confidence: 0.55,
      evidence: u.normalized ?? u.input,
    });
  }
  if (u.isIp) {
    const obfuscated = !host.includes(':') && authority !== null && authority.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase() !== host;
    if (obfuscated) {
      out.push({
        ...base,
        code: 'URL_OBFUSCATED_IP',
        category: 'URL_STRUCTURE',
        title: 'Hostname is an IP address written in obfuscated notation',
        description:
          `The host "${authority}" is an alternate (decimal, hex, octal or shortened) notation that browsers interpret as ${host}. ` +
          'This notation has no legitimate use in user-facing links and hides the destination from the reader.',
        severity: 'high',
        confidence: 0.85,
        evidence: u.normalized ?? u.input,
      });
    } else if (!reserved?.blocked) {
      out.push({
        ...base,
        code: 'URL_IP_HOST',
        category: 'URL_STRUCTURE',
        title: 'Hostname uses an IP address',
        description:
          'The URL directly references an IP address instead of a domain name. Public services almost always use domain names; ' +
          'IP-based links avoid domain registration and reputation systems.',
        severity: 'medium',
        confidence: 0.6,
        evidence: u.normalized ?? u.input,
      });
    }
  } else if (authority && /%[0-9a-f]{2}/i.test(authority)) {
    out.push({
      ...base,
      code: 'URL_ENCODED_HOSTNAME',
      category: 'URL_STRUCTURE',
      title: 'Hostname contains percent-encoded characters',
      description: `The hostname was written as "${authority}" and decodes to "${host}". Encoding characters in a hostname has no functional purpose and hides the real domain from a human reader.`,
      severity: 'medium',
      confidence: 0.7,
      evidence: u.input,
    });
  }

  if (u.username) {
    const looksLikeDomain = /[a-z0-9-]+\.[a-z]{2,}/i.test(u.username);
    out.push({
      ...base,
      code: 'URL_USERINFO',
      category: 'URL_STRUCTURE',
      title: looksLikeDomain ? 'URL hides the real host behind a domain-like username' : 'URL contains embedded credentials',
      description: looksLikeDomain
        ? `Everything before "@" in a URL is a username, not the destination. "${u.username}" looks like a domain, but the browser connects to "${host}".`
        : 'The URL embeds a username/password section. Browsers ignore or warn about this; it is rarely used legitimately in links sent to people.',
      severity: looksLikeDomain ? 'high' : 'medium',
      confidence: looksLikeDomain ? 0.85 : 0.55,
      evidence: u.input,
    });
  }

  if (u.port !== null && u.port !== undefined && u.port !== 80 && u.port !== 443) {
    out.push({
      ...base,
      code: 'URL_NONSTANDARD_PORT',
      category: 'URL_STRUCTURE',
      title: `Non-standard port ${u.port}`,
      description: 'Public websites are normally served on ports 80/443. A custom port is common for development or self-hosted services and uncommon for consumer-facing sign-in pages.',
      severity: 'low',
      confidence: 0.4,
      evidence: u.normalized ?? u.input,
    });
  }

  const pathAndQuery = `${u.path ?? ''}${u.query?.length ? '?' : ''}${u.query?.map((q) => `${q.key}=${q.value}`).join('&') ?? ''}`;
  const rawPath = refanged.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '');
  const encodedBytes = (rawPath.match(/%[0-9a-f]{2}/gi) ?? []).length;
  if (/%25[0-9a-f]{2}/i.test(rawPath)) {
    out.push({
      ...base,
      code: 'URL_DOUBLE_ENCODING',
      category: 'URL_STRUCTURE',
      title: 'Double percent-encoding in URL',
      description: 'Characters are encoded twice (e.g. %252F). This is used to slip content past filters that decode once; legitimate links rarely need it.',
      severity: 'medium',
      confidence: 0.5,
      evidence: rawPath.slice(0, 200),
    });
  } else if (rawPath.length > 30 && (encodedBytes * 3) / rawPath.length > 0.35) {
    out.push({
      ...base,
      code: 'URL_HEAVY_ENCODING',
      category: 'URL_STRUCTURE',
      title: 'Large share of the URL path is percent-encoded',
      description: `${encodedBytes} encoded characters make up over a third of the path, which hides its readable content. Tracking links also do this, so it is weak evidence.`,
      severity: 'low',
      confidence: 0.35,
      evidence: rawPath.slice(0, 200),
    });
  }

  // Domains embedded in the path, e.g. https://evil.example/www.paypal.com/signin
  for (const seg of (u.path ?? '').split('/').filter(Boolean)) {
    const s = decodeSafe(seg).toLowerCase();
    if (!s.includes('.')) continue;
    const p = parseDomain(s);
    if (!p.domain || !p.isIcann) continue;
    const brand = opts.brands.find((b) => isOfficialFor(b, p.domain));
    if ((s.startsWith('www.') || brand) && p.domain !== u.registrableDomain) {
      out.push({
        ...base,
        code: 'URL_DOMAIN_IN_PATH',
        category: 'URL_STRUCTURE',
        title: brand ? `${brand.name} domain appears in the path of another site` : 'A different domain appears in the URL path',
        description: `The path contains "${s}", but the page is served by "${host}". Placing a familiar domain in the path makes the link look like it belongs to that domain.`,
        severity: 'medium',
        confidence: brand ? 0.7 : 0.5,
        evidence: u.normalized ?? u.input,
      });
      break;
    }
  }

  // Brand tokens in the path/query on an unrelated domain (token match, never substrings of words).
  const tokens = new Set(decodeSafe(pathAndQuery).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
  for (const b of opts.brands) {
    if (isOfficialFor(b, u.registrableDomain)) continue;
    const kw = b.keywords.find((k) => tokens.has(k));
    if (kw && !out.some((i) => i.code === 'URL_DOMAIN_IN_PATH')) {
      out.push({
        ...base,
        code: 'URL_BRAND_IN_PATH',
        category: 'URL_STRUCTURE',
        title: `"${kw}" referenced in the URL of an unrelated domain`,
        description: `The path or query names ${b.name} (configured brand), but ${host} is not one of its configured official domains. ` +
          'Articles and integrations mention brands legitimately, so this only matters alongside other evidence. (Brand heuristic.)',
        severity: 'low',
        confidence: 0.4,
        evidence: u.normalized ?? u.input,
      });
      break;
    }
  }

  // Query parameters: embedded redirect targets and recipient addresses.
  let flaggedRedirect = false;
  let flaggedEmail = false;
  for (const { key, value } of u.query ?? []) {
    const decoded = decodeSafe(value);
    if (!flaggedRedirect && /^(https?:)?\/\/[^/]/i.test(decoded)) {
      const target = parseUrl(decoded.startsWith('//') ? `https:${decoded}` : decoded, u.origin);
      if (target.valid && target.registrableDomain && target.registrableDomain !== u.registrableDomain) {
        const known = opts.lists.redirectParams.includes(key.toLowerCase());
        out.push({
          ...base,
          code: 'URL_EMBEDDED_REDIRECT',
          category: 'URL_STRUCTURE',
          title: `Query parameter "${key}" carries a URL on another domain`,
          description:
            `The link passes "${target.hostname}" as a destination through ${host}. If ${host} redirects to it, a reputable domain is being used to launder the real destination (open redirect). ` +
            'Single sign-on and tracking links also do this legitimately; the redirect analysis shows where it actually leads.',
          severity: known ? 'medium' : 'low',
          confidence: known ? 0.55 : 0.4,
          evidence: `${key}=${decoded.slice(0, 200)}`,
        });
        flaggedRedirect = true;
      }
    }
    if (!flaggedEmail) {
      const email = decoded.match(EMAIL_RE)?.[0] ?? tryBase64(decoded)?.match(EMAIL_RE)?.[0];
      if (email) {
        out.push({
          ...base,
          code: 'URL_RECIPIENT_EMAIL',
          category: 'URL_STRUCTURE',
          title: 'Email address embedded in the link',
          description:
            'The link carries an email address (plain or base64-encoded). Phishing kits use this to pre-fill a fake sign-in form and to track who clicked. ' +
            'Unsubscribe and account links also embed addresses legitimately.',
          severity: 'medium',
          confidence: 0.45,
          evidence: `${key}=${decoded.slice(0, 120)} → ${email}`,
        });
        flaggedEmail = true;
      }
    }
  }
  if (!flaggedEmail && u.fragment) {
    const frag = decodeSafe(u.fragment);
    const email = frag.match(EMAIL_RE)?.[0] ?? tryBase64(frag)?.match(EMAIL_RE)?.[0];
    if (email) {
      out.push({
        ...base,
        code: 'URL_RECIPIENT_EMAIL',
        category: 'URL_STRUCTURE',
        title: 'Email address hidden in the URL fragment',
        description:
          'The part after "#" is never sent to the server in HTTP requests, so it is invisible to many URL scanners, yet page scripts can read it. ' +
          'Carrying a recipient address there is a known technique to pre-fill credential forms while evading inspection.',
        severity: 'medium',
        confidence: 0.6,
        evidence: `#${frag.slice(0, 120)} → ${email}`,
      });
    }
  }

  const lastSegment = (u.path ?? '').split('/').pop() ?? '';
  if (EXECUTABLE_EXT.test(lastSegment)) {
    out.push({
      ...base,
      code: 'URL_EXECUTABLE_DOWNLOAD',
      category: 'URL_STRUCTURE',
      title: 'Link points directly to an executable or script file',
      description: `The path ends in "${lastSegment}". Opening it would download content that can run code. Legitimate software downloads exist, but unsolicited links to them are a common malware delivery method.`,
      severity: 'medium',
      confidence: 0.6,
      evidence: u.normalized ?? u.input,
    });
  } else if (ARCHIVE_EXT.test(lastSegment)) {
    out.push({
      ...base,
      code: 'URL_ARCHIVE_DOWNLOAD',
      category: 'URL_STRUCTURE',
      title: 'Link points directly to an archive file',
      description: `The path ends in "${lastSegment}". Archives are used to deliver files past attachment filters; they are also common for legitimate file sharing.`,
      severity: 'low',
      confidence: 0.35,
      evidence: u.normalized ?? u.input,
    });
  }

  if (u.registrableDomain && opts.lists.urlShorteners.includes(u.registrableDomain)) {
    out.push({
      ...base,
      code: 'URL_SHORTENER',
      category: 'URL_STRUCTURE',
      title: `Link shortener (${u.registrableDomain}) hides the destination`,
      description: 'The real destination is not visible until the link is followed. See the redirect chain for where it resolves.',
      severity: 'low',
      confidence: 0.35,
      evidence: u.normalized ?? u.input,
    });
  }

  if ((u.normalized ?? '').length > 250) {
    out.push({
      ...base,
      code: 'URL_LONG',
      category: 'URL_STRUCTURE',
      title: `Very long URL (${u.normalized!.length} characters)`,
      description: 'Long URLs can push the meaningful part out of view in previews. Many legitimate tracking and SSO URLs are long; recorded as context only.',
      severity: 'info',
      confidence: 1,
      evidence: `${u.normalized!.slice(0, 160)}…`,
    });
  }

  return out;
}
