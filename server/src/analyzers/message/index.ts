import { parse } from 'tldts';
import type { Brand, ExtractedLink, MessageAnalysis } from '@phishlens/shared';
import type { Analyzer } from '../types.js';
import type { IndicatorDraft } from '../../engine/indicators/index.js';
import { excerptAround, refang } from '../../lib/text.js';
import { extractUrlsFromText, parseUrl } from '../url/parseUrl.js';
import { urlHeuristics } from '../url/heuristics.js';
import { MESSAGE_PATTERNS, PRESSURE_CATEGORIES } from './patterns.js';
import { subject } from '../../engine/subjects.js';
import { isIpLiteral } from '../../security/ip.js';

const MAX_LINKS = 25;
const ZERO_WIDTH = /[​-‍⁠﻿­]/g;

export function looksLikeHtml(text: string): boolean {
  return /<\s*(html|body|a\s|div|p|table|br|span|td|img)\b/i.test(text);
}

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number(d)));
}

/** Text a reader would see: scripts, styles and tags removed, entities decoded. */
export function htmlToText(html: string): string {
  return decodeEntities(
    html
      .replace(/<(script|style|head)\b[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d)>/gi, '\n')
      .replace(/<[^>]+>/g, ' '),
  )
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n')
    .trim();
}

function hostOf(href: string): string | null {
  const u = parseUrl(href, 'message');
  return u.valid && u.hostname ? u.hostname : null;
}

const regDomain = (host: string) => (isIpLiteral(host) ? host : parse(host, { allowPrivateDomains: true }).domain ?? host);

/** Host a human would read from link text such as "www.paypal.com/login" or "https://paypal.com". */
export function displayedHost(text: string): string | null {
  const t = refang(text.trim()).value;
  const m = t.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i);
  if (!m) return null;
  const p = parse(m[1]!);
  return p.isIcann && p.domain ? m[1]!.toLowerCase() : null;
}

export function extractLinks(text: string, isHtml: boolean): ExtractedLink[] {
  const links: ExtractedLink[] = [];
  const seen = new Set<string>();
  const push = (href: string, label: string | null, context: ExtractedLink['context']) => {
    const h = decodeEntities(href.trim());
    if (!/^(https?:|hxxps?:|www\.)/i.test(h) && !/^(javascript|data):/i.test(h)) return;
    const key = `${h}|${label ?? ''}`;
    if (seen.has(key) || links.length >= MAX_LINKS) return;
    seen.add(key);
    const hrefHost = hostOf(h);
    const shown = label ? displayedHost(label) : null;
    links.push({
      href: h,
      text: label,
      context,
      hrefHost,
      displayedHost: shown,
      mismatch: !!(shown && hrefHost && regDomain(shown) !== regDomain(hrefHost)),
    });
  };

  if (isHtml) {
    for (const m of text.matchAll(/<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi)) {
      const label = htmlToText(m[4] ?? '').replace(/\s+/g, ' ').trim();
      push(m[1] ?? m[2] ?? m[3] ?? '', label || null, 'html-anchor');
    }
  }
  for (const m of text.matchAll(/\[([^\]\n]{1,200})\]\((\S+?)\)/g)) push(m[2]!, m[1]!, 'markdown');
  // Text of anchors is what the reader sees, not where they go: exclude it from bare-URL extraction.
  const plain = isHtml ? htmlToText(text.replace(/<a\b[^>]*>[\s\S]*?<\/a>/gi, ' ')) : text.replace(/\[([^\]\n]{1,200})\]\((\S+?)\)/g, ' ');
  for (const u of extractUrlsFromText(plain)) {
    if (!links.some((l) => l.href === u.url)) push(u.url, null, 'plain');
  }
  return links;
}

export interface PatternHit {
  pattern: string;
  category: string;
  excerpt: string;
}

export function findPatterns(text: string): PatternHit[] {
  const hits: PatternHit[] = [];
  for (const p of MESSAGE_PATTERNS) {
    const m = p.re.exec(text);
    if (m) hits.push({ pattern: p.id, category: p.category, excerpt: excerptAround(text, m.index, m[0].length, 60) });
  }
  return hits;
}

/** Brands the message speaks for: "your PayPal account", "Microsoft Security Team", "© 2026 DHL". */
export function findBrandClaims(text: string, brands: Brand[]): { brand: Brand; excerpt: string }[] {
  const out: { brand: Brand; excerpt: string }[] = [];
  for (const b of brands) {
    for (const kw of b.keywords) {
      const re = new RegExp(String.raw`\b(?:your\s+${kw}\s+(?:account|id|order|package|subscription|payment|wallet)|${kw}\s+(?:support|security|team|service|services|customer care|billing|account team|help ?desk)|(?:©|copyright)\s*(?:\d{4}\s*)?${kw}|the\s+${kw}\s+team)\b`, 'i');
      const m = re.exec(text);
      if (m) {
        out.push({ brand: b, excerpt: excerptAround(text, m.index, m[0].length, 40) });
        break;
      }
    }
  }
  return out;
}

export function messageHeuristics(text: string, raw: string, analysis: MessageAnalysis): IndicatorDraft[] {
  const out: IndicatorDraft[] = [];
  const base = { source: 'Submitted message', provenance: 'user_input' as const, subject: subject.message() };

  for (const hit of analysis.patternHits) {
    const p = MESSAGE_PATTERNS.find((x) => x.id === hit.pattern)!;
    out.push({
      ...base,
      code: `MESSAGE_${p.id}`,
      category: 'MESSAGE_CONTENT',
      title: p.title,
      description: p.reason,
      severity: p.severity,
      confidence: p.confidence,
      evidence: `"${hit.excerpt}"`,
    });
  }

  const pressure = [...new Set(analysis.patternHits.map((h) => h.category))].filter((c) => PRESSURE_CATEGORIES.includes(c as never));
  if (pressure.length >= 3) {
    out.push({
      ...base,
      code: 'MESSAGE_SE_COMBINATION',
      category: 'MESSAGE_CONTENT',
      title: `Message combines ${pressure.length} social-engineering techniques`,
      description:
        'Individual phrases like a deadline or a payment request occur in ordinary mail. Several pressure techniques in one message (here: ' +
        `${pressure.map((c) => c.replace('_', ' ')).join(', ')}) is the structure of a social-engineering lure.`,
      severity: 'medium',
      confidence: 0.6,
      evidence: pressure.map((c) => `${c}: "${analysis.patternHits.find((h) => h.category === c)!.excerpt}"`).join(' · '),
    });
  }

  for (const l of analysis.links.filter((x) => x.mismatch)) {
    out.push({
      ...base,
      code: 'LINK_DISPLAY_MISMATCH',
      category: 'LINK',
      title: 'Displayed link differs from actual destination',
      description: `The text shows "${l.displayedHost}" but clicking goes to "${l.hrefHost}". Showing one address while linking to another has no legitimate purpose in user-facing mail (tracking redirects show the real brand domain, not a different one).`,
      severity: 'high',
      confidence: 0.8,
      evidence: `text "${l.text}" → href ${l.href.slice(0, 200)}`,
      subject: subject.url(parseUrl(l.href, 'message').normalized ?? l.href),
    });
  }

  const zw = (raw.match(ZERO_WIDTH) ?? []).length;
  if (zw >= 3) {
    out.push({
      ...base,
      code: 'MESSAGE_INVISIBLE_CHARACTERS',
      category: 'MESSAGE_CONTENT',
      title: `${zw} invisible characters embedded in text`,
      description: 'Zero-width and soft-hyphen characters split words so they look normal to a reader but do not match keyword filters. Ordinary mail rarely contains more than a stray one.',
      severity: 'medium',
      confidence: 0.55,
      evidence: `${zw} × U+200B/U+200C/U+200D/U+2060/U+FEFF/U+00AD`,
    });
  }

  if (analysis.isHtml && /<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?\s*[;"']|visibility\s*:\s*hidden)/i.test(raw)) {
    out.push({
      ...base,
      code: 'MESSAGE_HIDDEN_HTML_TEXT',
      category: 'MESSAGE_CONTENT',
      title: 'HTML contains hidden text',
      description: 'Elements styled to be invisible are used to pad messages with benign text that filters read but people do not. Also used legitimately for email preheaders.',
      severity: 'low',
      confidence: 0.3,
      evidence: raw.match(/<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden)[^"']*["'][^>]*>/i)?.[0]?.slice(0, 200) ?? 'hidden element',
    });
  }

  if (text.length > 0 && analysis.patternHits.length === 0 && analysis.links.length === 0) {
    out.push({
      ...base,
      code: 'MESSAGE_NO_PATTERNS',
      category: 'MESSAGE_CONTENT',
      title: 'No social-engineering patterns or links found',
      description: 'None of the configured patterns matched and the message contains no links. Absence of patterns is not proof of legitimacy: targeted messages can avoid all of them.',
      severity: 'info',
      confidence: 1,
      polarity: 'neutral',
      evidence: `${text.length} characters analysed`,
    });
  }
  return out;
}

export const messageAnalyzer: Analyzer = {
  id: 'message',
  label: 'Extracting indicators from message',
  dependsOn: [],
  applies: (ctx) => !!ctx.input.message,
  async run(ctx) {
    const raw = ctx.input.message!;
    const isHtml = looksLikeHtml(raw);
    const text = (isHtml ? htmlToText(raw) : raw).replace(ZERO_WIDTH, '');
    const links = extractLinks(raw.replace(ZERO_WIDTH, ''), isHtml);
    const analysis: MessageAnalysis = {
      length: raw.length,
      isHtml,
      links,
      patternHits: findPatterns(text),
      claimedBrands: findBrandClaims(text, ctx.brands).map((c) => c.brand.name),
    };
    ctx.state.message = analysis;

    for (const d of messageHeuristics(text, raw, analysis)) ctx.emit(d);
    for (const c of findBrandClaims(text, ctx.brands)) {
      ctx.emit({
        code: 'MESSAGE_BRAND_CLAIM',
        category: 'MESSAGE_CONTENT',
        title: `Message presents itself as ${c.brand.name}`,
        description: 'The text speaks on behalf of a configured brand. Context for correlation: it is only a concern if the sender and links do not belong to that brand.',
        severity: 'info',
        confidence: 1,
        polarity: 'neutral',
        evidence: `"${c.excerpt}"`,
        source: 'Submitted message',
        provenance: 'user_input',
        subject: subject.message(),
      });
    }

    // Each link is a URL in its own right.
    for (const l of links) {
      const u = parseUrl(l.href, 'message');
      ctx.state.urls.push(u);
      for (const d of urlHeuristics(u, { brands: ctx.brands, lists: ctx.settings.lists })) ctx.emit(d);
    }

    return {
      status: 'completed',
      detail: `${raw.length} characters${isHtml ? ' (HTML)' : ''}, ${links.length} link(s), ${analysis.patternHits.length} pattern match(es)`,
    };
  },
};
