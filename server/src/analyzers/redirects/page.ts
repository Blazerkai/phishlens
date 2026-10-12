import type { PageObservation } from '@phishlens/shared';

/**
 * Static inspection of an HTML response. No script execution, no sub-resource
 * fetching, no rendering: just what is literally present in the markup.
 */
export function inspectHtml(html: string, contentType: string | null, bytes: number): PageObservation & { metaRefresh: string | null; scriptRedirect: string | null } {
  const title = html.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i)?.[1]?.replace(/\s+/g, ' ').trim() ?? null;
  const hasPasswordField = /<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(html);
  const formActions = [...html.matchAll(/<form\b[^>]*\baction\s*=\s*["']([^"']+)["']/gi)].map((m) => decodeEntities(m[1]!)).slice(0, 10);
  const meta = html.match(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/i)?.[0];
  const metaUrl = meta?.match(/content\s*=\s*["']?\s*\d+\s*[;,]\s*url\s*=\s*['"]?([^"'>\s]+)/i)?.[1] ?? null;
  const script = html.match(/(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']/i);
  return {
    contentType,
    title: title ? decodeEntities(title) : null,
    hasPasswordField,
    formActions,
    bytesInspected: bytes,
    metaRefresh: metaUrl ? decodeEntities(metaUrl) : null,
    scriptRedirect: script ? (script[1] ?? script[2] ?? null) : null,
  };
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number(d)));
}
