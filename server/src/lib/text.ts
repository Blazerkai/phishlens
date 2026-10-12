/** Small, dependency-free text helpers used across analyzers. */

export function truncate(value: string, max = 300): string {
  const v = value.replace(/\s+/g, ' ').trim();
  return v.length > max ? `${v.slice(0, max - 1)}…` : v;
}

/** Returns the sentence-ish window around a match, for use as quoted evidence. */
export function excerptAround(text: string, index: number, length: number, radius = 70): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return `${prefix}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${suffix}`;
}

export function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

/** Damerau–Levenshtein (optimal string alignment) distance. */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array<number>(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) d[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
    }
  }
  return d[m]![n]!;
}

/**
 * Converts common "defanged" IOC notation back to its original form, e.g.
 * hxxps://example[.]com → https://example.com. Analysts routinely paste these.
 */
export function refang(value: string): { value: string; changed: boolean } {
  const out = value
    .trim()
    .replace(/^hxxp(s?):\/\//i, 'http$1://')
    .replace(/^hxxp(s?)\[:\]\/\//i, 'http$1://')
    .replace(/\[:\]/g, ':')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[@\]|\[at\]|\(at\)/gi, '@')
    .replace(/\[\/\]/g, '/');
  return { value: out, changed: out !== value.trim() };
}
