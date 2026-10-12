/**
 * A compact confusable-character skeleton, in the spirit of Unicode TR39.
 * It folds characters that render similarly to Latin letters (Cyrillic/Greek
 * homoglyphs, accented letters, digit substitutions and multi-letter look-alikes
 * such as "rn" → "m") so that "pаypa1" and "paypal" share a skeleton.
 *
 * It is intentionally limited to what matters for domain labels.
 */
const CHAR_MAP: Record<string, string> = {
  // Cyrillic
  а: 'a', в: 'b', с: 'c', ԁ: 'd', е: 'e', ё: 'e', һ: 'h', і: 'l', ї: 'l', ј: 'j', к: 'k', ӏ: 'l', м: 'm', н: 'h',
  о: 'o', р: 'p', ԛ: 'q', ѕ: 's', т: 't', у: 'y', х: 'x', ԝ: 'w', ь: 'b', ү: 'y', ɡ: 'g',
  // Greek
  α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'l', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w', ϲ: 'c',
  // Latin look-alikes
  ı: 'l', ł: 'l', ŀ: 'l', ƚ: 'l', ɩ: 'l', ȷ: 'j', ꞵ: 'b', ɑ: 'a', ɢ: 'g', ʏ: 'y', ꮃ: 'w', ß: 'b',
  // Digits and ASCII substitutions
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', i: 'l', '|': 'l',
};

const SEQUENCE_MAP: [RegExp, string][] = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
  [/nn/g, 'm'],
];

export function skeleton(value: string): string {
  const stripped = value
    .toLowerCase()
    .normalize('NFKD')
    .replace(/\p{M}/gu, '');
  let out = '';
  for (const ch of stripped) out += CHAR_MAP[ch] ?? ch;
  for (const [re, rep] of SEQUENCE_MAP) out = out.replace(re, rep);
  return out.replace(/[^a-z0-9]/g, '');
}

const SCRIPTS: [string, RegExp][] = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
  ['Thai', /\p{Script=Thai}/u],
  ['Devanagari', /\p{Script=Devanagari}/u],
  ['Georgian', /\p{Script=Georgian}/u],
  ['Cherokee', /\p{Script=Cherokee}/u],
];

export function scriptsOf(value: string): string[] {
  const found = new Set<string>();
  for (const ch of value) {
    if (/[\p{Script=Common}\p{Script=Inherited}]/u.test(ch)) continue;
    const hit = SCRIPTS.find(([, re]) => re.test(ch));
    found.add(hit ? hit[0] : 'Other');
  }
  return [...found];
}

/** Script combinations that are normal in real-world names (per UTS #39 "highly restrictive"). */
const ALLOWED_COMBINATIONS = [
  ['Latin', 'Han', 'Hiragana', 'Katakana'],
  ['Latin', 'Han', 'Hangul'],
  ['Latin', 'Han'],
];

export function isMixedScript(label: string): boolean {
  const s = scriptsOf(label);
  if (s.length <= 1) return false;
  return !ALLOWED_COMBINATIONS.some((combo) => s.every((x) => combo.includes(x)));
}
