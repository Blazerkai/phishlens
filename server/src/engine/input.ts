import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { InputSummary, InputType, InvestigationInput } from '@phishlens/shared';
import type { NormalizedInput } from '../analyzers/types.js';
import { refang } from '../lib/text.js';

export const LIMITS = {
  url: 4096,
  domain: 253 * 2,
  email: 512,
  headers: 256 * 1024,
  message: 512 * 1024,
};

const optionalText = (max: number, label: string) =>
  z
    .string()
    .max(max, `${label} exceeds ${max} characters`)
    .optional()
    .transform((v) => (v && v.trim() ? v : undefined));

/** Request schema for creating an investigation. At least one input is required. */
export const InvestigationInputSchema = z
  .object({
    url: optionalText(LIMITS.url, 'URL').refine((v) => !v || !/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(v), 'URL contains control characters'),
    domain: optionalText(LIMITS.domain, 'Domain'),
    email: optionalText(LIMITS.email, 'Email address'),
    headers: optionalText(LIMITS.headers, 'Headers'),
    message: optionalText(LIMITS.message, 'Message'),
  })
  .strict()
  .refine((v) => Object.values(v).some(Boolean), { message: 'Provide at least one of: url, domain, email, headers, message' });

export function normalizeInput(input: InvestigationInput): NormalizedInput {
  const notes: string[] = [];
  const out: NormalizedInput = { notes };
  if (input.url) {
    const r = refang(input.url);
    if (r.changed) notes.push(`Defanged URL re-fanged for analysis: ${r.value}`);
    out.url = input.url.trim();
  }
  if (input.domain) {
    const r = refang(input.domain);
    if (r.changed) notes.push(`Defanged domain re-fanged for analysis: ${r.value}`);
    out.domain = r.value.trim();
  }
  if (input.email) out.email = refang(input.email).value.trim();
  if (input.headers) out.headers = input.headers;
  if (input.message) out.message = input.message;
  return out;
}

export function inputTypes(input: InvestigationInput): InputType[] {
  return (['url', 'domain', 'email', 'headers', 'message'] as const).filter((k) => !!input[k]);
}

/**
 * What is persisted about each input. Short identifiers (URL, domain, address)
 * are kept because they are the subject of the investigation. Header blocks and
 * message bodies are only stored when RETAIN_RAW_CONTENT is enabled; otherwise
 * just a hash and length are kept so the input can be matched later.
 */
export function summarizeInputs(input: InvestigationInput, retainRaw: boolean): InputSummary[] {
  return inputTypes(input).map((type) => {
    const value = input[type]!;
    const isContent = type === 'headers' || type === 'message';
    const retained = !isContent || retainRaw;
    return { type, value: retained ? value : null, length: value.length, sha256: createHash('sha256').update(value).digest('hex'), retained };
  });
}

/** A short human-readable title derived from the most specific input. */
export function deriveTitle(input: NormalizedInput, subjectLine?: string | null): string {
  if (input.url) {
    try {
      return new URL(refang(input.url).value.includes('://') ? refang(input.url).value : `http://${refang(input.url).value}`).hostname || input.url.slice(0, 80);
    } catch {
      return input.url.slice(0, 80);
    }
  }
  if (input.domain) return input.domain.toLowerCase().slice(0, 120);
  if (subjectLine) return subjectLine.slice(0, 120);
  if (input.email) return input.email.slice(0, 120);
  if (input.headers) {
    const from = input.headers.match(/^from:\s*(.+)$/im)?.[1];
    if (from) return `Email from ${from.trim().slice(0, 100)}`;
    return 'Email headers';
  }
  return 'Message analysis';
}
