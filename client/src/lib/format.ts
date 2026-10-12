import type { IndicatorCategory, InputType, Severity, Verdict } from '@phishlens/shared';

export const VERDICT_LABEL: Record<Verdict, string> = {
  high_risk: 'High risk',
  suspicious: 'Suspicious',
  inconclusive: 'Inconclusive',
  benign: 'Benign',
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const CATEGORY_LABEL: Record<IndicatorCategory, string> = {
  URL_STRUCTURE: 'URL structure',
  DOMAIN: 'Domain',
  LOOKALIKE: 'Lookalike',
  DNS: 'DNS',
  DOMAIN_REGISTRATION: 'Registration',
  TLS: 'TLS',
  REDIRECT: 'Redirects',
  PAGE_CONTENT: 'Page content',
  EMAIL_AUTHENTICATION: 'Email authentication',
  EMAIL_HEADER: 'Email headers',
  SENDER: 'Sender identity',
  MESSAGE_CONTENT: 'Message content',
  LINK: 'Links',
  REPUTATION: 'Reputation',
  IDENTITY: 'Operator identity',
  CORRELATION: 'Correlation',
};

export const INPUT_LABEL: Record<InputType, string> = { url: 'URL', domain: 'Domain', email: 'Email', headers: 'Headers', message: 'Message' };

export function timeAgo(iso: string, now = Date.now()): string {
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} hour${h === 1 ? '' : 's'} ago`;
  const d = Math.round(h / 24);
  if (d === 1) return 'Yesterday';
  if (d < 30) return `${d} days ago`;
  return new Date(iso).toLocaleDateString();
}

export function clockTime(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
}

export function durationMs(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}
