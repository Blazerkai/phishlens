import { parse } from 'tldts';
import type { AnalyzerContext } from './types.js';
import { normalizeDomainInput } from './domain/parseDomain.js';
import { isIpLiteral } from '../security/ip.js';

export type TargetRole = 'submitted-domain' | 'submitted-url' | 'sender' | 'reply-to' | 'envelope' | 'email-address' | 'message-link' | 'redirect';

export interface NetworkTarget {
  host: string;
  registrableDomain: string | null;
  roles: Set<TargetRole>;
}

/**
 * Hosts worth spending network probes on, in priority order. The cap protects
 * both the investigated infrastructure and the analyst's network from fan-out.
 */
export function networkTargets(ctx: AnalyzerContext, limit = ctx.settings.network.maxTargets): NetworkTarget[] {
  const out = new Map<string, NetworkTarget>();
  const add = (raw: string | null | undefined, role: TargetRole) => {
    if (!raw) return;
    const host = normalizeDomainInput(raw);
    if (!host || isIpLiteral(host)) return;
    const existing = out.get(host);
    if (existing) {
      existing.roles.add(role);
      return;
    }
    if (out.size >= limit) return;
    out.set(host, { host, registrableDomain: parse(host, { allowPrivateDomains: true }).domain ?? null, roles: new Set([role]) });
  };

  add(ctx.input.domain, 'submitted-domain');
  for (const u of ctx.state.urls) if (u.origin === 'input' && u.valid) add(u.hostname, 'submitted-url');
  const e = ctx.state.email;
  if (e) {
    add(e.from?.domain, 'sender');
    for (const r of e.replyTo) add(r.domain, 'reply-to');
    add(e.returnPath?.domain, 'envelope');
  }
  add(ctx.state.emailAddress?.address.domain, 'email-address');
  for (const l of ctx.state.message?.links ?? []) add(l.hrefHost, 'message-link');
  return [...out.values()];
}

export const SENDER_ROLES: TargetRole[] = ['sender', 'reply-to', 'envelope', 'email-address'];
