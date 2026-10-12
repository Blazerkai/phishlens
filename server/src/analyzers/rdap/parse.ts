import type { RdapAnalysis } from '@phishlens/shared';

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}
interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, [string, unknown, string, unknown][]];
  publicIds?: { type?: string; identifier?: string }[];
}
export interface RdapDomainResponse {
  objectClassName?: string;
  ldhName?: string;
  events?: RdapEvent[];
  entities?: RdapEntity[];
  status?: string[];
}

function vcardName(e: RdapEntity): string | null {
  const fn = e.vcardArray?.[1]?.find((p) => p[0] === 'fn');
  return fn && typeof fn[3] === 'string' ? fn[3] : null;
}

/** Extracts registration facts from an RDAP (RFC 9083) domain object. */
export function parseRdap(json: RdapDomainResponse, now = new Date()): Pick<RdapAnalysis, 'registered' | 'expires' | 'lastChanged' | 'ageDays' | 'registrar' | 'statuses'> {
  const event = (action: string) => json.events?.find((e) => e.eventAction?.toLowerCase() === action)?.eventDate ?? null;
  const registered = event('registration');
  const registrarEntity = json.entities?.find((e) => e.roles?.includes('registrar'));
  const ageDays = registered ? Math.floor((now.getTime() - new Date(registered).getTime()) / 86_400_000) : null;
  return {
    registered,
    expires: event('expiration'),
    lastChanged: event('last changed'),
    ageDays: ageDays !== null && Number.isFinite(ageDays) ? ageDays : null,
    registrar: registrarEntity ? vcardName(registrarEntity) : null,
    statuses: json.status ?? [],
  };
}
