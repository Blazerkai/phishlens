/**
 * Deterministic reconstruction of the hustlance.com investigation as reported
 * (observed 2026-10). Only facts present in that report are encoded. Dates are
 * relative so the fixture does not age: the domain is 401 days old (registered
 * 2025-09-06, observed early Oct 2026) and the certificate expires in ~67 days.
 *
 * Nothing here is an allowlist: the same evidence under any other name must
 * produce the same result (see the "equivalent evidence" test).
 */
import { fakeDns, fakeHttp } from '../fakes.js';
import { fakeTls, rdapResponse } from '../scenario.js';

export const HUSTLANCE_TITLE = 'Hustlance – Freelancing Platform for Students | Find Freelance Work &amp; Earn Online';

/** 100 SANs: one shared Google Trust Services certificate for many tenants, as reported. */
export function sharedSans(host: string): string[] {
  const others = Array.from({ length: 98 }, (_, i) => `tenant-${i + 1}.example.net`);
  return ['food4fitness.com.au', ...others.slice(0, 49), host, ...others.slice(49)];
}

export function hustlanceLike(domain = 'hustlance.com', opts: { ageDays?: number; hsts?: string } = {}) {
  return {
    input: { url: `http://${domain}/` },
    services: {
      dns: fakeDns({
        [domain]: {
          A: ['199.36.158.100'],
          NS: ['ns57.domaincontrol.com', 'ns58.domaincontrol.com'],
          TXT: ['hosting-site=studenthub-30c32'],
        },
        [`_dmarc.${domain}`]: { TXT: ['v=DMARC1; p=quarantine'] },
      }),
      http: fakeHttp({
        [`http://${domain}/`]: { status: 301, headers: { location: `https://${domain}/` }, remoteAddress: '199.36.158.100' },
        [`https://${domain}/`]: {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', ...(opts.hsts ? { 'strict-transport-security': opts.hsts } : {}) },
          body: `<html><head><title>${HUSTLANCE_TITLE}</title></head><body><h1>Hustlance</h1><a href="/signup">Get started</a></body></html>`,
          remoteAddress: '199.36.158.100',
        },
        [`https://rdap.test/domain/${domain}`]: rdapResponse(opts.ageDays ?? 401, 'GoDaddy.com, LLC'),
      }),
      tls: fakeTls({
        issuedDaysAgo: 23,
        validityDays: 90,
        issuer: { O: 'Google Trust Services', CN: 'WR3' },
        subjectCN: () => 'food4fitness.com.au',
        sansFor: sharedSans,
      }),
    },
  };
}
