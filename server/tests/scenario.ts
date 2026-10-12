import type { PeerCertificate } from 'node:tls';
import type { Brand, OperatorVerification } from '@phishlens/shared';
import { runPipeline } from '../src/engine/pipeline.js';
import { defaultAnalyzers } from '../src/analyzers/registry.js';
import { normalizeInput } from '../src/engine/input.js';
import type { EngineServices } from '../src/analyzers/types.js';
import type { TlsService } from '../src/services/network/types.js';
import { lists, brands as defaultBrands } from './helpers.js';
import { noTls } from './fakes.js';

const fmt = (d: Date) => d.toUTCString().replace(/^\w+, (\d+) (\w+) (\d+) ([\d:]+) GMT$/, '$2 $1 $4 $3 GMT');

/** A TLS service that presents a configurable certificate for any host. Defaults: valid, trusted, covers the host. */
export function fakeTls(
  opts: {
    authorized?: boolean;
    authorizationError?: string | null;
    issuedDaysAgo?: number;
    validityDays?: number;
    subjectCN?: (host: string) => string;
    issuer?: { O: string; CN: string };
    sansFor?: (host: string) => string[];
    selfSigned?: boolean;
    fail?: Error;
  } = {},
): TlsService {
  return {
    async inspect(host) {
      if (opts.fail) throw opts.fail;
      const now = Date.now();
      const from = new Date(now - (opts.issuedDaysAgo ?? 30) * 86_400_000);
      const to = new Date(from.getTime() + (opts.validityDays ?? 90) * 86_400_000);
      const sans = opts.sansFor?.(host) ?? [host];
      const cn = opts.subjectCN?.(host) ?? sans[0];
      const cert = {
        subject: { CN: cn },
        issuer: opts.selfSigned ? { CN: cn } : (opts.issuer ?? { C: 'US', O: "Let's Encrypt", CN: 'R11' }),
        subjectaltname: sans.map((s) => `DNS:${s}`).join(', '),
        valid_from: fmt(from),
        valid_to: fmt(to),
        serialNumber: '01',
        fingerprint256: `FP:${host}`,
      } as unknown as PeerCertificate;
      const sanCovers = sans.some((s) => s === host || (s.startsWith('*.') && host.endsWith(s.slice(1)) && !host.slice(0, -s.length + 1).includes('.')));
      const error = opts.authorizationError !== undefined ? opts.authorizationError : !sanCovers ? 'ERR_TLS_CERT_ALTNAME_INVALID' : to.getTime() < now ? 'CERT_HAS_EXPIRED' : null;
      return {
        remoteAddress: '93.184.216.50',
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        authorized: opts.authorized ?? error === null,
        authorizationError: error,
        certificate: cert,
        chain: [],
      };
    },
  };
}

export function rdapResponse(daysOld: number, registrar = 'Test Registrar') {
  return {
    status: 200,
    headers: { 'content-type': 'application/rdap+json' },
    body: JSON.stringify({
      objectClassName: 'domain',
      events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - daysOld * 86_400_000).toISOString() }],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', registrar]]] }],
    }),
  };
}

export async function scenario(
  input: Parameters<typeof normalizeInput>[0],
  services: Partial<EngineServices>,
  opts: { probes?: boolean; brands?: Brand[]; identities?: OperatorVerification[] } = {},
) {
  const events: { stage: string; status: string; timestamp: string; detail?: string | null }[] = [];
  const result = await runPipeline({
    input: normalizeInput(input),
    analyzers: defaultAnalyzers,
    brands: opts.brands ?? defaultBrands,
    identities: opts.identities ?? [],
    settings: {
      lists,
      network: {
        probesEnabled: opts.probes ?? true,
        rdapEnabled: true,
        rdapBootstrapUrl: 'https://rdap.test/domain/',
        dnsServers: [],
        requestTimeoutMs: 1000,
        dnsTimeoutMs: 500,
        maxRedirects: 5,
        maxBodyBytes: 65536,
        allowedPorts: [80, 443, 8080, 8443],
        maxTargets: 6,
        maxMessageLinkProbes: 3,
      },
    },
    services: {
      dns: services.dns ?? { description: 'none', resolve: async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); }, reverse: async () => [] },
      http: services.http ?? { request: async () => { throw new Error('no http'); } },
      tls: services.tls ?? noTls,
      ...(services.reputation ? { reputation: services.reputation } : {}),
    },
    onTimeline: (e) => events.push(e),
  });
  return { ...result, events, codes: result.indicators.map((i) => i.code) };
}
