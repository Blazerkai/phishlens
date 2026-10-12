import tls from 'node:tls';
import type { PeerCertificate } from 'node:tls';
import { resolvePublicAddresses, type ResolveAllFn, systemResolveAll } from '../../security/ssrf.js';
import { isIpLiteral } from '../../security/ip.js';
import type { TlsInspection, TlsService } from './types.js';

/** Opens a TLS handshake (no HTTP request) to read the certificate presented for a host. */
export function createTlsService(opts: { allowedPorts: number[]; resolveAll?: ResolveAllFn }): TlsService {
  const resolveAll = opts.resolveAll ?? systemResolveAll;
  return {
    async inspect(host: string, port: number, timeoutMs: number): Promise<TlsInspection> {
      if (!opts.allowedPorts.includes(port)) throw new Error(`port ${port} is not in the outbound allow-list`);
      const [addr] = await resolvePublicAddresses(host, resolveAll);
      return new Promise<TlsInspection>((resolve, reject) => {
        const socket = tls.connect({
          host: addr!.address,
          port,
          servername: isIpLiteral(host) ? undefined : host,
          rejectUnauthorized: false,
          ALPNProtocols: ['http/1.1'],
        });
        const timer = setTimeout(() => {
          socket.destroy();
          reject(new Error(`TLS handshake timed out after ${timeoutMs} ms`));
        }, timeoutMs);
        socket.once('secureConnect', () => {
          clearTimeout(timer);
          const cert = socket.getPeerCertificate(true) as PeerCertificate & { issuerCertificate?: PeerCertificate };
          const chain: PeerCertificate[] = [];
          let cur = cert?.issuerCertificate as (PeerCertificate & { issuerCertificate?: PeerCertificate }) | undefined;
          const seen = new Set<string>([cert?.fingerprint256 ?? '']);
          while (cur && cur.fingerprint256 && !seen.has(cur.fingerprint256) && chain.length < 6) {
            seen.add(cur.fingerprint256);
            chain.push(cur);
            cur = cur.issuerCertificate as typeof cur;
          }
          const result: TlsInspection = {
            remoteAddress: socket.remoteAddress ?? null,
            protocol: socket.getProtocol(),
            cipher: socket.getCipher()?.name ?? null,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
            certificate: cert && Object.keys(cert).length ? cert : null,
            chain,
          };
          socket.end();
          resolve(result);
        });
        socket.once('error', (e) => {
          clearTimeout(timer);
          reject(e);
        });
      });
    },
  };
}
