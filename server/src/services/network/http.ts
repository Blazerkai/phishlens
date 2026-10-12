import http from 'node:http';
import https from 'node:https';
import type { IncomingMessage } from 'node:http';
import type { TLSSocket } from 'node:tls';
import { assertUrlAllowed, createSafeLookup, SsrfBlockedError, type ResolveAllFn, systemResolveAll } from '../../security/ssrf.js';
import { classifyIp } from '../../security/ip.js';
import type { HttpRequestOptions, HttpResponse, HttpService } from './types.js';

export const USER_AGENT = 'PhishLens/0.1 (+defensive phishing investigation; single-request inspection)';

/**
 * SSRF-safe HTTP client used for redirect inspection and RDAP.
 *  - validates scheme, port and hostname before connecting
 *  - resolves through a lookup that only yields public addresses and pins the socket to it
 *  - re-checks the connected peer address
 *  - never follows redirects (callers re-validate every hop)
 *  - sends no cookies or credentials; caps body size and total time
 */
export function createHttpService(opts: { allowedPorts: number[]; resolveAll?: ResolveAllFn }): HttpService {
  const resolveAll = opts.resolveAll ?? systemResolveAll;

  return {
    async request(rawUrl: string, ro: HttpRequestOptions): Promise<HttpResponse> {
      const url = assertUrlAllowed(rawUrl, { allowedPorts: opts.allowedPorts });
      const mod = url.protocol === 'https:' ? https : http;
      const started = Date.now();

      return new Promise<HttpResponse>((resolve, reject) => {
        let settled = false;
        const finish = (err: Error | null, value?: HttpResponse) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (err) reject(err);
          else resolve(value!);
        };

        const req = mod.request(
          url,
          {
            method: ro.method ?? 'GET',
            agent: false,
            lookup: createSafeLookup(resolveAll),
            headers: {
              'User-Agent': USER_AGENT,
              Accept: 'text/html,application/xhtml+xml,application/rdap+json,application/json;q=0.9,*/*;q=0.5',
              'Accept-Encoding': 'identity',
              Connection: 'close',
              ...(ro.body !== undefined ? { 'Content-Length': String(Buffer.byteLength(ro.body)) } : {}),
              ...ro.headers,
            },
            // Certificate problems are recorded by the TLS analyzer; inspection should still see the response.
            rejectUnauthorized: false,
          },
          (res: IncomingMessage) => {
            const remote = res.socket?.remoteAddress ?? null;
            if (remote && classifyIp(remote).blocked) {
              res.destroy();
              finish(new SsrfBlockedError(`connected peer ${remote} is not a public address`, url.href));
              return;
            }
            // Verification still runs with rejectUnauthorized=false: Node sets `authorized` from chain
            // trust plus the RFC 6125 hostname check against the SNI name (the requested host).
            const sock = res.socket as TLSSocket | null;
            const tlsInfo =
              url.protocol === 'https:' && sock && typeof sock.authorized === 'boolean'
                ? {
                    authorized: sock.authorized,
                    error: sock.authorizationError ? String(sock.authorizationError) : null,
                    fingerprint256: sock.getPeerCertificate?.()?.fingerprint256 ?? null,
                  }
                : null;
            const chunks: Buffer[] = [];
            let size = 0;
            let truncated = false;
            const done = () =>
              finish(null, {
                status: res.statusCode ?? 0,
                headers: res.headers,
                body: Buffer.concat(chunks),
                bodyTruncated: truncated,
                remoteAddress: remote,
                durationMs: Date.now() - started,
                tls: tlsInfo,
              });
            if (!ro.readBody || ro.maxBodyBytes === 0) {
              res.destroy();
              done();
              return;
            }
            res.on('data', (c: Buffer) => {
              if (size + c.length > ro.maxBodyBytes) {
                chunks.push(c.subarray(0, ro.maxBodyBytes - size));
                size = ro.maxBodyBytes;
                truncated = true;
                res.destroy();
                done();
                return;
              }
              chunks.push(c);
              size += c.length;
            });
            res.on('end', done);
            res.on('close', done);
            res.on('error', (e) => finish(e));
          },
        );
        const timer = setTimeout(() => {
          req.destroy();
          finish(new Error(`request timed out after ${ro.timeoutMs} ms`));
        }, ro.timeoutMs);
        req.on('error', (e) => finish(e));
        req.end(ro.body);
      });
    },
  };
}
