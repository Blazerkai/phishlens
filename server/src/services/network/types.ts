import type { PeerCertificate } from 'node:tls';

export type DnsRecordType = 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CNAME';

export interface DnsService {
  /** Human-readable description of the resolver in use (shown as evidence source). */
  readonly description: string;
  /** Resolves records of one type. Rejects with an Error carrying a DNS error `code` (ENODATA, ENOTFOUND, ETIMEOUT…). */
  resolve(name: string, type: DnsRecordType): Promise<string[]>;
  reverse(ip: string): Promise<string[]>;
}

export interface HttpRequestOptions {
  timeoutMs: number;
  maxBodyBytes: number;
  /** Read the response body (capped at maxBodyBytes). */
  readBody: boolean;
  method?: 'GET' | 'POST';
  /** Extra request headers (credentials for reputation APIs). Never logged. */
  headers?: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  bodyTruncated: boolean;
  remoteAddress: string | null;
  durationMs: number;
  /** For https: verification result of the certificate presented on *this* connection. */
  tls: { authorized: boolean; error: string | null; fingerprint256: string | null } | null;
}

export interface HttpService {
  /** Performs ONE request (never follows redirects). Must enforce SSRF policy. */
  request(url: string, opts: HttpRequestOptions): Promise<HttpResponse>;
}

export interface TlsInspection {
  remoteAddress: string | null;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  certificate: PeerCertificate | null;
  chain: PeerCertificate[];
}

export interface TlsService {
  inspect(host: string, port: number, timeoutMs: number): Promise<TlsInspection>;
}

/** Error raised when a network collector is disabled or cannot run in this environment. */
export class UnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnavailableError';
  }
}
