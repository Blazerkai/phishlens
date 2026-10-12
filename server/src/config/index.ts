import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const bool = (fallback: boolean) =>
  z
    .enum(['true', 'false', '1', '0', 'yes', 'no'])
    .optional()
    .transform((v) => (v === undefined ? fallback : ['true', '1', 'yes'].includes(v)));

const int = (fallback: number, min: number, max: number) =>
  z.coerce.number().int().min(min).max(max).optional().transform((v) => v ?? fallback);

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).optional().default('development'),
  PHISHLENS_ENV: z.string().optional(),
  HOST: z.string().optional().default('127.0.0.1'),
  PORT: int(4000, 1, 65535),
  DATABASE_PATH: z.string().optional(),
  CORS_ORIGINS: z.string().optional().default('http://localhost:5173,http://127.0.0.1:5173'),
  TRUST_PROXY: bool(false),

  NETWORK_PROBES_ENABLED: bool(true),
  RDAP_ENABLED: bool(true),
  RDAP_BOOTSTRAP_URL: z.string().optional().default('https://rdap.org/domain/'),
  DNS_SERVERS: z.string().optional(),
  REQUEST_TIMEOUT_MS: int(6000, 500, 30000),
  DNS_TIMEOUT_MS: int(3000, 250, 15000),
  MAX_REDIRECTS: int(8, 0, 20),
  MAX_BODY_BYTES: int(131072, 0, 1048576),
  ALLOWED_PORTS: z.string().optional().default('80,443,8080,8443'),
  MAX_NETWORK_TARGETS: int(6, 1, 25),
  MAX_MESSAGE_LINK_PROBES: int(3, 0, 10),

  RETAIN_RAW_CONTENT: bool(false),
  RETENTION_DAYS: int(30, 0, 3650),

  RATE_LIMIT_WINDOW_MS: int(60000, 1000, 3600000),
  RATE_LIMIT_MAX: int(120, 1, 100000),
  RATE_LIMIT_CREATE_MAX: int(10, 1, 10000),
  MAX_CONCURRENT_INVESTIGATIONS: int(2, 1, 16),

  BRANDS_SEED_FILE: z.string().optional(),

  GSB_API_KEY: z.string().optional(),
  URLHAUS_AUTH_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  TRANCO_ENABLED: bool(false),
  TRANCO_RANK_THRESHOLD: int(100000, 1, 1000000),
  TRANCO_MIN_DAYS: int(25, 1, 30),
  REPUTATION_TIMEOUT_MS: int(5000, 500, 30000),
  REPUTATION_CACHE_TTL_HOURS: int(24, 0, 720),
  REPUTATION_STALE_AFTER_DAYS: int(7, 1, 90),

  AI_PROVIDER: z.enum(['none', 'anthropic']).optional().default('none'),
  ANTHROPIC_API_KEY: z.string().optional(),
  AI_MODEL: z.string().optional().default('claude-opus-5-5'),
});

export type AppConfig = ReturnType<typeof loadConfig>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  const e = parsed.data;
  const isTest = e.NODE_ENV === 'test' || e.PHISHLENS_ENV === 'test';

  const allowedPorts = e.ALLOWED_PORTS.split(',')
    .map((p) => Number(p.trim()))
    .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);

  return {
    env: e.NODE_ENV,
    isTest,
    host: e.HOST,
    port: e.PORT,
    databasePath: isTest ? ':memory:' : path.resolve(serverRoot, e.DATABASE_PATH ?? 'data/phishlens.db'),
    corsOrigins: e.CORS_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean),
    trustProxy: e.TRUST_PROXY,
    network: {
      probesEnabled: e.NETWORK_PROBES_ENABLED,
      rdapEnabled: e.RDAP_ENABLED,
      rdapBootstrapUrl: e.RDAP_BOOTSTRAP_URL,
      dnsServers: e.DNS_SERVERS ? e.DNS_SERVERS.split(',').map((s) => s.trim()).filter(Boolean) : [],
      requestTimeoutMs: e.REQUEST_TIMEOUT_MS,
      dnsTimeoutMs: e.DNS_TIMEOUT_MS,
      maxRedirects: e.MAX_REDIRECTS,
      maxBodyBytes: e.MAX_BODY_BYTES,
      allowedPorts,
      maxTargets: e.MAX_NETWORK_TARGETS,
      maxMessageLinkProbes: e.MAX_MESSAGE_LINK_PROBES,
    },
    retention: {
      retainRawContent: e.RETAIN_RAW_CONTENT,
      days: e.RETENTION_DAYS,
    },
    rateLimit: {
      windowMs: e.RATE_LIMIT_WINDOW_MS,
      max: e.RATE_LIMIT_MAX,
      createMax: e.RATE_LIMIT_CREATE_MAX,
    },
    maxConcurrentInvestigations: e.MAX_CONCURRENT_INVESTIGATIONS,
    brandsSeedFile: path.resolve(serverRoot, e.BRANDS_SEED_FILE ?? 'config/brands.json'),
    reputation: {
      gsbApiKey: e.GSB_API_KEY || undefined,
      urlhausAuthKey: e.URLHAUS_AUTH_KEY || undefined,
      virustotalApiKey: e.VIRUSTOTAL_API_KEY || undefined,
      trancoEnabled: e.TRANCO_ENABLED,
      trancoRankThreshold: e.TRANCO_RANK_THRESHOLD,
      trancoMinDays: e.TRANCO_MIN_DAYS,
      timeoutMs: e.REPUTATION_TIMEOUT_MS,
      cacheTtlHours: e.REPUTATION_CACHE_TTL_HOURS,
      staleAfterDays: e.REPUTATION_STALE_AFTER_DAYS,
    },
    ai: {
      provider: e.AI_PROVIDER,
      anthropicApiKey: e.ANTHROPIC_API_KEY,
      model: e.AI_MODEL,
    },
    version: '0.1.0',
  };
}

export type NetworkConfig = AppConfig['network'];
export type ReputationConfig = AppConfig['reputation'];
