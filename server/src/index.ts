import { loadConfig } from './config/index.js';
import { initDatabase } from './database/index.js';
import { createNetworkServices } from './services/network/index.js';
import { InvestigationService } from './services/investigationService.js';
import { createSummarizer } from './services/ai/index.js';
import { createReputationService } from './services/reputation/index.js';
import { createProviders } from './services/reputation/providers.js';
import { createApp } from './app.js';
import { logger } from './lib/logger.js';

const config = loadConfig();
const { db, repo } = initDatabase(config);

const interrupted = repo.failInterrupted();
if (interrupted) logger.warn('marked interrupted investigations as failed', { count: interrupted });

const purge = () => {
  repo.purgeReputationCache(30);
  const removed = repo.purgeOlderThan(config.retention.days);
  if (removed) logger.info('retention purge', { removed, days: config.retention.days });
};
purge();
const purgeTimer = setInterval(purge, 6 * 3_600_000);
purgeTimer.unref();

const network = createNetworkServices(config.network);
const reputation = createReputationService({
  providers: createProviders(config.reputation),
  http: network.http,
  cache: repo.reputationCache(),
  timeoutMs: config.reputation.timeoutMs,
  cacheTtlHours: config.reputation.cacheTtlHours,
});
const service = new InvestigationService({ config, repo, services: { ...network, reputation } });
const ai = createSummarizer(config);
const app = createApp({ config, repo, service, ai, reputationProviders: reputation.providers });

const server = app.listen(config.port, config.host, () => {
  logger.info('PhishLens API listening', {
    url: `http://${config.host}:${config.port}`,
    database: config.databasePath,
    networkProbes: config.network.probesEnabled,
    rdap: config.network.rdapEnabled,
    retainRawContent: config.retention.retainRawContent,
    ai: ai.available ? ai.provider : 'disabled',
    reputation: reputation.providers.filter((p) => p.configured).map((p) => p.id),
  });
});
server.requestTimeout = 30_000;
server.headersTimeout = 15_000;

const shutdown = (signal: string) => {
  logger.info('shutting down', { signal });
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
