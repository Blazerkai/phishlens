import { randomUUID } from 'node:crypto';
import type { InvestigationInput } from '@phishlens/shared';
import type { AppConfig } from '../config/index.js';
import type { Repository } from '../database/repository.js';
import type { Analyzer, EngineServices } from '../analyzers/types.js';
import { defaultLists, type ReferenceLists } from '../config/lists.js';
import { defaultAnalyzers } from '../analyzers/registry.js';
import { runPipeline } from '../engine/pipeline.js';
import { deriveTitle, inputTypes, normalizeInput, summarizeInputs } from '../engine/input.js';
import { parseEmailHeaders } from '../analyzers/email/parseHeaders.js';
import { JobQueue } from './queue.js';
import { logger } from '../lib/logger.js';

export interface InvestigationServiceDeps {
  config: AppConfig;
  repo: Repository;
  services: EngineServices;
  analyzers?: readonly Analyzer[];
  lists?: ReferenceLists;
}

/**
 * Orchestrates an investigation's lifecycle: persist the request, queue analysis,
 * stream timeline events to the database as they happen, persist results.
 *
 * Raw header/message content lives only in memory for the duration of the job
 * unless RETAIN_RAW_CONTENT is enabled.
 */
export class InvestigationService {
  private readonly queue: JobQueue;

  constructor(private readonly deps: InvestigationServiceDeps) {
    this.queue = new JobQueue(deps.config.maxConcurrentInvestigations);
  }

  create(input: InvestigationInput): { id: string } {
    const id = randomUUID();
    const normalized = normalizeInput(input);
    const subjectLine = !input.url && !input.domain && input.headers ? parseEmailHeaders(input.headers).subject : null;
    const createdAt = new Date().toISOString();
    this.deps.repo.createInvestigation({
      id,
      title: deriveTitle(normalized, subjectLine),
      inputTypes: inputTypes(input),
      inputs: summarizeInputs(input, this.deps.config.retention.retainRawContent),
      createdAt,
    });
    this.deps.repo.addTimelineEvent(id, {
      timestamp: createdAt,
      stage: 'created',
      label: 'Investigation created',
      status: 'completed',
      detail: `Inputs: ${inputTypes(input).join(', ')}`,
    });
    this.queue.push(() => this.execute(id, normalized));
    return { id };
  }

  private async execute(id: string, input: ReturnType<typeof normalizeInput>): Promise<void> {
    const { repo, config } = this.deps;
    repo.setStatus(id, 'running');
    const brands = repo.listBrands();
    const identities = repo.listVerifications();
    try {
      const result = await runPipeline({
        input,
        analyzers: this.deps.analyzers ?? defaultAnalyzers,
        brands,
        identities,
        settings: { network: config.network, lists: this.deps.lists ?? defaultLists },
        services: this.deps.services,
        onTimeline: (e) => repo.addTimelineEvent(id, e),
      });
      const completedAt = new Date().toISOString();
      repo.saveResults(id, { ...result, completedAt });
      repo.addTimelineEvent(id, {
        timestamp: completedAt,
        stage: 'report',
        label: 'Risk assessment generated',
        status: 'completed',
        detail: `${result.indicators.length} indicator(s) recorded`,
      });
    } catch (err) {
      logger.error('investigation failed', { id, error: (err as Error).message });
      repo.addTimelineEvent(id, { timestamp: new Date().toISOString(), stage: 'pipeline', label: 'Investigation failed', status: 'failed', detail: 'Internal error during analysis' });
      repo.markFailed(id, 'Analysis failed due to an internal error. See server logs.');
    }
  }

  idle(): Promise<void> {
    return this.queue.idle();
  }

  queueSize() {
    return this.queue.size;
  }
}
