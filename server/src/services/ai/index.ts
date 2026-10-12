import type { AiSummary, InvestigationDetail } from '@phishlens/shared';
import type { AppConfig } from '../../config/index.js';
import { anthropicSummarizer } from './anthropic.js';

/**
 * Optional narrative layer over already-collected evidence.
 * It never produces indicators or verdicts; the deterministic engine does.
 */
export interface AiSummarizer {
  readonly available: boolean;
  readonly provider: string;
  summarize(d: InvestigationDetail): Promise<AiSummary>;
}

export function disabledSummarizer(reason: string): AiSummarizer {
  return {
    available: false,
    provider: 'none',
    async summarize() {
      return { status: 'unavailable', reason, generatedAt: new Date().toISOString() };
    },
  };
}

export function createSummarizer(config: AppConfig): AiSummarizer {
  if (config.ai.provider === 'anthropic') return anthropicSummarizer({ apiKey: config.ai.anthropicApiKey, model: config.ai.model });
  return disabledSummarizer('AI summaries are disabled (AI_PROVIDER=none). The investigation is complete without them.');
}
