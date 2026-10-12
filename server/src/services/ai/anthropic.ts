import Anthropic from '@anthropic-ai/sdk';
import type { AiSummary, InvestigationDetail } from '@phishlens/shared';
import type { AiSummarizer } from './index.js';
import { buildEvidencePrompt, enforceCitations, SYSTEM_PROMPT } from './evidencePrompt.js';
import { logger } from '../../lib/logger.js';

/**
 * Claude-backed narrative summary of collected evidence.
 * Server-side refusal fallback is enabled ("default" routing by refusal category).
 */
export function anthropicSummarizer(opts: { apiKey?: string; model: string }): AiSummarizer {
  const client = new Anthropic(opts.apiKey ? { apiKey: opts.apiKey } : {});
  return {
    available: true,
    provider: 'anthropic',
    async summarize(d: InvestigationDetail): Promise<AiSummary> {
      const generatedAt = new Date().toISOString();
      const { user, index } = buildEvidencePrompt(d);
      try {
        const response = await client.beta.messages.create({
          model: opts.model,
          max_tokens: 16000,
          betas: ['server-side-fallback-2026-07-01'],
          fallbacks: 'default',
          system: SYSTEM_PROMPT,
          messages: [{ role: 'user', content: user }],
        });
        if (response.stop_reason === 'refusal') {
          return { status: 'failed', reason: 'The model declined to summarise this evidence.', provider: 'anthropic', model: response.model, generatedAt };
        }
        const raw = response.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join(' ');
        const { text, cited, removed } = enforceCitations(raw, index);
        if (!text) return { status: 'failed', reason: 'The model response contained no sentences with valid evidence citations.', provider: 'anthropic', model: response.model, generatedAt };
        return { status: 'completed', provider: 'anthropic', model: response.model, text, citedIndicatorIds: cited, uncitedClaimsRemoved: removed, generatedAt };
      } catch (err) {
        let reason = 'AI provider request failed.';
        if (err instanceof Anthropic.AuthenticationError) reason = 'AI provider rejected the credentials (check ANTHROPIC_API_KEY).';
        else if (err instanceof Anthropic.RateLimitError) reason = 'AI provider rate limit reached; try again later.';
        else if (err instanceof Anthropic.BadRequestError) reason = 'AI provider rejected the request.';
        else if (err instanceof Anthropic.APIError) reason = `AI provider error (HTTP ${err.status ?? 'n/a'}).`;
        else if (err instanceof Anthropic.APIConnectionError) reason = 'Could not reach the AI provider.';
        logger.warn('ai summary failed', { id: d.id, error: (err as Error).message });
        return { status: 'failed', reason, provider: 'anthropic', model: opts.model, generatedAt };
      }
    },
  };
}
