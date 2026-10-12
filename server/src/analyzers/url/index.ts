import type { Analyzer } from '../types.js';
import { parseUrl } from './parseUrl.js';
import { urlHeuristics } from './heuristics.js';

export const urlAnalyzer: Analyzer = {
  id: 'url',
  label: 'Collecting URL information',
  dependsOn: [],
  applies: (ctx) => !!ctx.input.url,
  async run(ctx) {
    const u = parseUrl(ctx.input.url!, 'input');
    ctx.state.urls.push(u);
    for (const d of urlHeuristics(u, { brands: ctx.brands, lists: ctx.settings.lists })) ctx.emit(d);
    if (!u.valid) return { status: 'completed', detail: 'Input is not a valid URL' };
    return {
      status: 'completed',
      detail: `${u.scheme}://${u.hostname}${u.port ? `:${u.port}` : ''} · registrable domain ${u.registrableDomain ?? 'n/a'}`,
    };
  },
};
