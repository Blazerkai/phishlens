import type {
  AnalyzerRun,
  Brand,
  EvidenceGraph,
  OperatorVerification,
  Indicator,
  InvestigationArtifacts,
  RiskAssessment,
  TimelineStatus,
} from '@phishlens/shared';
import type { Analyzer, AnalyzerContext, AnalyzerResult, EngineServices, EngineSettings, NormalizedInput } from '../analyzers/types.js';
import { UnavailableError } from '../services/network/types.js';
import { IndicatorCollector } from './indicators/index.js';
import { assessRisk } from './verdict/index.js';
import { buildEvidenceGraph } from './graph/index.js';

export interface TimelineSink {
  (e: { stage: string; label: string; status: TimelineStatus; detail?: string | null; timestamp: string }): void;
}

export interface PipelineArgs {
  input: NormalizedInput;
  analyzers: readonly Analyzer[];
  brands: Brand[];
  identities?: OperatorVerification[];
  settings: EngineSettings;
  services: EngineServices;
  onTimeline?: TimelineSink;
  /** Upper bound for a single analyzer, as a safety net on top of per-request timeouts. */
  analyzerTimeoutMs?: number;
  now?: () => Date;
}

export interface PipelineResult {
  indicators: Indicator[];
  artifacts: InvestigationArtifacts;
  assessment: RiskAssessment;
  graph: EvidenceGraph;
  analyzerRuns: AnalyzerRun[];
}

export function emptyArtifacts(): InvestigationArtifacts {
  return { urls: [], domains: [], dns: [], tls: [], redirects: [], rdap: [], email: null, emailAddress: null, message: null, reputation: [] };
}

/** Validates that the analyzer set forms a DAG with no unknown dependencies. */
export function validateAnalyzerGraph(analyzers: readonly Analyzer[]): void {
  const ids = new Set(analyzers.map((a) => a.id));
  if (ids.size !== analyzers.length) throw new Error('Duplicate analyzer ids');
  for (const a of analyzers) {
    for (const d of a.dependsOn) if (!ids.has(d)) throw new Error(`Analyzer "${a.id}" depends on unknown "${d}"`);
  }
  const visiting = new Set<string>();
  const done = new Set<string>();
  const byId = new Map(analyzers.map((a) => [a.id, a]));
  const visit = (id: string) => {
    if (done.has(id)) return;
    if (visiting.has(id)) throw new Error(`Analyzer dependency cycle at "${id}"`);
    visiting.add(id);
    for (const d of byId.get(id)!.dependsOn) visit(d);
    visiting.delete(id);
    done.add(id);
  };
  for (const a of analyzers) visit(a.id);
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${what} exceeded ${ms} ms`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Runs analyzers in dependency order. Independent analyzers run concurrently.
 * A failing analyzer is isolated: it is recorded as failed, the rest continue,
 * and the assessment reflects the reduced coverage.
 */
export async function runPipeline(args: PipelineArgs): Promise<PipelineResult> {
  const now = args.now ?? (() => new Date());
  const timeline: TimelineSink = args.onTimeline ?? (() => {});
  const ts = () => now().toISOString();
  validateAnalyzerGraph(args.analyzers);

  const collector = new IndicatorCollector(now);
  const state = emptyArtifacts();
  const runs: AnalyzerRun[] = [];
  const finished = new Set<string>();

  const contextFor = (analyzerId: string): AnalyzerContext => ({
    input: args.input,
    state,
    brands: args.brands,
    identities: args.identities ?? [],
    settings: args.settings,
    services: args.services,
    indicators: collector,
    emit: (draft) => {
      collector.add(draft, analyzerId);
    },
  });

  for (const note of args.input.notes) timeline({ stage: 'input', label: 'Input normalised', status: 'info', detail: note, timestamp: ts() });

  const runOne = async (a: Analyzer) => {
    const ctx = contextFor(a.id);
    if (!a.applies(ctx)) {
      finished.add(a.id);
      return;
    }
    const started = now();
    timeline({ stage: a.id, label: a.label, status: 'started', timestamp: started.toISOString() });
    let result: AnalyzerResult;
    try {
      result = await withTimeout(a.run(ctx), args.analyzerTimeoutMs ?? 60_000, a.label);
    } catch (err) {
      result =
        err instanceof UnavailableError
          ? { status: 'unavailable', reason: err.message }
          : { status: 'failed', reason: err instanceof Error ? err.message : String(err) };
    }
    const finishedAt = now();
    runs.push({
      analyzer: a.id,
      label: a.label,
      status: result.status,
      ...(result.reason ? { reason: result.reason } : {}),
      startedAt: started.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - started.getTime(),
    });
    const status: TimelineStatus =
      result.status === 'completed' ? 'completed' : result.status === 'failed' ? 'failed' : result.status === 'unavailable' ? 'unavailable' : 'skipped';
    timeline({ stage: a.id, label: a.label, status, detail: result.detail ?? result.reason ?? null, timestamp: finishedAt.toISOString() });
    finished.add(a.id);
  };

  const remaining = new Set(args.analyzers.map((a) => a.id));
  while (remaining.size > 0) {
    const ready = args.analyzers.filter((a) => remaining.has(a.id) && a.dependsOn.every((d) => finished.has(d)));
    if (ready.length === 0) throw new Error('Analyzer scheduling stalled');
    for (const a of ready) remaining.delete(a.id);
    await Promise.all(ready.map(runOne));
  }

  const verdictStart = ts();
  timeline({ stage: 'verdict', label: 'Generating verdict', status: 'started', timestamp: verdictStart });
  const indicators = collector.list();
  const assessment = assessRisk(indicators, runs, state, { brandCount: args.brands.length });
  timeline({
    stage: 'verdict',
    label: 'Generating verdict',
    status: 'completed',
    detail: `${assessment.verdict.replace('_', ' ')} (risk score ${assessment.score})`,
    timestamp: ts(),
  });

  const graph = buildEvidenceGraph(state, indicators, args.input);
  return { indicators, artifacts: state, assessment, graph, analyzerRuns: runs };
}
