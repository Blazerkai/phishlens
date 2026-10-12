import type { Brand, CollectionStatus, InvestigationArtifacts, InvestigationInput, OperatorVerification } from '@phishlens/shared';
import type { ReputationService } from '../services/reputation/index.js';
import type { NetworkConfig } from '../config/index.js';
import type { IndicatorCollector, IndicatorDraft } from '../engine/indicators/index.js';
import type { ReferenceLists } from '../config/lists.js';
import type { DnsService, HttpService, TlsService } from '../services/network/types.js';

export type NormalizedInput = InvestigationInput & {
  /** Notes produced while normalising input (e.g. a defanged URL was re-fanged). */
  notes: string[];
};

export interface EngineSettings {
  network: NetworkConfig;
  lists: ReferenceLists;
}

export interface EngineServices {
  dns: DnsService;
  http: HttpService;
  tls: TlsService;
  /** Optional reputation providers; absent or unconfigured means "not checked", never "clean". */
  reputation?: ReputationService;
}

export interface AnalyzerContext {
  readonly input: NormalizedInput;
  /** Accumulated structured evidence. Analyzers append to their own section. */
  readonly state: InvestigationArtifacts;
  readonly brands: Brand[];
  /** Analyst-recorded operator verifications (all, including expired; revoked ones are excluded upstream). */
  readonly identities: OperatorVerification[];
  readonly settings: EngineSettings;
  readonly services: EngineServices;
  readonly indicators: IndicatorCollector;
  emit(draft: IndicatorDraft): void;
}

export interface AnalyzerResult {
  status: CollectionStatus;
  /** Why the analyzer could not complete (required for unavailable/failed). */
  reason?: string;
  /** Short factual summary for the timeline, e.g. "3 hops, final host example.com". */
  detail?: string;
}

/**
 * The analyzer contract. To add an analyzer: implement this interface and add it
 * to the registry. The pipeline handles ordering, parallelism, timing, timeline
 * events and failure isolation.
 */
export interface Analyzer {
  /** Stable identifier, used for dependencies and attribution of indicators. */
  readonly id: string;
  /** Human-readable stage label shown in progress and timeline. */
  readonly label: string;
  /** Analyzers whose output this one reads. */
  readonly dependsOn: readonly string[];
  /** Whether there is anything for this analyzer to do. Evaluated after dependencies finish. */
  applies(ctx: AnalyzerContext): boolean;
  run(ctx: AnalyzerContext): Promise<AnalyzerResult>;
}
