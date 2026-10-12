/**
 * PhishLens shared domain model.
 *
 * These types are the contract between the analysis engine, the API and the UI.
 * They are type-only: nothing here exists at runtime.
 */

// ---------------------------------------------------------------------------
// Indicators
// ---------------------------------------------------------------------------

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

export type IndicatorCategory =
  | 'URL_STRUCTURE'
  | 'DOMAIN'
  | 'LOOKALIKE'
  | 'DNS'
  | 'DOMAIN_REGISTRATION'
  | 'TLS'
  | 'REDIRECT'
  | 'PAGE_CONTENT'
  | 'EMAIL_AUTHENTICATION'
  | 'EMAIL_HEADER'
  | 'SENDER'
  | 'MESSAGE_CONTENT'
  | 'LINK'
  | 'REPUTATION'
  | 'IDENTITY'
  | 'CORRELATION';

/**
 * risk    – the observation raises concern
 * benign  – a verified positive observation (see positive-evidence families in the assessment)
 * neutral – context only; does not move the assessment
 * unknown – a check could not be completed; neither positive nor negative evidence
 */
export type Polarity = 'risk' | 'benign' | 'neutral' | 'unknown';

/**
 * Where the evidence behind an indicator came from.
 * user_input – data the investigator submitted (headers, message, URL text)
 * network    – a live observation made by PhishLens (DNS, TLS, HTTP)
 * analysis   – a deterministic derivation from other evidence
 * external   – a clearly identified third-party source (e.g. RDAP)
 */
export type Provenance = 'user_input' | 'network' | 'analysis' | 'external';

export interface Indicator {
  id: string;
  /** Stable rule identifier, e.g. URL_IP_HOST. Used for aggregation. */
  code: string;
  category: IndicatorCategory;
  title: string;
  /** Why this observation matters (the "reason"). */
  description: string;
  severity: Severity;
  /** How reliably this rule indicates what its title claims (0..1). Not a probability of phishing. */
  confidence: number;
  polarity: Polarity;
  /** The concrete observable that triggered the rule. */
  evidence: string;
  /** Where in the input / which observation the evidence was read from. */
  source: string;
  provenance: Provenance;
  analyzer: string;
  /** Evidence-graph node this indicator is attached to. */
  subject?: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

export const INPUT_TYPES = ['url', 'domain', 'email', 'headers', 'message'] as const;
export type InputType = (typeof INPUT_TYPES)[number];

export interface InvestigationInput {
  url?: string;
  domain?: string;
  email?: string;
  headers?: string;
  message?: string;
}

export interface InputSummary {
  type: InputType;
  /** Value is present only for short identifiers or when raw content retention is enabled. */
  value: string | null;
  length: number;
  sha256: string;
  retained: boolean;
}

// ---------------------------------------------------------------------------
// Analyzer artifacts (structured technical evidence)
// ---------------------------------------------------------------------------

export type CollectionStatus = 'completed' | 'failed' | 'unavailable' | 'skipped' | 'blocked';

export interface UrlAnalysis {
  input: string;
  origin: 'input' | 'message' | 'redirect' | 'email';
  valid: boolean;
  error?: string;
  scheme?: string;
  hostname?: string;
  /** Unicode form of an IDN hostname, when different. */
  hostnameUnicode?: string;
  port?: number | null;
  effectivePort?: number | null;
  path?: string;
  query?: { key: string; value: string }[];
  fragment?: string;
  username?: string;
  hasPassword?: boolean;
  subdomain?: string | null;
  registrableDomain?: string | null;
  publicSuffix?: string | null;
  isIp?: boolean;
  normalized?: string;
}

export interface DomainAnalysis {
  hostname: string;
  hostnameUnicode: string;
  isIp: boolean;
  subdomain: string | null;
  registrableDomain: string | null;
  publicSuffix: string | null;
  tld: string | null;
  labels: string[];
  subdomainDepth: number;
  isPunycode: boolean;
  isPrivateSuffix: boolean;
  scripts: string[];
  sources: string[];
  brandMatches: BrandMatch[];
}

export interface BrandMatch {
  brand: string;
  technique:
    | 'official'
    | 'keyword'
    | 'typosquat'
    | 'homoglyph'
    | 'official-domain-as-subdomain'
    | 'tld-swap';
  detail: string;
}

export interface Brand {
  id: number;
  name: string;
  /** Lower-case keywords that identify the brand in labels and text, e.g. "paypal". */
  keywords: string[];
  /** Registrable domains legitimately operated by the brand. */
  officialDomains: string[];
  createdAt: string;
}

export interface DnsRecordSet {
  type: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'CNAME' | 'PTR' | 'DMARC';
  status: 'ok' | 'nodata' | 'nxdomain' | 'error' | 'timeout' | 'skipped';
  values: string[];
  error?: string;
}

export interface SpfRecord {
  raw: string;
  mechanisms: string[];
  allQualifier: '+' | '-' | '~' | '?' | null;
  includes: string[];
}

export interface DmarcRecord {
  raw: string;
  policy: string | null;
  subdomainPolicy: string | null;
  pct: number | null;
  rua: string[];
}

export interface DnsAnalysis {
  name: string;
  status: CollectionStatus;
  reason?: string;
  resolver: string;
  records: DnsRecordSet[];
  spf: SpfRecord | null;
  dmarc: DmarcRecord | null;
  reverse: { ip: string; names: string[] }[];
  providers: { role: 'dns' | 'mail' | 'hosting'; name: string; basis: string }[];
  queriedAt: string;
}

export interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  subjectCN: string | null;
  issuerCN: string | null;
  issuerOrg: string | null;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  daysSinceIssued: number;
  sans: string[];
  serialNumber: string;
  fingerprint256: string;
  selfSigned: boolean;
}

export interface TlsAnalysis {
  host: string;
  port: number;
  status: CollectionStatus;
  reason?: string;
  remoteAddress?: string;
  protocol?: string | null;
  cipher?: string | null;
  authorized?: boolean;
  authorizationError?: string | null;
  hostnameMatches?: boolean;
  hostnameMismatchReason?: string | null;
  certificate?: CertificateInfo;
  chain?: { subjectCN: string | null; issuerCN: string | null; validTo: string }[];
  inspectedAt: string;
}

/** TLS verification of the connection that actually served an HTTPS hop. */
export interface HopTls {
  /** Chain trust + RFC 6125 hostname check against the SNI name (Node `authorized`). */
  authorized: boolean;
  error: string | null;
  fingerprint256: string | null;
}

export interface RedirectHop {
  index: number;
  tls?: HopTls | null;
  /** Strict-Transport-Security header on this response, if any. */
  hsts?: string | null;
  url: string;
  scheme: string;
  hostname: string;
  remoteAddress?: string;
  statusCode?: number;
  location?: string | null;
  kind: 'http' | 'meta-refresh' | 'final' | 'error' | 'blocked';
  durationMs?: number;
  error?: string;
}

export interface PageObservation {
  contentType: string | null;
  title: string | null;
  hasPasswordField: boolean;
  formActions: string[];
  /** A literal location assignment found in inline script. Not followed: PhishLens never executes scripts. */
  scriptRedirect: string | null;
  bytesInspected: number;
}

export interface RedirectAnalysis {
  startUrl: string;
  status: CollectionStatus;
  reason?: string;
  hops: RedirectHop[];
  finalUrl: string | null;
  redirectCount: number;
  page?: PageObservation;
  inspectedAt: string;
}

export interface RdapAnalysis {
  domain: string;
  status: CollectionStatus;
  reason?: string;
  source: string;
  registered?: string | null;
  expires?: string | null;
  lastChanged?: string | null;
  ageDays?: number | null;
  registrar?: string | null;
  statuses?: string[];
  queriedAt: string;
}

export interface EmailAddress {
  raw: string;
  displayName: string | null;
  address: string | null;
  localPart: string | null;
  domain: string | null;
}

export interface ReceivedHop {
  index: number;
  raw: string;
  from: string | null;
  fromRdns: string | null;
  fromIp: string | null;
  by: string | null;
  with: string | null;
  id: string | null;
  for: string | null;
  date: string | null;
  timestamp: string | null;
  delaySeconds: number | null;
  ipIsPrivate: boolean | null;
}

export type AuthResultValue =
  | 'pass'
  | 'fail'
  | 'softfail'
  | 'neutral'
  | 'none'
  | 'temperror'
  | 'permerror'
  | 'policy'
  | 'bestguesspass'
  | 'unknown';

export interface AuthMethodResult {
  method: 'spf' | 'dkim' | 'dmarc' | 'arc' | 'other';
  result: AuthResultValue;
  reason: string | null;
  properties: Record<string, string>;
  raw: string;
}

export interface AuthenticationResultsHeader {
  authservId: string | null;
  results: AuthMethodResult[];
  raw: string;
}

export interface DkimSignature {
  domain: string | null;
  selector: string | null;
  algorithm: string | null;
  signedHeaders: string[];
  raw: string;
}

export interface EmailHeaderAnalysis {
  headerCount: number;
  from: EmailAddress | null;
  to: EmailAddress[];
  cc: EmailAddress[];
  replyTo: EmailAddress[];
  returnPath: EmailAddress | null;
  sender: EmailAddress | null;
  subject: string | null;
  date: string | null;
  messageId: string | null;
  messageIdDomain: string | null;
  xMailer: string | null;
  received: ReceivedHop[];
  authenticationResults: AuthenticationResultsHeader[];
  receivedSpf: { result: AuthResultValue; raw: string } | null;
  dkimSignatures: DkimSignature[];
  summary: {
    spf: AuthResultValue | 'absent';
    dkim: AuthResultValue | 'absent';
    dmarc: AuthResultValue | 'absent';
    spfDomain: string | null;
    dkimDomains: string[];
    dmarcPolicy: string | null;
    spfAligned: boolean | null;
    dkimAligned: boolean | null;
  };
}

export interface ExtractedLink {
  href: string;
  text: string | null;
  context: 'html-anchor' | 'markdown' | 'plain';
  hrefHost: string | null;
  displayedHost: string | null;
  mismatch: boolean;
}

export interface MessageAnalysis {
  length: number;
  isHtml: boolean;
  links: ExtractedLink[];
  patternHits: { pattern: string; category: string; excerpt: string }[];
  claimedBrands: string[];
}

export interface EmailAddressAnalysis {
  address: EmailAddress;
  valid: boolean;
  freemail: boolean;
  roleAccount: boolean;
}

// ---------------------------------------------------------------------------
// Reputation and identity
// ---------------------------------------------------------------------------

export type ReputationProviderId = 'gsb' | 'urlhaus' | 'virustotal' | 'tranco';

/**
 * listed          – the provider lists the subject as malicious
 * historical      – listed in the past only (e.g. all URLs offline)
 * minority        – a few detections that are frequently false positives
 * not_listed      – no listing. NOT evidence of safety
 * popular         – sustained high popularity rank (positive corroboration)
 * not_popular     – not ranked / ranked low. Neutral
 * stale           – only an outdated result is available; not counted
 * error           – the provider failed or timed out; not counted
 * unavailable     – not configured or locally rate-limited; not counted
 */
export type ReputationStatus = 'listed' | 'historical' | 'minority' | 'not_listed' | 'popular' | 'not_popular' | 'stale' | 'error' | 'unavailable';

export interface ReputationObservation {
  provider: ReputationProviderId;
  providerName: string;
  /** Registrable domain or URL that was looked up. */
  subject: string;
  status: ReputationStatus;
  summary: string;
  /** The data sources behind a listing (e.g. VirusTotal engine names), used to avoid double counting. */
  underlyingSources: string[];
  details: Record<string, string | number | boolean | null>;
  /** When PhishLens obtained this result. */
  fetchedAt: string;
  /** Date of the provider's own data (scan date, list date), when known. */
  dataDate: string | null;
  cached: boolean;
  reference: string | null;
}

export interface ReputationProviderInfo {
  id: ReputationProviderId;
  name: string;
  kind: 'blocklist' | 'aggregator' | 'popularity';
  configured: boolean;
  requirement: string;
  terms: string;
}

export const VERIFICATION_METHODS = ['legal_entity_registry', 'direct_contact', 'contractual_relationship', 'official_publication', 'other'] as const;
export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];

/** An analyst's record that the operator of a domain was independently identified. */
export interface OperatorVerification {
  id: number;
  domain: string;
  operatorName: string;
  method: VerificationMethod;
  evidenceReference: string;
  verifiedBy: string;
  verifiedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  notes: string | null;
}

export interface InvestigationArtifacts {
  urls: UrlAnalysis[];
  domains: DomainAnalysis[];
  dns: DnsAnalysis[];
  tls: TlsAnalysis[];
  redirects: RedirectAnalysis[];
  rdap: RdapAnalysis[];
  email: EmailHeaderAnalysis | null;
  emailAddress: EmailAddressAnalysis | null;
  message: MessageAnalysis | null;
  /** Absent on investigations stored before reputation support. */
  reputation?: ReputationObservation[];
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

export const VERDICTS = ['benign', 'suspicious', 'high_risk', 'inconclusive'] as const;
export type Verdict = (typeof VERDICTS)[number];

export interface AssessmentContribution {
  indicatorId: string;
  code: string;
  title: string;
  category: IndicatorCategory;
  severity: Severity;
  confidence: number;
  points: number;
}

export interface AnalyzerRun {
  analyzer: string;
  label: string;
  status: CollectionStatus;
  reason?: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}

export interface RiskAssessment {
  verdict: Verdict;
  /** Heuristic risk score 0–100. Not a probability. */
  score: number;
  summary: string;
  rationale: string[];
  contributions: AssessmentContribution[];
  benignSignals: { indicatorId: string; title: string }[];
  coverage: {
    completed: string[];
    unavailable: { analyzer: string; reason: string }[];
    failed: { analyzer: string; reason: string }[];
  };
  limitations: string[];
  method: string;
  /** Benign indicators grouped into independent evidence families (absent on older investigations). */
  positiveEvidence?: PositiveEvidenceFamily[];
  /** Positive and risk evidence that point in different directions. */
  conflicts?: string[];
  /** What additional evidence would resolve an inconclusive result. */
  nextSteps?: string[];
}

/**
 * security_control – hygiene an operator controls (TLS, HTTPS enforcement, mail authentication);
 *                    freely available to attackers too, so it cannot establish legitimacy alone.
 * corroboration    – evidence about *who* operates the domain or its history (identity, maturity).
 */
export type PositiveEvidenceClass = 'security_control' | 'corroboration';

export interface PositiveEvidenceFamily {
  family: string;
  label: string;
  class: PositiveEvidenceClass;
  /** Whether this family counted towards the benign rule (false when contradicted). */
  counted: boolean;
  reason: string;
  indicatorIds: string[];
  titles: string[];
}

// ---------------------------------------------------------------------------
// Evidence graph
// ---------------------------------------------------------------------------

export type GraphNodeType =
  | 'investigation'
  | 'email'
  | 'address'
  | 'domain'
  | 'host'
  | 'ip'
  | 'url'
  | 'redirect'
  | 'certificate'
  | 'dns'
  | 'mailserver'
  | 'message'
  | 'registration';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  sublabel?: string;
  indicatorIds: string[];
  /** Highest severity among attached risk indicators, or null if none. */
  risk: Severity | null;
  facts: { label: string; value: string }[];
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  label: string;
}

export interface EvidenceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootId: string;
}

// ---------------------------------------------------------------------------
// Timeline / investigation
// ---------------------------------------------------------------------------

export type TimelineStatus = 'started' | 'completed' | 'failed' | 'skipped' | 'unavailable' | 'info';

export interface TimelineEvent {
  id: number;
  timestamp: string;
  stage: string;
  label: string;
  status: TimelineStatus;
  detail: string | null;
}

export type InvestigationStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface InvestigationSummary {
  id: string;
  title: string;
  status: InvestigationStatus;
  verdict: Verdict | null;
  score: number | null;
  indicatorCount: number;
  riskIndicatorCount: number;
  inputTypes: InputType[];
  createdAt: string;
  completedAt: string | null;
}

export interface InvestigationDetail extends InvestigationSummary {
  inputs: InputSummary[];
  indicators: Indicator[];
  assessment: RiskAssessment | null;
  artifacts: InvestigationArtifacts | null;
  graph: EvidenceGraph | null;
  timeline: TimelineEvent[];
  analyzerRuns: AnalyzerRun[];
  error: string | null;
}

export interface DashboardStats {
  totals: { total: number; suspicious: number; highRisk: number; benign: number; inconclusive: number; running: number };
  thisWeek: number;
  recent: InvestigationSummary[];
  commonIndicators: { code: string; title: string; category: IndicatorCategory; count: number; maxSeverity: Severity }[];
  latestPatterns: { investigationId: string; investigationTitle: string; title: string; severity: Severity; category: IndicatorCategory; timestamp: string }[];
  verdictByDay: { day: string; benign: number; suspicious: number; high_risk: number; inconclusive: number }[];
}

export interface PublicSettings {
  networkProbesEnabled: boolean;
  rdapEnabled: boolean;
  retainRawContent: boolean;
  retentionDays: number;
  maxRedirects: number;
  requestTimeoutMs: number;
  allowedPorts: number[];
  aiSummaryAvailable: boolean;
  aiProvider: string | null;
  version: string;
  reputationProviders: ReputationProviderInfo[];
}

export interface AiSummary {
  status: 'completed' | 'unavailable' | 'failed';
  reason?: string;
  provider?: string;
  model?: string;
  text?: string;
  citedIndicatorIds?: string[];
  uncitedClaimsRemoved?: number;
  generatedAt: string;
}
