import type { Analyzer } from './types.js';
import { urlAnalyzer } from './url/index.js';
import { emailHeaderAnalyzer, emailAddressAnalyzer } from './email/index.js';
import { messageAnalyzer } from './message/index.js';
import { domainAnalyzer } from './domain/index.js';
import { dnsAnalyzer } from './dns/index.js';
import { redirectAnalyzer } from './redirects/index.js';
import { tlsAnalyzer } from './tls/index.js';
import { rdapAnalyzer } from './rdap/index.js';
import { correlationAnalyzer } from './correlation/index.js';
import { reputationAnalyzer } from './reputation/index.js';
import { identityAnalyzer } from './identity/index.js';

/**
 * Every analyzer the pipeline runs. Order here is irrelevant: the pipeline
 * schedules by `dependsOn`. To add an analyzer, implement `Analyzer` and list it.
 *
 *   url ─┐  email-headers ─┐  email-address ─┐  message ─┐
 *        └──────────────── domain ───────────────────────┘
 *                     ┌──────┼────────┬─────────┐
 *                    dns   rdap   redirects ─ tls, reputation, identity
 *                     └──────┴────────┴─────────┴── correlation → verdict
 */
export const defaultAnalyzers: readonly Analyzer[] = [
  urlAnalyzer,
  emailHeaderAnalyzer,
  emailAddressAnalyzer,
  messageAnalyzer,
  domainAnalyzer,
  dnsAnalyzer,
  rdapAnalyzer,
  redirectAnalyzer,
  tlsAnalyzer,
  reputationAnalyzer,
  identityAnalyzer,
  correlationAnalyzer,
];
