# PhishLens architecture

## Pipeline

```
POST /api/investigations
  │  Zod validation · normalise (re-fang, trim) · persist inputs (hash unless retained)
  ▼
JobQueue (bounded concurrency)
  ▼
runPipeline()                                     engine/pipeline.ts
  │  schedules analyzers by dependsOn; independent ones run concurrently
  │  each analyzer: applies()? → timeline "started" → run() → timeline result
  │  a throwing analyzer is recorded as failed; the rest continue
  │
  │   url ─┐  email-headers ─┐  email-address ─┐  message ─┐
  │        └──────────────── domain ────────────────────────┘
  │                     ┌──────┼────────┬──────────┐
  │                    dns   rdap   redirects ── tls
  │                     └──────┴────────┴──────────┴── correlation
  ▼
assessRisk()  → verdict, score, rationale, contributions, limitations
buildEvidenceGraph()
  ▼
Repository.saveResults()  (one transaction: indicators, evidence, dns_records,
                           tls_certificates, redirects, email_headers, investigation)
```

Timeline events are written to `timeline_events` the moment they happen, so the UI's progress view (polling `GET /api/investigations/:id`) shows only stages that have actually started, with their real timestamps and outcomes. Stages whose `applies()` is false never appear.

## Evidence model

Everything the engine concludes is an `Indicator` (`shared/src/index.ts`):

| Field | Meaning |
|---|---|
| `code` | Stable rule ID, e.g. `URL_USERINFO`. Aggregated on the dashboard. |
| `category` | `URL_STRUCTURE`, `LOOKALIKE`, `DNS`, `TLS`, `REDIRECT`, `EMAIL_AUTHENTICATION`, `SENDER`, `MESSAGE_CONTENT`, `LINK`, `CORRELATION`, … |
| `title` / `description` | What was found / why it matters (the reason). |
| `severity` | `info` · `low` · `medium` · `high` · `critical` |
| `confidence` | How reliably the *rule* indicates what its title claims (0–1). Not a probability of phishing. |
| `polarity` | `risk`, `benign` (consistent with legitimacy) or `neutral` (context only). |
| `evidence` | The concrete observable (quoted text, header value, record, certificate field). |
| `source` | Where it was read: "Authentication-Results (mx.google.com)", "TLS handshake with host:443 (ip)", … |
| `provenance` | `user_input`, `network`, `analysis` or `external`. |
| `subject` | Evidence-graph node key, so the graph can show exactly which evidence concerns which entity. |
| `timestamp` | When the rule fired. |

`IndicatorCollector` enforces the invariants: evidence and source must be non-empty, confidence is clamped, duplicates are dropped.

Structured observations (parsed URL, DNS record sets, certificates, redirect hops, parsed headers…) are stored separately as **artifacts** in `InvestigationArtifacts`. If a collector cannot run, it returns `unavailable`/`failed`/`blocked` with a reason and produces **no** artifact — nothing is ever synthesised to fill the gap.

### Severity guidance used throughout

- **critical** — only for correlated, multi-source conclusions (e.g. a brand homoglyph domain that collects credentials).
- **high** — a single observation with very few legitimate explanations (display name containing another company's address, DMARC failure, displayed-vs-actual link mismatch, homoglyph domain).
- **medium** — suspicious but with common benign explanations (Reply-To at another organisation, IP-literal URL, expired certificate).
- **low** — weak signals that only matter in combination (plain HTTP, deep subdomains, elevated-abuse TLD).
- **info** — context (providers, registrar, SAN match) or benign signals.

## Scoring and verdict

`points = SEVERITY_POINTS[severity] × confidence` with `low 6 · medium 15 · high 30 · critical 50`. Within a category, contributions are multiplied by 1, 0.5, 0.25, 0.125 (in descending order) so repeated variations of one observation cannot outweigh independent evidence. The sum is capped at 100. Benign signals do not subtract.

Verdict rules (`engine/verdict/index.ts`), first match wins:

1. **High risk** — a critical finding with confidence ≥ 0.7, or high findings (confidence ≥ 0.6) in two independent categories, or score ≥ 60.
2. **Suspicious** — any high finding (confidence ≥ 0.6), or score ≥ 25.
3. **Benign** — score < 10, **no** risk finding of medium severity or above, at least two **independent positive-evidence families** of which at least one is **corroboration**, no contradicted family, and no evidence collector unavailable or failed.
4. **Inconclusive** — otherwise, with the missing evidence listed as next steps.

### Positive-evidence families (`engine/signals.ts`)

Benign indicators are grouped so correlated observations count once:

| Family | Class | Indicators |
|---|---|---|
| Transport security | security control | `TLS_VALID`, `TRANSPORT_HTTPS_UPGRADE`, `TRANSPORT_HSTS` |
| Sender authentication | security control | `EMAIL_SPF_PASS`, `EMAIL_DKIM_PASS`, `EMAIL_DMARC_PASS`, `DNS_DMARC_ENFORCED`, `CORR_CONSISTENT_SENDER` |
| Verified identity | corroboration | `DOMAIN_OFFICIAL_BRAND` (watchlist), `IDENTITY_VERIFIED` (analyst record) — one claim, counted once |
| Registration maturity | corroboration | `RDAP_ESTABLISHED` (≥ 2 years) |
| Sustained popularity | corroboration | `REPUTATION_POPULAR` (Tranco) |

Corroboration counts only when it concerns a **primary subject** (`primaryDomains`): the submitted domain, the final destination of the submitted URL, or the sender / submitted address domain. Evidence about domains that are merely linked, or redirected away from, is context. Any reputation listing contradicts popularity and identity. Blocklist absence is neutral; provider errors, timeouts, rate limits and stale data are `unknown`.

Security controls are attainable by any operator — on most hosting platforms the certificate and the HTTPS redirect are automatic — so they support but never alone establish legitimacy. A family is *not counted* when contradicted (a TLS risk finding, verification results disagreeing between connections, an authentication failure). Registrar, DNS/mail/hosting provider, SAN contents and mid-range domain age are neutral metadata. Observations whose check could not complete have polarity `unknown` and never count. The assessment records the families (`positiveEvidence`), `conflicts` and `nextSteps`.

### HTTP transport (`analyzers/redirects/transport.ts`)

`URL_PLAINTEXT_HTTP` is a neutral observation. Each http:// URL then gets exactly one transport outcome, so the URL and its redirect are not double-counted:

| Outcome | Finding |
|---|---|
| Same-site 3xx to HTTPS, all later hops HTTPS, destination certificate verified on the serving connection, status < 400 | `TRANSPORT_HTTPS_UPGRADE` (positive) + `TRANSPORT_HTTP_FIRST_REQUEST` (low, 0.15) when no HSTS |
| Content served over HTTP | `TRANSPORT_HTTP_CONTENT` (low; medium with a password field) |
| Anything else (cross-site, unverified certificate, loop, error, not inspected) | `TRANSPORT_HTTPS_UNVERIFIED` (low, 0.35 — the previous weight) |

The assessment always carries the rationale (which rule fired), the ranked contributions, benign signals, coverage (completed/unavailable/failed analyzers) and limitations. The weights are expert-set and uncalibrated; the UI and reports call the number a "risk assessment", never a probability.

## Adding an analyzer

1. Create `server/src/analyzers/<name>/index.ts` exporting an `Analyzer`:

   ```ts
   export const ctLogsAnalyzer: Analyzer = {
     id: 'ct-logs',
     label: 'Searching certificate transparency',     // shown in progress + timeline
     dependsOn: ['domain'],                            // reads ctx.state.domains
     applies: (ctx) => ctx.state.domains.length > 0,   // skipped stages never appear
     async run(ctx) {
       if (!configured) return { status: 'unavailable', reason: 'CT_API_URL not set' };
       // collect → push an artifact → ctx.emit({ code, category, title, description,
       //   severity, confidence, evidence, source, provenance: 'external', subject })
       return { status: 'completed', detail: '12 certificates found' };
     },
   };
   ```

2. Add it to `defaultAnalyzers` in `analyzers/registry.ts`. If later analyzers should use its output, add an artifact field to `InvestigationArtifacts` and list the new id in their `dependsOn` (correlation typically).
3. Use `ctx.services.http` for any outbound request — it enforces the SSRF policy. Never call `fetch` directly.
4. Keep heuristics as pure functions of the artifact (`heuristics.ts`) and test them without the network; use `tests/fakes.ts` for collectors.

The pipeline validates the dependency graph (unknown ids, cycles, duplicates) at run time.

## Network collection

| Collector | Targets | Safeguards |
|---|---|---|
| DNS | Submitted domain, URL host, From / Reply-To / Return-Path domains, address domain, message link hosts (capped by `MAX_NETWORK_TARGETS`), plus each registrable parent | Resolver timeout + hard timeout; PTR only for public IPs |
| Redirects | Submitted URL and up to `MAX_MESSAGE_LINK_PROBES` message links | SSRF guard on every hop, port allow-list, per-request and per-chain time budget, body cap, no cookies, no script execution |
| TLS | HTTPS endpoints: submitted URL, final redirect destinations, submitted domain (max 4) | Same resolution policy and connection pinning; handshake only |
| RDAP | ICANN registrable domains of targets (max 3; private-suffix platforms skipped) | Through the SSRF-guarded HTTP client; can be disabled |

## Build log by phase

| Phase | Delivered | Verification |
|---|---|---|
| 1. Setup, architecture, database | npm workspaces (shared/server/client), shared domain model, Zod-validated config, SQLite migrations and repository, analyzer contract, dependency-scheduled pipeline | Typecheck; `db:init` |
| 2. URL / domain | WHATWG-based URL parser with re-fanging, PSL registrable domains, URL heuristics, domain structure heuristics, confusable skeleton and brand lookalike engine | 53 tests |
| 3. DNS + TLS | Live resolver service, record parsers (SPF, DMARC, null MX), provider identification, DNS heuristics; TLS handshake service, certificate normalisation, RFC 6125 matching, TLS heuristics; RDAP | Fixed a bug where a missing `_dmarc` name was read as the domain not existing; 84 tests |
| 4. Redirects + SSRF | IP classification incl. embedded IPv4, URL/hostname policy, pinned lookup, SSRF-safe HTTP client, hop-by-hop redirect follower, meta refresh, static page inspection | Real local server never contacted, DNS-rebinding simulation; 168 tests |
| 5. Email headers | RFC 5322/2047 parser, Received chain, Authentication-Results (Google/Microsoft styles), DKIM-Signature, alignment, header heuristics, email-address analyzer | Realistic fixtures; 26 tests |
| 6. Message | Phrase-level patterns, technique combinations, HTML/markdown/plain link extraction, display mismatch, zero-width and hidden text | 17 tests |
| 7. Evidence engine + risk | Correlation rules, scoring, verdict engine, end-to-end scenarios | Mail-posture checks scoped per header role after a scenario exposed false positives; 234 tests |
| 8. Evidence graph | Graph builder keyed by indicator subjects; tidy-tree layout; interactive SVG with node inspection | Every indicator attached to exactly one node |
| 9. Timeline + reports | Live timeline persistence, investigation service and job queue, HTML/MD/JSON reports, REST API | Live runs against real sites (github.com, google.com, badssl.com, metadata IP); 255 tests |
| 10. Hardening | Rate limiting, CORS, security headers, CSP for UI/API/report, error handling, retention purge, restart recovery, XSS tests | Dependency audit clean; no shell/eval/raw-HTML usage |
| 11. UI | Dashboard, investigations, new investigation, live progress, detail tabs, evidence graph, email route, network evidence, timeline, reports, settings | Screenshots of the production build; fixed anchor text being extracted as a link |
| AI (optional) | Anthropic narrative over numbered structured evidence with enforced citations | Prompt/citation unit tests; live call not exercised in this build |
