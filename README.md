# PhishLens

A defensive phishing investigation workbench. Submit a suspicious URL, domain, email address, raw email headers, message — or any combination — and PhishLens collects observable evidence, analyses it with transparent deterministic rules, and produces an explainable verdict and an exportable investigation report.

```
INPUT → COLLECTION → NORMALIZATION → ANALYSIS → EVIDENCE → VERDICT
```

There is no AI in the analysis path. Every indicator carries the rule that produced it, the reason it matters, the concrete evidence, its source, and where that evidence came from (submitted data, a live network observation, deterministic analysis, or a named external source). An optional AI layer can narrate already-collected evidence; it cannot create indicators or change the verdict.

PhishLens is an analysis tool. It does not host pages, send mail, collect credentials or interact with phishing kits beyond a single read-only, SSRF-guarded HTTP inspection per hop.

---

## Quick start

Requirements: Node.js ≥ 22.12 (developed on 24), npm ≥ 10. No external database or services.

```bash
cd phishlens
npm install
npm run dev            # API on http://127.0.0.1:4000, UI on http://127.0.0.1:5173
```

Open http://127.0.0.1:5173 and choose **New Investigation**.

Production build (the API serves the built UI from one port):

```bash
npm run build
NODE_ENV=production npm start   # http://127.0.0.1:4000
```

## Commands

| Command (from repo root) | What it does |
|---|---|
| `npm run dev` | API (tsx watch) + Vite dev server with `/api` proxy |
| `npm run build` | Typecheck + bundle server (`server/dist`) and client (`client/dist`) |
| `npm start` | Run the built server (`NODE_ENV=production` also serves the UI) |
| `npm test` | All server and client tests |
| `npm run test:coverage` | Server tests with coverage for analyzers, engine, security |
| `npm run typecheck` | `tsc --noEmit` for server and client |
| `npm run db:init` | Create/migrate the SQLite database and print its state |
| `npm run test:watch -w server` | Server tests in watch mode |

## Configuration

All configuration is via environment variables, validated with Zod at startup (invalid values stop the server with a precise message). Copy `.env.example` to `server/.env`; it is loaded with Node's `--env-file-if-exists`. Every variable is optional.

| Variable | Default | Purpose |
|---|---|---|
| `HOST` / `PORT` | `127.0.0.1` / `4000` | Bind address. Loopback by default. |
| `DATABASE_PATH` | `data/phishlens.db` | SQLite file, relative to `server/`. |
| `CORS_ORIGINS` | `http://localhost:5173,…` | Allowed browser origins for the API. |
| `TRUST_PROXY` | `false` | Set `true` only behind one trusted reverse proxy (affects client IP for rate limiting). |
| `NETWORK_PROBES_ENABLED` | `true` | `false` disables all DNS/TLS/HTTP/RDAP collection; those stages report *unavailable*. |
| `RDAP_ENABLED` | `true` | Domain registration lookups via `RDAP_BOOTSTRAP_URL` (sends investigated registrable domains to rdap.org and the registry). |
| `DNS_SERVERS` | system resolver | Comma-separated resolvers, e.g. `1.1.1.1,9.9.9.9`. |
| `REQUEST_TIMEOUT_MS` / `DNS_TIMEOUT_MS` | `6000` / `3000` | Per-request timeouts. |
| `MAX_REDIRECTS` | `8` | Redirect hops followed per link. |
| `MAX_BODY_BYTES` | `131072` | HTML read per hop for static inspection. |
| `ALLOWED_PORTS` | `80,443,8080,8443` | Outbound port allow-list. |
| `MAX_NETWORK_TARGETS` | `6` | Hosts probed per investigation. |
| `MAX_MESSAGE_LINK_PROBES` | `3` | Message links whose redirect chains are followed. |
| `RETAIN_RAW_CONTENT` | `false` | Store raw headers and message bodies. Off: only SHA-256 + length + derived evidence. |
| `RETENTION_DAYS` | `30` | Investigations older than this are deleted (`0` = keep). |
| `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` | `60000` / `120` | API requests per IP per window. |
| `RATE_LIMIT_CREATE_MAX` | `10` | New investigations / AI summaries per IP per window. |
| `MAX_CONCURRENT_INVESTIGATIONS` | `2` | Analysis job concurrency. |
| `BRANDS_SEED_FILE` | `config/brands.json` | Brand watchlist seeded once into a new database. |
| `GSB_API_KEY` | — | Google Safe Browsing v4 Lookup. Free; **non-commercial use only** (commercial: Google Web Risk, paid). URLs are sent to Google. |
| `URLHAUS_AUTH_KEY` | — | URLhaus host lookups (free abuse.ch account). Domains are sent to abuse.ch. |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 domain reports. Free public key: 4 req/min, 500/day, **not for commercial products**; looked-up indicators become visible to the VirusTotal community. |
| `TRANCO_ENABLED` | `false` | Tranco popularity ranking (no key, 1 req/s). Domains are sent to tranco-list.eu. |
| `TRANCO_RANK_THRESHOLD` / `TRANCO_MIN_DAYS` | `100000` / `25` | "Sustained popularity" = within this rank on at least this many recent daily lists. |
| `REPUTATION_TIMEOUT_MS` | `5000` | Per-provider request timeout. |
| `REPUTATION_CACHE_TTL_HOURS` | `24` | Successful results are reused within this window; expired entries resurface only as *stale* when a live lookup fails. |
| `REPUTATION_STALE_AFTER_DAYS` | `7` | Provider data older than this is stale and never counted. |
| `AI_PROVIDER` | `none` | `anthropic` enables the optional narrative summary. |
| `ANTHROPIC_API_KEY` | — | Key for the AI layer (or an `ant auth login` profile). |
| `AI_MODEL` | `claude-opus-5-5` | Model for the AI narrative. |

## Database

SQLite via `better-sqlite3`, WAL mode, foreign keys on. Schema lives in ordered, append-only migrations (`server/src/database/migrations/index.ts`) recorded in `schema_migrations`; they run automatically at startup and with `npm run db:init`. On first creation the brand watchlist is seeded from `config/brands.json`.

| Table | Contents |
|---|---|
| `investigations` | Status, verdict, score, counts, assessment / graph / analyzer-run JSON |
| `inputs` | One row per submitted input: value (or NULL when not retained), length, SHA-256 |
| `indicators` | Every indicator with rule code, severity, confidence, polarity, evidence, source, provenance |
| `evidence` | Full structured artifact per analyzer (canonical source for the UI and reports) |
| `dns_records` | One row per observed record (queryable; used to link investigations sharing IPs) |
| `tls_certificates` | Observed certificates (fingerprint indexed; used for related investigations) |
| `redirects` | One row per redirect hop |
| `email_headers` | Parsed sender fields and authentication summary |
| `timeline_events` | Timestamped stage events written as the pipeline runs |
| `brands` | Brand watchlist for the lookalike heuristic |
| `operator_verifications` | Analyst-recorded operator identity (method, evidence reference, verifier, expiry, revocation) |
| `reputation_cache` | Successful provider results with fetch time (purged after 30 days) |

Deleting an investigation cascades to all of its rows.

## Tests

```bash
npm test                 # 326 server tests + client layout tests
npm run test:coverage    # ~92% line coverage of analyzers, engine and security
```

Tests use in-memory SQLite and fake DNS/HTTP/TLS services, so they are deterministic and offline. Coverage includes URL parsing and heuristics (including obfuscated IPs, userinfo tricks, defanged input), domain extraction and lookalikes (homoglyph, typosquat, brand-as-subdomain), DNS/SPF/DMARC parsing, TLS certificate evaluation, redirect handling (limits, loops, meta refresh, blocked internal hops), email header parsing (folding, RFC 2047, Received chains, Gmail- and Microsoft-style Authentication-Results, DKIM-Signature), From/Reply-To/Return-Path mismatches, message patterns, scoring and verdict rules, report escaping, API validation, rate limiting, CORS and retention. SSRF tests run a real local HTTP server and assert it is never contacted — including via a hostname that resolves to loopback.

## Project structure

```
phishlens/
├── shared/src/index.ts          Domain model shared by API and UI (types only)
├── server/
│   ├── config/brands.json       Brand watchlist seed (editable in Settings)
│   ├── src/
│   │   ├── analyzers/           One directory per analyzer
│   │   │   ├── types.ts         Analyzer contract
│   │   │   ├── registry.ts      The analyzer list (add new analyzers here)
│   │   │   ├── targets.ts       Which hosts get network probes, by role
│   │   │   ├── url/  domain/  dns/  tls/  redirects/  rdap/
│   │   │   ├── email/           Header parser + heuristics, email-address analyzer
│   │   │   ├── message/         Patterns, link extraction, display/href mismatch
│   │   │   └── correlation/     Cross-analyzer rules
│   │   ├── engine/
│   │   │   ├── pipeline.ts      Dependency scheduling, isolation, timeline events
│   │   │   ├── indicators/      Indicator model and invariants
│   │   │   ├── scoring/         Heuristic risk score
│   │   │   ├── verdict/         Verdict rules, rationale, limitations
│   │   │   ├── graph/           Evidence graph builder
│   │   │   └── input.ts         Input schema, normalisation, retention summary
│   │   ├── security/            IP classification, SSRF guard, rate limit, headers/CORS
│   │   ├── services/            Investigation lifecycle, job queue, reports, network clients, AI
│   │   ├── database/            Migrations, repository, CLI
│   │   ├── routes/api.ts        HTTP API
│   │   └── app.ts, index.ts
│   └── tests/                   unit/, integration/, fixtures/, fakes
├── client/src/
│   ├── pages/                   Dashboard, Investigations, New, Detail, Reports, Settings
│   ├── components/              Evidence graph, progress, indicators, evidence views, UI kit
│   └── lib/                     API client, graph layout, formatting
└── docs/ARCHITECTURE.md         Pipeline, evidence model, scoring, extension guide, phase log
```

## API

| Method & path | Purpose |
|---|---|
| `POST /api/investigations` | Create (body: any of `url`, `domain`, `email`, `headers`, `message`) → `202 {id}` |
| `GET /api/investigations` | List (`verdict`, `status`, `q`, `limit`, `offset`) |
| `GET /api/investigations/:id` | Detail incl. indicators, assessment, artifacts, graph, timeline |
| `DELETE /api/investigations/:id` | Delete with all evidence |
| `GET /api/investigations/:id/report?format=html\|md\|json[&download=1]` | Export report |
| `POST /api/investigations/:id/summary` | Optional AI narrative |
| `GET /api/dashboard` | Dashboard aggregates |
| `GET/POST/DELETE /api/brands` | Brand watchlist |
| `GET /api/settings`, `GET /api/health` | Public configuration, health |

## Security considerations

**Outbound requests (SSRF).** Every connection goes through one guard (`server/src/security/ssrf.ts`):
- Only `http`/`https`, only allow-listed ports.
- Hostnames such as `localhost`, `*.local`, `*.internal`, `metadata.google.internal` and single-label names are refused before resolution.
- Every resolved address must be public. Blocked: loopback, RFC 1918, CGNAT, link-local (incl. 169.254.169.254), multicast, reserved and documentation ranges, IPv6 ULA/link-local, and IPv4 embedded in IPv6 (mapped, NAT64, 6to4). A name with *any* non-public answer is refused.
- The socket connects to the exact address that was validated (custom `lookup`), so DNS rebinding between check and connect does not work; the connected peer is re-checked.
- Obfuscated IP notation (`http://2130706433/`, `0x7f.1`) is normalised by the WHATWG parser before checks.
- Redirects are never followed automatically: each hop is re-validated, capped by `MAX_REDIRECTS`, per-request timeouts and an overall chain budget. Bodies are size-capped; compressed responses are not requested. Pages are read statically — scripts never run.

**API.** Zod validation with strict schemas and length limits; 1 MB body cap; UUID-validated IDs; parameterised SQL only; per-IP rate limits (stricter for creating investigations); explicit CORS allow-list; generic error responses (no stack traces); CSP and other security headers on API, UI and reports; server request/header timeouts.

**Rendering.** React escapes all evidence; no `dangerouslySetInnerHTML`. The HTML report escapes every value and is served with `default-src 'none'`. Fonts are self-hosted so the UI makes no third-party requests.

**Data.** Raw headers and message bodies are held in memory only for the analysis unless `RETAIN_RAW_CONTENT=true`; otherwise only a SHA-256, the length and the derived evidence are stored. Indicator evidence is truncated to 500 characters, but it does contain excerpts of submitted content (quoted phrases, header values) — that is what makes it evidence. Investigations are purged after `RETENTION_DAYS`. Logs never contain submitted content.

**Execution.** No shell or child-process execution anywhere; no `eval`. Secrets come from the environment only.

**Operational notes.** Network probes reveal your egress IP to the investigated infrastructure (some phishing kits log or cloak based on visitor IPs) — run PhishLens from an appropriate network segment, or set `NETWORK_PROBES_ENABLED=false` for passive analysis. RDAP lookups disclose investigated domains to rdap.org and the registry. Bind to loopback (the default) or put an authenticating reverse proxy in front: **PhishLens has no user authentication of its own.**

## Implemented features

- Investigations from URL, domain, email address, raw headers, message, or any combination, with defanged input (`hxxps://example[.]com`) accepted.
- **URL analysis:** full component extraction (scheme, host, port, path, query, fragment, subdomain, registrable domain via the Public Suffix List incl. private suffixes); IP hosts, obfuscated IP notation, non-public addresses, userinfo deception, percent-encoded hosts, double/heavy encoding, domains and brand names in paths, embedded redirect parameters, recipient addresses in query/fragment (incl. base64), executable/archive downloads, shorteners, inline-content schemes. Words like "login" are never flagged on their own.
- **Domain analysis:** subdomain depth, domain-like subdomains, punycode/IDN with mixed-script detection, hyphen- and number-heavy names, configurable elevated-abuse TLD list, shared hosting platforms, and a configurable brand lookalike heuristic (official domain, homoglyph/confusable skeleton, typosquat edit distance, brand-as-subdomain, TLD swap, keyword).
- **DNS:** A, AAAA, CNAME, MX, NS, TXT, DMARC (with organisational-domain fallback), PTR; SPF/DMARC parsing; DNS, mail and hosting provider identification by pattern (context only); NXDOMAIN, non-public answers, parked domains; mail posture assessed per header role (MX for reply domains, SPF for the envelope domain, DMARC for the From domain).
- **TLS:** subject, issuer, validity, days remaining, SANs, chain, protocol, cipher, fingerprint; trust, RFC 6125 hostname matching, expiry, self-signed, legacy protocol. The issuing CA is never treated as a risk signal.
- **Redirects:** per-hop status, host, scheme, location, remote address, timing; HTTP and meta-refresh redirects; loop and limit detection; HTTPS downgrade, redirects to IPs or internal addresses; static page inspection (title, password fields, off-site form actions, script redirects).
- **Domain registration (RDAP):** registration date and age, registrar, status (hold).
- **Email headers:** RFC 5322 unfolding, RFC 2047 decoding, address lists, Received chain (oldest-first, delays, private hops), Authentication-Results (RFC 8601, Google and Microsoft styles), Received-SPF, DKIM-Signature, alignment; SPF/DKIM/DMARC results explained rather than auto-convicted; From vs Reply-To / Return-Path mismatches; display-name spoofing and brand claims; time reversal, date inconsistency, missing headers; only the top-most Authentication-Results is trusted.
- **Message analysis:** phrase-level urgency, threat, credential, payment (gift cards, bank-detail changes, crypto), secrecy, impersonation, reward, document-lure and greeting patterns; a separate indicator for *combinations* of techniques; HTML/markdown/plain link extraction with displayed-vs-actual URL mismatch; zero-width characters; hidden HTML text; brand claims.
- **Reputation (optional):** Google Safe Browsing, URLhaus, VirusTotal and Tranco through the SSRF-guarded client, with timeouts, quota spacing, caching and attribution. Listings are risk (independent confirmation escalates to critical; VirusTotal counts as independent only when its detections add a source not already listed directly); isolated VirusTotal detections are low weight; "not listed" is neutral; sustained popularity is corroboration; errors, timeouts, rate limits and stale data are *unknown* and never treated as clean.
- **Operator identity workflow:** analysts record independently verified operators (legal-entity registry, direct contact via an independently sourced channel, contractual relationship, official publication) with an evidence reference, verifier and expiry; DNS control is rejected as a method; verifications are revoked rather than deleted. They count as identity corroboration only for the investigated destination and never offset risk.
- **Correlation:** credential requests linking off the sender's domain, lookalike + credential collection, new domain + credential collection, brand claim vs sender, BEC structure, forged brand domain, unauthenticated sensitive requests, free-mail organisational claims; benign corroboration for authenticated senders whose links stay in-domain.
- **Risk assessment:** documented scoring with per-category diminishing returns, rule-based verdicts (Benign / Suspicious / High risk / Inconclusive), rationale, contributions, benign signals, coverage, and limitations. Benign signals never offset risk.
- **Evidence graph:** interactive relationship graph (email → addresses → domains → DNS/IPs/certificates/registration; message → links → redirects → destinations; mail route); click any node to see its facts and the exact indicators attached to it.
- **Timeline:** real timestamps written by the pipeline as each stage starts and ends; the progress view shows only stages that are actually running.
- **Reports:** printable HTML, Markdown and JSON with ID, date, inputs (or hashes), executive summary, verdict, risk assessment, indicators, DNS, TLS, redirect chain, email authentication, timeline and limitations.
- **Dashboard, investigation list with search/filter, related investigations** (shared IP or certificate), brand watchlist management, retention purge, crash isolation per analyzer, restart recovery.
- **Optional AI narrative** (Anthropic): receives only structured, numbered indicators (never the raw message), treats evidence text as untrusted data, must cite indicator numbers; sentences with missing or invalid citations are removed before display.

## Intentionally not implemented

- **Further threat-intelligence sources** (PhishTank, OpenPhish feeds, passive DNS, ASN/geo lookups, Google Web Risk for commercial use). The provider interface supports adding them.
- **WHOIS over port 43.** RDAP covers registration data with structured responses.
- **Certificate Transparency search** (crt.sh). Useful for finding sibling infrastructure; deferred for the same disclosure reasons.
- **Headless browser rendering / script execution / screenshots.** Executing attacker-controlled pages on the analyst's machine is a materially larger risk surface; static inspection is the safer default and its limits are stated in every report.
- **Attachment and `.eml` parsing** (MIME bodies, file hashing, macro analysis).
- **Authentication, users and roles.** Deploy behind an authenticating proxy for multi-user use.
- **Automated verdict calibration.** Weights are expert-set; there is no labelled dataset in this project to calibrate against, so the score is presented as a heuristic, never a probability.
- **An LLM in the analysis path.** By design.

## Suggested next improvements

1. Pluggable reputation providers implementing the analyzer interface, each reporting `unavailable` without credentials and labelled as external sources.
2. Certificate Transparency lookups to surface other certificates issued for lookalike names.
3. `.eml` upload with MIME parsing, attachment hashing and attachment-type indicators.
4. Optional sandboxed rendering (separate container, no credentials, egress-controlled) for script-driven redirects and screenshots.
5. Analyst feedback (confirmed phish / false positive) stored per investigation, then used to measure and calibrate rule confidence.
6. Authentication (OIDC) and per-analyst audit trail; case notes and status workflow.
7. STIX 2.1 / MISP export of indicators.
8. Bulk URL or mailbox-export triage via the existing job queue.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the pipeline design, evidence model, scoring method, how to add an analyzer, and the per-phase build log.
