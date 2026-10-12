import type {
  AiSummary,
  AnalyzerRun,
  Brand,
  DashboardStats,
  EvidenceGraph,
  Indicator,
  InputSummary,
  InputType,
  InvestigationArtifacts,
  InvestigationDetail,
  InvestigationStatus,
  InvestigationSummary,
  OperatorVerification,
  RiskAssessment,
  Severity,
  TimelineEvent,
  TimelineStatus,
  Verdict,
} from '@phishlens/shared';
import type { DB } from './db.js';

interface InvestigationRow {
  id: string;
  title: string;
  status: InvestigationStatus;
  verdict: Verdict | null;
  score: number | null;
  indicator_count: number;
  risk_indicator_count: number;
  input_types: string;
  assessment_json: string | null;
  graph_json: string | null;
  analyzer_runs_json: string | null;
  ai_summary_json: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function parseJson<T>(value: string | null, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function toSummary(row: InvestigationRow): InvestigationSummary {
  return {
    id: row.id,
    title: row.title,
    status: row.status,
    verdict: row.verdict,
    score: row.score,
    indicatorCount: row.indicator_count,
    riskIndicatorCount: row.risk_indicator_count,
    inputTypes: parseJson<InputType[]>(row.input_types, []),
    createdAt: row.created_at,
    completedAt: row.completed_at,
  };
}

export interface SaveResultsArgs {
  indicators: Indicator[];
  artifacts: InvestigationArtifacts;
  assessment: RiskAssessment;
  graph: EvidenceGraph;
  analyzerRuns: AnalyzerRun[];
  completedAt: string;
}

export interface ListFilters {
  verdict?: Verdict;
  status?: InvestigationStatus;
  q?: string;
  limit?: number;
  offset?: number;
}

export class Repository {
  constructor(private readonly db: DB) {}

  createInvestigation(args: {
    id: string;
    title: string;
    inputTypes: InputType[];
    inputs: InputSummary[];
    createdAt: string;
  }): void {
    const insertInv = this.db.prepare(
      `INSERT INTO investigations (id, title, status, input_types, created_at) VALUES (?, ?, 'queued', ?, ?)`,
    );
    const insertInput = this.db.prepare(
      `INSERT INTO inputs (investigation_id, type, value, length, sha256, retained) VALUES (?, ?, ?, ?, ?, ?)`,
    );
    this.db.transaction(() => {
      insertInv.run(args.id, args.title, JSON.stringify(args.inputTypes), args.createdAt);
      for (const i of args.inputs) {
        insertInput.run(args.id, i.type, i.value, i.length, i.sha256, i.retained ? 1 : 0);
      }
    })();
  }

  setStatus(id: string, status: InvestigationStatus): void {
    this.db.prepare('UPDATE investigations SET status = ? WHERE id = ?').run(status, id);
  }

  addTimelineEvent(
    investigationId: string,
    e: { timestamp: string; stage: string; label: string; status: TimelineStatus; detail?: string | null },
  ): TimelineEvent {
    const info = this.db
      .prepare(
        'INSERT INTO timeline_events (investigation_id, timestamp, stage, label, status, detail) VALUES (?, ?, ?, ?, ?, ?)',
      )
      .run(investigationId, e.timestamp, e.stage, e.label, e.status, e.detail ?? null);
    return { id: Number(info.lastInsertRowid), ...e, detail: e.detail ?? null };
  }

  saveResults(id: string, r: SaveResultsArgs): void {
    const db = this.db;
    const insInd = db.prepare(
      `INSERT INTO indicators (id, investigation_id, code, category, title, description, severity, confidence, polarity,
        evidence, source, provenance, analyzer, subject, timestamp)
       VALUES (@id, @investigation_id, @code, @category, @title, @description, @severity, @confidence, @polarity,
        @evidence, @source, @provenance, @analyzer, @subject, @timestamp)`,
    );
    const insEvidence = db.prepare(
      'INSERT INTO evidence (investigation_id, kind, subject, provenance, data_json, collected_at) VALUES (?, ?, ?, ?, ?, ?)',
    );
    const insDns = db.prepare(
      'INSERT INTO dns_records (investigation_id, name, type, value, status, queried_at) VALUES (?, ?, ?, ?, ?, ?)',
    );
    const insTls = db.prepare(
      `INSERT INTO tls_certificates (investigation_id, host, port, status, subject_cn, issuer_cn, issuer_org, valid_from,
        valid_to, sans_json, fingerprint256, serial_number, authorized, authorization_error, hostname_matches, inspected_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insRedirect = db.prepare(
      `INSERT INTO redirects (investigation_id, chain_index, start_url, hop_index, url, hostname, scheme, status_code,
        location, kind, remote_address, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insEmail = db.prepare(
      `INSERT INTO email_headers (investigation_id, from_address, from_display, reply_to, return_path, subject, date,
        message_id, spf, dkim, dmarc, dmarc_policy, received_count, auth_results_json, received_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const b = (v: boolean | undefined | null) => (v === undefined || v === null ? null : v ? 1 : 0);

    db.transaction(() => {
      for (const ind of r.indicators) {
        insInd.run({ ...ind, investigation_id: id, subject: ind.subject ?? null });
      }

      const a = r.artifacts;
      const ev = (kind: string, subject: string | null, provenance: string, data: unknown, at: string) =>
        insEvidence.run(id, kind, subject, provenance, JSON.stringify(data), at);

      for (const u of a.urls) ev('url', u.input, u.origin === 'input' ? 'user_input' : 'analysis', u, r.completedAt);
      for (const d of a.domains) ev('domain', d.hostname, 'analysis', d, r.completedAt);
      for (const d of a.dns) {
        ev('dns', d.name, 'network', d, d.queriedAt);
        for (const set of d.records) {
          if (set.values.length === 0) insDns.run(id, d.name, set.type, null, set.status, d.queriedAt);
          for (const v of set.values) insDns.run(id, d.name, set.type, v, set.status, d.queriedAt);
        }
      }
      for (const t of a.tls) {
        ev('tls', `${t.host}:${t.port}`, 'network', t, t.inspectedAt);
        const c = t.certificate;
        insTls.run(
          id, t.host, t.port, t.status, c?.subjectCN ?? null, c?.issuerCN ?? null, c?.issuerOrg ?? null,
          c?.validFrom ?? null, c?.validTo ?? null, c ? JSON.stringify(c.sans) : null, c?.fingerprint256 ?? null,
          c?.serialNumber ?? null, b(t.authorized), t.authorizationError ?? null, b(t.hostnameMatches), t.inspectedAt,
        );
      }
      a.redirects.forEach((chain, ci) => {
        ev('redirect', chain.startUrl, 'network', chain, chain.inspectedAt);
        for (const h of chain.hops) {
          insRedirect.run(
            id, ci, chain.startUrl, h.index, h.url, h.hostname, h.scheme, h.statusCode ?? null, h.location ?? null,
            h.kind, h.remoteAddress ?? null, h.error ?? null,
          );
        }
      });
      for (const d of a.rdap) ev('rdap', d.domain, 'external', d, d.queriedAt);
      for (const o of a.reputation ?? []) ev('reputation', `${o.provider}:${o.subject}`, 'external', o, o.fetchedAt);
      if (a.email) {
        const e = a.email;
        ev('email', e.from?.address ?? null, 'user_input', e, r.completedAt);
        insEmail.run(
          id, e.from?.address ?? null, e.from?.displayName ?? null,
          e.replyTo.map((x) => x.address ?? x.raw).join(', ') || null, e.returnPath?.address ?? null,
          e.subject, e.date, e.messageId, e.summary.spf, e.summary.dkim, e.summary.dmarc, e.summary.dmarcPolicy,
          e.received.length, JSON.stringify(e.authenticationResults), JSON.stringify(e.received),
        );
      }
      if (a.emailAddress) ev('email_address', a.emailAddress.address.address, 'user_input', a.emailAddress, r.completedAt);
      if (a.message) ev('message', null, 'user_input', a.message, r.completedAt);

      db.prepare(
        `UPDATE investigations SET status = 'completed', verdict = ?, score = ?, indicator_count = ?,
          risk_indicator_count = ?, assessment_json = ?, graph_json = ?, analyzer_runs_json = ?, completed_at = ?
         WHERE id = ?`,
      ).run(
        r.assessment.verdict,
        r.assessment.score,
        r.indicators.length,
        r.indicators.filter((i) => i.polarity === 'risk').length,
        JSON.stringify(r.assessment),
        JSON.stringify(r.graph),
        JSON.stringify(r.analyzerRuns),
        r.completedAt,
        id,
      );
    })();
  }

  markFailed(id: string, error: string, analyzerRuns: AnalyzerRun[] = []): void {
    this.db
      .prepare(
        `UPDATE investigations SET status = 'failed', error = ?, analyzer_runs_json = ?, completed_at = ? WHERE id = ?`,
      )
      .run(error, JSON.stringify(analyzerRuns), new Date().toISOString(), id);
  }

  /** Investigations interrupted by a restart cannot be resumed (raw input is not persisted by default). */
  failInterrupted(): number {
    return this.db
      .prepare(
        `UPDATE investigations SET status = 'failed', error = 'Interrupted by server restart before completion', completed_at = ?
         WHERE status IN ('queued','running')`,
      )
      .run(new Date().toISOString()).changes;
  }

  list(f: ListFilters = {}): { items: InvestigationSummary[]; total: number } {
    const where: string[] = [];
    const params: unknown[] = [];
    if (f.verdict) {
      where.push('verdict = ?');
      params.push(f.verdict);
    }
    if (f.status) {
      where.push('status = ?');
      params.push(f.status);
    }
    if (f.q) {
      where.push(`(title LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\')`);
      const like = `%${f.q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
      params.push(like, like);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = (this.db.prepare(`SELECT COUNT(*) AS n FROM investigations ${clause}`).get(...params) as { n: number }).n;
    const rows = this.db
      .prepare(`SELECT * FROM investigations ${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .all(...params, f.limit ?? 50, f.offset ?? 0) as InvestigationRow[];
    return { items: rows.map(toSummary), total };
  }

  getRow(id: string): InvestigationRow | undefined {
    return this.db.prepare('SELECT * FROM investigations WHERE id = ?').get(id) as InvestigationRow | undefined;
  }

  getTimeline(id: string): TimelineEvent[] {
    return this.db
      .prepare('SELECT id, timestamp, stage, label, status, detail FROM timeline_events WHERE investigation_id = ? ORDER BY id')
      .all(id) as TimelineEvent[];
  }

  getDetail(id: string): InvestigationDetail | null {
    const row = this.getRow(id);
    if (!row) return null;

    const inputs = (
      this.db.prepare('SELECT type, value, length, sha256, retained FROM inputs WHERE investigation_id = ? ORDER BY id').all(id) as {
        type: InputType;
        value: string | null;
        length: number;
        sha256: string;
        retained: number;
      }[]
    ).map((i) => ({ ...i, retained: i.retained === 1 }));

    const indicators = (
      this.db.prepare('SELECT * FROM indicators WHERE investigation_id = ?').all(id) as (Indicator & {
        investigation_id?: string;
        subject: string | null;
      })[]
    ).map(({ investigation_id: _drop, subject, ...rest }) => ({ ...rest, ...(subject ? { subject } : {}) }) as Indicator);

    const evidenceRows = this.db
      .prepare('SELECT kind, data_json FROM evidence WHERE investigation_id = ? ORDER BY id')
      .all(id) as { kind: string; data_json: string }[];
    let artifacts: InvestigationArtifacts | null = null;
    if (row.status === 'completed') {
      artifacts = { urls: [], domains: [], dns: [], tls: [], redirects: [], rdap: [], email: null, emailAddress: null, message: null, reputation: [] };
      for (const e of evidenceRows) {
        const data = parseJson<unknown>(e.data_json, null);
        if (data === null) continue;
        switch (e.kind) {
          case 'url': artifacts.urls.push(data as never); break;
          case 'domain': artifacts.domains.push(data as never); break;
          case 'dns': artifacts.dns.push(data as never); break;
          case 'tls': artifacts.tls.push(data as never); break;
          case 'redirect': artifacts.redirects.push(data as never); break;
          case 'rdap': artifacts.rdap.push(data as never); break;
          case 'reputation': artifacts.reputation!.push(data as never); break;
          case 'email': artifacts.email = data as never; break;
          case 'email_address': artifacts.emailAddress = data as never; break;
          case 'message': artifacts.message = data as never; break;
        }
      }
    }

    return {
      ...toSummary(row),
      inputs,
      indicators,
      assessment: parseJson<RiskAssessment | null>(row.assessment_json, null),
      artifacts,
      graph: parseJson<EvidenceGraph | null>(row.graph_json, null),
      timeline: this.getTimeline(id),
      analyzerRuns: parseJson<AnalyzerRun[]>(row.analyzer_runs_json, []),
      error: row.error,
    };
  }

  deleteInvestigation(id: string): boolean {
    return this.db.prepare('DELETE FROM investigations WHERE id = ?').run(id).changes > 0;
  }

  purgeOlderThan(days: number, now = new Date()): number {
    if (days <= 0) return 0;
    const cutoff = new Date(now.getTime() - days * 86_400_000).toISOString();
    return this.db.prepare(`DELETE FROM investigations WHERE created_at < ? AND status NOT IN ('queued','running')`).run(cutoff)
      .changes;
  }

  saveAiSummary(id: string, summary: AiSummary): void {
    this.db.prepare('UPDATE investigations SET ai_summary_json = ? WHERE id = ?').run(JSON.stringify(summary), id);
  }

  getAiSummary(id: string): AiSummary | null {
    const row = this.db.prepare('SELECT ai_summary_json FROM investigations WHERE id = ?').get(id) as
      | { ai_summary_json: string | null }
      | undefined;
    return parseJson<AiSummary | null>(row?.ai_summary_json ?? null, null);
  }

  dashboard(now = new Date()): DashboardStats {
    const db = this.db;
    const counts = db
      .prepare(
        `SELECT
           COUNT(*) AS total,
           SUM(verdict = 'suspicious') AS suspicious,
           SUM(verdict = 'high_risk') AS highRisk,
           SUM(verdict = 'benign') AS benign,
           SUM(verdict = 'inconclusive') AS inconclusive,
           SUM(status IN ('queued','running')) AS running
         FROM investigations`,
      )
      .get() as Record<string, number | null>;
    const weekAgo = new Date(now.getTime() - 7 * 86_400_000).toISOString();
    const thisWeek = (db.prepare('SELECT COUNT(*) AS n FROM investigations WHERE created_at >= ?').get(weekAgo) as { n: number }).n;

    const recent = (db.prepare('SELECT * FROM investigations ORDER BY created_at DESC LIMIT 8').all() as InvestigationRow[]).map(
      toSummary,
    );

    const common = db
      .prepare(
        `SELECT code, title, category, COUNT(DISTINCT investigation_id) AS count,
           MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS sev
         FROM indicators WHERE polarity = 'risk'
         GROUP BY code ORDER BY count DESC, sev DESC LIMIT 10`,
      )
      .all() as { code: string; title: string; category: string; count: number; sev: number }[];
    const rankToSeverity = (n: number) =>
      (Object.entries(SEVERITY_RANK).find(([, r]) => r === n)?.[0] ?? 'info') as Severity;

    const latest = db
      .prepare(
        `SELECT i.investigation_id AS investigationId, v.title AS investigationTitle, i.title, i.severity, i.category, i.timestamp
         FROM indicators i JOIN investigations v ON v.id = i.investigation_id
         WHERE i.polarity = 'risk' AND i.severity IN ('medium','high','critical')
         ORDER BY i.timestamp DESC LIMIT 10`,
      )
      .all() as DashboardStats['latestPatterns'];

    const since = new Date(now.getTime() - 13 * 86_400_000);
    since.setUTCHours(0, 0, 0, 0);
    const byDay = db
      .prepare(
        `SELECT substr(created_at, 1, 10) AS day, verdict, COUNT(*) AS n FROM investigations
         WHERE created_at >= ? AND verdict IS NOT NULL GROUP BY day, verdict`,
      )
      .all(since.toISOString()) as { day: string; verdict: Verdict; n: number }[];
    const verdictByDay: DashboardStats['verdictByDay'] = [];
    for (let d = 0; d < 14; d++) {
      const day = new Date(since.getTime() + d * 86_400_000).toISOString().slice(0, 10);
      const entry = { day, benign: 0, suspicious: 0, high_risk: 0, inconclusive: 0 };
      for (const r of byDay) if (r.day === day) entry[r.verdict] = r.n;
      verdictByDay.push(entry);
    }

    return {
      totals: {
        total: counts.total ?? 0,
        suspicious: counts.suspicious ?? 0,
        highRisk: counts.highRisk ?? 0,
        benign: counts.benign ?? 0,
        inconclusive: counts.inconclusive ?? 0,
        running: counts.running ?? 0,
      },
      thisWeek,
      recent,
      commonIndicators: common.map((c) => ({
        code: c.code,
        title: c.title,
        category: c.category as DashboardStats['commonIndicators'][number]['category'],
        count: c.count,
        maxSeverity: rankToSeverity(c.sev),
      })),
      latestPatterns: latest,
      verdictByDay,
    };
  }

  /** Other investigations that observed the same indicator value (domain, IP, certificate). */
  related(id: string): { id: string; title: string; verdict: Verdict | null; shared: string }[] {
    return this.db
      .prepare(
        `SELECT DISTINCT v.id, v.title, v.verdict, d2.value AS shared
         FROM dns_records d1
         JOIN dns_records d2 ON d2.value = d1.value AND d2.type IN ('A','AAAA') AND d2.investigation_id != d1.investigation_id
         JOIN investigations v ON v.id = d2.investigation_id
         WHERE d1.investigation_id = ? AND d1.type IN ('A','AAAA') AND d1.value IS NOT NULL
         UNION
         SELECT DISTINCT v.id, v.title, v.verdict, 'certificate ' || substr(t2.fingerprint256, 1, 23) AS shared
         FROM tls_certificates t1
         JOIN tls_certificates t2 ON t2.fingerprint256 = t1.fingerprint256 AND t2.investigation_id != t1.investigation_id
         JOIN investigations v ON v.id = t2.investigation_id
         WHERE t1.investigation_id = ? AND t1.fingerprint256 IS NOT NULL
         LIMIT 25`,
      )
      .all(id, id) as { id: string; title: string; verdict: Verdict | null; shared: string }[];
  }

  // -- operator verifications -------------------------------------------------

  listVerifications(opts: { includeRevoked?: boolean } = {}): OperatorVerification[] {
    const rows = this.db
      .prepare(`SELECT * FROM operator_verifications ${opts.includeRevoked ? '' : 'WHERE revoked_at IS NULL'} ORDER BY domain, verified_at DESC`)
      .all() as Record<string, string | number | null>[];
    return rows.map((r) => ({
      id: Number(r.id),
      domain: String(r.domain),
      operatorName: String(r.operator_name),
      method: r.method as OperatorVerification['method'],
      evidenceReference: String(r.evidence_reference),
      verifiedBy: String(r.verified_by),
      verifiedAt: String(r.verified_at),
      expiresAt: String(r.expires_at),
      revokedAt: (r.revoked_at as string | null) ?? null,
      notes: (r.notes as string | null) ?? null,
    }));
  }

  addVerification(v: Omit<OperatorVerification, 'id' | 'revokedAt'>): OperatorVerification {
    const info = this.db
      .prepare(
        `INSERT INTO operator_verifications (domain, operator_name, method, evidence_reference, verified_by, verified_at, expires_at, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(v.domain, v.operatorName, v.method, v.evidenceReference, v.verifiedBy, v.verifiedAt, v.expiresAt, v.notes);
    return { id: Number(info.lastInsertRowid), ...v, revokedAt: null };
  }

  /** Verifications are revoked, never deleted, so past investigations stay explainable. */
  revokeVerification(id: number): boolean {
    return this.db.prepare('UPDATE operator_verifications SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(new Date().toISOString(), id).changes > 0;
  }

  // -- reputation cache -------------------------------------------------------

  reputationCache() {
    const get = this.db.prepare('SELECT result_json, fetched_at FROM reputation_cache WHERE provider = ? AND subject = ?');
    const set = this.db.prepare('INSERT OR REPLACE INTO reputation_cache (provider, subject, result_json, fetched_at) VALUES (?, ?, ?, ?)');
    return {
      get: (provider: string, subject: string) => {
        const r = get.get(provider, subject) as { result_json: string; fetched_at: string } | undefined;
        return r ? { result: parseJson(r.result_json, null as never), fetchedAt: r.fetched_at } : null;
      },
      set: (provider: string, subject: string, result: unknown, fetchedAt: string) => void set.run(provider, subject, JSON.stringify(result), fetchedAt),
    };
  }

  purgeReputationCache(olderThanDays: number, now = new Date()): number {
    const cutoff = new Date(now.getTime() - olderThanDays * 86_400_000).toISOString();
    return this.db.prepare('DELETE FROM reputation_cache WHERE fetched_at < ?').run(cutoff).changes;
  }

  // -- brands -----------------------------------------------------------------

  listBrands(): Brand[] {
    return (
      this.db.prepare('SELECT * FROM brands ORDER BY name').all() as {
        id: number;
        name: string;
        keywords_json: string;
        official_domains_json: string;
        created_at: string;
      }[]
    ).map((r) => ({
      id: r.id,
      name: r.name,
      keywords: parseJson<string[]>(r.keywords_json, []),
      officialDomains: parseJson<string[]>(r.official_domains_json, []),
      createdAt: r.created_at,
    }));
  }

  addBrand(b: { name: string; keywords: string[]; officialDomains: string[] }): Brand {
    const createdAt = new Date().toISOString();
    const info = this.db
      .prepare('INSERT INTO brands (name, keywords_json, official_domains_json, created_at) VALUES (?, ?, ?, ?)')
      .run(b.name, JSON.stringify(b.keywords), JSON.stringify(b.officialDomains), createdAt);
    return { id: Number(info.lastInsertRowid), ...b, createdAt };
  }

  deleteBrand(id: number): boolean {
    return this.db.prepare('DELETE FROM brands WHERE id = ?').run(id).changes > 0;
  }

  brandCount(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM brands').get() as { n: number }).n;
  }
}
