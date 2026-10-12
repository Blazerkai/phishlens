/**
 * Ordered, append-only schema migrations.
 * Never edit a migration that has shipped — add a new one.
 */
export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const migrations: Migration[] = [
  {
    version: 1,
    name: 'initial_schema',
    sql: /* sql */ `
      CREATE TABLE investigations (
        id                   TEXT PRIMARY KEY,
        title                TEXT NOT NULL,
        status               TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
        verdict              TEXT CHECK (verdict IN ('benign','suspicious','high_risk','inconclusive')),
        score                REAL,
        indicator_count      INTEGER NOT NULL DEFAULT 0,
        risk_indicator_count INTEGER NOT NULL DEFAULT 0,
        input_types          TEXT NOT NULL,
        assessment_json      TEXT,
        graph_json           TEXT,
        analyzer_runs_json   TEXT,
        ai_summary_json      TEXT,
        error                TEXT,
        created_at           TEXT NOT NULL,
        completed_at         TEXT
      );
      CREATE INDEX idx_investigations_created ON investigations (created_at DESC);
      CREATE INDEX idx_investigations_verdict ON investigations (verdict);

      CREATE TABLE inputs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        type             TEXT NOT NULL CHECK (type IN ('url','domain','email','headers','message')),
        value            TEXT,
        length           INTEGER NOT NULL,
        sha256           TEXT NOT NULL,
        retained         INTEGER NOT NULL CHECK (retained IN (0,1))
      );
      CREATE INDEX idx_inputs_investigation ON inputs (investigation_id);

      CREATE TABLE indicators (
        id               TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        code             TEXT NOT NULL,
        category         TEXT NOT NULL,
        title            TEXT NOT NULL,
        description      TEXT NOT NULL,
        severity         TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
        confidence       REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
        polarity         TEXT NOT NULL CHECK (polarity IN ('risk','benign','neutral')),
        evidence         TEXT NOT NULL,
        source           TEXT NOT NULL,
        provenance       TEXT NOT NULL CHECK (provenance IN ('user_input','network','analysis','external')),
        analyzer         TEXT NOT NULL,
        subject          TEXT,
        timestamp        TEXT NOT NULL
      );
      CREATE INDEX idx_indicators_investigation ON indicators (investigation_id);
      CREATE INDEX idx_indicators_code ON indicators (code);

      CREATE TABLE evidence (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        kind             TEXT NOT NULL,
        subject          TEXT,
        provenance       TEXT NOT NULL,
        data_json        TEXT NOT NULL,
        collected_at     TEXT NOT NULL
      );
      CREATE INDEX idx_evidence_investigation ON evidence (investigation_id);

      CREATE TABLE dns_records (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        name             TEXT NOT NULL,
        type             TEXT NOT NULL,
        value            TEXT,
        status           TEXT NOT NULL,
        queried_at       TEXT NOT NULL
      );
      CREATE INDEX idx_dns_investigation ON dns_records (investigation_id);
      CREATE INDEX idx_dns_value ON dns_records (value);

      CREATE TABLE tls_certificates (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id    TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        host                TEXT NOT NULL,
        port                INTEGER NOT NULL,
        status              TEXT NOT NULL,
        subject_cn          TEXT,
        issuer_cn           TEXT,
        issuer_org          TEXT,
        valid_from          TEXT,
        valid_to            TEXT,
        sans_json           TEXT,
        fingerprint256      TEXT,
        serial_number       TEXT,
        authorized          INTEGER,
        authorization_error TEXT,
        hostname_matches    INTEGER,
        inspected_at        TEXT NOT NULL
      );
      CREATE INDEX idx_tls_investigation ON tls_certificates (investigation_id);
      CREATE INDEX idx_tls_fingerprint ON tls_certificates (fingerprint256);

      CREATE TABLE redirects (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        chain_index      INTEGER NOT NULL,
        start_url        TEXT NOT NULL,
        hop_index        INTEGER NOT NULL,
        url              TEXT NOT NULL,
        hostname         TEXT,
        scheme           TEXT,
        status_code      INTEGER,
        location         TEXT,
        kind             TEXT NOT NULL,
        remote_address   TEXT,
        error            TEXT
      );
      CREATE INDEX idx_redirects_investigation ON redirects (investigation_id);

      CREATE TABLE email_headers (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id  TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        from_address      TEXT,
        from_display      TEXT,
        reply_to          TEXT,
        return_path       TEXT,
        subject           TEXT,
        date              TEXT,
        message_id        TEXT,
        spf               TEXT,
        dkim              TEXT,
        dmarc             TEXT,
        dmarc_policy      TEXT,
        received_count    INTEGER NOT NULL,
        auth_results_json TEXT,
        received_json     TEXT
      );
      CREATE INDEX idx_email_headers_investigation ON email_headers (investigation_id);

      CREATE TABLE timeline_events (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        timestamp        TEXT NOT NULL,
        stage            TEXT NOT NULL,
        label            TEXT NOT NULL,
        status           TEXT NOT NULL,
        detail           TEXT
      );
      CREATE INDEX idx_timeline_investigation ON timeline_events (investigation_id, id);

      CREATE TABLE brands (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        name                  TEXT NOT NULL UNIQUE COLLATE NOCASE,
        keywords_json         TEXT NOT NULL,
        official_domains_json TEXT NOT NULL,
        created_at            TEXT NOT NULL
      );
    `,
  },
  {
    version: 2,
    name: 'indicator_polarity_unknown',
    // SQLite cannot alter a CHECK constraint in place: rebuild the table.
    sql: /* sql */ `
      CREATE TABLE indicators_v2 (
        id               TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations (id) ON DELETE CASCADE,
        code             TEXT NOT NULL,
        category         TEXT NOT NULL,
        title            TEXT NOT NULL,
        description      TEXT NOT NULL,
        severity         TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
        confidence       REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
        polarity         TEXT NOT NULL CHECK (polarity IN ('risk','benign','neutral','unknown')),
        evidence         TEXT NOT NULL,
        source           TEXT NOT NULL,
        provenance       TEXT NOT NULL CHECK (provenance IN ('user_input','network','analysis','external')),
        analyzer         TEXT NOT NULL,
        subject          TEXT,
        timestamp        TEXT NOT NULL
      );
      INSERT INTO indicators_v2 SELECT id, investigation_id, code, category, title, description, severity, confidence,
        polarity, evidence, source, provenance, analyzer, subject, timestamp FROM indicators;
      DROP TABLE indicators;
      ALTER TABLE indicators_v2 RENAME TO indicators;
      CREATE INDEX idx_indicators_investigation ON indicators (investigation_id);
      CREATE INDEX idx_indicators_code ON indicators (code);
    `,
  },
  {
    version: 3,
    name: 'reputation_cache_and_operator_verifications',
    sql: /* sql */ `
      CREATE TABLE reputation_cache (
        provider    TEXT NOT NULL,
        subject     TEXT NOT NULL,
        result_json TEXT NOT NULL,
        fetched_at  TEXT NOT NULL,
        PRIMARY KEY (provider, subject)
      );

      CREATE TABLE operator_verifications (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        domain             TEXT NOT NULL,
        operator_name      TEXT NOT NULL,
        method             TEXT NOT NULL CHECK (method IN ('legal_entity_registry','direct_contact','contractual_relationship','official_publication','other')),
        evidence_reference TEXT NOT NULL CHECK (length(evidence_reference) >= 8),
        verified_by        TEXT NOT NULL,
        verified_at        TEXT NOT NULL,
        expires_at         TEXT NOT NULL,
        revoked_at         TEXT,
        notes              TEXT
      );
      CREATE INDEX idx_operator_verifications_domain ON operator_verifications (domain);
    `,
  },
];
