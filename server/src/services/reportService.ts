import type { Indicator, InvestigationDetail, Severity, Verdict } from '@phishlens/shared';

const VERDICT_LABEL: Record<Verdict, string> = { benign: 'BENIGN', suspicious: 'SUSPICIOUS', high_risk: 'HIGH RISK', inconclusive: 'INCONCLUSIVE' };
const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const POLARITY_TEXT: Record<Indicator['polarity'], string> = {
  risk: 'negative (raises concern)',
  benign: 'positive (verified)',
  neutral: 'neutral (context only)',
  unknown: 'unknown (check could not be completed)',
};

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Escapes characters that would change Markdown structure inside table cells and inline text. */
export function escapeMd(value: unknown): string {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/([|*_`[\]<>#])/g, '\\$1')
    .replace(/\r?\n/g, ' ');
}

function sortIndicators(list: Indicator[]): Indicator[] {
  return [...list].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.confidence - a.confidence);
}

function inputLines(d: InvestigationDetail): { label: string; value: string }[] {
  return d.inputs.map((i) => ({
    label: i.type,
    value: i.value !== null ? (i.value.length > 300 ? `${i.value.slice(0, 300)}… (${i.length} chars)` : i.value) : `[not retained] ${i.length} characters, SHA-256 ${i.sha256}`,
  }));
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

export function renderMarkdown(d: InvestigationDetail, generatedAt = new Date()): string {
  const a = d.assessment;
  const art = d.artifacts;
  const L: string[] = [];
  const h = (s: string) => L.push('', s, '');

  L.push(`# PhishLens Investigation Report`);
  L.push('');
  L.push(`| Field | Value |`, `|---|---|`);
  L.push(`| Investigation ID | \`${d.id}\` |`);
  L.push(`| Title | ${escapeMd(d.title)} |`);
  L.push(`| Created | ${d.createdAt} |`);
  L.push(`| Completed | ${d.completedAt ?? '—'} |`);
  L.push(`| Status | ${d.status} |`);
  L.push(`| Report generated | ${generatedAt.toISOString()} |`);

  h('## Input');
  for (const i of inputLines(d)) L.push(`- **${i.label}**: ${escapeMd(i.value)}`);

  if (a) {
    h('## Executive summary');
    L.push(`**Verdict: ${VERDICT_LABEL[a.verdict]}** — Risk assessment score ${a.score}/100 (heuristic; not a probability).`);
    L.push('');
    L.push(escapeMd(a.summary));
    h('## Risk assessment');
    L.push('**Why:**');
    for (const r of a.rationale) L.push(`- ${escapeMd(r)}`);
    if (a.contributions.length) {
      L.push('', '| Contribution | Severity | Confidence | Points |', '|---|---|---|---|');
      for (const c of a.contributions.slice(0, 15)) L.push(`| ${escapeMd(c.title)} | ${c.severity} | ${c.confidence} | ${c.points} |`);
    }
    if (a.positiveEvidence) {
      L.push('', '**Positive evidence (independent families):**');
      if (!a.positiveEvidence.length) L.push('- None verified. Absence of risk findings is not treated as evidence of legitimacy.');
      for (const f of a.positiveEvidence) {
        L.push(`- **${escapeMd(f.label)}** (${f.class === 'corroboration' ? 'corroboration' : 'security control'}; ${f.counted ? 'counted once' : 'not counted'}) — ${escapeMd(f.reason)}`);
        for (const t of f.titles) L.push(`  - ${escapeMd(t)}`);
      }
    } else if (a.benignSignals.length) {
      L.push('', '**Benign signals:**');
      for (const b of a.benignSignals) L.push(`- ${escapeMd(b.title)}`);
    }
    if (a.conflicts?.length) {
      L.push('', '**Conflicting evidence:**');
      for (const c of a.conflicts) L.push(`- ${escapeMd(c)}`);
    }
    if (a.nextSteps?.length) {
      L.push('', '**To resolve this result:**');
      for (const n of a.nextSteps) L.push(`- ${escapeMd(n)}`);
    }
    L.push('', `_Method:_ ${escapeMd(a.method)}`);
  }

  h('## Indicators');
  if (d.indicators.length === 0) L.push('No indicators were recorded.');
  for (const i of sortIndicators(d.indicators)) {
    L.push(`### [${i.severity.toUpperCase()}] ${escapeMd(i.title)}`);
    L.push(`- **Category:** ${i.category} · **Rule:** \`${i.code}\` · **Assessment:** ${POLARITY_TEXT[i.polarity]} · **Rule confidence:** ${i.confidence}`);
    L.push(`- **Reason:** ${escapeMd(i.description)}`);
    L.push(`- **Evidence:** ${escapeMd(i.evidence)}`);
    L.push(`- **Source:** ${escapeMd(i.source)} (${i.provenance}) · ${i.timestamp}`);
    L.push('');
  }

  if (art) {
    h('## Technical evidence');
    if (art.urls.length) {
      L.push('### URLs', '', '| URL | Origin | Host | Registrable domain |', '|---|---|---|---|');
      for (const u of art.urls) L.push(`| ${escapeMd(u.normalized ?? u.input)} | ${u.origin} | ${escapeMd(u.hostnameUnicode ?? u.hostname ?? '')} | ${escapeMd(u.registrableDomain ?? '')} |`);
    }
    h('### DNS information');
    if (!art.dns.length) L.push('No DNS records were collected (see limitations).');
    for (const dn of art.dns) {
      L.push(`**${escapeMd(dn.name)}** — ${escapeMd(dn.resolver)} at ${dn.queriedAt}`);
      L.push('', '| Type | Status | Values |', '|---|---|---|');
      for (const r of dn.records) L.push(`| ${r.type} | ${r.status} | ${escapeMd(r.values.join(', ') || r.error || '')} |`);
      if (dn.providers.length) L.push('', `Providers: ${dn.providers.map((p) => `${escapeMd(p.name)} (${p.role})`).join(', ')}`);
      L.push('');
    }
    h('### TLS information');
    if (!art.tls.length) L.push('No TLS endpoints were inspected.');
    for (const t of art.tls) {
      if (!t.certificate) {
        L.push(`- ${escapeMd(t.host)}:${t.port} — ${t.status}: ${escapeMd(t.reason ?? '')}`);
        continue;
      }
      const c = t.certificate;
      L.push(`**${escapeMd(t.host)}:${t.port}** (${escapeMd(t.remoteAddress ?? '')}, ${t.protocol ?? ''})`);
      L.push(`- Subject: ${escapeMd(c.subjectCN ?? '—')} · Issuer: ${escapeMd(c.issuerOrg ?? c.issuerCN ?? '—')}`);
      L.push(`- Valid ${c.validFrom} → ${c.validTo} (${c.daysRemaining} days remaining)`);
      L.push(`- Trusted chain: ${t.authorized ? 'yes' : `no (${escapeMd(t.authorizationError ?? '')})`} · Hostname match: ${t.hostnameMatches ? 'yes' : 'no'}`);
      L.push(`- SANs: ${escapeMd(c.sans.slice(0, 20).join(', '))}${c.sans.length > 20 ? ` (+${c.sans.length - 20})` : ''}`);
      L.push(`- SHA-256: \`${c.fingerprint256}\``);
      L.push('');
    }
    h('### Redirect chain');
    if (!art.redirects.length) L.push('No redirect chains were inspected.');
    for (const r of art.redirects) {
      L.push(`Start: ${escapeMd(r.startUrl)} — ${r.redirectCount} redirect(s)${r.reason ? `; ${escapeMd(r.reason)}` : ''}`);
      L.push('', '| # | Status | Host | Scheme | Location / result |', '|---|---|---|---|---|');
      for (const hop of r.hops) L.push(`| ${hop.index} | ${hop.statusCode ?? hop.kind} | ${escapeMd(hop.hostname)} | ${hop.scheme} | ${escapeMd(hop.location ?? hop.error ?? (hop.kind === 'final' ? 'final destination' : ''))} |`);
      if (r.page) L.push('', `Final page: title "${escapeMd(r.page.title ?? '')}", password field: ${r.page.hasPasswordField ? 'yes' : 'no'}, form actions: ${escapeMd(r.page.formActions.join(', ') || 'none')}`);
      L.push('');
    }
    h('### Reputation');
    if (!art.reputation?.length) L.push('Reputation was not checked (no provider configured or queried). This is not a clean result.');
    else {
      L.push('| Provider | Subject | Result | Detail | Fetched |', '|---|---|---|---|---|');
      for (const o of art.reputation) L.push(`| ${escapeMd(o.providerName)} | ${escapeMd(o.subject)} | ${o.status} | ${escapeMd(o.summary)} | ${o.fetchedAt}${o.cached ? ' (cached)' : ''} |`);
      L.push('', '_A blocklist not listing a domain is neutral, not evidence of safety. error / unavailable / stale results are unknown._');
    }
    if (art.rdap.length) {
      h('### Domain registration (RDAP)');
      for (const r of art.rdap) L.push(`- ${escapeMd(r.domain)}: ${r.status === 'completed' ? `registered ${r.registered ?? 'unknown'} (${r.ageDays ?? '?'} days), registrar ${escapeMd(r.registrar ?? 'unknown')}` : `${r.status}: ${escapeMd(r.reason ?? '')}`} — source ${escapeMd(r.source)}`);
    }
    h('### Email authentication');
    if (!art.email) L.push('No email headers were submitted.');
    else {
      const e = art.email;
      L.push(`- From: ${escapeMd(e.from?.raw ?? '—')}`);
      L.push(`- Reply-To: ${escapeMd(e.replyTo.map((r) => r.raw).join(', ') || '—')}`);
      L.push(`- Return-Path: ${escapeMd(e.returnPath?.address ?? '—')}`);
      L.push(`- Subject: ${escapeMd(e.subject ?? '—')}`);
      L.push(`- Date: ${escapeMd(e.date ?? '—')} · Message-ID: ${escapeMd(e.messageId ?? '—')}`);
      L.push(`- SPF: **${e.summary.spf}** (${escapeMd(e.summary.spfDomain ?? '—')}, aligned: ${e.summary.spfAligned ?? 'n/a'})`);
      L.push(`- DKIM: **${e.summary.dkim}** (${escapeMd(e.summary.dkimDomains.join(', ') || '—')}, aligned: ${e.summary.dkimAligned ?? 'n/a'})`);
      L.push(`- DMARC: **${e.summary.dmarc}**${e.summary.dmarcPolicy ? ` (policy ${e.summary.dmarcPolicy})` : ''}`);
      L.push('', '**Mail route (oldest first):**', '', '| Hop | From | IP | By | Time |', '|---|---|---|---|---|');
      for (const r of e.received) L.push(`| ${r.index + 1} | ${escapeMd(r.from ?? '')} | ${escapeMd(r.fromIp ?? '')} | ${escapeMd(r.by ?? '')} | ${r.timestamp ?? escapeMd(r.date ?? '')} |`);
    }
  }

  h('## Timeline');
  L.push('| Time (UTC) | Stage | Status | Detail |', '|---|---|---|---|');
  for (const t of d.timeline) L.push(`| ${t.timestamp} | ${escapeMd(t.label)} | ${t.status} | ${escapeMd(t.detail ?? '')} |`);

  h('## Limitations');
  for (const l of a?.limitations ?? ['Assessment not available.']) L.push(`- ${escapeMd(l)}`);
  L.push('', '---', '_Generated by PhishLens. Every finding above is traceable to submitted data, a live network observation made at the stated time, a deterministic analysis rule, or a named external source._');
  return L.join('\n');
}

// ---------------------------------------------------------------------------
// HTML (standalone, printable)
// ---------------------------------------------------------------------------

const SEV_COLOR: Record<Severity, string> = { critical: '#9f1239', high: '#c2410c', medium: '#a16207', low: '#4d7c0f', info: '#475569' };
const VERDICT_COLOR: Record<Verdict, string> = { high_risk: '#9f1239', suspicious: '#c2410c', inconclusive: '#475569', benign: '#15803d' };

export function renderHtml(d: InvestigationDetail, generatedAt = new Date()): string {
  const a = d.assessment;
  const art = d.artifacts;
  const e = escapeHtml;
  const table = (head: string[], rows: string[][]) =>
    `<table><thead><tr>${head.map((x) => `<th>${e(x)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  const sev = (s: Severity) => `<span class="sev" style="color:${SEV_COLOR[s]};border-color:${SEV_COLOR[s]}">${s.toUpperCase()}</span>`;

  const sections: string[] = [];
  sections.push(`<section><h2>Input</h2>${table(['Type', 'Value'], inputLines(d).map((i) => [e(i.label), `<code>${e(i.value)}</code>`]))}</section>`);

  if (a) {
    sections.push(`<section><h2>Executive summary</h2>
      <div class="verdict" style="border-color:${VERDICT_COLOR[a.verdict]}"><div class="v" style="color:${VERDICT_COLOR[a.verdict]}">${VERDICT_LABEL[a.verdict]}</div>
      <div><div class="score">Risk assessment ${a.score}<span>/100</span></div><div class="muted">Heuristic score — not a probability</div></div></div>
      <p>${e(a.summary)}</p></section>`);
    sections.push(`<section><h2>Risk assessment</h2><h3>Why</h3><ul>${a.rationale.map((r) => `<li>${e(r)}</li>`).join('')}</ul>
      ${a.contributions.length ? table(['Contributing indicator', 'Severity', 'Confidence', 'Points'], a.contributions.slice(0, 15).map((c) => [e(c.title), sev(c.severity), e(c.confidence), e(c.points)])) : ''}
      ${
        a.positiveEvidence
          ? `<h3>Positive evidence (independent families)</h3>${
              a.positiveEvidence.length
                ? `<ul>${a.positiveEvidence.map((f) => `<li><strong>${e(f.label)}</strong> <span class="muted">(${f.class === 'corroboration' ? 'corroboration' : 'security control'}; ${f.counted ? 'counted once' : 'not counted'})</span> — ${e(f.reason)}<ul>${f.titles.map((t) => `<li>${e(t)}</li>`).join('')}</ul></li>`).join('')}</ul>`
                : '<p class="muted">None verified. Absence of risk findings is not treated as evidence of legitimacy.</p>'
            }`
          : a.benignSignals.length
            ? `<h3>Benign signals</h3><ul>${a.benignSignals.map((b) => `<li>${e(b.title)}</li>`).join('')}</ul>`
            : ''
      }
      ${a.conflicts?.length ? `<h3>Conflicting evidence</h3><ul>${a.conflicts.map((c) => `<li>${e(c)}</li>`).join('')}</ul>` : ''}
      ${a.nextSteps?.length ? `<h3>To resolve this result</h3><ul>${a.nextSteps.map((n) => `<li>${e(n)}</li>`).join('')}</ul>` : ''}
      <p class="muted"><strong>Method.</strong> ${e(a.method)}</p></section>`);
  }

  sections.push(`<section><h2>Indicators (${d.indicators.length})</h2>${sortIndicators(d.indicators)
    .map(
      (i) => `<div class="ind"><div class="ind-h">${sev(i.severity)} <strong>${e(i.title)}</strong> <span class="muted">${e(i.category)} · ${e(i.code)} · rule confidence ${e(i.confidence)} · ${e(POLARITY_TEXT[i.polarity])}</span></div>
      <div class="kv"><span>Reason</span><div>${e(i.description)}</div><span>Evidence</span><div><code>${e(i.evidence)}</code></div><span>Source</span><div>${e(i.source)} (${e(i.provenance)}) · ${e(i.timestamp)}</div></div></div>`,
    )
    .join('')}</section>`);

  if (art) {
    sections.push(`<section><h2>DNS information</h2>${
      art.dns.length
        ? art.dns
            .map((dn) => `<h3>${e(dn.name)}</h3><p class="muted">${e(dn.resolver)} · ${e(dn.queriedAt)}${dn.providers.length ? ` · ${dn.providers.map((p) => e(`${p.name} (${p.role})`)).join(', ')}` : ''}</p>${table(['Type', 'Status', 'Values'], dn.records.map((r) => [e(r.type), e(r.status), `<code>${e(r.values.join('\n') || r.error || '')}</code>`]))}`)
            .join('')
        : '<p class="muted">No DNS records were collected (see limitations).</p>'
    }</section>`);
    sections.push(`<section><h2>TLS information</h2>${
      art.tls.length
        ? art.tls
            .map((t) =>
              t.certificate
                ? `<h3>${e(t.host)}:${t.port}</h3>${table(['Field', 'Value'], [
                    ['Subject CN', e(t.certificate.subjectCN ?? '—')],
                    ['Issuer', e(t.certificate.issuerOrg ?? t.certificate.issuerCN ?? '—')],
                    ['Validity', `${e(t.certificate.validFrom)} → ${e(t.certificate.validTo)} (${t.certificate.daysRemaining} days remaining)`],
                    ['Trusted chain', t.authorized ? 'yes' : `no — ${e(t.authorizationError ?? '')}`],
                    ['Hostname match', t.hostnameMatches ? 'yes' : `no — ${e(t.hostnameMismatchReason ?? '')}`],
                    ['SANs', `<code>${e(t.certificate.sans.slice(0, 30).join(', '))}</code>`],
                    ['Chain', e((t.chain ?? []).map((c) => c.subjectCN).join(' → ') || '—')],
                    ['SHA-256', `<code>${e(t.certificate.fingerprint256)}</code>`],
                    ['Connection', e(`${t.remoteAddress ?? ''} ${t.protocol ?? ''} ${t.cipher ?? ''}`)],
                  ])}`
                : `<p>${e(t.host)}:${t.port} — ${e(t.status)}: ${e(t.reason ?? '')}</p>`,
            )
            .join('')
        : '<p class="muted">No TLS endpoints were inspected.</p>'
    }</section>`);
    sections.push(`<section><h2>Redirect chain</h2>${
      art.redirects.length
        ? art.redirects
            .map(
              (r) => `<p><strong>${e(r.startUrl)}</strong> — ${r.redirectCount} redirect(s)${r.reason ? ` · ${e(r.reason)}` : ''}</p>${table(['#', 'Status', 'Host', 'Scheme', 'Location / result'], r.hops.map((hop) => [String(hop.index), e(hop.statusCode ?? hop.kind), e(hop.hostname), e(hop.scheme), `<code>${e(hop.location ?? hop.error ?? (hop.kind === 'final' ? 'final destination' : ''))}</code>`]))}${r.page ? `<p class="muted">Final page title “${e(r.page.title ?? '')}”, password field: ${r.page.hasPasswordField ? 'yes' : 'no'}, form actions: ${e(r.page.formActions.join(', ') || 'none')}</p>` : ''}`,
            )
            .join('')
        : '<p class="muted">No redirect chains were inspected.</p>'
    }</section>`);
    sections.push(`<section><h2>Reputation</h2>${
      art.reputation?.length
        ? `${table(['Provider', 'Subject', 'Result', 'Detail', 'Fetched'], art.reputation.map((o) => [e(o.providerName), e(o.subject), e(o.status), e(o.summary), `${e(o.fetchedAt)}${o.cached ? ' (cached)' : ''}`]))}<p class="muted">A blocklist not listing a domain is neutral, not evidence of safety. error / unavailable / stale results are unknown.</p>`
        : '<p class="muted">Reputation was not checked (no provider configured or queried). This is not a clean result.</p>'
    }</section>`);
    if (art.rdap.length) {
      sections.push(`<section><h2>Domain registration</h2>${table(['Domain', 'Registered', 'Age', 'Registrar', 'Source'], art.rdap.map((r) => [e(r.domain), e(r.registered ?? r.reason ?? r.status), e(r.ageDays ?? '—'), e(r.registrar ?? '—'), e(r.source)]))}</section>`);
    }
    if (art.email) {
      const m = art.email;
      sections.push(`<section><h2>Email authentication</h2>${table(['Field', 'Value'], [
        ['From', e(m.from?.raw ?? '—')],
        ['Reply-To', e(m.replyTo.map((r) => r.raw).join(', ') || '—')],
        ['Return-Path', e(m.returnPath?.address ?? '—')],
        ['Subject', e(m.subject ?? '—')],
        ['Date', e(m.date ?? '—')],
        ['Message-ID', e(m.messageId ?? '—')],
        ['SPF', `<strong>${e(m.summary.spf)}</strong> · ${e(m.summary.spfDomain ?? '—')} · aligned ${e(m.summary.spfAligned ?? 'n/a')}`],
        ['DKIM', `<strong>${e(m.summary.dkim)}</strong> · ${e(m.summary.dkimDomains.join(', ') || '—')} · aligned ${e(m.summary.dkimAligned ?? 'n/a')}`],
        ['DMARC', `<strong>${e(m.summary.dmarc)}</strong>${m.summary.dmarcPolicy ? ` · policy ${e(m.summary.dmarcPolicy)}` : ''}`],
      ])}<h3>Mail route (oldest first)</h3>${table(['Hop', 'From', 'IP', 'By', 'Time'], m.received.map((r) => [String(r.index + 1), e(r.from ?? ''), e(r.fromIp ?? ''), e(r.by ?? ''), e(r.timestamp ?? r.date ?? '')]))}</section>`);
    }
  }

  sections.push(`<section><h2>Timeline</h2>${table(['Time (UTC)', 'Stage', 'Status', 'Detail'], d.timeline.map((t) => [`<code>${e(t.timestamp)}</code>`, e(t.label), e(t.status), e(t.detail ?? '')]))}</section>`);
  sections.push(`<section><h2>Limitations</h2><ul>${(a?.limitations ?? ['Assessment not available.']).map((l) => `<li>${e(l)}</li>`).join('')}</ul></section>`);

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>PhishLens report ${e(d.id)}</title>
<style>
  :root{--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--bg:#fff}
  *{box-sizing:border-box} body{font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:var(--fg);background:var(--bg);margin:0;padding:32px;max-width:1000px;margin:auto}
  header{border-bottom:2px solid var(--fg);padding-bottom:12px;margin-bottom:8px} h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:28px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line);text-transform:uppercase;letter-spacing:.04em} h3{font-size:13px;margin:16px 0 6px}
  table{width:100%;border-collapse:collapse;margin:6px 0 10px} th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:5px 8px} th{font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}
  code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all;white-space:pre-wrap} .muted{color:var(--muted)}
  .meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;color:var(--muted)} .meta b{color:var(--fg);font-weight:500}
  .verdict{display:flex;gap:24px;align-items:center;border:2px solid;border-radius:6px;padding:12px 16px;margin:8px 0} .verdict .v{font-size:22px;font-weight:700;letter-spacing:.06em} .score{font-size:18px;font-weight:600} .score span{color:var(--muted);font-size:13px}
  .sev{display:inline-block;font-size:10px;font-weight:700;border:1px solid;border-radius:3px;padding:0 5px;letter-spacing:.05em}
  .ind{border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:8px 0;break-inside:avoid} .ind-h{margin-bottom:6px} .kv{display:grid;grid-template-columns:80px 1fr;gap:3px 12px} .kv span{color:var(--muted);font-size:11px;text-transform:uppercase}
  footer{margin-top:32px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding-top:8px}
  @media print{body{padding:0} section{break-inside:auto} h2{break-after:avoid}}
</style></head><body>
<header><h1>PhishLens Investigation Report</h1>
<div class="meta"><span>Investigation ID</span><b><code>${e(d.id)}</code></b><span>Title</span><b>${e(d.title)}</b><span>Created</span><b>${e(d.createdAt)}</b><span>Completed</span><b>${e(d.completedAt ?? '—')}</b><span>Report generated</span><b>${e(generatedAt.toISOString())}</b></div></header>
${sections.join('\n')}
<footer>Generated by PhishLens. Every finding is traceable to submitted data, a live network observation made at the stated time, a deterministic analysis rule, or a named external source. The risk score is heuristic and uncalibrated.</footer>
</body></html>`;
}

export function renderJson(d: InvestigationDetail, generatedAt = new Date()): string {
  return JSON.stringify({ format: 'phishlens-report', version: 1, generatedAt: generatedAt.toISOString(), investigation: d }, null, 2);
}
