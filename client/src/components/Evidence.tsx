import { ArrowDown, Lock, LockOpen, ShieldAlert } from 'lucide-react';
import type { DnsAnalysis, EmailHeaderAnalysis, RdapAnalysis, RedirectAnalysis, ReputationObservation, TlsAnalysis } from '@phishlens/shared';
import { dateTime } from '../lib/format';
import { AuthPill, cx, Empty, KeyValue, Panel } from './ui';

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

export function EmailEvidence({ e }: { e: EmailHeaderAnalysis }) {
  const s = e.summary;
  const aligned = (v: boolean | null) => (v === null ? 'n/a' : v ? 'aligned' : 'not aligned');
  const origin = e.received.find((h) => h.fromIp && !h.ipIsPrivate) ?? e.received[0];
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <div className="space-y-4">
        <Panel title="Authentication (top-most Authentication-Results)">
          <div className="flex flex-wrap gap-2">
            <AuthPill label="SPF" result={s.spf} />
            <AuthPill label="DKIM" result={s.dkim} />
            <AuthPill label="DMARC" result={s.dmarc} />
          </div>
          <KeyValue
            className="mt-4"
            items={[
              { label: 'SPF domain', value: `${s.spfDomain ?? '—'} · ${aligned(s.spfAligned)}`, mono: true },
              { label: 'DKIM domain(s)', value: `${s.dkimDomains.join(', ') || '—'} · ${aligned(s.dkimAligned)}`, mono: true },
              { label: 'DMARC policy', value: s.dmarcPolicy ?? '—', mono: true },
              { label: 'Evaluated by', value: e.authenticationResults[0]?.authservId ?? (e.authenticationResults.length ? 'receiving system (no authserv-id)' : e.receivedSpf ? 'Received-SPF only' : 'not present'), mono: true },
            ]}
          />
          <p className="mt-3 text-[12px] text-faint">
            A failed check is evidence, not a verdict: forwarding and mailing lists break SPF/DKIM for legitimate mail, and attackers pass all three for domains they own.
          </p>
        </Panel>
        <Panel title="Header fields">
          <KeyValue
            items={[
              { label: 'From', value: e.from?.raw ?? '—', mono: true },
              { label: 'Reply-To', value: e.replyTo.map((r) => r.raw).join(', ') || '—', mono: true },
              { label: 'Return-Path', value: e.returnPath?.address ?? e.returnPath?.raw ?? '—', mono: true },
              { label: 'To', value: e.to.map((r) => r.address ?? r.raw).join(', ') || '—', mono: true },
              { label: 'Subject', value: e.subject ?? '—' },
              { label: 'Date', value: e.date ?? '—', mono: true },
              { label: 'Message-ID', value: e.messageId ?? '—', mono: true },
              ...(e.xMailer ? [{ label: 'X-Mailer', value: e.xMailer, mono: true }] : []),
              { label: 'DKIM signatures', value: e.dkimSignatures.map((d) => `d=${d.domain} s=${d.selector}`).join(' · ') || 'none', mono: true },
            ]}
          />
        </Panel>
      </div>
      <Panel title={`Mail route · ${e.received.length} hop(s), oldest first`}>
        {e.received.length === 0 ? (
          <Empty title="No Received headers">The delivery path cannot be reconstructed from the submitted headers.</Empty>
        ) : (
          <ol className="space-y-0">
            <RouteNode title="Sender" sub={e.from?.address ?? 'unknown'} detail={origin?.fromIp ? `originating IP ${origin.fromIp}` : undefined} tone="sender" />
            {e.received.map((h) => (
              <div key={h.index}>
                <RouteArrow label={[h.with, h.delaySeconds !== null ? `${h.delaySeconds >= 0 ? '+' : ''}${h.delaySeconds}s` : null].filter(Boolean).join(' · ')} warn={h.delaySeconds !== null && h.delaySeconds < -300} />
                <RouteNode
                  title={h.by ?? 'unknown server'}
                  sub={`from ${h.from ?? '?'}${h.fromRdns && h.fromRdns !== h.from ? ` (${h.fromRdns})` : ''}${h.fromIp ? ` [${h.fromIp}]` : ''}`}
                  detail={h.timestamp ? dateTime(h.timestamp) : (h.date ?? undefined)}
                  tone={h.index === e.received.length - 1 ? 'recipient' : 'relay'}
                  badge={h.ipIsPrivate ? 'internal IP' : undefined}
                />
              </div>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

function RouteNode({ title, sub, detail, tone, badge }: { title: string; sub: string; detail?: string; tone: 'sender' | 'relay' | 'recipient'; badge?: string }) {
  return (
    <li className={cx('rounded-md border px-3 py-2', tone === 'sender' ? 'border-accent/40 bg-accent/[0.05]' : tone === 'recipient' ? 'border-v-benign/30' : 'border-line')}>
      <div className="flex items-center justify-between gap-2">
        <span className="mono truncate text-fg">{title}</span>
        <span className="shrink-0 text-[10.5px] uppercase tracking-wider text-faint">
          {badge ? <span className="mr-2 text-dim">{badge}</span> : null}
          {tone === 'sender' ? 'sender' : tone === 'recipient' ? 'recipient server' : 'relay'}
        </span>
      </div>
      <div className="mono truncate text-[11.5px] text-dim">{sub}</div>
      {detail && <div className="text-[11px] text-faint">{detail}</div>}
    </li>
  );
}

function RouteArrow({ label, warn }: { label?: string; warn?: boolean }) {
  return (
    <div className="flex items-center gap-2 py-1 pl-4 text-[11px] text-faint">
      <ArrowDown size={13} className={warn ? 'text-sev-medium' : ''} />
      <span className={warn ? 'text-sev-medium' : ''}>{label}{warn ? ' · timestamp earlier than previous hop' : ''}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------------

export function RedirectChain({ r }: { r: RedirectAnalysis }) {
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <span className="mono truncate text-dim">{r.startUrl}</span>
        <span className="text-[12px] text-faint">
          {r.redirectCount} redirect(s){r.reason ? ` · ${r.reason}` : ''}
        </span>
      </div>
      <ol>
        {r.hops.map((h, i) => {
          const label = i === 0 ? 'Original URL' : h.kind === 'blocked' ? 'Blocked by policy' : h.kind === 'error' ? 'Error' : i === r.hops.length - 1 ? 'Final destination' : 'Redirect';
          const bad = h.kind === 'blocked' || h.kind === 'error';
          return (
            <li key={i}>
              {i > 0 && (
                <div className="flex items-center gap-2 py-1 pl-4 text-[11px] text-faint">
                  <ArrowDown size={13} /> {r.hops[i - 1]!.kind === 'meta-refresh' ? 'meta refresh' : `HTTP ${r.hops[i - 1]!.statusCode ?? ''} Location`}
                </div>
              )}
              <div className={cx('rounded-md border px-3 py-2', bad ? 'border-sev-high/40 bg-sev-high/[0.04]' : i === r.hops.length - 1 ? 'border-accent/40' : 'border-line')}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="label">{label}</span>
                  <span className="flex items-center gap-3 text-[11.5px] text-faint">
                    {h.scheme === 'https' ? <Lock size={12} className="text-v-benign" /> : h.scheme === 'http' ? <LockOpen size={12} className="text-sev-medium" /> : null}
                    {h.statusCode && <span className="mono text-dim">HTTP {h.statusCode}</span>}
                    {h.remoteAddress && <span className="mono">{h.remoteAddress}</span>}
                    {h.durationMs !== undefined && <span className="mono">{h.durationMs} ms</span>}
                  </span>
                </div>
                <div className="mono mt-1 break-all text-fg">{h.url}</div>
                <div className="mt-0.5 text-[11.5px] text-dim">
                  host <span className="mono">{h.hostname}</span> · scheme <span className="mono">{h.scheme}</span>
                  {h.location && (
                    <>
                      {' '}
                      · location <span className="mono break-all">{h.location}</span>
                    </>
                  )}
                </div>
                {h.error && (
                  <div className="mt-1 flex items-start gap-1.5 text-[12px] text-sev-high">
                    <ShieldAlert size={13} className="mt-0.5 shrink-0" /> {h.error}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      {r.page && (
        <KeyValue
          className="mt-3"
          items={[
            { label: 'Page title', value: r.page.title ?? '—' },
            { label: 'Content type', value: r.page.contentType ?? '—', mono: true },
            { label: 'Password field', value: r.page.hasPasswordField ? 'present' : 'none' },
            { label: 'Form actions', value: r.page.formActions.join(', ') || 'none', mono: true },
            ...(r.page.scriptRedirect ? [{ label: 'Script redirect', value: `${r.page.scriptRedirect} (not followed)`, mono: true }] : []),
            { label: 'Inspected', value: `${r.page.bytesInspected.toLocaleString()} bytes, static only` },
          ]}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DNS / TLS / RDAP
// ---------------------------------------------------------------------------

export function DnsBlock({ d }: { d: DnsAnalysis }) {
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
        <span className="mono text-[13px] text-fg">{d.name}</span>
        <span className="text-[11.5px] text-faint">
          {d.resolver} · {dateTime(d.queriedAt)}
        </span>
      </div>
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full min-w-[480px] text-left text-[12px]">
          <tbody className="divide-y divide-line">
            {d.records.map((r) => (
              <tr key={r.type}>
                <td className="mono w-20 px-3 py-1.5 text-dim">{r.type}</td>
                <td className="w-20 px-3 py-1.5">
                  <span className={cx('text-[11px] uppercase tracking-wider', r.status === 'ok' ? 'text-v-benign' : r.status === 'nodata' ? 'text-faint' : 'text-sev-medium')}>{r.status}</span>
                </td>
                <td className="mono break-all px-3 py-1.5 text-fg">{r.values.length ? r.values.map((v) => <div key={v}>{v}</div>) : <span className="text-faint">{r.error ?? '—'}</span>}</td>
              </tr>
            ))}
            {d.reverse.length > 0 && (
              <tr>
                <td className="mono px-3 py-1.5 text-dim">PTR</td>
                <td className="px-3 py-1.5 text-[11px] uppercase tracking-wider text-faint">reverse</td>
                <td className="mono px-3 py-1.5">
                  {d.reverse.map((r) => (
                    <div key={r.ip}>
                      {r.ip} → {r.names.join(', ') || <span className="text-faint">no PTR</span>}
                    </div>
                  ))}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {d.providers.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {d.providers.map((p) => (
            <span key={p.role + p.name} className="rounded border border-line px-2 py-0.5 text-[11.5px] text-dim" title={p.basis}>
              <span className="text-faint">{p.role}:</span> {p.name}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function TlsBlock({ t }: { t: TlsAnalysis }) {
  if (!t.certificate) {
    return (
      <div className="rounded-md border border-line px-3 py-2 text-[12.5px]">
        <span className="mono">{t.host}:{t.port}</span> — <span className="text-dim">{t.status}</span>
        {t.reason && <div className="text-[12px] text-faint">{t.reason}</div>}
      </div>
    );
  }
  const c = t.certificate;
  const ok = t.authorized && t.hostnameMatches && c.daysRemaining >= 0;
  return (
    <div className={cx('rounded-md border px-4 py-3', ok ? 'border-line' : 'border-sev-high/40')}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="mono text-[13px]">{t.host}:{t.port}</span>
        <span className={cx('flex items-center gap-1.5 text-[11.5px] font-medium uppercase tracking-wider', ok ? 'text-v-benign' : 'text-sev-high')}>
          {ok ? <Lock size={12} /> : <ShieldAlert size={12} />} {ok ? 'Certificate valid' : 'Certificate problems'}
        </span>
      </div>
      <KeyValue
        items={[
          { label: 'Subject', value: c.subjectCN ?? JSON.stringify(c.subject), mono: true },
          { label: 'Issuer', value: [c.issuerOrg, c.issuerCN].filter(Boolean).join(' · ') || '—', mono: true },
          { label: 'Valid from', value: dateTime(c.validFrom) },
          { label: 'Expires', value: `${dateTime(c.validTo)} (${c.daysRemaining >= 0 ? `${c.daysRemaining} days remaining` : `expired ${-c.daysRemaining} days ago`})` },
          { label: 'Trusted chain', value: t.authorized ? 'yes' : `no — ${t.authorizationError ?? ''}` },
          { label: 'Hostname match', value: t.hostnameMatches ? 'yes' : `no — ${t.hostnameMismatchReason ?? ''}` },
          { label: `SANs (${c.sans.length})`, value: c.sans.slice(0, 12).join(', ') + (c.sans.length > 12 ? ` … +${c.sans.length - 12}` : ''), mono: true },
          { label: 'Chain', value: (t.chain ?? []).map((x) => x.subjectCN).filter(Boolean).join(' → ') || '—', mono: true },
          { label: 'Connection', value: [t.remoteAddress, t.protocol, t.cipher].filter(Boolean).join(' · '), mono: true },
          { label: 'SHA-256', value: c.fingerprint256, mono: true },
        ]}
      />
    </div>
  );
}

const REP_TONE: Record<ReputationObservation['status'], { label: string; cls: string }> = {
  listed: { label: 'listed malicious', cls: 'text-sev-critical border-sev-critical/50' },
  historical: { label: 'past abuse', cls: 'text-sev-high border-sev-high/45' },
  minority: { label: 'isolated detections', cls: 'text-sev-medium border-sev-medium/45' },
  not_listed: { label: 'not listed (neutral)', cls: 'text-dim border-line-strong' },
  popular: { label: 'popular (corroboration)', cls: 'text-v-benign border-v-benign/40' },
  not_popular: { label: 'not ranked (neutral)', cls: 'text-dim border-line-strong' },
  stale: { label: 'stale — unknown', cls: 'text-sev-medium border-sev-medium/45' },
  error: { label: 'error — unknown', cls: 'text-sev-medium border-sev-medium/45' },
  unavailable: { label: 'unavailable — unknown', cls: 'text-sev-medium border-sev-medium/45' },
};

export function ReputationBlock({ items }: { items: ReputationObservation[] }) {
  return (
    <ul className="divide-y divide-line rounded-md border border-line">
      {items.map((o) => (
        <li key={`${o.provider}:${o.subject}`} className="px-3 py-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12.5px]">
              {o.providerName} <span className="mono text-faint">· {o.subject}</span>
            </span>
            <span className={cx('rounded-[3px] border px-1.5 text-[10.5px] uppercase tracking-wider', REP_TONE[o.status].cls)}>{REP_TONE[o.status].label}</span>
          </div>
          <div className="mt-0.5 text-[12px] text-dim">{o.summary}</div>
          <div className="text-[11px] text-faint">
            fetched {dateTime(o.fetchedAt)}
            {o.cached ? ' (cached)' : ''}
            {o.dataDate ? ` · provider data ${o.dataDate.slice(0, 10)}` : ''}
            {o.reference ? ` · ${o.reference}` : ''}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function RdapBlock({ r }: { r: RdapAnalysis }) {
  return (
    <div className="rounded-md border border-line px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="mono text-[13px]">{r.domain}</span>
        <span className="text-[11.5px] text-faint">{r.source}</span>
      </div>
      {r.status === 'completed' && r.registered ? (
        <KeyValue
          items={[
            { label: 'Registered', value: `${dateTime(r.registered)} (${r.ageDays} days ago)` },
            { label: 'Expires', value: dateTime(r.expires) },
            { label: 'Registrar', value: r.registrar ?? '—' },
            { label: 'Status', value: r.statuses?.join(', ') || '—', mono: true },
          ]}
        />
      ) : (
        <div className="text-[12.5px] text-dim">
          {r.status}: {r.reason ?? 'no registration date published'}
        </div>
      )}
    </div>
  );
}
