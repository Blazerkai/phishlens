import { useState } from 'react';
import { Link, useNavigate, useOutletContext, useParams } from 'react-router-dom';
import { Download, ExternalLink, Sparkles, Trash2 } from 'lucide-react';
import type { PublicSettings } from '@phishlens/shared';
import { api, type InvestigationView } from '../lib/api';
import { useResource } from '../lib/hooks';
import { CATEGORY_LABEL, clockTime, dateTime, durationMs, INPUT_LABEL, shortId } from '../lib/format';
import { PageHeader } from '../components/Layout';
import { Button, cx, Empty, ErrorNote, KeyValue, Panel, SeverityBadge, Spinner, Tabs, VerdictBadge } from '../components/ui';
import { ProgressPanel } from '../components/Progress';
import { ScoreMeter } from '../components/ScoreMeter';
import { IndicatorList } from '../components/IndicatorList';
import { EvidenceGraph } from '../components/EvidenceGraph';
import { DnsBlock, EmailEvidence, RdapBlock, RedirectChain, ReputationBlock, TlsBlock } from '../components/Evidence';

type Tab = 'overview' | 'indicators' | 'graph' | 'email' | 'network' | 'timeline';

export function InvestigationDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const settings = useOutletContext<PublicSettings | null>();
  const [tab, setTab] = useState<Tab>('overview');
  const { data: d, error, setData } = useResource(() => api.get(id), [id], {
    pollMs: 600,
    pollWhile: (x) => x.status === 'queued' || x.status === 'running',
  });

  if (error && !d) {
    return (
      <div className="p-6">
        <ErrorNote error={error} />
        <Link to="/investigations" className="mt-3 inline-block text-[12.5px] text-accent">Back to investigations</Link>
      </div>
    );
  }
  if (!d) return <div className="flex items-center gap-2 p-6 text-dim"><Spinner /> Loading investigation</div>;

  const done = d.status === 'completed';
  const a = d.assessment;
  const art = d.artifacts;
  const riskCount = d.indicators.filter((i) => i.polarity === 'risk' && i.severity !== 'info').length;

  const remove = async () => {
    if (!confirm('Delete this investigation and all of its evidence? This cannot be undone.')) return;
    await api.remove(d.id);
    navigate('/investigations');
  };

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'indicators', label: 'Indicators', count: d.indicators.length },
    { id: 'graph', label: 'Evidence graph' },
    ...(art?.email ? [{ id: 'email' as Tab, label: 'Email' }] : []),
    ...(art && (art.dns.length || art.tls.length || art.redirects.length || art.rdap.length || art.reputation?.length) ? [{ id: 'network' as Tab, label: 'Network' }] : []),
    { id: 'timeline', label: 'Timeline', count: d.timeline.length },
  ];

  return (
    <div>
      <PageHeader
        title={<span className={/\s/.test(d.title) ? '' : 'mono text-[16px]'}>{d.title}</span>}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="mono">{shortId(d.id)}</span>
            <span>{dateTime(d.createdAt)}</span>
            <span>{d.inputTypes.map((t) => INPUT_LABEL[t]).join(' + ')}</span>
          </span>
        }
        actions={
          done && (
            <>
              <a href={api.reportUrl(d.id, 'html')} target="_blank" rel="noopener noreferrer"><Button><ExternalLink size={13} /> Report</Button></a>
              <a href={api.reportUrl(d.id, 'md', true)}><Button><Download size={13} /> Markdown</Button></a>
              <a href={api.reportUrl(d.id, 'json', true)}><Button><Download size={13} /> JSON</Button></a>
              <Button variant="danger" onClick={remove} aria-label="Delete investigation"><Trash2 size={13} /></Button>
            </>
          )
        }
      />

      <div className="space-y-4 p-4 md:p-6">
        {(d.status === 'queued' || d.status === 'running') && <ProgressPanel events={d.timeline} status={d.status} />}
        {d.status === 'failed' && (
          <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/5 px-4 py-3 text-[13px] text-sev-critical">
            {d.error ?? 'The investigation failed.'}
          </div>
        )}

        {done && a && (
          <>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
              <div className="rounded-lg border border-line bg-panel p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <VerdictBadge verdict={a.verdict} size="lg" />
                  <span className="text-[12px] text-dim">
                    {riskCount} risk indicator{riskCount === 1 ? '' : 's'} · {a.benignSignals.length} benign signal{a.benignSignals.length === 1 ? '' : 's'} · {d.indicators.length} total
                  </span>
                </div>
                <p className="mt-3 text-[13.5px] leading-relaxed text-fg">{a.summary}</p>
                <div className="mt-4">
                  <div className="label mb-1.5">Why?</div>
                  <ul className="space-y-1">
                    {a.rationale.map((r) => (
                      <li key={r} className="flex gap-2 text-[12.5px] text-dim"><span className="text-faint">•</span>{r}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="rounded-lg border border-line bg-panel p-4">
                <ScoreMeter score={a.score} verdict={a.verdict} />
                <p className="mt-2 text-[11.5px] leading-snug text-faint">Thresholds: benign &lt; 10 (with ≥ 2 benign signals) · suspicious ≥ 25 · high risk ≥ 60, or rule-based escalation on critical / multiple high findings.</p>
              </div>
            </div>

            <Tabs tabs={tabs} value={tab} onChange={setTab} />

            {tab === 'overview' && <Overview d={d} settings={settings} onAi={(s) => setData({ ...d, aiSummary: s })} goIndicators={() => setTab('indicators')} />}
            {tab === 'indicators' && <Panel bodyClassName="p-0"><IndicatorList indicators={d.indicators} families={a.positiveEvidence} /></Panel>}
            {tab === 'graph' && (
              <Panel bodyClassName="p-0">{d.graph ? <EvidenceGraph graph={d.graph} indicators={d.indicators} /> : <Empty title="No graph available" />}</Panel>
            )}
            {tab === 'email' && art?.email && <EmailEvidence e={art.email} />}
            {tab === 'network' && art && <Network d={d} />}
            {tab === 'timeline' && <Timeline d={d} />}
          </>
        )}
        {!done && d.status !== 'failed' && d.timeline.length === 0 && <Empty title="Waiting for the analysis to start" />}
        {d.status === 'failed' && <Timeline d={d} />}
      </div>
    </div>
  );
}

function Overview({ d, settings, onAi, goIndicators }: { d: InvestigationView; settings: PublicSettings | null; onAi: (s: InvestigationView['aiSummary']) => void; goIndicators: () => void }) {
  const a = d.assessment!;
  const [aiBusy, setAiBusy] = useState(false);
  const [aiError, setAiError] = useState<Error | null>(null);
  const indById = new Map(d.indicators.map((i) => [i.id, i]));

  const runAi = async () => {
    setAiBusy(true);
    setAiError(null);
    try {
      onAi(await api.summarize(d.id));
    } catch (e) {
      setAiError(e as Error);
    } finally {
      setAiBusy(false);
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,0.8fr)]">
      <div className="space-y-4">
        <Panel title="Contributing evidence" bodyClassName="p-0" actions={<button onClick={goIndicators} className="text-[12px] text-dim hover:text-fg">All indicators →</button>}>
          {a.contributions.length === 0 ? (
            <Empty title="No risk indicators contributed to the score" />
          ) : (
            <ul className="divide-y divide-line">
              {a.contributions.slice(0, 10).map((c) => {
                const ind = indById.get(c.indicatorId);
                return (
                  <li key={c.indicatorId} className="grid grid-cols-[64px_minmax(0,1fr)_48px] items-start gap-3 px-4 py-2.5">
                    <SeverityBadge severity={c.severity} className="mt-0.5" />
                    <div className="min-w-0">
                      <div className="text-[13px]">{c.title}</div>
                      {ind && <div className="mono truncate text-faint" title={ind.evidence}>{ind.evidence}</div>}
                      <div className="text-[11.5px] text-faint">{CATEGORY_LABEL[c.category]} · confidence {c.confidence}</div>
                    </div>
                    <div className="text-right text-[12px] tabular-nums text-dim" title="Points contributed to the score">+{c.points}</div>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
        {a.positiveEvidence ? (
          <Panel title="Positive evidence · independent families">
            {a.positiveEvidence.length === 0 ? (
              <p className="text-[12.5px] text-dim">No verified positive evidence. Absence of risk findings is not treated as evidence of legitimacy.</p>
            ) : (
              <ul className="space-y-3">
                {a.positiveEvidence.map((f) => (
                  <li key={f.family}>
                    <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                      <span className={cx('size-1.5 rounded-full', f.counted ? 'bg-v-benign' : 'bg-sev-medium')} />
                      <span className="font-medium">{f.label}</span>
                      <span className="rounded-[3px] border border-line px-1.5 text-[10px] uppercase tracking-wider text-faint">{f.class === 'corroboration' ? 'corroboration' : 'security control'}</span>
                      <span className={cx('text-[11px]', f.counted ? 'text-v-benign' : 'text-sev-medium')}>{f.counted ? 'counted once' : 'not counted'}</span>
                    </div>
                    <div className="mt-0.5 pl-3.5 text-[12px] text-faint">{f.reason}</div>
                    <ul className="mt-1 space-y-0.5 pl-3.5">
                      {f.indicatorIds.map((id, n) => (
                        <li key={id} className="text-[12px] text-dim">
                          {f.titles[n]}
                          <span className="mono block truncate text-faint">{indById.get(id)?.evidence}</span>
                        </li>
                      ))}
                    </ul>
                    {f.indicatorIds.length > 1 && <div className="mt-0.5 pl-3.5 text-[11px] text-faint">{f.indicatorIds.length} correlated observations → one independent signal</div>}
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-[11.5px] text-faint">
              Benign requires two independent families, at least one of them corroboration (verified identity or registration maturity), and no risk finding of medium severity or above. Security controls alone are attainable by any operator, including attackers. Positive evidence never offsets risk.
            </p>
          </Panel>
        ) : a.benignSignals.length > 0 && (
          <Panel title="Benign signals">
            <ul className="space-y-1.5">
              {a.benignSignals.map((b) => (
                <li key={b.indicatorId} className="flex items-start gap-2 text-[12.5px]">
                  <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-v-benign" />
                  <span>
                    {b.title}
                    <span className="mono block text-faint">{indById.get(b.indicatorId)?.evidence}</span>
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-[11.5px] text-faint">Benign signals never offset risk indicators; they only allow a benign verdict when risk is low.</p>
          </Panel>
        )}
        {a.conflicts && a.conflicts.length > 0 && (
          <Panel title="Conflicting evidence">
            <ul className="space-y-1.5 text-[12.5px] text-sev-medium">
              {a.conflicts.map((c) => <li key={c}>{c}</li>)}
            </ul>
          </Panel>
        )}
        {a.nextSteps && a.nextSteps.length > 0 && (
          <Panel title="To resolve this result">
            <ul className="space-y-1.5 text-[12.5px] text-dim">
              {a.nextSteps.map((s) => (
                <li key={s} className="flex gap-2"><span className="text-faint">→</span>{s}</li>
              ))}
            </ul>
          </Panel>
        )}
        {d.related.length > 0 && (
          <Panel title="Related investigations (shared infrastructure)" bodyClassName="p-0">
            <ul className="divide-y divide-line">
              {d.related.map((r) => (
                <li key={r.id + r.shared}>
                  <Link to={`/investigations/${r.id}`} className="flex items-center justify-between gap-3 px-4 py-2 hover:bg-hover">
                    <span className="min-w-0">
                      <span className="block truncate">{r.title}</span>
                      <span className="mono text-faint">{r.shared}</span>
                    </span>
                    <VerdictBadge verdict={r.verdict} />
                  </Link>
                </li>
              ))}
            </ul>
          </Panel>
        )}
      </div>

      <div className="space-y-4">
        <Panel title="Coverage">
          <div className="space-y-1.5 text-[12.5px]">
            {d.analyzerRuns.map((r) => (
              <div key={r.analyzer} className="flex items-start justify-between gap-3">
                <span className="text-dim">{r.label}</span>
                <span className={cx('shrink-0 text-[11px] uppercase tracking-wider', r.status === 'completed' ? 'text-v-benign' : r.status === 'failed' ? 'text-sev-critical' : 'text-sev-medium')}>
                  {r.status} <span className="normal-case tracking-normal text-faint">{durationMs(r.durationMs)}</span>
                </span>
              </div>
            ))}
          </div>
          {[...a.coverage.unavailable, ...a.coverage.failed].length > 0 && (
            <ul className="mt-3 space-y-1 border-t border-line pt-3 text-[12px] text-faint">
              {[...a.coverage.unavailable, ...a.coverage.failed].map((u) => (
                <li key={u.analyzer}><span className="text-dim">{u.analyzer}:</span> {u.reason}</li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="AI narrative (optional)"
          actions={
            settings?.aiSummaryAvailable && (
              <Button onClick={runAi} disabled={aiBusy}>
                {aiBusy ? <Spinner /> : <Sparkles size={13} />} {d.aiSummary ? 'Regenerate' : 'Summarise evidence'}
              </Button>
            )
          }
        >
          {d.aiSummary?.status === 'completed' ? (
            <div>
              <p className="whitespace-pre-wrap text-[12.5px] leading-relaxed text-fg">{d.aiSummary.text}</p>
              <p className="mt-3 text-[11px] text-faint">
                Generated by {d.aiSummary.provider} {d.aiSummary.model} from the structured evidence only, {dateTime(d.aiSummary.generatedAt)}. It cites {d.aiSummary.citedIndicatorIds?.length ?? 0} indicator(s)
                {d.aiSummary.uncitedClaimsRemoved ? `; ${d.aiSummary.uncitedClaimsRemoved} sentence(s) without valid citations were removed` : ''}. The verdict above does not depend on it.
              </p>
            </div>
          ) : (
            <p className="text-[12.5px] text-dim">
              {settings?.aiSummaryAvailable
                ? 'Produce a plain-language explanation of the collected evidence. The model receives only the structured indicators — never the raw message — and must cite indicator IDs.'
                : 'Disabled. The deterministic investigation is complete without it. Configure AI_PROVIDER to enable a narrative summary of the collected evidence.'}
            </p>
          )}
          {aiError && <div className="mt-2"><ErrorNote error={aiError} /></div>}
        </Panel>

        <Panel title="Limitations">
          <ul className="space-y-1.5 text-[12px] text-dim">
            {a.limitations.map((l) => (
              <li key={l} className="flex gap-2"><span className="text-faint">–</span>{l}</li>
            ))}
          </ul>
        </Panel>

        <Panel title="Input">
          <KeyValue
            items={d.inputs.map((i) => ({
              label: INPUT_LABEL[i.type],
              value: i.value !== null ? (i.value.length > 240 ? `${i.value.slice(0, 240)}…` : i.value) : `not retained · ${i.length.toLocaleString()} chars · sha256 ${i.sha256.slice(0, 16)}…`,
              mono: true,
            }))}
          />
        </Panel>
      </div>
    </div>
  );
}

function Network({ d }: { d: InvestigationView }) {
  const art = d.artifacts!;
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <div className="space-y-4">
        <Panel title={`Redirect chain${art.redirects.length > 1 ? 's' : ''}`}>
          {art.redirects.length === 0 ? <Empty title="No links were followed" /> : <div className="space-y-6">{art.redirects.map((r) => <RedirectChain key={r.startUrl} r={r} />)}</div>}
        </Panel>
        <Panel title="TLS certificates">
          {art.tls.length === 0 ? <Empty title="No HTTPS endpoints inspected" /> : <div className="space-y-3">{art.tls.map((t) => <TlsBlock key={`${t.host}:${t.port}`} t={t} />)}</div>}
        </Panel>
        <Panel title="Reputation">
          {art.reputation && art.reputation.length > 0 ? (
            <>
              <ReputationBlock items={art.reputation} />
              <p className="mt-2 text-[11.5px] text-faint">A blocklist not listing a domain is neutral, not evidence of safety. Errors, timeouts and stale data are unknown.</p>
            </>
          ) : (
            <Empty title="Reputation not checked">{d.analyzerRuns.find((r) => r.analyzer === 'reputation')?.reason ?? 'No reputation provider was queried for this investigation.'}</Empty>
          )}
        </Panel>
        {art.rdap.length > 0 && (
          <Panel title="Domain registration (RDAP)">
            <div className="space-y-3">{art.rdap.map((r) => <RdapBlock key={r.domain} r={r} />)}</div>
          </Panel>
        )}
      </div>
      <Panel title="DNS records">
        {art.dns.length === 0 ? <Empty title="No DNS data collected" /> : <div className="space-y-5">{art.dns.map((x) => <DnsBlock key={x.name} d={x} />)}</div>}
      </Panel>
    </div>
  );
}

function Timeline({ d }: { d: InvestigationView }) {
  const t0 = d.timeline[0] ? new Date(d.timeline[0].timestamp).getTime() : 0;
  return (
    <Panel title="Investigation timeline" bodyClassName="p-0">
      <ol className="relative">
        {d.timeline.map((e) => (
          <li key={e.id} className="grid grid-cols-[110px_72px_minmax(0,1fr)] items-start gap-3 border-b border-line px-4 py-2 last:border-0 sm:grid-cols-[120px_80px_220px_minmax(0,1fr)]">
            <span className="mono text-dim">{clockTime(e.timestamp)}</span>
            <span className="mono text-right text-faint">+{durationMs(new Date(e.timestamp).getTime() - t0)}</span>
            <span className="flex items-center gap-2 text-[12.5px]">
              <span className={cx('size-1.5 shrink-0 rounded-full', e.status === 'completed' ? 'bg-v-benign' : e.status === 'failed' ? 'bg-sev-critical' : e.status === 'unavailable' ? 'bg-sev-medium' : e.status === 'started' ? 'bg-accent' : 'bg-faint')} />
              {e.label} <span className="text-[11px] text-faint">{e.status}</span>
            </span>
            <span className="col-span-3 truncate text-[12px] text-faint sm:col-span-1" title={e.detail ?? ''}>{e.detail}</span>
          </li>
        ))}
      </ol>
    </Panel>
  );
}
