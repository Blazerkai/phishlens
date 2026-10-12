import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, Plus } from 'lucide-react';
import type { DashboardStats, Verdict } from '@phishlens/shared';
import { api } from '../lib/api';
import { useResource } from '../lib/hooks';
import { CATEGORY_LABEL, timeAgo, VERDICT_LABEL } from '../lib/format';
import { PageHeader } from '../components/Layout';
import { Button, cx, Empty, ErrorNote, Panel, SEV_TEXT, SeverityBadge, Spinner, VERDICT_BG, VerdictBadge } from '../components/ui';
import { InputChips } from '../components/InputChips';

const STACK: Verdict[] = ['benign', 'inconclusive', 'suspicious', 'high_risk'];

function Stat({ label, value, tone, to }: { label: string; value: number; tone?: Verdict; to?: string }) {
  const body = (
    <div className="flex h-full flex-col justify-between gap-3 rounded-lg border border-line bg-panel px-4 py-3 transition-colors hover:border-line-strong">
      <div className="flex items-center gap-2">
        {tone && <span className={cx('size-1.5 rounded-full', VERDICT_BG[tone])} />}
        <span className="label">{label}</span>
      </div>
      <div className="text-[28px] font-semibold leading-none tracking-tight tabular-nums">{value}</div>
    </div>
  );
  return to ? <Link to={to}>{body}</Link> : body;
}

/** 14-day stacked bar chart of verdicts. Hover a day for exact counts. */
function VerdictTrend({ data }: { data: DashboardStats['verdictByDay'] }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 640;
  const H = 230;
  const pad = { l: 26, r: 4, t: 8, b: 20 };
  const totals = data.map((d) => STACK.reduce((s, v) => s + d[v], 0));
  const max = Math.max(4, ...totals);
  const step = (W - pad.l - pad.r) / data.length;
  const bw = Math.min(26, step - 6);
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
  const ticks = [0, Math.ceil(max / 2), max];
  const h = hover !== null ? data[hover] : null;

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-dim">
        {[...STACK].reverse().map((v) => (
          <span key={v} className="flex items-center gap-1.5">
            <span className={cx('size-2 rounded-sm', VERDICT_BG[v])} />
            {VERDICT_LABEL[v]}
          </span>
        ))}
      </div>
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Verdicts per day, last 14 days" onMouseLeave={() => setHover(null)}>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke="var(--color-line)" strokeWidth={1} />
              <text x={pad.l - 6} y={y(t) + 3.5} textAnchor="end" fontSize={10} fill="var(--color-faint)">
                {t}
              </text>
            </g>
          ))}
          {data.map((d, i) => {
            const x = pad.l + i * step + (step - bw) / 2;
            let acc = 0;
            const segs = STACK.filter((v) => d[v] > 0);
            return (
              <g key={d.day} onMouseEnter={() => setHover(i)}>
                <rect x={pad.l + i * step} y={pad.t} width={step} height={H - pad.t - pad.b} fill={hover === i ? 'var(--color-hover)' : 'transparent'} />
                {segs.map((v, si) => {
                  const y0 = y(acc);
                  acc += d[v];
                  const y1 = y(acc);
                  const top = si === segs.length - 1;
                  const hgt = Math.max(0, y0 - y1 - (si > 0 ? 2 : 0));
                  return top ? (
                    <path
                      key={v}
                      d={`M${x},${y0 - (si > 0 ? 2 : 0)} V${y1 + 3} Q${x},${y1} ${x + 3},${y1} H${x + bw - 3} Q${x + bw},${y1} ${x + bw},${y1 + 3} V${y0 - (si > 0 ? 2 : 0)} Z`}
                      fill={`var(--color-v-${v === 'high_risk' ? 'high' : v})`}
                    />
                  ) : (
                    <rect key={v} x={x} y={y1} width={bw} height={hgt} fill={`var(--color-v-${v === 'high_risk' ? 'high' : v})`} />
                  );
                })}
                {(i % 2 === 1 || data.length <= 7) && (
                  <text x={x + bw / 2} y={H - 6} textAnchor="middle" fontSize={10} fill="var(--color-faint)">
                    {new Date(`${d.day}T00:00:00Z`).toLocaleDateString([], { month: 'short', day: 'numeric', timeZone: 'UTC' })}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
        {h && hover !== null && (
          <div
            className="pointer-events-none absolute top-0 z-10 min-w-36 rounded-md border border-line-strong bg-raised px-3 py-2 text-[12px] shadow-xl"
            style={{ left: `${Math.min(78, ((pad.l + hover * step + step) / W) * 100)}%` }}
          >
            <div className="mb-1 font-medium">{new Date(`${h.day}T00:00:00Z`).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' })}</div>
            {[...STACK].reverse().map((v) => (
              <div key={v} className="flex items-center justify-between gap-4 text-dim">
                <span className="flex items-center gap-1.5">
                  <span className={cx('size-1.5 rounded-full', VERDICT_BG[v])} />
                  {VERDICT_LABEL[v]}
                </span>
                <span className="tabular-nums text-fg">{h[v]}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function DashboardPage() {
  const { data, error, loading } = useResource(() => api.dashboard(), [], { pollMs: 5000, pollWhile: (d) => d.totals.running > 0 });

  return (
    <div>
      <PageHeader
        title="Security investigations"
        subtitle="Deterministic phishing analysis. Every verdict is traceable to observable evidence."
        actions={
          <Link to="/new">
            <Button variant="primary">
              <Plus size={14} /> New investigation
            </Button>
          </Link>
        }
      />
      <div className="space-y-4 p-4 md:p-6">
        <ErrorNote error={error} />
        {loading && !data && (
          <div className="flex items-center gap-2 text-dim">
            <Spinner /> Loading
          </div>
        )}
        {data && (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
              <Stat label="Total" value={data.totals.total} to="/investigations" />
              <Stat label="High risk" value={data.totals.highRisk} tone="high_risk" to="/investigations?verdict=high_risk" />
              <Stat label="Suspicious" value={data.totals.suspicious} tone="suspicious" to="/investigations?verdict=suspicious" />
              <Stat label="Inconclusive" value={data.totals.inconclusive} tone="inconclusive" to="/investigations?verdict=inconclusive" />
              <Stat label="Benign" value={data.totals.benign} tone="benign" to="/investigations?verdict=benign" />
              <Stat label="This week" value={data.thisWeek} />
            </div>

            <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
              <Panel title="Verdicts · last 14 days">
                {data.totals.total === 0 ? <Empty title="No investigations yet" /> : <VerdictTrend data={data.verdictByDay} />}
              </Panel>
              <Panel title="Most common indicators" bodyClassName="p-0">
                {data.commonIndicators.length === 0 ? (
                  <Empty title="No risk indicators recorded yet" />
                ) : (
                  <ul className="divide-y divide-line">
                    {data.commonIndicators.slice(0, 7).map((c) => {
                      const pct = (c.count / Math.max(1, data.totals.total)) * 100;
                      return (
                        <li key={c.code} className="px-4 py-2">
                          <div className="flex items-center justify-between gap-3">
                            <span className="truncate text-[12.5px]">{c.title}</span>
                            <span className="shrink-0 text-[12px] tabular-nums text-dim">
                              {c.count} <span className="text-faint">inv.</span>
                            </span>
                          </div>
                          <div className="mt-1.5 flex items-center gap-2">
                            <div className="h-1 flex-1 rounded-full bg-raised">
                              <div className="h-1 rounded-full bg-accent/70" style={{ width: `${Math.max(3, pct)}%` }} />
                            </div>
                            <span className={cx('w-14 text-right text-[10px] uppercase tracking-wider', SEV_TEXT[c.maxSeverity])}>{c.maxSeverity}</span>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </Panel>
            </div>

            <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
              <Panel
                title="Recent investigations"
                bodyClassName="p-0"
                actions={
                  <Link to="/investigations" className="flex items-center gap-1 text-[12px] text-dim hover:text-fg">
                    All <ArrowRight size={12} />
                  </Link>
                }
              >
                {data.recent.length === 0 ? (
                  <Empty title="No investigations yet">Start one from New Investigation.</Empty>
                ) : (
                  <ul className="divide-y divide-line">
                    {data.recent.map((r) => (
                      <li key={r.id}>
                        <Link to={`/investigations/${r.id}`} className="grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-1 px-4 py-2.5 hover:bg-hover sm:grid-cols-[minmax(0,1fr)_120px_100px_110px]">
                          <div className="min-w-0">
                            <div className="truncate font-medium">{r.title}</div>
                            <InputChips types={r.inputTypes} />
                          </div>
                          <div>{r.status === 'completed' ? <VerdictBadge verdict={r.verdict} /> : <span className="text-[11px] uppercase tracking-wider text-dim">{r.status}</span>}</div>
                          <div className="hidden text-[12px] text-dim sm:block">
                            {r.riskIndicatorCount} <span className="text-faint">risk / {r.indicatorCount}</span>
                          </div>
                          <div className="hidden text-right text-[12px] text-faint sm:block">{timeAgo(r.createdAt)}</div>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="Latest detected patterns" bodyClassName="p-0">
                {data.latestPatterns.length === 0 ? (
                  <Empty title="Nothing of medium severity or above yet" />
                ) : (
                  <ul className="divide-y divide-line">
                    {data.latestPatterns.map((p, i) => (
                      <li key={i}>
                        <Link to={`/investigations/${p.investigationId}`} className="flex items-start gap-3 px-4 py-2.5 hover:bg-hover">
                          <SeverityBadge severity={p.severity} className="mt-0.5" />
                          <div className="min-w-0">
                            <div className="truncate text-[12.5px]">{p.title}</div>
                            <div className="truncate text-[11.5px] text-faint">
                              {CATEGORY_LABEL[p.category]} · {p.investigationTitle} · {timeAgo(p.timestamp)}
                            </div>
                          </div>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
