import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Plus, Search } from 'lucide-react';
import { VERDICTS } from '@phishlens/shared';
import { api } from '../lib/api';
import { useResource } from '../lib/hooks';
import { dateTime, shortId, timeAgo, VERDICT_LABEL } from '../lib/format';
import { PageHeader } from '../components/Layout';
import { Button, cx, Empty, ErrorNote, Panel, Spinner, VerdictBadge } from '../components/ui';
import { InputChips } from '../components/InputChips';

const PAGE = 25;

export function InvestigationsPage() {
  const [params, setParams] = useSearchParams();
  const verdict = params.get('verdict') ?? '';
  const q = params.get('q') ?? '';
  const page = Number(params.get('page') ?? '0');
  const [query, setQuery] = useState(q);

  useEffect(() => {
    const t = setTimeout(() => {
      if (query !== q) setParams((p) => { const n = new URLSearchParams(p); if (query) n.set('q', query); else n.delete('q'); n.delete('page'); return n; });
    }, 250);
    return () => clearTimeout(t);
  }, [query, q, setParams]);

  const { data, error, loading } = useResource(
    () => api.list({ verdict: verdict || undefined, q: q || undefined, limit: PAGE, offset: page * PAGE }),
    [verdict, q, page],
    { pollMs: 2000, pollWhile: (d) => d.items.some((i) => i.status === 'queued' || i.status === 'running') },
  );

  const setVerdict = (v: string) => setParams((p) => { const n = new URLSearchParams(p); if (v) n.set('verdict', v); else n.delete('verdict'); n.delete('page'); return n; });

  return (
    <div>
      <PageHeader
        title="Investigations"
        subtitle={data ? `${data.total} investigation${data.total === 1 ? '' : 's'}` : ' '}
        actions={<Link to="/new"><Button variant="primary"><Plus size={14} /> New investigation</Button></Link>}
      />
      <div className="space-y-4 p-4 md:p-6">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full max-w-xs">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-2.5 text-faint" />
            <input className="input pl-8" placeholder="Search title or ID" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search investigations" />
          </div>
          <div className="flex flex-wrap gap-1">
            {['', ...VERDICTS].map((v) => (
              <button
                key={v || 'all'}
                onClick={() => setVerdict(v)}
                className={cx('h-8 rounded-md border px-3 text-[12px]', verdict === v ? 'border-accent/60 bg-accent/10 text-fg' : 'border-line text-dim hover:text-fg')}
              >
                {v ? VERDICT_LABEL[v as keyof typeof VERDICT_LABEL] : 'All'}
              </button>
            ))}
          </div>
        </div>
        <ErrorNote error={error} />
        <Panel bodyClassName="p-0">
          {loading && !data ? (
            <div className="flex items-center gap-2 p-4 text-dim"><Spinner /> Loading</div>
          ) : !data || data.items.length === 0 ? (
            <Empty title="No investigations match">Adjust the filter or start a new investigation.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left">
                <thead>
                  <tr className="border-b border-line">
                    {['Subject', 'Verdict', 'Score', 'Indicators', 'Created', 'ID'].map((h) => (
                      <th key={h} className="label px-4 py-2 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {data.items.map((r) => (
                    <tr key={r.id} className="hover:bg-hover">
                      <td className="max-w-[380px] px-4 py-2.5">
                        <Link to={`/investigations/${r.id}`} className="block truncate font-medium hover:text-accent">{r.title}</Link>
                        <InputChips types={r.inputTypes} />
                      </td>
                      <td className="px-4 py-2.5">
                        {r.status === 'completed' ? <VerdictBadge verdict={r.verdict} /> : (
                          <span className={cx('flex items-center gap-2 text-[11px] uppercase tracking-wider', r.status === 'failed' ? 'text-sev-critical' : 'text-dim')}>
                            {(r.status === 'running' || r.status === 'queued') && <Spinner className="size-3" />} {r.status}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 tabular-nums text-dim">{r.score ?? '—'}</td>
                      <td className="px-4 py-2.5 tabular-nums text-dim">{r.riskIndicatorCount} <span className="text-faint">/ {r.indicatorCount}</span></td>
                      <td className="px-4 py-2.5 text-[12px] text-dim" title={dateTime(r.createdAt)}>{timeAgo(r.createdAt)}</td>
                      <td className="mono px-4 py-2.5 text-faint">{shortId(r.id)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        {data && data.total > PAGE && (
          <div className="flex items-center justify-end gap-2 text-[12px] text-dim">
            <span>Page {page + 1} of {Math.ceil(data.total / PAGE)}</span>
            <Button disabled={page === 0} onClick={() => setParams((p) => { const n = new URLSearchParams(p); n.set('page', String(page - 1)); return n; })}>Previous</Button>
            <Button disabled={(page + 1) * PAGE >= data.total} onClick={() => setParams((p) => { const n = new URLSearchParams(p); n.set('page', String(page + 1)); return n; })}>Next</Button>
          </div>
        )}
      </div>
    </div>
  );
}
