import { Link } from 'react-router-dom';
import { Download, ExternalLink } from 'lucide-react';
import { api } from '../lib/api';
import { useResource } from '../lib/hooks';
import { dateTime, shortId } from '../lib/format';
import { PageHeader } from '../components/Layout';
import { Button, Empty, ErrorNote, Panel, Spinner, VerdictBadge } from '../components/ui';

export function ReportsPage() {
  const { data, error, loading } = useResource(() => api.list({ status: 'completed', limit: 100 }), []);
  return (
    <div>
      <PageHeader title="Reports" subtitle="Export completed investigations as a printable HTML report, Markdown for tickets, or JSON for tooling." />
      <div className="space-y-4 p-4 md:p-6">
        <ErrorNote error={error} />
        <Panel bodyClassName="p-0">
          {loading && !data ? (
            <div className="flex items-center gap-2 p-4 text-dim"><Spinner /> Loading</div>
          ) : !data?.items.length ? (
            <Empty title="No completed investigations yet" />
          ) : (
            <ul className="divide-y divide-line">
              {data.items.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                  <div className="min-w-0">
                    <Link to={`/investigations/${r.id}`} className="block truncate font-medium hover:text-accent">{r.title}</Link>
                    <div className="flex flex-wrap items-center gap-3 text-[12px] text-faint">
                      <span className="mono">{shortId(r.id)}</span>
                      <span>{dateTime(r.completedAt)}</span>
                      <VerdictBadge verdict={r.verdict} />
                      <span>score {r.score}</span>
                      <span>{r.indicatorCount} indicators</span>
                    </div>
                  </div>
                  <div className="flex gap-1.5">
                    <a href={api.reportUrl(r.id, 'html')} target="_blank" rel="noopener noreferrer"><Button><ExternalLink size={13} /> HTML</Button></a>
                    <a href={api.reportUrl(r.id, 'md', true)}><Button><Download size={13} /> MD</Button></a>
                    <a href={api.reportUrl(r.id, 'json', true)}><Button><Download size={13} /> JSON</Button></a>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <p className="text-[12px] text-faint">Tip: open the HTML report and use your browser’s Print → Save as PDF to attach it to a ticket. Reports include inputs (or their hashes when raw content is not retained), every indicator with its evidence, technical observations, the timeline and limitations.</p>
      </div>
    </div>
  );
}
