import { Check, CircleSlash, Minus, X } from 'lucide-react';
import type { TimelineEvent } from '@phishlens/shared';
import { clockTime, durationMs } from '../lib/format';
import { cx, Spinner } from './ui';

export interface StageState {
  stage: string;
  label: string;
  status: 'running' | 'completed' | 'failed' | 'unavailable' | 'skipped';
  startedAt: string;
  finishedAt: string | null;
  detail: string | null;
}

/** Folds timeline events into one row per stage. Only stages that actually started appear. */
export function stagesFromTimeline(events: TimelineEvent[]): StageState[] {
  const out = new Map<string, StageState>();
  for (const e of events) {
    if (e.stage === 'created' || e.stage === 'report' || e.stage === 'input') continue;
    if (e.status === 'started') {
      out.set(e.stage, { stage: e.stage, label: e.label, status: 'running', startedAt: e.timestamp, finishedAt: null, detail: null });
    } else {
      const s = out.get(e.stage);
      if (!s) continue;
      s.status = e.status === 'completed' ? 'completed' : e.status === 'failed' ? 'failed' : e.status === 'unavailable' ? 'unavailable' : 'skipped';
      s.finishedAt = e.timestamp;
      s.detail = e.detail;
    }
  }
  return [...out.values()];
}

const ICON = {
  running: <Spinner className="size-3.5" />,
  completed: <Check size={14} className="text-v-benign" />,
  failed: <X size={14} className="text-sev-critical" />,
  unavailable: <CircleSlash size={13} className="text-sev-medium" />,
  skipped: <Minus size={14} className="text-faint" />,
};

export function ProgressPanel({ events, status }: { events: TimelineEvent[]; status: string }) {
  const stages = stagesFromTimeline(events);
  const created = events.find((e) => e.stage === 'created');
  return (
    <div className="rounded-lg border border-line bg-panel">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <div className="flex items-center gap-2 text-[13px] font-medium">
          <Spinner /> {status === 'queued' ? 'Queued' : 'Analysis running'}
        </div>
        <span className="text-[11.5px] text-faint">Live stages from the analysis engine — nothing here is simulated</span>
      </div>
      <ol className="divide-y divide-line">
        {created && (
          <li className="grid grid-cols-[20px_1fr_auto] items-center gap-3 px-4 py-2">
            <Check size={14} className="text-v-benign" />
            <span className="text-[12.5px]">Investigation created</span>
            <span className="mono text-faint">{clockTime(created.timestamp)}</span>
          </li>
        )}
        {stages.map((s) => (
          <li key={s.stage} className="grid grid-cols-[20px_1fr_auto] items-start gap-3 px-4 py-2">
            <span className="mt-0.5">{ICON[s.status]}</span>
            <div className="min-w-0">
              <div className={cx('text-[12.5px]', s.status === 'running' ? 'text-fg' : 'text-dim')}>{s.label}</div>
              {s.detail && <div className="truncate text-[11.5px] text-faint">{s.detail}</div>}
            </div>
            <span className="mono text-faint">
              {s.finishedAt ? durationMs(new Date(s.finishedAt).getTime() - new Date(s.startedAt).getTime()) : clockTime(s.startedAt)}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}
