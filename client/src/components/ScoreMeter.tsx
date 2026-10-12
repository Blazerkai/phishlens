import type { Verdict } from '@phishlens/shared';
import { cx, VERDICT_BG } from './ui';

/** Risk score bar with the verdict thresholds marked. The score is heuristic, not a probability. */
export function ScoreMeter({ score, verdict }: { score: number; verdict: Verdict }) {
  const marks = [
    { at: 10, label: '10' },
    { at: 25, label: '25' },
    { at: 60, label: '60' },
  ];
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="label">Risk assessment</span>
        <span className="text-[12px] text-faint">heuristic score — not a probability</span>
      </div>
      <div className="mt-1 flex items-baseline gap-1">
        <span className="text-[30px] font-semibold leading-none tabular-nums">{score}</span>
        <span className="text-[13px] text-faint">/ 100</span>
      </div>
      <div className="relative mt-3 h-1.5 rounded-full bg-raised" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score} aria-label="Risk score">
        <div className={cx('absolute inset-y-0 left-0 rounded-full', VERDICT_BG[verdict])} style={{ width: `${Math.max(1.5, score)}%` }} />
        {marks.map((m) => (
          <div key={m.at} className="absolute -top-1 h-3.5 w-px bg-line-strong" style={{ left: `${m.at}%` }} />
        ))}
      </div>
      <div className="relative mt-1 h-3 text-[10px] text-faint">
        {marks.map((m) => (
          <span key={m.at} className="absolute -translate-x-1/2" style={{ left: `${m.at}%` }}>
            {m.label}
          </span>
        ))}
      </div>
    </div>
  );
}
