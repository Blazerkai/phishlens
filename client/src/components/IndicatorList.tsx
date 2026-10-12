import { useMemo, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import type { Indicator, PositiveEvidenceFamily, Severity } from '@phishlens/shared';
import { CATEGORY_LABEL, clockTime, SEVERITY_ORDER } from '../lib/format';
import { cx, Empty, SeverityBadge } from './ui';

const PROVENANCE_LABEL: Record<Indicator['provenance'], string> = {
  user_input: 'Submitted data',
  network: 'Live network observation',
  analysis: 'Deterministic analysis',
  external: 'External source',
};

const POLARITY_LABEL: Record<Indicator['polarity'], string> = {
  risk: 'Negative — raises concern',
  benign: 'Positive — verified',
  neutral: 'Neutral — context only',
  unknown: 'Unknown — check could not be completed',
};

export function IndicatorRow({ i, defaultOpen = false, compact = false, family }: { i: Indicator; defaultOpen?: boolean; compact?: boolean; family?: PositiveEvidenceFamily }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <li id={`ind-${i.id}`} className="scroll-mt-20">
      <button
        onClick={() => setOpen(!open)}
        className={cx('grid w-full grid-cols-[14px_64px_minmax(0,1fr)] items-center gap-3 px-4 py-2.5 text-left hover:bg-hover', !compact && 'sm:grid-cols-[14px_64px_minmax(0,1fr)_150px_70px]')}
        aria-expanded={open}
      >
        <ChevronRight size={13} className={cx('text-faint transition-transform', open && 'rotate-90')} />
        <SeverityBadge severity={i.severity} />
        <span className="min-w-0">
          <span className="block truncate text-[13px]">
            {i.title}
            {i.polarity === 'benign' && <span className="ml-2 rounded-[3px] border border-v-benign/40 px-1 text-[10px] uppercase tracking-wider text-v-benign">positive</span>}
            {i.polarity === 'unknown' && <span className="ml-2 rounded-[3px] border border-sev-medium/40 px-1 text-[10px] uppercase tracking-wider text-sev-medium">unknown</span>}
          </span>
          {!open && <span className="mono block truncate text-faint">{i.evidence}</span>}
        </span>
        {!compact && <span className="hidden truncate text-[12px] text-dim sm:block">{CATEGORY_LABEL[i.category]}</span>}
        {!compact && <span className="hidden text-right text-[12px] tabular-nums text-faint sm:block" title="Rule confidence">{Math.round(i.confidence * 100)}%</span>}
      </button>
      {open && (
        <div className={cx('grid gap-x-6 gap-y-2.5 border-t border-line/60 bg-bg/40 px-4 py-3 text-[12.5px]', compact ? 'pl-4' : 'pl-[46px] md:grid-cols-[96px_1fr]')}>
          <span className="label pt-0.5">Reason</span>
          <p className="text-dim">{i.description}</p>
          <span className="label pt-0.5">Evidence</span>
          <pre className="mono overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-line bg-bg px-3 py-2 text-fg">{i.evidence}</pre>
          <span className="label pt-0.5">Source</span>
          <span className="text-dim">
            {i.source} <span className="text-faint">· {PROVENANCE_LABEL[i.provenance]}</span>
          </span>
          <span className="label pt-0.5">Assessment</span>
          <span className="text-dim">
            {POLARITY_LABEL[i.polarity]} · confidence {Math.round(i.confidence * 100)}% (reliability of this rule, not a probability)
            {family && (
              <span className="block text-faint">
                Evidence family: {family.label} · {family.indicatorIds.length > 1 ? `correlated with ${family.indicatorIds.length - 1} other observation(s), counted once` : 'independent'}
                {!family.counted && ' · not counted (contradicted)'}
              </span>
            )}
          </span>
          <span className="label pt-0.5">Rule</span>
          <span className="mono text-faint">
            {i.code} · analyzer {i.analyzer} · confidence {i.confidence} · {i.polarity} · {clockTime(i.timestamp)}
          </span>
        </div>
      )}
    </li>
  );
}

export function IndicatorList({ indicators, families = [] }: { indicators: Indicator[]; families?: PositiveEvidenceFamily[] }) {
  const familyOf = useMemo(() => new Map(families.flatMap((f) => f.indicatorIds.map((id) => [id, f] as const))), [families]);
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const [showContext, setShowContext] = useState(true);
  const sorted = useMemo(
    () =>
      [...indicators]
        .filter((i) => (sev === 'all' ? true : i.severity === sev))
        .filter((i) => showContext || i.polarity === 'risk')
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.confidence - a.confidence),
    [indicators, sev, showContext],
  );
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, indicators.filter((i) => i.severity === s).length]));

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2">
        <div className="flex flex-wrap gap-1">
          {(['all', ...SEVERITY_ORDER] as const).map((s) => (
            <button
              key={s}
              onClick={() => setSev(s)}
              className={cx('h-7 rounded-md border px-2.5 text-[11.5px] capitalize', sev === s ? 'border-accent/60 bg-accent/10 text-fg' : 'border-line text-dim hover:text-fg')}
            >
              {s} <span className="text-faint">{s === 'all' ? indicators.length : counts[s]}</span>
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-[12px] text-dim">
          <input type="checkbox" checked={showContext} onChange={(e) => setShowContext(e.target.checked)} className="accent-[var(--color-accent)]" />
          Show context &amp; benign signals
        </label>
      </div>
      {sorted.length === 0 ? <Empty title="No indicators match this filter" /> : <ul className="divide-y divide-line">{sorted.map((i) => <IndicatorRow key={i.id} i={i} family={familyOf.get(i.id)} />)}</ul>}
    </div>
  );
}
