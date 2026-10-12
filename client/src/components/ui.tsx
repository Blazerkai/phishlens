import type { ButtonHTMLAttributes, ReactNode } from 'react';
import type { Severity, Verdict } from '@phishlens/shared';
import { VERDICT_LABEL } from '../lib/format';

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ');
}

export const SEV_TEXT: Record<Severity, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
};
export const SEV_BG: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
};
export const SEV_BORDER: Record<Severity, string> = {
  critical: 'border-sev-critical/50',
  high: 'border-sev-high/50',
  medium: 'border-sev-medium/45',
  low: 'border-sev-low/45',
  info: 'border-line-strong',
};
export const VERDICT_TEXT: Record<Verdict, string> = {
  high_risk: 'text-v-high',
  suspicious: 'text-v-suspicious',
  inconclusive: 'text-v-inconclusive',
  benign: 'text-v-benign',
};
export const VERDICT_BG: Record<Verdict, string> = {
  high_risk: 'bg-v-high',
  suspicious: 'bg-v-suspicious',
  inconclusive: 'bg-v-inconclusive',
  benign: 'bg-v-benign',
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cx(
        'inline-flex h-[18px] min-w-[58px] items-center justify-center rounded-[3px] border px-1.5 text-[10px] font-semibold uppercase tracking-[0.07em]',
        SEV_TEXT[severity],
        SEV_BORDER[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}

export function VerdictBadge({ verdict, size = 'sm' }: { verdict: Verdict | null; size?: 'sm' | 'lg' }) {
  if (!verdict) return <span className="text-[11px] uppercase tracking-wider text-faint">Pending</span>;
  return (
    <span className={cx('inline-flex items-center gap-1.5 font-semibold uppercase', VERDICT_TEXT[verdict], size === 'lg' ? 'text-lg tracking-[0.08em]' : 'text-[11px] tracking-[0.07em]')}>
      <span className={cx('rounded-full', VERDICT_BG[verdict], size === 'lg' ? 'size-2.5' : 'size-1.5')} />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function Panel({ title, actions, children, className, bodyClassName }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string }) {
  return (
    <section className={cx('rounded-lg border border-line bg-panel', className)}>
      {(title || actions) && (
        <header className="flex min-h-10 items-center justify-between gap-3 border-b border-line px-4 py-2">
          <h2 className="label">{title}</h2>
          {actions}
        </header>
      )}
      <div className={cx('p-4', bodyClassName)}>{children}</div>
    </section>
  );
}

export function Button({ variant = 'default', className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'default' | 'primary' | 'ghost' | 'danger' }) {
  return (
    <button
      {...rest}
      className={cx(
        'inline-flex h-8 items-center justify-center gap-1.5 rounded-md px-3 text-[12.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        variant === 'primary' && 'bg-accent text-[#06101f] hover:bg-[#82b5ff]',
        variant === 'default' && 'border border-line-strong bg-raised text-fg hover:bg-hover',
        variant === 'ghost' && 'text-dim hover:bg-hover hover:text-fg',
        variant === 'danger' && 'border border-sev-critical/40 text-sev-critical hover:bg-sev-critical/10',
        className,
      )}
    />
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-line">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={cx(
            '-mb-px flex shrink-0 items-center gap-2 border-b-2 px-3 py-2 text-[12.5px] font-medium transition-colors',
            value === t.id ? 'border-accent text-fg' : 'border-transparent text-dim hover:text-fg',
          )}
        >
          {t.label}
          {t.count !== undefined && <span className="rounded bg-raised px-1.5 text-[11px] text-faint">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-6 py-10 text-center">
      <div className="text-[13px] font-medium text-dim">{title}</div>
      {children && <div className="max-w-md text-[12.5px] text-faint">{children}</div>}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <span className={cx('inline-block size-3.5 animate-spin rounded-full border-2 border-line-strong border-t-accent', className)} aria-label="Loading" />;
}

export function KeyValue({ items, className }: { items: { label: ReactNode; value: ReactNode; mono?: boolean }[]; className?: string }) {
  return (
    <dl className={cx('grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-5 gap-y-1.5', className)}>
      {items.map((i, idx) => (
        <div key={idx} className="contents">
          <dt className="text-[12px] text-faint">{i.label}</dt>
          <dd className={cx('min-w-0 break-words text-[12.5px] text-fg', i.mono && 'mono')}>{i.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function StatusDot({ status }: { status: 'ok' | 'warn' | 'bad' | 'off' }) {
  const c = { ok: 'bg-v-benign', warn: 'bg-sev-medium', bad: 'bg-sev-critical', off: 'bg-faint' }[status];
  return <span className={cx('inline-block size-1.5 rounded-full', c)} />;
}

export function ErrorNote({ error }: { error: Error | null }) {
  if (!error) return null;
  return <div className="rounded-md border border-sev-critical/40 bg-sev-critical/5 px-3 py-2 text-[12.5px] text-sev-critical">{error.message}</div>;
}

export function AuthPill({ label, result }: { label: string; result: string }) {
  const tone =
    result === 'pass' ? 'text-v-benign border-v-benign/40' : result === 'fail' ? 'text-sev-critical border-sev-critical/50' : result === 'softfail' ? 'text-sev-high border-sev-high/45' : 'text-dim border-line-strong';
  return (
    <span className={cx('inline-flex items-center gap-2 rounded-md border px-2.5 py-1', tone)}>
      <span className="text-[11px] font-semibold tracking-[0.06em] text-faint">{label}</span>
      <span className="text-[12.5px] font-semibold uppercase">{result}</span>
    </span>
  );
}
