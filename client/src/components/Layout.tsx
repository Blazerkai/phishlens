import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { FileText, LayoutDashboard, ListTree, Menu, Plus, Settings, X } from 'lucide-react';
import type { PublicSettings } from '@phishlens/shared';
import { api } from '../lib/api';
import { cx, StatusDot } from './ui';

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/investigations', label: 'Investigations', icon: ListTree, end: false },
  { to: '/new', label: 'New Investigation', icon: Plus, end: false },
  { to: '/reports', label: 'Reports', icon: FileText, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
];

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <circle cx="14" cy="14" r="8" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <path d="M20 20 26 26" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
      <circle cx="14" cy="14" r="2.4" fill="#f2994a" />
    </svg>
  );
}

export function Layout() {
  const [settings, setSettings] = useState<PublicSettings | null>(null);
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => {
    api.settings().then(setSettings).catch(() => setSettings(null));
  }, []);
  useEffect(() => setOpen(false), [location.pathname]);

  const nav = (
    <nav className="flex flex-col gap-0.5 p-2">
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          className={({ isActive }) =>
            cx(
              'flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] transition-colors',
              isActive ? 'bg-raised font-medium text-fg shadow-[inset_2px_0_0_var(--color-accent)]' : 'text-dim hover:bg-hover hover:text-fg',
            )
          }
        >
          <Icon size={15} strokeWidth={1.75} />
          {label}
        </NavLink>
      ))}
    </nav>
  );

  const status = (
    <div className="space-y-1.5 border-t border-line px-4 py-3 text-[11.5px] text-faint">
      <div className="flex items-center gap-2">
        <StatusDot status={settings ? (settings.networkProbesEnabled ? 'ok' : 'off') : 'bad'} />
        {settings ? (settings.networkProbesEnabled ? 'Network probes enabled' : 'Network probes disabled') : 'API unreachable'}
      </div>
      {settings && (
        <>
          <div className="flex items-center gap-2">
            <StatusDot status={settings.rdapEnabled ? 'ok' : 'off'} />
            RDAP {settings.rdapEnabled ? 'enabled' : 'disabled'}
          </div>
          <div className="flex items-center gap-2">
            <StatusDot status={settings.retainRawContent ? 'warn' : 'ok'} />
            {settings.retainRawContent ? 'Raw content retained' : 'Raw content not retained'}
          </div>
          <div className="pt-1 text-faint/80">v{settings.version}</div>
        </>
      )}
    </div>
  );

  return (
    <div className="flex h-full min-h-0">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-panel md:flex">
        <div className="flex h-12 items-center gap-2 border-b border-line px-4">
          <LogoMark className="size-5 text-accent" />
          <span className="text-[14px] font-semibold tracking-tight">PhishLens</span>
        </div>
        <div className="flex-1 overflow-y-auto">{nav}</div>
        {status}
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 items-center gap-3 border-b border-line bg-panel px-4 md:hidden">
          <button onClick={() => setOpen(!open)} className="text-dim" aria-label="Toggle navigation">
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
          <LogoMark className="size-5 text-accent" />
          <span className="font-semibold">PhishLens</span>
        </header>
        {open && <div className="border-b border-line bg-panel md:hidden">{nav}{status}</div>}
        <main className="min-h-0 flex-1 overflow-y-auto">
          <Outlet context={settings} />
        </main>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: React.ReactNode; subtitle?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 border-b border-line px-4 py-4 md:px-6">
      <div className="min-w-0">
        <h1 className="truncate text-[17px] font-semibold tracking-tight">{title}</h1>
        {subtitle && <div className="mt-0.5 text-[12.5px] text-dim">{subtitle}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
