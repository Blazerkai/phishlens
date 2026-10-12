import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Maximize2, Minus, Plus } from 'lucide-react';
import type { EvidenceGraph as Graph, GraphNode, GraphNodeType, Indicator, Severity } from '@phishlens/shared';
import { layoutGraph, NODE_H, NODE_W } from '../lib/graphLayout';
import { SEVERITY_ORDER } from '../lib/format';
import { IndicatorRow } from './IndicatorList';
import { Button, cx, Empty, KeyValue, SeverityBadge } from './ui';

const TYPE_LABEL: Record<GraphNodeType, string> = {
  investigation: 'Investigation',
  email: 'Email',
  address: 'Address',
  domain: 'Domain',
  host: 'Host',
  ip: 'IP',
  url: 'URL',
  redirect: 'Redirect',
  certificate: 'TLS certificate',
  dns: 'DNS',
  mailserver: 'Mail server',
  message: 'Message',
  registration: 'Registration',
};

const RISK_COLOR: Record<Severity, string> = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
  info: 'var(--color-line-strong)',
};

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function EvidenceGraph({ graph, indicators }: { graph: Graph; indicators: Indicator[] }) {
  const layout = useMemo(() => layoutGraph(graph), [graph]);
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const indById = useMemo(() => new Map(indicators.map((i) => [i.id, i])), [indicators]);
  const [selected, setSelected] = useState<string>(() => {
    // Start on the riskiest node, so the most important evidence is one glance away.
    const ranked = [...graph.nodes].filter((n) => n.risk).sort((a, b) => SEVERITY_ORDER.indexOf(a.risk!) - SEVERITY_ORDER.indexOf(b.risk!));
    return ranked[0]?.id ?? graph.rootId;
  });
  const svgRef = useRef<SVGSVGElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const PAD = 24;

  const fit = useCallback(() => {
    const el = svgRef.current;
    if (!el) return;
    const { width, height } = el.getBoundingClientRect();
    const k = Math.min(1.15, (width - PAD * 2) / layout.width, (height - PAD * 2) / layout.height);
    setView({ k, x: (width - layout.width * k) / 2, y: (height - layout.height * k) / 2 });
  }, [layout]);

  /** Large graphs open at a readable zoom centred on a node instead of shrinking everything to fit. */
  const focus = useCallback(
    (nodeId: string) => {
      const el = svgRef.current;
      const p = layout.nodes.get(nodeId);
      if (!el || !p) return;
      const { width, height } = el.getBoundingClientRect();
      const fitK = Math.min((width - PAD * 2) / layout.width, (height - PAD * 2) / layout.height);
      if (fitK >= 0.7) return fit();
      const k = 0.9;
      setView({ k, x: width / 2 - (p.x + NODE_W / 2) * k, y: height / 2 - (p.y + NODE_H / 2) * k });
    },
    [layout, fit],
  );
  const initialFocus = useRef(selected);
  useEffect(() => {
    focus(initialFocus.current);
  }, [focus]);

  const onWheel = (e: React.WheelEvent) => {
    const rect = svgRef.current!.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const k = Math.min(2.5, Math.max(0.25, view.k * (e.deltaY < 0 ? 1.1 : 1 / 1.1)));
    setView({ k, x: mx - ((mx - view.x) * k) / view.k, y: my - ((my - view.y) * k) / view.k });
  };
  const zoom = (f: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    const k = Math.min(2.5, Math.max(0.25, view.k * f));
    setView({ k, x: rect.width / 2 - ((rect.width / 2 - view.x) * k) / view.k, y: rect.height / 2 - ((rect.height / 2 - view.y) * k) / view.k });
  };

  const sel = byId.get(selected);
  const selIndicators = (sel?.indicatorIds ?? []).map((id) => indById.get(id)!).filter(Boolean).sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const neighbours = new Set(graph.edges.filter((e) => e.from === selected || e.to === selected).flatMap((e) => [e.from, e.to]));

  const edgePath = (from: string, to: string) => {
    const a = layout.nodes.get(from)!;
    const b = layout.nodes.get(to)!;
    const forward = b.x > a.x;
    const x1 = forward ? a.x + NODE_W : a.x;
    const y1 = a.y + NODE_H / 2;
    const x2 = forward ? b.x : b.x + NODE_W;
    const y2 = b.y + NODE_H / 2;
    const dx = Math.max(40, Math.abs(x2 - x1) / 2) * (forward ? 1 : -1);
    return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`;
  };

  return (
    <div className="grid min-h-[640px] lg:grid-cols-[minmax(0,1fr)_400px]">
      <div className="relative min-h-[560px] border-b border-line lg:border-b-0 lg:border-r">
        <div className="absolute right-3 top-3 z-10 flex gap-1">
          <Button variant="default" className="size-8 px-0" onClick={() => zoom(1.2)} aria-label="Zoom in"><Plus size={14} /></Button>
          <Button variant="default" className="size-8 px-0" onClick={() => zoom(1 / 1.2)} aria-label="Zoom out"><Minus size={14} /></Button>
          <Button variant="default" className="size-8 px-0" onClick={fit} aria-label="Fit to view"><Maximize2 size={13} /></Button>
        </div>
        <div className="absolute bottom-3 left-3 z-10 flex flex-wrap gap-x-3 gap-y-1 rounded-md border border-line bg-panel/95 px-2.5 py-1.5 text-[11px] text-faint">
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
            <span key={s} className="flex items-center gap-1.5 capitalize">
              <span className="h-2.5 w-1 rounded-sm" style={{ background: RISK_COLOR[s] }} /> {s}
            </span>
          ))}
          <span>· drag to pan, scroll to zoom, click a node to inspect</span>
        </div>
        <svg
          ref={svgRef}
          className={cx('absolute inset-0 h-full w-full touch-none select-none', drag.current ? 'cursor-grabbing' : 'cursor-grab')}
          onWheel={onWheel}
          onPointerDown={(e) => {
            if ((e.target as Element).closest('[data-node]')) return;
            drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
            (e.currentTarget as SVGSVGElement).setPointerCapture(e.pointerId);
          }}
          onPointerMove={(e) => {
            if (!drag.current) return;
            setView((v) => ({ ...v, x: drag.current!.vx + e.clientX - drag.current!.x, y: drag.current!.vy + e.clientY - drag.current!.y }));
          }}
          onPointerUp={() => (drag.current = null)}
          role="img"
          aria-label="Evidence relationship graph"
        >
          <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {graph.edges.map((e) => {
              const active = e.from === selected || e.to === selected;
              const tree = layout.treeEdges.has(`${e.from}->${e.to}`);
              const a = layout.nodes.get(e.from)!;
              const b = layout.nodes.get(e.to)!;
              return (
                <g key={e.id}>
                  <path d={edgePath(e.from, e.to)} fill="none" stroke={active ? 'var(--color-accent)' : 'var(--color-line-strong)'} strokeWidth={active ? 1.6 : 1} strokeDasharray={tree ? undefined : '4 4'} opacity={active ? 1 : 0.85} />
                  {active && (
                    <text x={(a.x + NODE_W + b.x) / 2} y={(a.y + b.y) / 2 + NODE_H / 2 - 5} textAnchor="middle" fontSize={10} fill="var(--color-dim)" style={{ paintOrder: 'stroke', stroke: 'var(--color-bg)', strokeWidth: 4 }}>
                      {e.label}
                    </text>
                  )}
                </g>
              );
            })}
            {graph.nodes.map((n) => {
              const p = layout.nodes.get(n.id)!;
              return <Node key={n.id} n={n} x={p.x} y={p.y} selected={n.id === selected} dim={!!selected && n.id !== selected && !neighbours.has(n.id)} onSelect={() => setSelected(n.id)} />;
            })}
          </g>
        </svg>
      </div>

      <aside className="max-h-[760px] overflow-y-auto">
        {!sel ? (
          <Empty title="Select a node" />
        ) : (
          <div>
            <div className="border-b border-line px-4 py-3">
              <div className="label">{TYPE_LABEL[sel.type]}</div>
              <div className="mono mt-1 break-all text-[13px] text-fg">{sel.label}</div>
              {sel.sublabel && <div className="mt-0.5 text-[12px] text-dim">{sel.sublabel}</div>}
              {sel.risk && (
                <div className="mt-2 flex items-center gap-2 text-[12px] text-dim">
                  Highest risk on this node <SeverityBadge severity={sel.risk} />
                </div>
              )}
            </div>
            {sel.facts.length > 0 && (
              <div className="border-b border-line px-4 py-3">
                <div className="label mb-2">Observed facts</div>
                <KeyValue items={sel.facts.map((f) => ({ label: f.label, value: f.value, mono: true }))} />
              </div>
            )}
            <div>
              <div className="label px-4 pb-1 pt-3">Evidence attached ({selIndicators.length})</div>
              {selIndicators.length === 0 ? (
                <div className="px-4 pb-4 text-[12.5px] text-faint">No indicators reference this entity directly.</div>
              ) : (
                <ul className="divide-y divide-line">{selIndicators.map((i) => <IndicatorRow key={i.id} i={i} compact />)}</ul>
              )}
            </div>
            <ConnectedList graph={graph} id={sel.id} onSelect={setSelected} byId={byId} />
          </div>
        )}
      </aside>
    </div>
  );
}

function ConnectedList({ graph, id, onSelect, byId }: { graph: Graph; id: string; onSelect: (id: string) => void; byId: Map<string, GraphNode> }) {
  const links = graph.edges.filter((e) => e.from === id || e.to === id);
  if (!links.length) return null;
  return (
    <div className="border-t border-line px-4 py-3">
      <div className="label mb-2">Connected</div>
      <ul className="space-y-1">
        {links.map((e) => {
          const other = byId.get(e.from === id ? e.to : e.from)!;
          return (
            <li key={e.id}>
              <button onClick={() => onSelect(other.id)} className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-[12px] hover:bg-hover">
                <span className="w-24 shrink-0 text-faint">{e.from === id ? e.label : `← ${e.label}`}</span>
                <span className="mono truncate text-dim">{other.label}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function Node({ n, x, y, selected, dim, onSelect }: { n: GraphNode; x: number; y: number; selected: boolean; dim: boolean; onSelect: () => void }) {
  const risk = n.risk ? RISK_COLOR[n.risk] : 'var(--color-line-strong)';
  return (
    <g
      data-node
      transform={`translate(${x},${y})`}
      onClick={onSelect}
      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onSelect()}
      role="button"
      tabIndex={0}
      aria-label={`${TYPE_LABEL[n.type]} ${n.label}${n.risk ? `, ${n.risk} risk` : ''}`}
      className="cursor-pointer outline-none"
      opacity={dim ? 0.45 : 1}
    >
      <rect width={NODE_W} height={NODE_H} rx={6} fill={selected ? 'var(--color-raised)' : 'var(--color-panel)'} stroke={selected ? 'var(--color-accent)' : 'var(--color-line-strong)'} strokeWidth={selected ? 1.5 : 1} />
      <rect x={0} y={0} width={3.5} height={NODE_H} rx={1.5} fill={risk} />
      <text x={12} y={16} fontSize={9.5} letterSpacing="0.08em" fill="var(--color-faint)">
        {TYPE_LABEL[n.type].toUpperCase()}
        {n.indicatorIds.length > 0 && <tspan fill="var(--color-dim)">{`  · ${n.indicatorIds.length}`}</tspan>}
      </text>
      <text x={12} y={32} fontSize={12} fill="var(--color-fg)" fontFamily="var(--font-mono)">
        {clip(n.label, 25)}
      </text>
      <title>{`${n.label}${n.sublabel ? `\n${n.sublabel}` : ''}`}</title>
    </g>
  );
}
