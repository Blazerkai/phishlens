import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Plus, Trash2 } from 'lucide-react';
import { VERIFICATION_METHODS, type PublicSettings, type VerificationMethod } from '@phishlens/shared';
import { api, ApiError } from '../lib/api';
import { useResource } from '../lib/hooks';
import { PageHeader } from '../components/Layout';
import { Button, cx, Empty, ErrorNote, KeyValue, Panel, StatusDot } from '../components/ui';
import { dateTime } from '../lib/format';

const METHOD_LABEL: Record<VerificationMethod, string> = {
  legal_entity_registry: 'Legal-entity registry record',
  direct_contact: 'Direct contact via an independently sourced channel',
  contractual_relationship: 'Existing contractual / business relationship',
  official_publication: 'Official publication (filing, annual report)',
  other: 'Other documented method',
};

const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);

export function SettingsPage() {
  const settings = useOutletContext<PublicSettings | null>();
  const brands = useResource(() => api.brands(), []);
  const [form, setForm] = useState({ name: '', keywords: '', domains: '' });
  const [err, setErr] = useState<Error | null>(null);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      await api.addBrand({ name: form.name.trim(), keywords: list(form.keywords), officialDomains: list(form.domains) });
      setForm({ name: '', keywords: '', domains: '' });
      await brands.refresh();
    } catch (x) {
      setErr(x instanceof ApiError && x.issues.length ? new Error(x.issues.map((i) => `${i.path}: ${i.message}`).join('; ')) : (x as Error));
    }
  };
  const remove = async (id: number) => {
    await api.deleteBrand(id);
    await brands.refresh();
  };

  const onOff = (v: boolean | undefined) => (
    <span className="flex items-center gap-2"><StatusDot status={v ? 'ok' : 'off'} />{v ? 'enabled' : 'disabled'}</span>
  );

  return (
    <div>
      <PageHeader title="Settings" subtitle="Runtime configuration is read from environment variables on the server; the brand watchlist is managed here." />
      <div className="grid gap-4 p-4 md:p-6 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
        <div className="space-y-4">
          <Panel title="Collection">
            {settings ? (
              <KeyValue
                items={[
                  { label: 'Network probes', value: onOff(settings.networkProbesEnabled) },
                  { label: 'RDAP lookups', value: onOff(settings.rdapEnabled) },
                  { label: 'Allowed ports', value: settings.allowedPorts.join(', '), mono: true },
                  { label: 'Max redirects', value: settings.maxRedirects, mono: true },
                  { label: 'Request timeout', value: `${settings.requestTimeoutMs} ms`, mono: true },
                ]}
              />
            ) : <Empty title="API unreachable" />}
          </Panel>
          <Panel title="Data handling">
            {settings && (
              <KeyValue
                items={[
                  { label: 'Raw content', value: settings.retainRawContent ? 'retained (RETAIN_RAW_CONTENT=true)' : 'not retained — SHA-256 and derived evidence only' },
                  { label: 'Retention', value: settings.retentionDays > 0 ? `investigations deleted after ${settings.retentionDays} days` : 'kept indefinitely' },
                  { label: 'AI narrative', value: settings.aiSummaryAvailable ? `enabled (${settings.aiProvider})` : 'disabled' },
                  { label: 'Version', value: settings.version, mono: true },
                ]}
              />
            )}
          </Panel>
        </div>

        <div className="space-y-4">
        <Panel title="Reputation providers">
          <p className="mb-3 text-[12.5px] text-dim">
            Optional. Configure with environment variables and restart. A blocklist not listing a domain is <strong className="font-medium text-fg">neutral</strong>; only listings (risk) and sustained popularity (corroboration) affect the verdict. Unavailable providers are reported as unknown, never as clean.
          </p>
          <ul className="space-y-2.5">
            {(settings?.reputationProviders ?? []).map((p) => (
              <li key={p.id} className="text-[12.5px]">
                <div className="flex items-center gap-2">
                  <StatusDot status={p.configured ? 'ok' : 'off'} />
                  <span className="font-medium">{p.name}</span>
                  <span className="text-[11px] text-faint">{p.kind} · {p.configured ? 'configured' : 'not configured'}</span>
                </div>
                <div className="pl-3.5 text-[12px] text-faint">{p.requirement}. {p.terms}</div>
              </li>
            ))}
          </ul>
        </Panel>
        <VerifiedOperators />

        <Panel title="Brand watchlist">
          <p className="mb-3 text-[12.5px] text-dim">
            Used by the lookalike-domain and brand-claim <strong className="font-medium text-fg">heuristics</strong>. It is deliberately not a global brand database: list your own organisation, its vendors and the services your users rely on. A domain is only treated as official if it is listed here.
          </p>
          <form onSubmit={add} className="grid gap-2 rounded-md border border-line p-3 md:grid-cols-[1fr_1fr_1.4fr_auto]">
            <input className="input" placeholder="Name (e.g. Contoso)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} aria-label="Brand name" />
            <input className="input mono" placeholder="keywords: contoso" value={form.keywords} onChange={(e) => setForm({ ...form, keywords: e.target.value })} aria-label="Keywords" />
            <input className="input mono" placeholder="official domains: contoso.com, contoso.net" value={form.domains} onChange={(e) => setForm({ ...form, domains: e.target.value })} aria-label="Official domains" />
            <Button type="submit" variant="primary" disabled={!form.name.trim() || !list(form.keywords).length}><Plus size={13} /> Add</Button>
          </form>
          <div className="mt-2"><ErrorNote error={err ?? brands.error} /></div>
          {brands.data && brands.data.length === 0 && <Empty title="Watchlist is empty">Lookalike detection is inactive until brands are added.</Empty>}
          {brands.data && brands.data.length > 0 && (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-[520px] text-left text-[12.5px]">
                <thead><tr className="border-b border-line">{['Brand', 'Keywords', 'Official domains', ''].map((h) => <th key={h} className="label px-2 py-2 font-medium">{h}</th>)}</tr></thead>
                <tbody className="divide-y divide-line">
                  {brands.data.map((b) => (
                    <tr key={b.id}>
                      <td className="px-2 py-2 font-medium">{b.name}</td>
                      <td className="mono px-2 py-2 text-dim">{b.keywords.join(', ')}</td>
                      <td className="mono px-2 py-2 text-dim">{b.officialDomains.join(', ') || '—'}</td>
                      <td className="px-2 py-2 text-right"><Button variant="ghost" onClick={() => remove(b.id)} aria-label={`Remove ${b.name}`}><Trash2 size={13} /></Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        </div>
      </div>
    </div>
  );
}

function VerifiedOperators() {
  const list = useResource(() => api.verifications(), []);
  const empty = { domain: '', operatorName: '', method: 'legal_entity_registry' as VerificationMethod, evidenceReference: '', verifiedBy: '', validDays: 365 };
  const [form, setForm] = useState(empty);
  const [err, setErr] = useState<Error | null>(null);
  const now = Date.now();

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      await api.addVerification(form);
      setForm(empty);
      await list.refresh();
    } catch (x) {
      setErr(x instanceof ApiError && x.issues.length ? new Error(x.issues.map((i) => `${i.path}: ${i.message}`).join('; ')) : (x as Error));
    }
  };

  return (
    <Panel title="Verified operators">
      <p className="mb-3 text-[12.5px] text-dim">
        Record that you independently established <strong className="font-medium text-fg">who operates</strong> a domain. It counts as identity corroboration only for that domain as the investigated destination, expires, and never offsets risk findings. Controlling DNS or a website does not qualify — anyone who registers a domain has that.
      </p>
      <form onSubmit={add} className="grid gap-2 rounded-md border border-line p-3 md:grid-cols-2">
        <input className="input mono" placeholder="Domain (e.g. example.com)" value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} aria-label="Domain" />
        <input className="input" placeholder="Operator (legal name)" value={form.operatorName} onChange={(e) => setForm({ ...form, operatorName: e.target.value })} aria-label="Operator name" />
        <select className="input" value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value as VerificationMethod })} aria-label="Verification method">
          {VERIFICATION_METHODS.map((m) => <option key={m} value={m}>{METHOD_LABEL[m]}</option>)}
        </select>
        <input className="input" placeholder="Verified by (analyst)" value={form.verifiedBy} onChange={(e) => setForm({ ...form, verifiedBy: e.target.value })} aria-label="Verified by" />
        <input className="input md:col-span-2" placeholder="Supporting evidence (registry name and ID, ticket, document reference)" value={form.evidenceReference} onChange={(e) => setForm({ ...form, evidenceReference: e.target.value })} aria-label="Evidence reference" />
        <label className="flex items-center gap-2 text-[12px] text-dim">
          Valid for
          <input type="number" min={1} max={730} className="input w-24" value={form.validDays} onChange={(e) => setForm({ ...form, validDays: Number(e.target.value) })} aria-label="Valid days" />
          days
        </label>
        <div className="flex justify-end"><Button type="submit" variant="primary" disabled={!form.domain || !form.operatorName || !form.evidenceReference || !form.verifiedBy}><Plus size={13} /> Record verification</Button></div>
      </form>
      <div className="mt-2"><ErrorNote error={err ?? list.error} /></div>
      {list.data && list.data.length === 0 && <Empty title="No verified operators recorded" />}
      {list.data && list.data.length > 0 && (
        <ul className="mt-3 divide-y divide-line">
          {list.data.map((v) => {
            const state = v.revokedAt ? 'revoked' : Date.parse(v.expiresAt) < now ? 'expired' : 'active';
            return (
              <li key={v.id} className="flex flex-wrap items-start justify-between gap-2 py-2 text-[12.5px]">
                <div className="min-w-0">
                  <div><span className="mono">{v.domain}</span> → <span className="font-medium">{v.operatorName}</span></div>
                  <div className="text-[12px] text-faint">{METHOD_LABEL[v.method]} · {v.evidenceReference}</div>
                  <div className="text-[11px] text-faint">by {v.verifiedBy} · {dateTime(v.verifiedAt)} · expires {dateTime(v.expiresAt)}</div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={cx('text-[11px] uppercase tracking-wider', state === 'active' ? 'text-v-benign' : 'text-faint')}>{state}</span>
                  {state === 'active' && <Button variant="ghost" onClick={async () => { await api.revokeVerification(v.id); await list.refresh(); }}>Revoke</Button>}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
