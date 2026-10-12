import { useState } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { AtSign, FileCode2, Globe, Layers, Link2, MessageSquareText, Play } from 'lucide-react';
import type { InvestigationInput, PublicSettings } from '@phishlens/shared';
import { api, ApiError } from '../lib/api';
import { PageHeader } from '../components/Layout';
import { Button, cx, Panel, Spinner } from '../components/ui';

type Mode = 'url' | 'domain' | 'email' | 'headers' | 'message' | 'combined';
type Field = keyof InvestigationInput;

const MODES: { id: Mode; label: string; icon: typeof Link2; hint: string }[] = [
  { id: 'url', label: 'URL', icon: Link2, hint: 'Parse the URL, follow redirects safely, inspect TLS, DNS and registration.' },
  { id: 'domain', label: 'Domain', icon: Globe, hint: 'Structure, lookalike checks, DNS, mail posture, TLS and registration.' },
  { id: 'email', label: 'Email', icon: AtSign, hint: 'Sender address: mailbox provider, brand claims, domain mail posture.' },
  { id: 'headers', label: 'Email Headers', icon: FileCode2, hint: 'SPF / DKIM / DMARC results, sender alignment, Received route anomalies.' },
  { id: 'message', label: 'Message', icon: MessageSquareText, hint: 'Social-engineering patterns, links and displayed-vs-actual URL mismatches.' },
  { id: 'combined', label: 'Combined', icon: Layers, hint: 'Submit several pieces of evidence together so findings can be correlated.' },
];

const FIELDS: Record<Field, { label: string; placeholder: string; multiline: boolean; max: number }> = {
  url: { label: 'URL', placeholder: 'https://example.com/login   (defanged hxxps://example[.]com is accepted)', multiline: false, max: 4096 },
  domain: { label: 'Domain', placeholder: 'example.com', multiline: false, max: 506 },
  email: { label: 'Email address', placeholder: 'security@example.com', multiline: false, max: 512 },
  headers: { label: 'Raw email headers', placeholder: 'Paste the full header block (Received, Authentication-Results, From, Reply-To…). In Outlook: File → Properties → Internet headers. In Gmail: ⋮ → Show original.', multiline: true, max: 262144 },
  message: { label: 'Message', placeholder: 'Paste the message text or HTML source.', multiline: true, max: 524288 },
};

const FIELDS_BY_MODE: Record<Mode, Field[]> = {
  url: ['url'],
  domain: ['domain'],
  email: ['email'],
  headers: ['headers'],
  message: ['message'],
  combined: ['url', 'email', 'headers', 'message', 'domain'],
};

export function NewInvestigationPage() {
  const settings = useOutletContext<PublicSettings | null>();
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>('url');
  const [values, setValues] = useState<InvestigationInput>({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);

  const fields = FIELDS_BY_MODE[mode];
  const payload = Object.fromEntries(fields.map((f) => [f, values[f]?.trim() ? values[f] : undefined]).filter(([, v]) => v)) as InvestigationInput;
  const ready = Object.keys(payload).length > 0;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!ready) return;
    setSubmitting(true);
    setError(null);
    try {
      const { id } = await api.create(payload);
      navigate(`/investigations/${id}`);
    } catch (err) {
      setError(err as Error);
      setSubmitting(false);
    }
  }

  const issues = error instanceof ApiError ? error.issues : [];

  return (
    <div>
      <PageHeader title="New investigation" subtitle="Submit what you have. Each input enables the analyzers that can use it; nothing is guessed when an input is missing." />
      <form onSubmit={submit} className="grid gap-4 p-4 md:p-6 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-4">
          <div role="radiogroup" aria-label="Evidence type" className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            {MODES.map(({ id, label, icon: Icon }) => (
              <button
                type="button"
                role="radio"
                aria-checked={mode === id}
                key={id}
                onClick={() => setMode(id)}
                className={cx(
                  'flex h-16 flex-col items-start justify-between rounded-lg border px-3 py-2 text-left transition-colors',
                  mode === id ? 'border-accent/70 bg-accent/[0.07]' : 'border-line bg-panel hover:border-line-strong',
                )}
              >
                <Icon size={15} className={mode === id ? 'text-accent' : 'text-faint'} />
                <span className="text-[12.5px] font-medium">{label}</span>
              </button>
            ))}
          </div>
          <p className="text-[12.5px] text-dim">{MODES.find((m) => m.id === mode)!.hint}</p>

          <Panel bodyClassName="space-y-4">
            {fields.map((f) => {
              const def = FIELDS[f];
              const v = values[f] ?? '';
              const fieldIssue = issues.find((i) => i.path === f);
              return (
                <label key={f} className="block">
                  <div className="mb-1.5 flex items-center justify-between">
                    <span className="label">{def.label}{mode === 'combined' && <span className="ml-1 normal-case tracking-normal text-faint/70">(optional)</span>}</span>
                    {def.multiline && v.length > 0 && <span className="text-[11px] tabular-nums text-faint">{v.length.toLocaleString()} chars</span>}
                  </div>
                  {def.multiline ? (
                    <textarea
                      className="input mono min-h-44 resize-y leading-relaxed"
                      placeholder={def.placeholder}
                      value={v}
                      maxLength={def.max}
                      spellCheck={false}
                      onChange={(e) => setValues({ ...values, [f]: e.target.value })}
                    />
                  ) : (
                    <input
                      className="input mono"
                      placeholder={def.placeholder}
                      value={v}
                      maxLength={def.max}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(e) => setValues({ ...values, [f]: e.target.value })}
                    />
                  )}
                  {fieldIssue && <div className="mt-1 text-[12px] text-sev-critical">{fieldIssue.message}</div>}
                </label>
              );
            })}
          </Panel>

          {error && !issues.some((i) => fields.includes(i.path as Field)) && (
            <div className="rounded-md border border-sev-critical/40 bg-sev-critical/5 px-3 py-2 text-[12.5px] text-sev-critical">{error.message}</div>
          )}

          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" disabled={!ready || submitting} className="h-9 px-4 tracking-[0.06em]">
              {submitting ? <Spinner className="border-t-[#06101f]" /> : <Play size={13} fill="currentColor" />}
              START INVESTIGATION
            </Button>
            {!ready && <span className="text-[12px] text-faint">Provide at least one input.</span>}
          </div>
        </div>

        <aside className="space-y-4">
          <Panel title="What happens">
            <ol className="space-y-2 text-[12.5px] text-dim">
              <li><span className="text-fg">Collection.</span> Inputs are parsed locally. Live DNS, TLS, HTTP and RDAP observations are made only for hosts referenced by the evidence.</li>
              <li><span className="text-fg">Analysis.</span> Deterministic rules turn observations into indicators, each with a reason, evidence and source.</li>
              <li><span className="text-fg">Assessment.</span> Indicators are correlated and summarised into an explainable verdict. No AI is involved.</li>
            </ol>
          </Panel>
          <Panel title="Safety">
            <ul className="space-y-1.5 text-[12.5px] text-dim">
              <li>Outbound requests never reach private, loopback or link-local addresses, and are limited to ports {settings?.allowedPorts.join(', ') ?? '80, 443'}.</li>
              <li>At most {settings?.maxRedirects ?? 8} redirects are followed; pages are read statically, scripts never run.</li>
              <li>{settings?.retainRawContent ? 'Raw headers and message bodies are retained (RETAIN_RAW_CONTENT=true).' : 'Raw headers and message bodies are not stored — only a SHA-256 and the derived evidence.'}</li>
              {settings && !settings.networkProbesEnabled && <li className="text-sev-medium">Network probes are disabled: DNS, TLS, redirect and RDAP data will be reported as unavailable.</li>}
            </ul>
          </Panel>
        </aside>
      </form>
    </div>
  );
}
