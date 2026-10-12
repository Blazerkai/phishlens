import type {
  AiSummary,
  Brand,
  DashboardStats,
  InvestigationDetail,
  InvestigationInput,
  InvestigationSummary,
  OperatorVerification,
  PublicSettings,
  Verdict,
} from '@phishlens/shared';

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly issues: { path: string; message: string }[] = [],
  ) {
    super(message);
  }
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
  });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(body.message ?? `Request failed (${res.status})`, res.status, body.issues ?? []);
  return body as T;
}

export type InvestigationView = InvestigationDetail & {
  aiSummary: AiSummary | null;
  related: { id: string; title: string; verdict: Verdict | null; shared: string }[];
};

export const api = {
  settings: () => call<PublicSettings>('/settings'),
  dashboard: () => call<DashboardStats>('/dashboard'),
  list: (q: { verdict?: string; q?: string; limit?: number; offset?: number; status?: string } = {}) => {
    const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => [k, String(v)]));
    return call<{ items: InvestigationSummary[]; total: number }>(`/investigations${p.size ? `?${p}` : ''}`);
  },
  get: (id: string) => call<InvestigationView>(`/investigations/${encodeURIComponent(id)}`),
  create: (input: InvestigationInput) => call<{ id: string }>('/investigations', { method: 'POST', body: JSON.stringify(input) }),
  remove: (id: string) => call<void>(`/investigations/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  summarize: (id: string) => call<AiSummary>(`/investigations/${encodeURIComponent(id)}/summary`, { method: 'POST' }),
  reportUrl: (id: string, format: 'html' | 'md' | 'json', download = false) =>
    `/api/investigations/${encodeURIComponent(id)}/report?format=${format}${download ? '&download=1' : ''}`,
  brands: () => call<Brand[]>('/brands'),
  addBrand: (b: { name: string; keywords: string[]; officialDomains: string[] }) => call<Brand>('/brands', { method: 'POST', body: JSON.stringify(b) }),
  deleteBrand: (id: number) => call<void>(`/brands/${id}`, { method: 'DELETE' }),
  verifications: () => call<OperatorVerification[]>('/identity?includeRevoked=1'),
  addVerification: (v: { domain: string; operatorName: string; method: string; evidenceReference: string; verifiedBy: string; validDays: number; notes?: string }) =>
    call<OperatorVerification>('/identity', { method: 'POST', body: JSON.stringify(v) }),
  revokeVerification: (id: number) => call<void>(`/identity/${id}/revoke`, { method: 'POST' }),
};
