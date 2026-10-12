import { parse } from 'tldts';
import type { EvidenceGraph, GraphEdge, GraphNode, GraphNodeType, Indicator, InvestigationArtifacts } from '@phishlens/shared';
import type { NormalizedInput } from '../../analyzers/types.js';
import { subject } from '../subjects.js';
import { maxSeverity } from '../indicators/index.js';
import { isIpLiteral } from '../../security/ip.js';
import { normalizeDomainInput } from '../../analyzers/domain/parseDomain.js';

/**
 * Builds the relationship graph between observed entities. Nodes are keyed by
 * the same subject keys analyzers attach to indicators, so clicking a node in
 * the UI shows exactly the evidence about that entity.
 */
export function buildEvidenceGraph(a: InvestigationArtifacts, indicators: Indicator[], input: NormalizedInput): EvidenceGraph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const root = subject.root();

  const node = (id: string, type: GraphNodeType, label: string, sublabel?: string, facts: GraphNode['facts'] = []): GraphNode => {
    const existing = nodes.get(id);
    if (existing) {
      for (const f of facts) if (!existing.facts.some((x) => x.label === f.label)) existing.facts.push(f);
      if (sublabel && !existing.sublabel) existing.sublabel = sublabel;
      return existing;
    }
    const n: GraphNode = { id, type, label, ...(sublabel ? { sublabel } : {}), indicatorIds: [], risk: null, facts };
    nodes.set(id, n);
    return n;
  };
  const edge = (from: string, to: string, label: string) => {
    if (from === to || !nodes.has(from) || !nodes.has(to)) return;
    const id = `${from}->${to}`;
    if (!edges.has(id) && !edges.has(`${to}->${from}`)) edges.set(id, { id, from, to, label });
  };

  node(root, 'investigation', 'Investigation');

  /** host → registrable domain → infrastructure (DNS, IPs, certificate, registration). */
  const hostNode = (hostname: string): string => {
    const h = hostname.toLowerCase();
    if (isIpLiteral(h)) {
      node(subject.ip(h), 'ip', h, 'IP address');
      return subject.ip(h);
    }
    const reg = parse(h, { allowPrivateDomains: true }).domain ?? h;
    const domId = subject.domain(reg);
    const d = a.domains.find((x) => x.hostname === reg || x.registrableDomain === reg);
    node(domId, 'domain', reg, d?.hostnameUnicode && d.hostnameUnicode !== reg && d.hostname === reg ? d.hostnameUnicode : 'domain');
    if (reg === h) return domId;
    const hostId = subject.host(h);
    node(hostId, 'host', h, 'hostname');
    edge(hostId, domId, 'part of');
    return hostId;
  };

  // --- Email headers -----------------------------------------------------------
  const e = a.email;
  if (e) {
    const emailId = subject.email();
    node(emailId, 'email', e.subject ? `“${e.subject.slice(0, 60)}”` : 'Email', 'email headers', [
      { label: 'SPF', value: e.summary.spf },
      { label: 'DKIM', value: e.summary.dkim },
      { label: 'DMARC', value: e.summary.dmarc },
      ...(e.date ? [{ label: 'Date', value: e.date }] : []),
    ]);
    edge(root, emailId, 'contains');
    const addr = (x: { address: string | null; domain: string | null; displayName?: string | null } | null, rel: string) => {
      if (!x?.address) return;
      const id = subject.address(x.address);
      node(id, 'address', x.address, rel, x.displayName ? [{ label: 'Display name', value: x.displayName }] : []);
      edge(emailId, id, rel);
      if (x.domain) edge(id, hostNode(x.domain), 'domain');
    };
    addr(e.from, 'From');
    e.replyTo.forEach((r) => addr(r, 'Reply-To'));
    addr(e.returnPath, 'Return-Path');

    // Mail route: origin → relays → recipient
    let prev = emailId;
    e.received.forEach((h, i) => {
      const id = subject.mailserver(i);
      const label = h.by ?? h.from ?? `hop ${i + 1}`;
      node(id, 'mailserver', label, `hop ${i + 1}${h.fromIp ? ` · from ${h.fromIp}` : ''}`, [
        ...(h.from ? [{ label: 'From (HELO)', value: h.from }] : []),
        ...(h.fromIp ? [{ label: 'From IP', value: h.fromIp }] : []),
        ...(h.with ? [{ label: 'Protocol', value: h.with }] : []),
        ...(h.timestamp ? [{ label: 'Time', value: h.timestamp }] : []),
      ]);
      edge(prev, id, i === 0 ? 'route' : 'relayed to');
      prev = id;
    });
  }

  // --- Submitted email address ---------------------------------------------------
  if (a.emailAddress?.address.address) {
    const x = a.emailAddress.address;
    const id = subject.address(x.address!);
    node(id, 'address', x.address!, 'submitted address');
    edge(root, id, 'submitted');
    if (x.domain) edge(id, hostNode(x.domain), 'domain');
  }

  // --- Submitted domain --------------------------------------------------------------
  if (input.domain) {
    const h = normalizeDomainInput(input.domain);
    if (h) edge(root, hostNode(h), 'submitted');
  }

  // --- Message and its links ------------------------------------------------------------
  if (a.message) {
    const id = subject.message();
    node(id, 'message', 'Message', `${a.message.links.length} link(s)`, [
      { label: 'Length', value: `${a.message.length} chars` },
      { label: 'Format', value: a.message.isHtml ? 'HTML' : 'text' },
    ]);
    edge(a.email ? subject.email() : root, id, 'body');
  }

  // --- URLs ------------------------------------------------------------------------------
  for (const u of a.urls.filter((x) => x.valid && x.normalized && x.origin !== 'redirect')) {
    const id = subject.url(u.normalized!);
    node(id, 'url', u.normalized!.length > 70 ? `${u.normalized!.slice(0, 67)}…` : u.normalized!, u.origin === 'input' ? 'submitted URL' : 'link', [
      { label: 'Scheme', value: u.scheme ?? '' },
      ...(u.port ? [{ label: 'Port', value: String(u.port) }] : []),
    ]);
    edge(u.origin === 'message' ? subject.message() : root, id, u.origin === 'message' ? 'links to' : 'submitted');
    if (u.hostname) edge(id, hostNode(u.hostname), 'host');
  }

  // --- Redirect chains -------------------------------------------------------------------------
  for (const r of a.redirects) {
    const startId = subject.url(r.startUrl);
    if (!nodes.has(startId)) continue;
    let prev = startId;
    for (const h of r.hops.slice(1)) {
      const id = subject.redirect(r.startUrl, h.index);
      node(id, 'redirect', h.hostname || h.url.slice(0, 40), `hop ${h.index}${h.statusCode ? ` · HTTP ${h.statusCode}` : ` · ${h.kind}`}`, [
        { label: 'URL', value: h.url },
        ...(h.remoteAddress ? [{ label: 'Address', value: h.remoteAddress }] : []),
        ...(h.error ? [{ label: 'Result', value: h.error }] : []),
      ]);
      edge(prev, id, h.index === 1 ? 'redirects to' : 'then');
      prev = id;
    }
    const last = r.hops[r.hops.length - 1];
    if (last && r.redirectCount > 0 && last.hostname && last.kind !== 'blocked') edge(prev, hostNode(last.hostname), 'final destination');
    // Page facts live on the final hop.
    if (r.page && last) {
      const id = r.hops.length > 1 ? subject.redirect(r.startUrl, last.index) : startId;
      const n = nodes.get(id);
      if (n) {
        if (r.page.title) n.facts.push({ label: 'Page title', value: r.page.title });
        n.facts.push({ label: 'Password field', value: r.page.hasPasswordField ? 'yes' : 'no' });
      }
    }
  }

  // --- Infrastructure per hostname: DNS, IPs, certificate, registration --------------------------
  for (const d of a.dns) {
    const owner = hostNode(d.name);
    const dnsId = subject.dns(d.name);
    const facts = d.records.filter((r) => r.values.length).map((r) => ({ label: r.type, value: r.values.slice(0, 3).join(', ') + (r.values.length > 3 ? ` (+${r.values.length - 3})` : '') }));
    node(dnsId, 'dns', `DNS ${d.name}`, d.providers.map((p) => p.name).join(', ') || `${facts.length} record type(s)`, facts);
    edge(owner, dnsId, 'DNS');
    for (const ip of d.records.filter((r) => r.type === 'A' || r.type === 'AAAA').flatMap((r) => r.values).slice(0, 4)) {
      const ptr = d.reverse.find((x) => x.ip === ip)?.names[0];
      node(subject.ip(ip), 'ip', ip, ptr ?? 'IP address', ptr ? [{ label: 'PTR', value: ptr }] : []);
      edge(owner, subject.ip(ip), 'resolves to');
    }
  }
  for (const t of a.tls) {
    if (!t.certificate) continue;
    const owner = hostNode(t.host);
    const id = subject.certificate(t.host, t.port);
    node(id, 'certificate', t.certificate.subjectCN ?? t.host, t.certificate.issuerOrg ?? t.certificate.issuerCN ?? 'certificate', [
      { label: 'Issuer', value: t.certificate.issuerOrg ?? t.certificate.issuerCN ?? '—' },
      { label: 'Valid to', value: t.certificate.validTo.slice(0, 10) },
      { label: 'Trusted', value: t.authorized ? 'yes' : 'no' },
      { label: 'Hostname match', value: t.hostnameMatches ? 'yes' : 'no' },
    ]);
    edge(owner, id, 'TLS');
  }
  for (const r of a.rdap) {
    if (r.status !== 'completed' || !r.registered) continue;
    const owner = hostNode(r.domain);
    const id = subject.rdap(r.domain);
    node(id, 'registration', `Registered ${r.registered.slice(0, 10)}`, r.registrar ?? 'RDAP', [
      ...(r.ageDays !== null && r.ageDays !== undefined ? [{ label: 'Age', value: `${r.ageDays} days` }] : []),
      ...(r.registrar ? [{ label: 'Registrar', value: r.registrar }] : []),
    ]);
    edge(owner, id, 'registration');
  }

  // Domains analysed but not yet connected (e.g. redirect destinations without DNS) hang off the root.
  for (const n of nodes.values()) {
    if (n.id === root) continue;
    const connected = [...edges.values()].some((x) => x.to === n.id || x.from === n.id);
    if (!connected) edge(root, n.id, 'observed');
  }

  // --- Attach indicators ------------------------------------------------------------------------
  /** Finds the closest existing node for an indicator subject (URL → its host → its domain → root). */
  const resolve = (s: string | undefined): string => {
    if (!s) return root;
    if (nodes.has(s)) return s;
    let host: string | null = null;
    if (s.startsWith('host:')) host = s.slice(5);
    else if (s.startsWith('url:')) {
      try {
        host = new URL(s.slice(4)).hostname.replace(/^\[|\]$/g, '');
      } catch {
        host = null;
      }
    }
    if (!host) return root;
    if (nodes.has(subject.host(host))) return subject.host(host);
    if (isIpLiteral(host)) return nodes.has(subject.ip(host)) ? subject.ip(host) : root;
    const reg = parse(host, { allowPrivateDomains: true }).domain ?? host;
    return nodes.has(subject.domain(reg)) ? subject.domain(reg) : root;
  };
  for (const i of indicators) nodes.get(resolve(i.subject))!.indicatorIds.push(i.id);
  const byId = new Map(indicators.map((i) => [i.id, i]));
  for (const n of nodes.values()) {
    n.risk = maxSeverity(n.indicatorIds.map((id) => byId.get(id)!).filter((i) => i.polarity === 'risk' && i.severity !== 'info').map((i) => i.severity));
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()], rootId: root };
}
