import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Box,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  Copy,
  Database,
  FileCheck2,
  FileText,
  Fingerprint,
  FolderOpen,
  Gauge,
  Globe2,
  Layers3,
  LockKeyhole,
  LogOut,
  Menu,
  MoreHorizontal,
  Network,
  Play,
  Plus,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  TriangleAlert,
  Upload,
  X,
  XCircle,
} from 'lucide-react';
import type { Asset, Control, Engagement, Evidence, Finding, Run, State, Tool } from './types';
import './styles.css';

const nav = [
  { label: 'Overview', icon: Gauge },
  { label: 'Engagements', icon: FolderOpen },
  { label: 'Asset inventory', icon: Globe2 },
  { label: 'Assessments', icon: Activity },
  { label: 'Findings', icon: TriangleAlert },
  { label: 'Tool library', icon: Box },
  { label: 'Evidence', icon: Database },
  { label: 'Reports', icon: FileText },
];
const assurance = [
  { label: 'Authorization', icon: Fingerprint },
  { label: 'Audit trail', icon: FileCheck2 },
  { label: 'Controls', icon: ShieldCheck },
  { label: 'Engine & policy', icon: Settings2 },
];
const date = (value: string) =>
  new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
const time = (value: string) =>
  new Date(value).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
const pretty = (value: string) =>
  value.replaceAll('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase());
const weights: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
async function api<T>(url: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-Rudy-Request': '1', ...options.headers },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
function Badge({ value, kind }: { value: string; kind?: string }) {
  return (
    <span className={`badge ${kind || value.toLowerCase().replaceAll(' ', '-')}`}>
      <span />
      {pretty(value)}
    </span>
  );
}
function Empty({ title, body, action }: { title: string; body: string; action?: React.ReactNode }) {
  return (
    <div className="empty">
      <Layers3 size={30} />
      <h3>{title}</h3>
      <p>{body}</p>
      {action}
    </div>
  );
}
function App() {
  const [data, setData] = useState<State | null>(null),
    [page, setPage] = useState('Overview'),
    [search, setSearch] = useState(''),
    [domain, setDomain] = useState('all'),
    [severity, setSeverity] = useState('all'),
    [engagement, setEngagement] = useState('all'),
    [modal, setModal] = useState<{ type: string; value?: unknown } | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [mobile, setMobile] = useState(false);
  const lastFocus = useRef<HTMLElement | null>(null),
    dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    api<State>('/api/state')
      .catch(() => api<State>('/api/demo'))
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);
  useEffect(() => {
    if (!data || data.demo || !data.runs.some((r) => r.state === 'running')) return;
    const handle = setInterval(() => {
      api<State>('/api/state')
        .then(setData)
        .catch((e) => setNotice(e.message));
    }, 2000);
    return () => clearInterval(handle);
  }, [data]);
  useEffect(() => {
    if (!notice) return;
    const handle = setTimeout(() => setNotice(''), 6000);
    return () => clearTimeout(handle);
  }, [notice]);
  useEffect(() => {
    if (!modal) {
      lastFocus.current?.focus();
      return;
    }
    lastFocus.current = document.activeElement as HTMLElement;
    dialogRef.current?.querySelector<HTMLElement>('button,input,select,textarea')?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) setModal(null);
      if (e.key === 'Tab') {
        const nodes = Array.from(
          dialogRef.current?.querySelectorAll<HTMLElement>(
            'button:not([disabled]),input:not([disabled]),textarea,select,a[href]',
          ) || [],
        );
        const first = nodes[0],
          last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [modal, busy]);
  const navigate = (next: string) => {
    setPage(next);
    setSearch('');
    setSeverity('all');
    setMobile(false);
  };
  const open = (type: string, value?: unknown) => {
    setError('');
    setModal({ type, value });
  };
  const requireWorkspace = (type: string, value?: unknown) => {
    if (data?.demo) {
      open('connect');
      return;
    }
    if (data?.role === 'viewer') {
      setNotice('You are connected as a viewer. An operator must make this change.');
      return;
    }
    open(type, value);
  };
  async function act(url: string, body?: unknown, method = 'POST', keepOpen = false) {
    setBusy(true);
    setError('');
    try {
      const result = await api(url, {
        method,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      setData(await api<State>('/api/state'));
      if (!keepOpen) setModal(null);
      setNotice('Workspace updated.');
      return result;
    } catch (e) {
      setError((e as Error).message);
      throw e;
    } finally {
      setBusy(false);
    }
  }
  async function download(url: string, name: string) {
    if (data?.demo) {
      setNotice('Connect a workspace to export real assessment evidence.');
      return;
    }
    try {
      const res = await fetch(url);
      if (!res.ok) {
        const e = await res.json();
        throw new Error(e.error);
      }
      const blob = await res.blob(),
        href = URL.createObjectURL(blob),
        a = document.createElement('a');
      a.href = href;
      a.download = name;
      a.click();
      URL.revokeObjectURL(href);
      setData(await api<State>('/api/state'));
    } catch (e) {
      setNotice((e as Error).message);
    }
  }
  const onSubmit =
    (handler: (f: FormData) => Promise<unknown>) => async (e: React.FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      try {
        await handler(new FormData(e.currentTarget));
      } catch {
        /* the action error is displayed in the dialog */
      }
    };
  if (!data)
    return (
      <div className="loading">
        <Shield size={38} />
        <h2>Rudy Central</h2>
        <p>{error || 'Opening your security workspace…'}</p>
        {error && <button onClick={() => location.reload()}>Retry connection</button>}
      </div>
    );
  const match = (...values: unknown[]) =>
    values.join(' ').toLowerCase().includes(search.toLowerCase());
  const scoped = <T extends { engagementId?: string }>(rows: T[]) =>
    rows.filter((r) => engagement === 'all' || r.engagementId === engagement);
  const findings = scoped(data.findings)
    .filter(
      (f) =>
        match(f.title, f.asset, f.source, f.severity) &&
        (severity === 'all' || f.severity === severity),
    )
    .sort((a, b) => (weights[b.severity] || 0) - (weights[a.severity] || 0));
  const assets = scoped(data.assets).filter((a) => match(a.name, a.origin)),
    runs = scoped(data.runs).filter((r) => match(r.name, r.target));
  const allFindings = scoped(data.findings),
    openFindings = allFindings.filter((f) => ['open', 'in_progress'].includes(f.status)),
    highRisk = openFindings.filter((f) => ['high', 'critical'].includes(f.severity));
  const tools = data.catalog.filter(
    (t) => (domain === 'all' || t.domain === domain) && match(t.name, t.description, t.status),
  );
  const selectedEngagement =
    data.engagements.find((e) => e.id === engagement) || data.engagements[0];
  const currentFinding =
    modal?.type === 'finding'
      ? data.findings.find((f) => f.id === (modal.value as Finding).id)
      : undefined;
  const currentAsset =
    modal?.type === 'asset'
      ? data.assets.find((a) => a.id === (modal.value as Asset).id)
      : undefined;
  const pageInfo: Record<string, [string, string]> = {
    Overview: ['Security overview', 'A clear view of your scope, exposure, and next steps.'],
    Engagements: [
      'Every assessment starts with scope.',
      'Define objectives, accountable owners, and the work to be done.',
    ],
    'Asset inventory': [
      'Know what you are authorized to test.',
      'Exact targets. Verifiable ownership. No implicit scope.',
    ],
    Assessments: [
      'From authorization to evidence.',
      'Run bounded checks and track every assessment.',
    ],
    Findings: [
      'Focus on what needs attention.',
      'Validate observations, assign ownership, and track remediation.',
    ],
    'Tool library': [
      'Your security toolkit, organized.',
      'Every discipline in one workbench. Integration status is explicit.',
    ],
    Evidence: [
      'Evidence you can trace.',
      'Original artifacts, normalized findings, and SHA-256 provenance.',
    ],
    Reports: [
      'Make the assessment actionable.',
      'Export a reproducible record with findings, remediation, and evidence.',
    ],
    Authorization: [
      'Permission is part of the protocol.',
      'Ownership proof is required before a target can be assessed.',
    ],
    'Audit trail': [
      'Every consequential action, recorded.',
      'HMAC-linked events with a verifiable local integrity checkpoint.',
    ],
    Controls: [
      'Connect security work to controls.',
      'Record implementation and gaps. Evidence does not imply certification.',
    ],
    'Engine & policy': [
      'Deliberate limits. Clear boundaries.',
      'Inspect the execution policy and the local sensor architecture.',
    ],
  };
  function FindingsTable({ compact = false }: { compact?: boolean }) {
    const rows = compact ? findings.slice(0, 5) : findings;
    return rows.length ? (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Finding / affected asset</th>
              <th>Severity</th>
              <th>Source</th>
              <th>Status</th>
              <th aria-label="Open finding" />
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id} onClick={() => open('finding', f)}>
                <td>
                  <button
                    className="table-link"
                    onClick={(e) => {
                      e.stopPropagation();
                      open('finding', f);
                    }}
                  >
                    {f.title}
                  </button>
                  <small className="mono">{f.asset}</small>
                </td>
                <td>
                  <Badge value={f.severity} />
                </td>
                <td>
                  <span className="source">{f.source}</span>
                </td>
                <td>
                  <span className="status-text">
                    <i className={f.status} />
                    {pretty(f.status)}
                  </span>
                </td>
                <td>
                  <ChevronRight size={15} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <Empty
        title="No findings in this view"
        body="Run an authorized assessment or import an existing result to begin."
      />
    );
  }
  function AssetCards({ authorization = false }: { authorization?: boolean }) {
    return assets.length ? (
      <div className="asset-grid">
        {assets.map((a) => (
          <button className="asset-card" key={a.id} onClick={() => open('asset', a)}>
            <div className="flex spread">
              <div className="icon-tile">
                <Globe2 size={21} />
              </div>
              <Badge value={a.state} />
            </div>
            <h3>{a.name}</h3>
            <p className="mono">{a.origin}</p>
            <div className="asset-footer">
              <span>
                {a.method === 'dns'
                  ? 'DNS TXT proof'
                  : a.method === 'https'
                    ? 'HTTPS file proof'
                    : 'Imported scope'}
              </span>
              <ArrowUpRight size={16} />
            </div>
            {authorization && a.permit && (
              <small>Permit expires {new Date(a.permit.expiresAt).toLocaleString()}</small>
            )}
          </button>
        ))}
      </div>
    ) : (
      <Empty
        title="No assets authorized yet"
        body="Add an exact HTTPS origin and publish the generated ownership challenge."
        action={
          <button className="primary" onClick={() => requireWorkspace('new-asset')}>
            <Plus size={15} />
            Add an asset
          </button>
        }
      />
    );
  }
  function ReportCard({ item }: { item: Engagement }) {
    if (!data) return null;
    const count = data.findings.filter((f) => f.engagementId === item.id).length;
    return (
      <article className="report-card">
        <div className="report-cover">
          <span>RUDY CENTRAL</span>
          <div>
            <FileText size={32} />
            <h3>
              Security
              <br />
              assessment
            </h3>
          </div>
          <small>CONFIDENTIAL / {new Date().getFullYear()}</small>
        </div>
        <div className="report-meta">
          <Badge value={data.demo ? 'sample' : 'ready'} />
          <h3>{item.name}</h3>
          <p>
            {count} findings · {data.evidence.filter((e) => e.engagementId === item.id).length}{' '}
            evidence artifacts
          </p>
          <div className="button-row">
            <button onClick={() => download(`/api/reports/${item.id}`, 'rudy-assessment.html')}>
              <ArrowDownToLine size={15} />
              HTML / Print PDF
            </button>
            <button
              onClick={() =>
                download(`/api/reports/${item.id}?format=json`, 'rudy-assessment.json')
              }
            >
              JSON
            </button>
          </div>
        </div>
      </article>
    );
  }
  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobile ? 'expanded' : ''}`}>
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            navigate('Overview');
          }}
        >
          <div className="brand-mark">
            <Shield size={24} strokeWidth={1.7} />
          </div>
          <span>
            RUDY<span className="brand-thin">CENTRAL</span>
            <small>SECURITY WORKBENCH</small>
          </span>
        </a>
        <button
          className="workspace-switch"
          onClick={() => open(data.demo ? 'connect' : 'workspace')}
        >
          <span className="workspace-monogram">R</span>
          <span>
            Rudy workspace
            <small>{data.demo ? 'Demonstration' : `${pretty(data.role)} session`}</small>
          </span>
          <ChevronDown size={14} />
        </button>
        <p className="nav-label">WORKSPACE</p>
        <nav aria-label="Main navigation">
          {nav.map((n) => (
            <button
              key={n.label}
              className={page === n.label ? 'active' : ''}
              onClick={() => navigate(n.label)}
            >
              <n.icon size={17} />
              <span>{n.label}</span>
              {n.label === 'Findings' && <b>{openFindings.length}</b>}
            </button>
          ))}
        </nav>
        <p className="nav-label assurance-label">ASSURANCE</p>
        <nav aria-label="Assurance navigation">
          {assurance.map((n) => (
            <button
              key={n.label}
              className={page === n.label ? 'active' : ''}
              onClick={() => navigate(n.label)}
            >
              <n.icon size={17} />
              <span>{n.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="engine-indicator">
            <span />
            <div>
              Local control plane
              <small>
                {data.demo ? 'Preview · no live activity' : 'Connected · authorization enforced'}
              </small>
            </div>
          </div>
          <button className="profile" onClick={() => open(data.demo ? 'connect' : 'workspace')}>
            <span>RS</span>
            <div>
              Rudy Systems<small>{data.demo ? 'Connect your workspace' : pretty(data.role)}</small>
            </div>
            <MoreHorizontal size={17} />
          </button>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="mobile-menu"
              onClick={() => setMobile(!mobile)}
              aria-label="Toggle navigation"
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{page}</strong>
          </div>
          <div className="top-actions">
            <span className={`environment ${data.demo ? 'demo' : ''}`}>
              <span />
              {data.demo ? 'DEMO WORKSPACE' : 'LOCAL WORKSPACE'}
            </span>
            <button
              className="help-button"
              aria-label="Workspace guide"
              onClick={() => open('guide')}
            >
              <BookOpen size={17} />
            </button>
            <span className="avatar">RS</span>
          </div>
        </header>
        <main>
          <div className="context-line">
            <span>
              <span className="green-dot" /> AUTHORIZED SECURITY OPERATIONS
            </span>
            <label className="engagement-select">
              <FolderOpen size={14} />
              <select
                aria-label="Filter by engagement"
                value={engagement}
                onChange={(e) => setEngagement(e.target.value)}
              >
                <option value="all">All engagements</option>
                {data.engagements.map((e) => (
                  <option value={e.id} key={e.id}>
                    {e.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="page-heading">
            <div>
              <h1>{page === 'Overview' ? 'Security overview' : page}</h1>
              <p>{pageInfo[page][1]}</p>
            </div>
            <div className="button-row">
              {page === 'Overview' ? (
                <>
                  <button onClick={() => navigate('Reports')}>
                    <ArrowDownToLine size={15} />
                    Reports
                  </button>
                  <button className="primary" onClick={() => requireWorkspace('new-run')}>
                    <Plus size={16} />
                    New assessment
                  </button>
                </>
              ) : page === 'Tool library' ? (
                <span className="count-tag">{data.catalog.length} catalog entries</span>
              ) : page === 'Audit trail' ? (
                <button onClick={() => download('/api/audit/export', 'rudy-audit.json')}>
                  <ArrowDownToLine size={15} />
                  Export checkpoint
                </button>
              ) : ['Asset inventory', 'Authorization'].includes(page) ? (
                <button className="primary" onClick={() => requireWorkspace('new-asset')}>
                  <Plus size={16} />
                  Authorize asset
                </button>
              ) : page === 'Engagements' ? (
                <button className="primary" onClick={() => requireWorkspace('new-engagement')}>
                  <Plus size={16} />
                  New engagement
                </button>
              ) : page === 'Assessments' ? (
                <button className="primary" onClick={() => requireWorkspace('new-run')}>
                  <Plus size={16} />
                  New assessment
                </button>
              ) : ['Findings', 'Evidence'].includes(page) ? (
                <button className="primary" onClick={() => requireWorkspace('import')}>
                  <Upload size={15} />
                  Import evidence
                </button>
              ) : page === 'Controls' ? (
                <button className="primary" onClick={() => requireWorkspace('new-control')}>
                  <Plus size={15} />
                  Add control
                </button>
              ) : null}
            </div>
          </div>
          {data.demo && (
            <div className="demo-banner">
              <div>
                <Box size={15} />
                <span>
                  <b>Explore the workbench.</b> Sample data only. No targets have been contacted.
                </span>
              </div>
              <button onClick={() => open('connect')}>
                Connect workspace <ArrowRight size={14} />
              </button>
            </div>
          )}
          {page === 'Overview' && (
            <>
              <section className="metrics">
                <Metric
                  label="Assets in scope"
                  value={scoped(data.assets).length}
                  icon={<Globe2 size={18} />}
                  detail={
                    data.demo
                      ? 'Illustrative asset inventory'
                      : `${scoped(data.assets).filter((a) => a.state === 'verified' && a.permit && a.permit.expiresAt > Date.now()).length} with current permits`
                  }
                />
                <Metric
                  label="Open findings"
                  value={openFindings.length}
                  icon={<Layers3 size={18} />}
                  detail="Awaiting remediation"
                />
                <Metric
                  label="Priority findings"
                  value={highRisk.length}
                  icon={<TriangleAlert size={18} />}
                  detail="Critical & high severity"
                  alert
                />
                <Metric
                  label="Completed assessments"
                  value={runs.filter((r) => r.state === 'completed').length}
                  icon={<CheckCircle2 size={18} />}
                  detail={data.demo ? 'Sample assessment' : 'Persisted assessment records'}
                />
              </section>
              <div className="overview-grid">
                <section className="panel posture">
                  <div className="panel-heading">
                    <div>
                      <span className="eyebrow">EXPOSURE SNAPSHOT</span>
                      <h2>Prioritize with context.</h2>
                    </div>
                    <span className="subtle">{data.demo ? 'Sample dataset' : 'Current scope'}</span>
                  </div>
                  <div className="posture-body">
                    <div className="donut" style={{ background: donutGradient(openFindings) }}>
                      <div>
                        <strong>{openFindings.length}</strong>
                        <span>OPEN FINDINGS</span>
                      </div>
                    </div>
                    <div className="severity-legend">
                      {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                        <div key={s}>
                          <span>
                            <i className={s} />
                            {pretty(s)}
                          </span>
                          <b>{openFindings.filter((f) => f.severity === s).length}</b>
                          <div className="legend-bar">
                            <span
                              className={s}
                              style={{
                                width: `${(100 * openFindings.filter((f) => f.severity === s).length) / (openFindings.length || 1)}%`,
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="panel-foot">
                    <ShieldCheck size={15} />
                    <span>
                      {data.demo
                        ? 'Synthetic observations demonstrate the triage workflow.'
                        : 'Severity is a triage signal. Validate exploitability and business impact.'}
                    </span>
                  </div>
                </section>
                <section className="panel scope-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="eyebrow">TRUST BEFORE TESTING</span>
                      <h2>Scope comes first.</h2>
                    </div>
                    <Fingerprint size={22} />
                  </div>
                  <p>
                    Every live assessment starts with proof of control and a time-bound
                    authorization.
                  </p>
                  <div className="scope-steps">
                    <div>
                      <span>01</span>
                      <div>
                        <b>Prove ownership</b>
                        <small>DNS record or HTTPS challenge</small>
                      </div>
                      <Check size={16} />
                    </div>
                    <div>
                      <span>02</span>
                      <div>
                        <b>Define the boundary</b>
                        <small>Exact origin · bounded checks</small>
                      </div>
                      <Check size={16} />
                    </div>
                    <div>
                      <span>03</span>
                      <div>
                        <b>Keep an evidence trail</b>
                        <small>Signed scope · hashed artifacts</small>
                      </div>
                      <Check size={16} />
                    </div>
                  </div>
                  <button className="text-action" onClick={() => navigate('Authorization')}>
                    Review authorization <ArrowRight size={16} />
                  </button>
                </section>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <div className="flex">
                    <h2>Finding work queue</h2>
                    <span className="number-pill">{findings.length}</span>
                  </div>
                  <button className="text-action" onClick={() => navigate('Findings')}>
                    View all findings <ArrowUpRight size={15} />
                  </button>
                </div>
                <FindingsTable compact />
              </section>
              <div className="lower-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Recent activity</h2>
                    <button
                      className="icon-button"
                      aria-label="View audit trail"
                      onClick={() => navigate('Audit trail')}
                    >
                      <ArrowUpRight size={17} />
                    </button>
                  </div>
                  <div className="activity-list">
                    {data.audit.slice(0, 3).map((a) => (
                      <div key={a.seq}>
                        <span className="activity-icon">
                          <Check size={13} />
                        </span>
                        <div>
                          <b>{pretty(a.action.replaceAll('.', ' '))}</b>
                          <small>{a.detail}</small>
                        </div>
                        <time>{time(a.time)}</time>
                      </div>
                    ))}
                    {!data.audit.length && (
                      <p className="muted">Workspace actions will appear here.</p>
                    )}
                  </div>
                </section>
                <section className="tool-callout">
                  <div className="tool-cubes">
                    <Box size={22} />
                    <Network size={22} />
                    <Code2 size={22} />
                  </div>
                  <h2>
                    One workspace.
                    <br />
                    Every security discipline.
                  </h2>
                  <p>
                    {data.catalog.length} tools and references across {data.domains.length} domains.
                    Native checks and import adapters, clearly identified.
                  </p>
                  <button className="text-action" onClick={() => navigate('Tool library')}>
                    Explore the tool library <ArrowRight size={16} />
                  </button>
                </section>
              </div>
            </>
          )}
          {[
            'Findings',
            'Asset inventory',
            'Assessments',
            'Evidence',
            'Tool library',
            'Engagements',
            'Audit trail',
          ].includes(page) && (
            <div className="filter-bar">
              <div className="search-box">
                <Search size={16} />
                <input
                  aria-label={`Search ${page.toLowerCase()}`}
                  placeholder={`Search ${page.toLowerCase()}…`}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                {search && (
                  <button onClick={() => setSearch('')} aria-label="Clear search">
                    <X size={14} />
                  </button>
                )}
              </div>
              {page === 'Findings' && (
                <label className="filter-select">
                  <SlidersHorizontal size={15} />
                  <select
                    aria-label="Severity filter"
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                  >
                    <option value="all">All severities</option>
                    {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                      <option value={s} key={s}>
                        {pretty(s)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {page === 'Tool library' && <span className="muted">{tools.length} results</span>}
            </div>
          )}
          {page === 'Findings' && (
            <section className="panel">
              <FindingsTable />
            </section>
          )}
          {page === 'Engagements' && (
            <div className="engagement-grid">
              {data.engagements
                .filter((e) => match(e.name, e.client))
                .map((e) => (
                  <article className="panel engagement-card" key={e.id}>
                    <div className="flex spread">
                      <div className="icon-tile">
                        <FolderOpen size={20} />
                      </div>
                      <Badge value={e.status} />
                    </div>
                    <h2>{e.name}</h2>
                    <p className="muted">{e.client}</p>
                    <p>{e.objective}</p>
                    <div className="mini-metrics">
                      <span>
                        <b>{data.assets.filter((a) => a.engagementId === e.id).length}</b> Assets
                      </span>
                      <span>
                        <b>{data.findings.filter((f) => f.engagementId === e.id).length}</b>{' '}
                        Findings
                      </span>
                    </div>
                    <button
                      className="text-action"
                      onClick={() => {
                        setEngagement(e.id);
                        navigate('Overview');
                      }}
                    >
                      Open engagement <ArrowRight size={16} />
                    </button>
                  </article>
                ))}
              {!data.engagements.length && (
                <Empty
                  title="Create your first engagement"
                  body="Group authorized assets, findings, and evidence under a clear assessment objective."
                />
              )}
            </div>
          )}
          {page === 'Asset inventory' && <AssetCards />}
          {page === 'Authorization' && (
            <>
              <div className="authorization-intro">
                <ShieldCheck size={32} />
                <div>
                  <h2>Verification is required, every time.</h2>
                  <p>
                    Publish the exact challenge, verify it, and receive a 24-hour permit. The engine
                    checks the proof again before each run. Removing the proof stops future
                    assessments.
                  </p>
                </div>
                <span className="policy-tag">POLICY v1.0</span>
              </div>
              <AssetCards authorization />
              <div className="note-panel">
                <LockKeyhole size={18} />
                <p>
                  Ownership proof demonstrates control of an origin. It does not replace written
                  permission or establish authority over shared infrastructure. Public HTTPS origins
                  only; IP ranges, internal networks, cloud accounts, and wireless testing need
                  separate authorization adapters.
                </p>
              </div>
            </>
          )}
          {page === 'Assessments' && (
            <>
              <div className="native-profiles">
                {data.nativeChecks.map((n) => (
                  <article key={n.id} className="panel profile-card">
                    <div className="flex spread">
                      <Terminal size={21} />
                      <Badge value="native" />
                    </div>
                    <h3>{n.name}</h3>
                    <p>{n.description}</p>
                    <button
                      className="text-action"
                      onClick={() =>
                        n.id === 'web-baseline'
                          ? requireWorkspace('new-run')
                          : n.id === 'evidence-import'
                            ? requireWorkspace('import')
                            : navigate('Engine & policy')
                      }
                    >
                      {n.id === 'web-baseline'
                        ? 'Configure assessment'
                        : n.id === 'evidence-import'
                          ? 'Import results'
                          : 'View sensor setup'}{' '}
                      <ArrowRight size={15} />
                    </button>
                  </article>
                ))}
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Assessment history</h2>
                  <span className="muted">{runs.length} records</span>
                </div>
                {runs.length ? (
                  <div className="run-list">
                    {runs.map((r) => (
                      <button key={r.id} onClick={() => open('run', r)}>
                        <span className={`run-icon ${r.state}`}>
                          {r.state === 'completed' ? (
                            <Check size={19} />
                          ) : r.state === 'running' ? (
                            <Activity size={19} />
                          ) : (
                            <Clock3 size={19} />
                          )}
                        </span>
                        <span>
                          <b>{r.name}</b>
                          <small className="mono">{r.target}</small>
                        </span>
                        <Badge value={r.state} />
                        <span className="run-date">{date(r.createdAt)}</span>
                        <ChevronRight size={17} />
                      </button>
                    ))}
                  </div>
                ) : (
                  <Empty
                    title="No assessments yet"
                    body="Authorize an asset before starting a web baseline."
                  />
                )}
              </section>
            </>
          )}
          {page === 'Tool library' && (
            <>
              <div className="domain-tabs">
                <button
                  className={domain === 'all' ? 'selected' : ''}
                  onClick={() => setDomain('all')}
                >
                  All domains <span>{data.catalog.length}</span>
                </button>
                {data.domains.map((d) => (
                  <button
                    className={domain === d.id ? 'selected' : ''}
                    key={d.id}
                    onClick={() => setDomain(d.id)}
                  >
                    {d.name}
                    <span>{d.count}</span>
                  </button>
                ))}
              </div>
              <div className="tool-grid">
                {tools.map((t) => (
                  <button key={t.id} className="tool-card" onClick={() => open('tool', t)}>
                    <div className="flex spread">
                      <div className="tool-letter">{t.name.slice(0, 2).toUpperCase()}</div>
                      <ArrowUpRight size={15} />
                    </div>
                    <h3>{t.name}</h3>
                    <p>{t.description}</p>
                    <div className="tool-card-footer">
                      <Badge value={t.status} />
                      <span>{data.domains.find((d) => d.id === t.domain)?.name}</span>
                    </div>
                  </button>
                ))}
              </div>
              {!tools.length && (
                <Empty title="No matching tools" body="Try a different domain or search term." />
              )}
              <div className="note-panel">
                <Box size={18} />
                <p>
                  Catalog inclusion is not a bundled installation or a direct integration. “Import
                  ready” means a supported exported evidence format. External products require
                  separate installation, licensing, and authorization.
                </p>
              </div>
            </>
          )}
          {page === 'Evidence' && (
            <section className="panel">
              {scoped(data.evidence).filter((e) => match(e.name, e.format, e.sha256)).length ? (
                <div className="evidence-list">
                  {scoped(data.evidence)
                    .filter((e) => match(e.name, e.format, e.sha256))
                    .map((e) => (
                      <div key={e.id}>
                        <div className="icon-tile">
                          <FileCheck2 size={21} />
                        </div>
                        <div>
                          <h3>{e.name}</h3>
                          <p>
                            {e.format.toUpperCase()} · {e.findingCount} findings ·{' '}
                            {date(e.createdAt)}
                          </p>
                          <small className="mono">SHA-256 {e.sha256}</small>
                        </div>
                        <button
                          aria-label={`Download ${e.name}`}
                          onClick={() => download(`/api/evidence/${e.id}`, `${e.id}.json`)}
                        >
                          <ArrowDownToLine size={17} />
                        </button>
                      </div>
                    ))}
                </div>
              ) : (
                <Empty
                  title="Build an evidence register"
                  body="Import a supported tool export or complete a native assessment. Artifacts remain local."
                />
              )}
            </section>
          )}
          {page === 'Reports' && (
            <>
              <div className="report-grid">
                {data.engagements
                  .filter((e) => engagement === 'all' || e.id === engagement)
                  .map((e) => (
                    <ReportCard key={e.id} item={e} />
                  ))}
              </div>
              {!data.engagements.length && (
                <Empty
                  title="Your reports begin with an engagement"
                  body="Create an engagement, collect evidence, and export a report when you are ready."
                />
              )}
              <div className="note-panel">
                <FileText size={18} />
                <p>
                  HTML reports include printable layouts, source attribution, remediation, evidence
                  hashes, and an audit checkpoint. Open a downloaded report in your browser and use
                  Print → Save as PDF.
                </p>
              </div>
            </>
          )}
          {page === 'Audit trail' && (
            <>
              <div className={`integrity-banner ${data.integrity.valid ? '' : 'invalid'}`}>
                <ShieldCheck size={21} />
                <div>
                  <b>
                    {data.demo
                      ? 'Sample activity trail'
                      : data.integrity.valid
                        ? 'Audit chain verified'
                        : 'Audit integrity check failed'}
                  </b>
                  <p>
                    {data.demo
                      ? 'Connect a workspace to inspect its actual audit chain.'
                      : `${data.integrity.count} events verified · latest 250 shown`}
                  </p>
                </div>
                <span className="mono">
                  {data.demo ? 'DEMO' : data.integrity.head?.slice(0, 16)}
                </span>
              </div>
              <section className="panel">
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Event</th>
                        <th>Actor</th>
                        <th>Detail</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.audit
                        .filter((a) => match(a.action, a.detail, a.actor))
                        .map((a) => (
                          <tr key={a.seq}>
                            <td>
                              <b>{a.action}</b>
                              <small className="mono">#{String(a.seq).padStart(5, '0')}</small>
                            </td>
                            <td>{a.actor}</td>
                            <td className="audit-detail mono">{a.detail}</td>
                            <td className="nowrap">
                              {date(a.time)} · {time(a.time)}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </section>
              <div className="note-panel">
                <LockKeyhole size={18} />
                <p>
                  The chain detects edits without the local audit key. It is not tamper-proof
                  against a host administrator, and cannot detect tail deletion without a trusted
                  external checkpoint. Export checkpoints to an independently controlled system.
                </p>
              </div>
            </>
          )}
          {page === 'Controls' && (
            <div className="control-grid">
              {scoped(data.controls).map((c) => (
                <button
                  className="panel control-card"
                  onClick={() => open('control', c)}
                  key={c.id}
                >
                  <div className="flex spread">
                    <ShieldCheck size={22} />
                    <Badge value={c.status} />
                  </div>
                  <h3>{c.name}</h3>
                  <p>{c.description}</p>
                  <span className="text-action">
                    Review control <ArrowRight size={15} />
                  </span>
                </button>
              ))}
              {!data.controls.length && (
                <Empty
                  title="Record the controls that matter"
                  body="Add assessment-specific controls and document their implementation status."
                />
              )}
            </div>
          )}
          {page === 'Engine & policy' && (
            <>
              <div className="engine-grid">
                <section className="panel policy-card">
                  <span className="eyebrow">EXECUTION BOUNDARY</span>
                  <h2>Bounded by design.</h2>
                  <dl>
                    {[
                      ['Network scope', 'Public HTTPS · port 443'],
                      ['Target matching', 'Exact origin; no wildcards'],
                      ['Ownership proof', 'DNS TXT / HTTPS challenge'],
                      ['Permit lifetime', '24 hours'],
                      ['Concurrency', '1 active assessment'],
                      ['HTTP request budget', 'At most 2 per run, including proof'],
                      ['Request limits', '10 seconds / 256 KiB response'],
                      ['Redirect behavior', 'Never follow'],
                      ['Execution model', 'Fixed native checks; no shell input'],
                      ['Workspace access', 'Operator / viewer · 8-hour sessions'],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <dt>{k}</dt>
                        <dd>{v}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
                <section className="panel sensor-card">
                  <div className="sensor-graphic">
                    <Layers3 size={48} />
                    <span>USER SPACE</span>
                    <div />
                    <span>KERNEL BOUNDARY</span>
                  </div>
                  <span className="eyebrow">LINUX SENSOR</span>
                  <h2>
                    Local visibility.
                    <br />
                    Explicit privilege.
                  </h2>
                  <p>
                    The included unprivileged collector reads Linux posture and emits an offline
                    JSON artifact. Import it to create review findings.
                  </p>
                  <code>npm run sensor -- --out snapshot.json</code>
                  <p>
                    An optional eBPF tracepoint example counts process executions without collecting
                    arguments. It is source only and has not been built or tested on this Windows
                    host.
                  </p>
                  <Badge value="Linux validation pending" />
                </section>
              </div>
              <div className="note-panel">
                <TriangleAlert size={18} />
                <p>
                  This is a single-workspace release. Multi-tenant isolation, federated sign-in,
                  distributed workers, licensed tool connectors, and a packaged kernel sensor
                  require additional engineering and validation.
                </p>
              </div>
            </>
          )}
          <footer>
            <span>
              RUDY CENTRAL <b>/</b> Security starts with authorization.
            </span>
            <span>
              v0.1.0 <i /> {data.demo ? 'Demonstration' : 'Local workspace'}
            </span>
          </footer>
        </main>
      </div>
      {notice && (
        <div className="toast" role="status">
          <CheckCircle2 size={17} />
          {notice}
          <button aria-label="Dismiss notification" onClick={() => setNotice('')}>
            <X size={16} />
          </button>
        </div>
      )}
      {modal && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget && !busy) setModal(null);
          }}
        >
          <div
            className={`modal ${['finding', 'asset', 'tool', 'run'].includes(modal.type) ? 'detail-modal' : ''}`}
            role="dialog"
            aria-modal="true"
            aria-labelledby="dialog-title"
            ref={dialogRef}
          >
            <button
              className="modal-close"
              aria-label="Close dialog"
              disabled={busy}
              onClick={() => setModal(null)}
            >
              <X size={20} />
            </button>
            {modal.type === 'connect' && (
              <>
                <div className="modal-icon">
                  <LockKeyhole size={25} />
                </div>
                <span className="eyebrow">YOUR LOCAL WORKSPACE</span>
                <h2 id="dialog-title">Connect to Rudy Central</h2>
                <p>
                  Use the workspace key generated on the machine running the engine. Assessment data
                  stays on that machine.
                </p>
                <form
                  onSubmit={onSubmit(async (f) => {
                    await act('/api/session', { key: f.get('key') });
                    setEngagement('all');
                  })}
                >
                  <label>
                    Workspace key
                    <input
                      name="key"
                      type="password"
                      autoComplete="current-password"
                      required
                      placeholder="Paste your workspace key"
                    />
                  </label>
                  <div className="form-note">
                    Find it in <code>.data/admin-key</code> in your installation. For a shared
                    read-only session, use the configured viewer key.
                  </div>
                  <button className="primary full" disabled={busy}>
                    {busy ? 'Connecting…' : 'Connect workspace'}
                    <ArrowRight size={16} />
                  </button>
                </form>
              </>
            )}
            {modal.type === 'workspace' && (
              <>
                <h2 id="dialog-title">Workspace connection</h2>
                <p>
                  Connected as <b>{data.role}</b>. Sessions expire after eight hours. Data is stored
                  in the engine’s local SQLite database.
                </p>
                <button
                  onClick={async () => {
                    try {
                      await api('/api/session', { method: 'DELETE' });
                      setData(await api<State>('/api/demo'));
                      setEngagement('all');
                      setModal(null);
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  <LogOut size={16} />
                  Disconnect workspace
                </button>
              </>
            )}
            {modal.type === 'new-engagement' && (
              <>
                <span className="eyebrow">DEFINE THE WORK</span>
                <h2 id="dialog-title">New engagement</h2>
                <p>A shared context for scope, evidence, and remediation.</p>
                <form
                  onSubmit={onSubmit(async (f) => {
                    await act('/api/engagements', {
                      name: f.get('name'),
                      client: f.get('client'),
                      objective: f.get('objective'),
                    });
                  })}
                >
                  <label>
                    Engagement name
                    <input
                      name="name"
                      required
                      maxLength={240}
                      placeholder="Quarterly application assessment"
                    />
                  </label>
                  <label>
                    Client / organization
                    <input name="client" required maxLength={240} placeholder="Organization name" />
                  </label>
                  <label>
                    Objective & authorization context
                    <textarea
                      name="objective"
                      required
                      minLength={10}
                      maxLength={4000}
                      placeholder="Describe the assessment objective, accountable owner, and written permission reference."
                    />
                  </label>
                  <button className="primary full" disabled={busy}>
                    Create engagement
                    <ArrowRight size={16} />
                  </button>
                </form>
              </>
            )}
            {modal.type === 'new-asset' && (
              <>
                <span className="eyebrow">EXPLICIT TARGET SCOPE</span>
                <h2 id="dialog-title">Authorize an asset</h2>
                <p>
                  The generated challenge must be published by someone who controls this origin.
                </p>
                {!data.engagements.length ? (
                  <Empty
                    title="Create an engagement first"
                    body="Every asset must belong to an assessment engagement."
                    action={
                      <button onClick={() => open('new-engagement')}>Create engagement</button>
                    }
                  />
                ) : (
                  <form
                    onSubmit={onSubmit(async (f) => {
                      const result = await act(
                        '/api/assets',
                        {
                          engagementId: f.get('engagementId'),
                          name: f.get('name'),
                          origin: f.get('origin'),
                          method: f.get('method'),
                          authorized: f.get('authorized') === 'on',
                        },
                        'POST',
                        true,
                      );
                      open('asset', result);
                    })}
                  >
                    <EngagementSelect data={data} selected={selectedEngagement?.id} />
                    <label>
                      Asset name
                      <input name="name" required placeholder="Customer portal" maxLength={240} />
                    </label>
                    <label>
                      Exact HTTPS origin
                      <input
                        name="origin"
                        type="url"
                        required
                        placeholder="https://portal.your-domain.com"
                      />
                    </label>
                    <label>
                      Ownership proof
                      <select name="method">
                        <option value="dns">DNS TXT record (recommended)</option>
                        <option value="https">HTTPS well-known file</option>
                      </select>
                    </label>
                    <label className="checkbox">
                      <input name="authorized" type="checkbox" required />
                      <span>
                        I own this asset or hold explicit written authorization to assess this
                        origin. Shared infrastructure is outside my scope.
                      </span>
                    </label>
                    <button className="primary full" disabled={busy}>
                      Generate challenge
                      <Fingerprint size={17} />
                    </button>
                  </form>
                )}
              </>
            )}
            {currentAsset && (
              <>
                <div className="flex spread modal-pretitle">
                  <span className="eyebrow">ASSET AUTHORIZATION</span>
                  <Badge value={currentAsset.state} />
                </div>
                <h2 id="dialog-title">{currentAsset.name}</h2>
                <p className="mono">{currentAsset.origin}</p>
                {currentAsset.state === 'demo' ? (
                  <div className="form-note">
                    This is a synthetic asset. Connect your workspace and add an origin you control
                    to generate a real challenge.
                  </div>
                ) : currentAsset.state === 'revoked' ? (
                  <div className="form-note">
                    Authorization has been revoked. Create a new authorization to test this origin
                    again.
                  </div>
                ) : (
                  <>
                    <h3>1. Publish the ownership proof</h3>
                    <p>
                      {currentAsset.method === 'dns'
                        ? 'Create this DNS TXT record:'
                        : 'Serve a plain-text file with HTTP status 200 at:'}
                    </p>
                    <CopyBlock
                      label={currentAsset.method === 'dns' ? 'DNS record name' : 'HTTPS URL'}
                      value={
                        currentAsset.method === 'dns'
                          ? `_rudy-central.${new URL(currentAsset.origin).hostname}`
                          : `${currentAsset.origin}/.well-known/rudy-central/${currentAsset.id}.txt`
                      }
                    />
                    <CopyBlock
                      label="Exact content"
                      value={`rudy-central-verification=${currentAsset.id}.${currentAsset.challenge}`}
                    />
                    <p className="subtle">
                      {currentAsset.permit
                        ? `Permit expires ${new Date(currentAsset.permit.expiresAt).toLocaleString()}`
                        : `Challenge expires ${new Date(currentAsset.challengeExpiresAt || 0).toLocaleString()}`}
                      . Keep the proof published while assessments are authorized.
                    </p>
                    <h3>2. Verify and issue a scoped permit</h3>
                    <p>Only the web baseline can run. Every assessment revalidates this proof.</p>
                    <div className="button-row">
                      <button
                        className="primary"
                        disabled={busy || data.role === 'viewer'}
                        onClick={() =>
                          act(`/api/assets/${currentAsset.id}/verify`, {}, 'POST', true).catch(
                            () => {},
                          )
                        }
                      >
                        {busy ? 'Checking…' : 'Verify ownership'}
                        <ShieldCheck size={17} />
                      </button>
                      <button
                        className="danger-button"
                        disabled={busy || data.role === 'viewer'}
                        onClick={() =>
                          act(`/api/assets/${currentAsset.id}/revoke`, {}, 'POST', true).catch(
                            () => {},
                          )
                        }
                      >
                        Revoke authorization
                      </button>
                    </div>
                  </>
                )}
              </>
            )}
            {modal.type === 'new-run' && (
              <>
                <span className="eyebrow">NATIVE ASSESSMENT</span>
                <h2 id="dialog-title">Start a web baseline</h2>
                <p>
                  One HTTPS response, configuration observations, and a traceable evidence artifact.
                </p>
                <form
                  onSubmit={onSubmit(async (f) => {
                    await act('/api/runs', {
                      assetId: f.get('assetId'),
                      profile: 'web-baseline',
                      authorized: f.get('authorized') === 'on',
                    });
                    navigate('Assessments');
                  })}
                >
                  <label>
                    Authorized asset
                    <select name="assetId" required>
                      <option value="">Select a verified asset</option>
                      {data.assets
                        .filter(
                          (a) =>
                            a.state === 'verified' && a.permit && a.permit.expiresAt > Date.now(),
                        )
                        .map((a) => (
                          <option value={a.id} key={a.id}>
                            {a.name} · {a.origin}
                          </option>
                        ))}
                    </select>
                  </label>
                  <div className="form-note">
                    <b>Assessment budget</b>
                    <br />
                    Revalidate ownership → one GET / → save evidence.
                    <br />
                    No crawling, exploit attempts, redirects, or credential testing.
                  </div>
                  <label className="checkbox">
                    <input name="authorized" type="checkbox" required />
                    <span>
                      I confirm this assessment is within my written authorization and approved
                      testing window.
                    </span>
                  </label>
                  <button
                    className="primary full"
                    disabled={
                      busy ||
                      !data.assets.some(
                        (a) =>
                          a.state === 'verified' && a.permit && a.permit.expiresAt > Date.now(),
                      )
                    }
                  >
                    <Play size={16} />
                    Start assessment
                  </button>
                  <button className="full" type="button" onClick={() => open('new-asset')}>
                    Authorize another asset
                  </button>
                </form>
              </>
            )}
            {modal.type === 'run' &&
              (() => {
                const r =
                  data.runs.find((x) => x.id === (modal.value as Run).id) || (modal.value as Run);
                return (
                  <>
                    <span className="eyebrow">ASSESSMENT RECORD</span>
                    <h2 id="dialog-title">{r.name}</h2>
                    <p className="mono">{r.target}</p>
                    <Badge value={r.state} />
                    <dl className="details">
                      <div>
                        <dt>Started</dt>
                        <dd>{new Date(r.createdAt).toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt>Findings</dt>
                        <dd>{r.findingCount}</dd>
                      </div>
                    </dl>
                    {r.steps && (
                      <ol className="run-steps">
                        {r.steps.map((s) => (
                          <li key={s}>
                            <CheckCircle2 size={17} />
                            {s}
                          </li>
                        ))}
                      </ol>
                    )}
                    {r.error && <div className="form-error">{r.error}</div>}
                    {r.state === 'running' && (
                      <button
                        className="danger-button"
                        disabled={busy}
                        onClick={() =>
                          act(`/api/runs/${r.id}/cancel`, {}, 'POST', true).catch(() => {})
                        }
                      >
                        Cancel assessment
                      </button>
                    )}
                  </>
                );
              })()}
            {currentFinding && (
              <>
                <div className="modal-pretitle flex">
                  <Badge value={currentFinding.severity} />
                  <span className="eyebrow">{currentFinding.source}</span>
                </div>
                <h2 id="dialog-title">{currentFinding.title}</h2>
                <p className="mono">{currentFinding.asset}</p>
                <div className="finding-confidence">
                  <Fingerprint size={15} />
                  {currentFinding.confidence}
                </div>
                <h3>Observation</h3>
                <p>{currentFinding.description}</p>
                <h3>Evidence</h3>
                <pre>{currentFinding.evidence}</pre>
                <h3>Remediation</h3>
                <p>{currentFinding.remediation}</p>
                <form
                  onSubmit={onSubmit(async (f) => {
                    if (data.demo) {
                      requireWorkspace('finding', currentFinding);
                      return;
                    }
                    await act(
                      `/api/findings/${currentFinding.id}`,
                      { status: f.get('status'), owner: f.get('owner'), notes: f.get('notes') },
                      'PATCH',
                    );
                  })}
                >
                  <div className="form-columns">
                    <label>
                      Status
                      <select name="status" defaultValue={currentFinding.status}>
                        {['open', 'in_progress', 'resolved', 'accepted', 'false_positive'].map(
                          (s) => (
                            <option value={s} key={s}>
                              {pretty(s)}
                            </option>
                          ),
                        )}
                      </select>
                    </label>
                    <label>
                      Owner
                      <input
                        name="owner"
                        defaultValue={currentFinding.owner || ''}
                        placeholder="Assignee"
                        maxLength={120}
                      />
                    </label>
                  </div>
                  <label>
                    Analyst notes
                    <textarea
                      name="notes"
                      defaultValue={currentFinding.notes || ''}
                      placeholder="Validation, remediation, or acceptance rationale"
                      maxLength={8000}
                    />
                  </label>
                  <button className="primary full" disabled={busy || data.role === 'viewer'}>
                    Save triage
                    <Check size={16} />
                  </button>
                </form>
              </>
            )}
            {modal.type === 'import' && (
              <>
                <span className="eyebrow">LOCAL EVIDENCE INGESTION</span>
                <h2 id="dialog-title">Import assessment evidence</h2>
                <p>Files are parsed as data. Tools, scripts, and payloads are never executed.</p>
                {!data.engagements.length ? (
                  <Empty
                    title="Create an engagement first"
                    body="Evidence must have an assessment context."
                    action={
                      <button onClick={() => open('new-engagement')}>Create engagement</button>
                    }
                  />
                ) : (
                  <form
                    onSubmit={onSubmit(async (f) => {
                      const file = f.get('file') as File;
                      if (!file?.size) throw new Error('Choose an evidence file.');
                      if (file.size > 4000000) {
                        setError('File exceeds the 4 MB limit.');
                        return;
                      }
                      await act('/api/imports', {
                        engagementId: f.get('engagementId'),
                        name: file.name,
                        format: f.get('format'),
                        content: await file.text(),
                      });
                    })}
                  >
                    <EngagementSelect data={data} selected={selectedEngagement?.id} />
                    <label>
                      Export format
                      <select
                        name="format"
                        defaultValue={typeof modal.value === 'string' ? modal.value : 'sarif'}
                      >
                        {[
                          ['sarif', 'SARIF 2.1.0'],
                          ['semgrep', 'Semgrep JSON'],
                          ['nuclei', 'Nuclei JSON / JSONL'],
                          ['trivy', 'Trivy JSON'],
                          ['prowler', 'Prowler OCSF JSON'],
                          ['normalized', 'Normalized findings JSON'],
                          ['linux-snapshot', 'Rudy Linux snapshot'],
                        ].map(([v, n]) => (
                          <option key={v} value={v}>
                            {n}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="upload-area">
                      <Upload size={27} />
                      <b>Choose a JSON, JSONL, or SARIF file</b>
                      <span>4 MB maximum · 500 findings per artifact</span>
                      <input name="file" type="file" accept=".json,.jsonl,.sarif" required />
                    </label>
                    <div className="form-note">
                      Original evidence is retained locally. Review exports for credentials or
                      unrelated personal data before importing.
                    </div>
                    <button className="primary full" disabled={busy}>
                      Import & normalize
                      <ArrowRight size={16} />
                    </button>
                  </form>
                )}
              </>
            )}
            {modal.type === 'tool' &&
              (() => {
                const t = modal.value as Tool;
                return (
                  <>
                    <div className="tool-letter large">{t.name.slice(0, 2).toUpperCase()}</div>
                    <span className="eyebrow">
                      {data.domains.find((d) => d.id === t.domain)?.name}
                    </span>
                    <h2 id="dialog-title">{t.name}</h2>
                    <Badge value={t.status} />
                    <p>{t.description}</p>
                    <h3>Integration boundary</h3>
                    <p>{t.requirements}</p>
                    <dl className="details">
                      <div>
                        <dt>Execution</dt>
                        <dd>{t.execution}</dd>
                      </div>
                      <div>
                        <dt>Evidence format</dt>
                        <dd>
                          {['sarif', 'semgrep', 'nuclei', 'trivy', 'prowler'].includes(t.adapter)
                            ? t.adapter.toUpperCase()
                            : 'Normalized JSON (manual export)'}
                        </dd>
                      </div>
                    </dl>
                    <button
                      className="primary full"
                      onClick={() =>
                        requireWorkspace(
                          'import',
                          ['sarif', 'semgrep', 'nuclei', 'trivy', 'prowler'].includes(t.adapter)
                            ? t.adapter
                            : 'normalized',
                        )
                      }
                    >
                      Import authorized evidence
                      <Upload size={16} />
                    </button>
                  </>
                );
              })()}
            {modal.type === 'new-control' && (
              <>
                <h2 id="dialog-title">Add an assessment control</h2>
                <form
                  onSubmit={onSubmit(async (f) => {
                    await act('/api/controls', {
                      engagementId: f.get('engagementId'),
                      name: f.get('name'),
                      description: f.get('description'),
                      status: f.get('status'),
                    });
                  })}
                >
                  <EngagementSelect data={data} selected={selectedEngagement?.id} />
                  <label>
                    Control name
                    <input
                      name="name"
                      required
                      maxLength={240}
                      placeholder="Privileged access review"
                    />
                  </label>
                  <label>
                    Expected evidence
                    <textarea name="description" maxLength={2000} required />
                  </label>
                  <label>
                    Status
                    <select name="status">
                      <option value="review">Needs review</option>
                      <option value="implemented">Implemented</option>
                      <option value="gap">Gap identified</option>
                    </select>
                  </label>
                  <button className="primary full" disabled={busy || !data.engagements.length}>
                    Add control
                    <Plus size={16} />
                  </button>
                </form>
              </>
            )}
            {modal.type === 'control' &&
              (() => {
                const c = modal.value as Control;
                return (
                  <>
                    <h2 id="dialog-title">{c.name}</h2>
                    <p>{c.description}</p>
                    <form
                      onSubmit={onSubmit(async (f) => {
                        if (data.demo) {
                          open('connect');
                          return;
                        }
                        await act(
                          `/api/controls/${c.id}`,
                          { status: f.get('status'), notes: f.get('notes') },
                          'PATCH',
                        );
                      })}
                    >
                      <label>
                        Status
                        <select name="status" defaultValue={c.status}>
                          <option value="review">Needs review</option>
                          <option value="implemented">Implemented</option>
                          <option value="gap">Gap identified</option>
                        </select>
                      </label>
                      <label>
                        Evidence references and review notes
                        <textarea name="notes" defaultValue={c.notes} maxLength={4000} />
                      </label>
                      <button className="primary full" disabled={busy || data.role === 'viewer'}>
                        Save review
                        <Check size={16} />
                      </button>
                    </form>
                  </>
                );
              })()}
            {modal.type === 'guide' && (
              <>
                <span className="eyebrow">GETTING STARTED</span>
                <h2 id="dialog-title">Scope. Assess. Substantiate.</h2>
                <ol className="guide-list">
                  <li>
                    <b>Connect the engine</b>
                    <p>
                      Use the key from your local installation. Demo data never mixes with your
                      workspace.
                    </p>
                  </li>
                  <li>
                    <b>Create an engagement</b>
                    <p>Record the organization, objective, and authorization reference.</p>
                  </li>
                  <li>
                    <b>Authorize exact assets</b>
                    <p>
                      Publish a DNS or HTTPS proof and verify ownership. Authorization expires after
                      24 hours.
                    </p>
                  </li>
                  <li>
                    <b>Assess or import</b>
                    <p>
                      Run native web checks, or import results from your separately installed
                      security tools.
                    </p>
                  </li>
                  <li>
                    <b>Validate and report</b>
                    <p>
                      Triage findings, record evidence, and export a report with a verifiable audit
                      checkpoint.
                    </p>
                  </li>
                </ol>
              </>
            )}
            {error && (
              <div className="form-error" role="alert">
                <XCircle size={17} />
                {error}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
function Metric({
  label,
  value,
  detail,
  icon,
  alert = false,
}: {
  label: string;
  value: number;
  detail: string;
  icon: React.ReactNode;
  alert?: boolean;
}) {
  return (
    <article className={`metric ${alert ? 'attention' : ''}`}>
      <div>
        <span>{label}</span>
        {icon}
      </div>
      <strong>{String(value).padStart(2, '0')}</strong>
      <small>
        {alert && <span className="orange-dot" />}
        {detail}
      </small>
    </article>
  );
}
function EngagementSelect({ data, selected }: { data: State; selected?: string }) {
  return (
    <label>
      Engagement
      <select name="engagementId" defaultValue={selected} required>
        {data.engagements.map((e) => (
          <option key={e.id} value={e.id}>
            {e.name}
          </option>
        ))}
      </select>
    </label>
  );
}
function CopyBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="copy-block">
      <span>{label}</span>
      <div>
        <code>{value}</code>
        <button
          aria-label={`Copy ${label}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? <Check size={16} /> : <Copy size={16} />}
        </button>
      </div>
    </div>
  );
}
function donutGradient(findings: Finding[]) {
  const colors: Record<string, string> = {
    critical: '#a74041',
    high: '#d58355',
    medium: '#d8b55c',
    low: '#729b88',
    info: '#cbd5cf',
  };
  let start = 0;
  const parts = ['critical', 'high', 'medium', 'low', 'info'].map((s) => {
    const end =
        start + (360 * findings.filter((f) => f.severity === s).length) / (findings.length || 1),
      part = `${colors[s]} ${start}deg ${end}deg`;
    start = end;
    return part;
  });
  return findings.length ? `conic-gradient(${parts.join(',')})` : '#e7ece9';
}
createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
