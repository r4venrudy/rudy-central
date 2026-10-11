import React, { useEffect, useRef, useState } from 'react';
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Fingerprint,
  Layers3,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  Terminal,
  Upload,
  X,
} from 'lucide-react';
import type { Engagement } from './types';
import type {
  Envelope,
  KernelCapture,
  KernelCaptureRecord,
  KernelSensor,
} from '../server/kernel.mts';
import './kernel.css';

type KernelState = {
  sensors: KernelSensor[];
  captures: KernelCaptureRecord[];
  authorityPublicKey: string;
  engine: { localPlatform: string };
};
type Props = {
  demo: boolean;
  role: string;
  engagements: Engagement[];
  scope: string;
  onConnect: () => void;
  onChanged: () => Promise<void>;
};
async function api<T>(route: string, body?: unknown): Promise<T> {
  const response = await fetch(route, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Rudy-Request': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}
function save(name: string, value: unknown) {
  const href = URL.createObjectURL(
    new Blob([typeof value === 'string' ? value : JSON.stringify(value, null, 2)], {
      type: 'application/json',
    }),
  );
  const a = document.createElement('a');
  a.href = href;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
const label = (value: string) => value.replaceAll('_', ' ');
const at = (value: number) => new Date(value).toLocaleString();
const sampleSensor: KernelSensor = {
  schema: 'rudy.sensor-enrollment.v1',
  id: 'demo-sensor',
  createdAt: new Date().toISOString(),
  bootId: '00000000-0000-4000-8000-000000000000',
  architecture: 'x86_64',
  name: 'Atlas · application host',
  hostname: 'atlas.example.test',
  uid: 1000,
  state: 'enrolled',
  engagementId: 'demo',
  kernel: '6.8.0 · illustrative',
  hostId: 'a'.repeat(64),
  publicKey: 'b'.repeat(64),
};
const sampleEvents = Array.from({ length: 24 }, (_, i) => ({
  timestampNs: String(17000000000n + BigInt(i) * 850000000n),
  cgroupId: '10488',
  pid: 2450 + Math.floor(i / 3),
  tid: 2450 + Math.floor(i / 3),
  uid: 1000,
  kind: ['process_exec', 'connect_attempt', 'process_exit'][i % 3] as
    'process_exec' | 'connect_attempt' | 'process_exit',
  comm: ['node', 'curl', 'worker'][Math.floor(i / 3) % 3],
}));
const sampleCapture: KernelCapture = {
  schema: 'rudy.kernel-capture.v1',
  agentVersion: '0.2.0',
  permit: { payload: 'illustrative', signature: 'illustrative' },
  startedAt: Date.now() - 3600000,
  finishedAt: Date.now() - 3570000,
  hooks: ['sched/sched_process_exec', 'sched/sched_process_exit', 'syscalls/sys_enter_connect'],
  stopReason: 'duration_elapsed',
  events: sampleEvents,
  readerUid: 65534,
  noNewPrivileges: true,
  programSha256: 'c'.repeat(64),
  counters: { seen: 24, emitted: 24, ringDropped: 0, budgetDropped: 0, decodeErrors: 0 },
  host: {
    kernel: '6.8.0 · illustrative',
    hostId: sampleSensor.hostId,
    bootId: sampleSensor.bootId,
    hostname: sampleSensor.hostname,
    architecture: 'x86_64',
  },
};
const sampleRecord: KernelCaptureRecord = {
  id: 'demo-capture',
  createdAt: new Date().toISOString(),
  permitId: 'demo-permit',
  evidenceId: 'demo-evidence',
  sensorId: 'demo-sensor',
  engagementId: 'demo',
  startedAt: Date.now() - 3600000,
  finishedAt: Date.now() - 3570000,
  eventCount: 24,
  counts: { process_exec: 8, process_exit: 8, connect_attempt: 8 },
  counters: sampleCapture.counters,
  kernel: '6.8.0 · illustrative',
  programSha256: sampleCapture.programSha256,
  stopReason: 'duration_elapsed',
};

export default function KernelPanel({
  demo,
  role,
  engagements,
  scope,
  onConnect,
  onChanged,
}: Props) {
  const [state, setState] = useState<KernelState | null>(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState('');
  const [dialog, setDialog] = useState<{
    type: 'enroll' | 'permit' | 'import' | 'revoke';
    sensor?: KernelSensor;
  } | null>(null);
  const [selected, setSelected] = useState<{
      record: KernelCaptureRecord;
      capture: KernelCapture;
    } | null>(null),
    [filter, setFilter] = useState(''),
    [page, setPage] = useState(0),
    [permit, setPermit] = useState<Envelope | null>(null);
  const modalRef = useRef<HTMLDialogElement>(null),
    returnFocus = useRef<HTMLElement | null>(null);
  const refresh = async () => setState(await api<KernelState>('/api/kernel'));
  useEffect(() => {
    if (demo) {
      setState({
        sensors: [sampleSensor],
        captures: [sampleRecord],
        authorityPublicKey: '',
        engine: { localPlatform: 'demo' },
      });
      setSelected({ record: sampleRecord, capture: sampleCapture });
    } else {
      setState(null);
      setSelected(null);
      refresh().catch((e) => setError(e.message));
    }
  }, [demo]);
  useEffect(() => {
    if (dialog) {
      returnFocus.current = document.activeElement as HTMLElement;
      modalRef.current?.showModal();
    } else {
      modalRef.current?.close();
      returnFocus.current?.focus();
    }
  }, [dialog]);
  useEffect(() => {
    if (!demo && scope !== 'all') {
      setSelected((current) => (current?.record.engagementId === scope ? current : null));
      setPage(0);
    }
  }, [scope, demo]);
  const open = (type: NonNullable<typeof dialog>['type'], sensor?: KernelSensor) => {
    if (demo) {
      onConnect();
      return;
    }
    if (role !== 'operator') {
      setNotice('An operator must authorize this action.');
      return;
    }
    setError('');
    setPermit(null);
    setDialog({ type, sensor });
  };
  async function submit(
    event: React.FormEvent<HTMLFormElement>,
    action: (data: FormData) => Promise<void>,
  ) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      await action(new FormData(event.currentTarget));
      await refresh();
      await onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function inspect(record: KernelCaptureRecord) {
    setError('');
    setPage(0);
    setFilter('');
    try {
      setSelected(
        demo
          ? { record: sampleRecord, capture: sampleCapture }
          : await api(`/api/kernel/captures/${record.id}`),
      );
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const inScope = (engagementId: string) => demo || scope === 'all' || scope === engagementId;
  const sensors = state?.sensors.filter((s) => inScope(s.engagementId)) || [],
    captures = state?.captures.filter((c) => inScope(c.engagementId)) || [];
  const events =
    selected?.capture.events.filter((e) =>
      `${e.kind} ${e.comm} ${e.pid} ${e.uid}`.toLowerCase().includes(filter.toLowerCase()),
    ) || [];
  const stats = captures.reduce(
    (a, c) => ({
      events: a.events + c.eventCount,
      dropped:
        a.dropped + c.counters.ringDropped + c.counters.budgetDropped + c.counters.decodeErrors,
    }),
    { events: 0, dropped: 0 },
  );
  return (
    <div className="kernel-workspace">
      <section className="kernel-hero">
        <div>
          <span className="eyebrow">RUDY NATIVE / KERNEL OBSERVABILITY</span>
          <h2>
            Below the application.
            <br />
            Inside the evidence.
          </h2>
          <p>
            Signed, bounded Linux captures. Follow processes and connection attempts from kernel
            tracepoints to reviewable evidence.
          </p>
          <div className="kernel-tags">
            <span>
              <Cpu size={13} /> Rust + eBPF
            </span>
            <span>
              <LockKeyhole size={13} /> Ed25519 authority
            </span>
            <span>Linux x86_64</span>
          </div>
        </div>
        <div className="kernel-stack" aria-label="Telemetry architecture">
          <div>
            <span>01</span>
            <b>Linux kernel</b>
            <small>3 fixed tracepoints</small>
          </div>
          <i />
          <div>
            <span>02</span>
            <b>Rust reader</b>
            <small>Root dropped after attach</small>
          </div>
          <i />
          <div>
            <span>03</span>
            <b>Evidence vault</b>
            <small>Signed capture · SHA-256</small>
          </div>
        </div>
      </section>
      {demo && (
        <div className="kernel-message">
          <Fingerprint size={17} />
          <p>
            <b>Illustrative telemetry.</b> These 24 example events explain the workflow. Connect a
            workspace to enroll your Linux host and import a real capture.
          </p>
        </div>
      )}
      {!demo && state?.engine.localPlatform !== 'linux' && (
        <div className="kernel-message">
          <Cpu size={17} />
          <p>
            Your workbench is running on{' '}
            {state?.engine.localPlatform === 'win32'
              ? 'Windows'
              : state?.engine.localPlatform || 'this computer'}
            . Capture events with the Linux agent on your authorized host, then import the signed
            artifact here.
          </p>
        </div>
      )}
      {!dialog && error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="kernel-message" role="status">
          {notice}
          <button onClick={() => setNotice('')} aria-label="Dismiss kernel notice">
            <X size={14} />
          </button>
        </p>
      )}
      <div className="kernel-metrics">
        {[
          [sensors.filter((s) => s.state === 'enrolled').length, 'Enrolled hosts'],
          [captures.length, 'Verified captures'],
          [stats.events.toLocaleString(), 'Captured events'],
          [stats.dropped.toLocaleString(), 'Dropped / suppressed'],
        ].map(([value, title]) => (
          <div key={title}>
            <small>{title}</small>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      <section className="panel kernel-hosts">
        <header>
          <div>
            <span className="eyebrow">HOST AUTHORIZATION</span>
            <h3>Sensor registry</h3>
          </div>
          <div className="button-row">
            <button
              disabled={busy || demo}
              onClick={() => refresh().catch((e) => setError(e.message))}
              aria-label="Refresh kernel registry"
            >
              <RefreshCw size={15} />
            </button>
            <button onClick={() => open('import')}>
              <Upload size={15} />
              Import capture
            </button>
            <button className="primary" onClick={() => open('enroll')}>
              <Plus size={15} />
              Enroll host
            </button>
          </div>
        </header>
        {sensors.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host / kernel</th>
                  <th>Authorized UID</th>
                  <th>Last capture</th>
                  <th>Authorization</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sensors.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <b>{s.name}</b>
                      <small>
                        {s.hostname} · {s.kernel}
                      </small>
                    </td>
                    <td>
                      <code>{s.uid}</code>
                    </td>
                    <td>
                      {s.lastCaptureAt
                        ? new Date(s.lastCaptureAt).toLocaleString()
                        : 'No real capture yet'}
                    </td>
                    <td>
                      <span className={`kernel-state ${s.state}`}>{s.state}</span>
                    </td>
                    <td>
                      <div className="button-row">
                        <button disabled={s.state === 'revoked'} onClick={() => open('permit', s)}>
                          Issue permit
                          <ArrowRight size={14} />
                        </button>
                        <button disabled={s.state === 'revoked'} onClick={() => open('revoke', s)}>
                          Revoke
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">
            <Cpu size={28} />
            <h3>No Linux hosts enrolled</h3>
            <p>
              Build the native agent, generate its public enrollment record, and bind it to an
              engagement.
            </p>
            <code>rudy-agent enroll --key-file sensor.key</code>
          </div>
        )}
      </section>
      <div className="kernel-evidence-grid">
        <section className="panel kernel-capture-list">
          <header>
            <span className="eyebrow">CAPTURE HISTORY</span>
            <h3>Verified artifacts</h3>
            <p>Showing up to 100 recent captures.</p>
          </header>
          {captures.length ? (
            captures.map((c) => (
              <button
                key={c.id}
                className={selected?.record.id === c.id ? 'selected' : ''}
                onClick={() => inspect(c)}
              >
                <Activity size={18} />
                <span>
                  <b>{sensors.find((s) => s.id === c.sensorId)?.name || 'Linux host'}</b>
                  <small>{at(c.startedAt)}</small>
                  <small>
                    {c.eventCount.toLocaleString()} events ·{' '}
                    {((c.finishedAt - c.startedAt) / 1000).toFixed(1)}s
                  </small>
                </span>
                <ArrowRight size={15} />
              </button>
            ))
          ) : (
            <div className="empty">
              <Layers3 size={25} />
              <p>Imported captures appear here after both signatures and scope checks pass.</p>
            </div>
          )}
        </section>
        <section className="panel kernel-events">
          <header>
            <div>
              <span className="eyebrow">EVENT EXPLORER</span>
              <h3>{selected ? 'Trace the capture.' : 'Waiting for evidence.'}</h3>
            </div>
            {selected && !demo && (
              <a
                className="kernel-download"
                href={`/api/evidence/${selected.record.evidenceId}`}
                download
              >
                <ArrowDownToLine size={16} />
                Artifact
              </a>
            )}
          </header>
          {selected ? (
            <>
              <div className="kernel-event-counts">
                {(['process_exec', 'connect_attempt', 'process_exit'] as const).map((kind) => (
                  <div key={kind}>
                    <span className={`event-dot ${kind}`} />
                    <span>{label(kind)}</span>
                    <b>{selected.record.counts[kind] || 0}</b>
                  </div>
                ))}
              </div>
              <div className="kernel-assurance">
                <ShieldCheck size={16} />
                <span>
                  {demo ? 'Illustrative evidence' : 'Sensor signature verified'} · reader UID 65534
                  · no_new_privs
                </span>
              </div>
              <div className="kernel-event-filter">
                <input
                  aria-label="Filter kernel events"
                  placeholder="Filter by process, event, PID or UID…"
                  value={filter}
                  onChange={(e) => {
                    setFilter(e.target.value);
                    setPage(0);
                  }}
                />
                <span>{events.length} events</span>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Event</th>
                      <th>Process</th>
                      <th>PID / TID</th>
                      <th>UID</th>
                      <th>Monotonic time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.slice(page * 25, (page + 1) * 25).map((e, i) => (
                      <tr key={`${page}-${i}`}>
                        <td>
                          <span className={`event-dot ${e.kind}`} />
                          {label(e.kind)}
                        </td>
                        <td>
                          <code>{e.comm || 'unknown'}</code>
                        </td>
                        <td>
                          {e.pid} / {e.tid}
                        </td>
                        <td>{e.uid}</td>
                        <td>
                          <code>{(Number(e.timestampNs) / 1e9).toFixed(6)}s</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="kernel-pagination">
                <button disabled={page === 0} onClick={() => setPage(page - 1)}>
                  Previous
                </button>
                <span>
                  {page + 1} / {Math.max(1, Math.ceil(events.length / 25))}
                </span>
                <button
                  disabled={(page + 1) * 25 >= events.length}
                  onClick={() => setPage(page + 1)}
                >
                  Next
                </button>
              </div>
              <div className="kernel-provenance">
                <dl className="kernel-counter-detail">
                  {Object.entries(selected.capture.counters).map(([name, value]) => (
                    <div key={name}>
                      <dt>{name.replace(/([A-Z])/g, ' $1').toLowerCase()}</dt>
                      <dd>{value.toLocaleString()}</dd>
                    </div>
                  ))}
                </dl>
                <span>Embedded eBPF object / SHA-256</span>
                <code>{selected.capture.programSha256}</code>
                <small>
                  Connection attempts record the syscall event, not its result or destination. Event
                  absence does not prove security. Signatures identify an enrolled key; they are not
                  remote host attestation.
                </small>
              </div>
            </>
          ) : (
            <div className="empty">
              <Terminal size={30} />
              <h3>Inspect what the kernel observed</h3>
              <p>Select a signed capture to inspect process metadata and collection counters.</p>
            </div>
          )}
        </section>
      </div>
      <div className="kernel-message">
        <LockKeyhole size={17} />
        <p>
          Capture permits expire after 15 minutes and bind one host, boot, sensor key, and UID. Each
          capture is limited to 300 seconds and 10,000 events. Offline revocation blocks import and
          new permits; an already issued offline permit can run until its deadline.
        </p>
      </div>
      <dialog
        ref={modalRef}
        className="kernel-dialog"
        aria-label={
          dialog
            ? {
                enroll: 'Enroll a Linux host',
                permit: 'Authorize kernel capture',
                import: 'Import kernel capture',
                revoke: 'Revoke sensor',
              }[dialog.type]
            : 'Kernel action'
        }
        onCancel={(e) => {
          e.preventDefault();
          if (!busy) setDialog(null);
        }}
      >
        <button
          className="modal-close"
          disabled={busy}
          aria-label="Close kernel dialog"
          onClick={() => setDialog(null)}
        >
          <X size={18} />
        </button>
        {dialog?.type === 'enroll' && (
          <>
            <span className="eyebrow">LOCAL INSTALLATION / EXPLICIT SCOPE</span>
            <h2>Enroll a Linux host</h2>
            <p>
              On the host you administer, run the Rust agent and paste its public enrollment JSON.
              Keep <code>sensor.key</code> private.
            </p>
            <pre>rudy-agent enroll --key-file sensor.key</pre>
            <form
              onSubmit={(e) =>
                submit(e, async (f) => {
                  await api('/api/kernel/sensors', {
                    engagementId: f.get('engagementId'),
                    name: f.get('name'),
                    uid: Number(f.get('uid')),
                    enrollment: JSON.parse(String(f.get('enrollment'))),
                    authorized: true,
                  });
                  setDialog(null);
                  setNotice('Host enrolled. Issue a permit to authorize a bounded capture.');
                })
              }
            >
              <label>
                Engagement
                <select required name="engagementId" defaultValue={scope === 'all' ? '' : scope}>
                  <option value="" disabled>
                    Select an engagement
                  </option>
                  {engagements.map((e) => (
                    <option key={e.id} value={e.id}>
                      {e.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Sensor name
                <input
                  name="name"
                  required
                  maxLength={120}
                  placeholder="Production application host"
                />
              </label>
              <label>
                Authorized Linux UID
                <input
                  type="number"
                  name="uid"
                  required
                  min={0}
                  max={4294967295}
                  defaultValue={1000}
                />
              </label>
              <label>
                Public enrollment JSON
                <textarea
                  name="enrollment"
                  required
                  rows={6}
                  placeholder='{"schema":"rudy.sensor-enrollment.v1", ...}'
                />
              </label>
              <label className="checkbox">
                <input type="checkbox" required />I administer this host and have written
                authorization for this UID’s process metadata.
              </label>
              <button className="primary" disabled={busy || !engagements.length}>
                Enroll authorized host
              </button>
            </form>
          </>
        )}
        {dialog?.type === 'permit' && (
          <>
            <span className="eyebrow">ED25519 / ONE CAPTURE</span>
            <h2>Authorize {dialog.sensor?.name}</h2>
            <p>
              Bound to this boot and UID <b>{dialog.sensor?.uid}</b>. Install the authority public
              key through a trusted channel before running the agent.
            </p>
            {permit ? (
              <>
                <div className="kernel-message">
                  <CheckCircle2 size={18} />
                  Permit issued. It expires in 15 minutes.
                </div>
                <div className="button-row">
                  <button onClick={() => save('capture-permit.json', permit)}>
                    <ArrowDownToLine size={15} />
                    Download permit
                  </button>
                  <button
                    onClick={() => save('rudy-authority.pub', state!.authorityPublicKey + '\n')}
                  >
                    <ArrowDownToLine size={15} />
                    Authority key
                  </button>
                </div>
                <pre>
                  {'sudo rudy-agent capture \\\n  --key-file sensor.key \\\n  --authority rudy-authority.pub \\\n  --permit capture-permit.json \\\n  --out capture.json --seconds ' +
                    JSON.parse(atob(permit.payload.replaceAll('-', '+').replaceAll('_', '/')))
                      .maxDurationSeconds}
                </pre>
                <p>
                  The output file is root-owned. Read it with sudo and transfer it securely to this
                  workbench. Every capture attempt consumes the permit locally.
                </p>
              </>
            ) : (
              <form
                onSubmit={(e) =>
                  submit(e, async (f) => {
                    setPermit(
                      await api<Envelope>(`/api/kernel/sensors/${dialog.sensor!.id}/permit`, {
                        maxDurationSeconds: Number(f.get('seconds')),
                        maxEvents: Number(f.get('events')),
                        authorized: true,
                      }),
                    );
                  })
                }
              >
                <label>
                  Maximum duration (seconds)
                  <input
                    name="seconds"
                    type="number"
                    min={1}
                    max={300}
                    defaultValue={30}
                    required
                  />
                </label>
                <label>
                  Event budget
                  <input
                    name="events"
                    type="number"
                    min={1}
                    max={10000}
                    defaultValue={1000}
                    required
                  />
                </label>
                <label className="checkbox">
                  <input type="checkbox" required />I authorize this bounded, read-only capture.
                </label>
                <button className="primary" disabled={busy}>
                  Issue signed permit
                </button>
              </form>
            )}
          </>
        )}
        {dialog?.type === 'import' && (
          <>
            <span className="eyebrow">VERIFY / NORMALIZE / PRESERVE</span>
            <h2>Import a kernel capture</h2>
            <p>
              The server checks the enrolled sensor’s signature, authority signature, host and UID
              scope, timestamps, counters, and replay state before accepting the artifact.
            </p>
            <form
              onSubmit={(e) =>
                submit(e, async (f) => {
                  const file = f.get('file') as File;
                  if (!file?.size || file.size > 5000000)
                    throw new Error('Choose a JSON capture under 5 MB.');
                  await api('/api/kernel/captures', {
                    sensorId: f.get('sensorId'),
                    artifact: JSON.parse(await file.text()),
                  });
                  setDialog(null);
                  setNotice('Capture verified and saved to the evidence vault.');
                })
              }
            >
              <label>
                Enrolled sensor
                <select name="sensorId" required defaultValue="">
                  <option value="" disabled>
                    Select a sensor
                  </option>
                  {sensors
                    .filter((s) => s.state === 'enrolled')
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                </select>
              </label>
              <label>
                Signed capture JSON
                <input name="file" type="file" accept=".json,application/json" required />
              </label>
              <button className="primary" disabled={busy}>
                Verify and import
              </button>
            </form>
          </>
        )}
        {dialog?.type === 'revoke' && (
          <>
            <span className="eyebrow">REVOKE HOST AUTHORIZATION</span>
            <h2>Revoke {dialog.sensor?.name}?</h2>
            <p>
              New permits and further imports from this sensor will be blocked. A capture already
              running offline stops at its kernel deadline; revocation cannot remotely interrupt it.
            </p>
            <form
              onSubmit={(e) =>
                submit(e, async () => {
                  await api(`/api/kernel/sensors/${dialog.sensor!.id}/revoke`, {});
                  setDialog(null);
                  setNotice('Sensor revoked and outstanding imports blocked.');
                })
              }
            >
              <button className="danger" disabled={busy}>
                Revoke sensor
              </button>
            </form>
          </>
        )}
        {error && dialog && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </dialog>
    </div>
  );
}
