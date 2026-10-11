import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import type { Express } from 'express';
import { z } from 'zod';
import type { Store } from './store.mts';
import { PolicyError, digest } from './security.mts';

const hexKey = z.string().regex(/^[a-f0-9]{64}$/);
const uid = z.number().int().min(0).max(4294967295);
const boundedNumber = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const envelopeSchema = z
  .object({
    payload: z
      .string()
      .min(1)
      .max(4000000)
      .regex(/^[A-Za-z0-9_-]+$/),
    signature: z
      .string()
      .length(86)
      .regex(/^[A-Za-z0-9_-]+$/),
  })
  .strict();
export type Envelope = z.infer<typeof envelopeSchema>;
export const permitSchema = z
  .object({
    schema: z.literal('rudy.kernel-permit.v1'),
    id: z.string().uuid(),
    sensorId: z.string().uuid(),
    engagementId: z.string().uuid(),
    hostId: hexKey,
    bootId: z.string().uuid(),
    publicKey: hexKey,
    uid,
    issuedAt: boundedNumber,
    expiresAt: boundedNumber,
    maxDurationSeconds: z.number().int().min(1).max(300),
    maxEvents: z.number().int().min(1).max(10000),
  })
  .strict();
export type KernelPermit = z.infer<typeof permitSchema>;
export type KernelPermitRecord = KernelPermit & {
  createdAt: string;
  state: 'issued' | 'consumed' | 'revoked';
  envelope: Envelope;
};
const enrollmentSchema = z
  .object({
    schema: z.literal('rudy.sensor-enrollment.v1'),
    hostId: hexKey,
    bootId: z.string().uuid(),
    hostname: z.string().min(1).max(253),
    kernel: z.string().min(1).max(120),
    architecture: z.literal('x86_64'),
    publicKey: hexKey,
  })
  .strict();
export type KernelSensor = z.infer<typeof enrollmentSchema> & {
  id: string;
  createdAt: string;
  engagementId: string;
  name: string;
  uid: number;
  state: 'enrolled' | 'revoked';
  lastCaptureAt?: string;
};
const eventSchema = z
  .object({
    timestampNs: z.string().regex(/^\d{1,20}$/),
    cgroupId: z.string().regex(/^\d{1,20}$/),
    pid: uid,
    tid: uid,
    uid,
    kind: z.enum(['process_exec', 'process_exit', 'connect_attempt']),
    comm: z.string().max(64),
  })
  .strict();
export const captureSchema = z
  .object({
    schema: z.literal('rudy.kernel-capture.v1'),
    agentVersion: z.literal('0.2.0'),
    permit: envelopeSchema,
    host: z
      .object({
        hostId: hexKey,
        bootId: z.string().uuid(),
        hostname: z.string().max(253),
        kernel: z.string().max(120),
        architecture: z.literal('x86_64'),
      })
      .strict(),
    startedAt: boundedNumber,
    finishedAt: boundedNumber,
    hooks: z.tuple([
      z.literal('sched/sched_process_exec'),
      z.literal('sched/sched_process_exit'),
      z.literal('syscalls/sys_enter_connect'),
    ]),
    programSha256: hexKey,
    readerUid: z.literal(65534),
    noNewPrivileges: z.literal(true),
    stopReason: z.enum(['duration_elapsed', 'operator_signal']),
    counters: z
      .object({
        seen: boundedNumber,
        emitted: boundedNumber,
        ringDropped: boundedNumber,
        budgetDropped: boundedNumber,
        decodeErrors: boundedNumber,
      })
      .strict(),
    events: z.array(eventSchema).max(10000),
  })
  .strict();
export type KernelCapture = z.infer<typeof captureSchema>;
export type KernelCaptureRecord = {
  id: string;
  createdAt: string;
  engagementId: string;
  sensorId: string;
  permitId: string;
  evidenceId: string;
  startedAt: number;
  finishedAt: number;
  eventCount: number;
  counts: Record<string, number>;
  counters: KernelCapture['counters'];
  programSha256: string;
  kernel: string;
  stopReason: string;
};
export function generateAuthority() {
  return crypto.generateKeyPairSync('ed25519').privateKey;
}
export function authorityPublic(key: KeyObject) {
  return crypto
    .createPublicKey(key)
    .export({ type: 'spki', format: 'der' })
    .subarray(-32)
    .toString('hex');
}
export function loadAuthority(filename: string): KeyObject {
  if (!fs.existsSync(filename))
    fs.writeFileSync(filename, generateAuthority().export({ type: 'pkcs8', format: 'pem' }), {
      mode: 0o600,
      flag: 'wx',
    });
  const key = crypto.createPrivateKey(fs.readFileSync(filename));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Kernel authority must be Ed25519.');
  return key;
}
export function signEnvelope(payload: unknown, key: KeyObject): Envelope {
  const bytes = Buffer.from(JSON.stringify(payload));
  return {
    payload: bytes.toString('base64url'),
    signature: crypto.sign(null, bytes, key).toString('base64url'),
  };
}
export function verifyEnvelope(envelope: Envelope, publicKey: string): unknown {
  const bytes = Buffer.from(envelope.payload, 'base64url');
  const key = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(hexKey.parse(publicKey), 'hex'),
    ]),
    format: 'der',
    type: 'spki',
  });
  if (!crypto.verify(null, bytes, key, Buffer.from(envelope.signature, 'base64url')))
    throw new PolicyError('Invalid sensor or authority signature.', 403);
  try {
    return JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    throw new PolicyError('Invalid signed JSON.');
  }
}
export function kernelState(store: Store) {
  return {
    sensors: store.list('sensor'),
    captures: store.list('kernelCapture').slice(0, 100),
    permits: store
      .list('kernelPermit')
      .slice(0, 100)
      .map(({ envelope, ...p }) => p),
    engine: {
      version: '0.2.0',
      runtime: 'Rust + libbpf',
      kernel: 'Linux x86_64',
      mode: 'Bounded offline capture',
      hooks: 3,
      localPlatform: process.platform,
      maxEvents: 10000,
      maxDurationSeconds: 300,
    },
  };
}
export function validateCapture(
  c: KernelCapture,
  p: KernelPermitRecord,
  sensor: KernelSensor,
  now = Date.now(),
) {
  if (sensor.state !== 'enrolled' || p.state !== 'issued')
    throw new PolicyError(
      'Sensor or permit is revoked, or this permit has already been consumed.',
      403,
    );
  if (
    p.sensorId !== sensor.id ||
    p.engagementId !== sensor.engagementId ||
    p.publicKey !== sensor.publicKey ||
    p.hostId !== sensor.hostId ||
    p.bootId !== sensor.bootId ||
    p.uid !== sensor.uid ||
    c.host.hostId !== p.hostId ||
    c.host.bootId !== p.bootId
  )
    throw new PolicyError('Capture does not match the enrolled host and scope.', 403);
  if (c.permit.payload !== p.envelope.payload || c.permit.signature !== p.envelope.signature)
    throw new PolicyError('Capture permit does not match the issued permit.', 403);
  if (
    c.startedAt < p.issuedAt ||
    c.startedAt >= p.expiresAt ||
    c.finishedAt < c.startedAt ||
    c.finishedAt > p.expiresAt + 5000 ||
    c.finishedAt > now + 5000 ||
    c.finishedAt - c.startedAt > p.maxDurationSeconds * 1000 + 5000
  )
    throw new PolicyError('Capture is outside the authorized time window.', 403);
  if (c.events.length > p.maxEvents || c.events.some((e) => e.uid !== p.uid))
    throw new PolicyError('Capture exceeds its event or UID scope.', 403);
  const counts = c.counters;
  if (
    counts.emitted > p.maxEvents ||
    counts.seen !== counts.emitted + counts.ringDropped + counts.budgetDropped ||
    counts.emitted !== c.events.length + counts.decodeErrors
  )
    throw new PolicyError('Capture counter accounting is inconsistent.');
}
export function mountKernelRoutes(app: Express, store: Store, authority: KeyObject) {
  app.get('/api/kernel', (_req, res) =>
    res.json({ ...kernelState(store), authorityPublicKey: authorityPublic(authority) }),
  );
  app.get('/api/kernel/authority', (_req, res) =>
    res
      .type('text/plain')
      .set('Content-Disposition', 'attachment; filename="rudy-authority.pub"')
      .send(authorityPublic(authority) + '\n'),
  );
  app.post('/api/kernel/sensors', (req, res) => {
    const body = z
      .object({
        engagementId: z.string().uuid(),
        name: z.string().trim().min(1).max(120),
        uid,
        enrollment: enrollmentSchema,
        authorized: z.literal(true),
      })
      .strict()
      .parse(req.body);
    if (!store.get('engagement', body.engagementId))
      throw new PolicyError('Engagement not found.', 404);
    if (
      store
        .list('sensor')
        .some((s) => s.publicKey === body.enrollment.publicKey && s.state === 'enrolled')
    )
      throw new PolicyError('This sensor key is already enrolled.', 409);
    if (store.list('sensor').filter((s) => s.state === 'enrolled').length >= 100)
      throw new PolicyError('Workspace sensor limit reached.', 409);
    const row = store.transaction(() => {
      const s = store.create('sensor', {
        ...body.enrollment,
        engagementId: body.engagementId,
        name: body.name,
        uid: body.uid,
        state: 'enrolled',
      });
      store.audit(req.actor, 'sensor.enrolled', `${s.id} ${s.hostId} uid=${s.uid}`);
      return s;
    });
    res.status(201).json(row);
  });
  app.post('/api/kernel/sensors/:id/permit', (req, res) => {
    const sensor = store.get('sensor', z.string().uuid().parse(req.params.id));
    if (!sensor || sensor.state !== 'enrolled')
      throw new PolicyError('Sensor is missing or revoked.', 403);
    const body = z
      .object({
        maxDurationSeconds: z.number().int().min(1).max(300),
        maxEvents: z.number().int().min(1).max(10000),
        authorized: z.literal(true),
      })
      .strict()
      .parse(req.body);
    const now = Date.now();
    if (
      store
        .list('kernelPermit')
        .some((p) => p.sensorId === sensor.id && p.state === 'issued' && now - p.issuedAt < 10000)
    )
      throw new PolicyError('Wait 10 seconds between permit requests.', 429);
    const p: KernelPermit = {
      schema: 'rudy.kernel-permit.v1',
      id: crypto.randomUUID(),
      sensorId: sensor.id,
      engagementId: sensor.engagementId,
      hostId: sensor.hostId,
      bootId: sensor.bootId,
      publicKey: sensor.publicKey,
      uid: sensor.uid,
      issuedAt: now,
      expiresAt: now + 900000,
      maxDurationSeconds: body.maxDurationSeconds,
      maxEvents: body.maxEvents,
    };
    const envelope = signEnvelope(p, authority);
    store.transaction(() => {
      store.put('kernelPermit', {
        ...p,
        createdAt: new Date(now).toISOString(),
        state: 'issued',
        envelope,
      });
      store.audit(req.actor, 'kernel.permit_issued', `${p.id} ${sensor.id} uid=${p.uid}`);
    });
    res.status(201).json(envelope);
  });
  app.post('/api/kernel/sensors/:id/revoke', (req, res) => {
    const sensor = store.get('sensor', z.string().uuid().parse(req.params.id));
    if (!sensor) throw new PolicyError('Sensor not found.', 404);
    const row = store.transaction(() => {
      const row = store.put('sensor', { ...sensor, state: 'revoked' });
      for (const p of store.list('kernelPermit'))
        if (p.sensorId === sensor.id && p.state === 'issued')
          store.put('kernelPermit', { ...p, state: 'revoked' });
      store.audit(req.actor, 'sensor.revoked', sensor.id);
      return row;
    });
    res.json(row);
  });
  app.post('/api/kernel/captures', (req, res) => {
    const body = z
      .object({ sensorId: z.string().uuid(), artifact: envelopeSchema })
      .strict()
      .parse(req.body);
    const sensor = store.get('sensor', body.sensorId);
    if (!sensor || sensor.state !== 'enrolled')
      throw new PolicyError('Sensor not found or revoked.', 403);
    const capture = captureSchema.parse(verifyEnvelope(body.artifact, sensor.publicKey));
    const signedPermit = permitSchema.parse(
      verifyEnvelope(capture.permit, authorityPublic(authority)),
    );
    const permit = store.get('kernelPermit', signedPermit.id);
    if (!permit) throw new PolicyError('Unknown capture permit.', 403);
    validateCapture(capture, permit, sensor);
    const raw = JSON.stringify(body.artifact),
      counts: Record<string, number> = { process_exec: 0, process_exit: 0, connect_attempt: 0 };
    for (const event of capture.events) counts[event.kind]++;
    const result = store.transaction(() => {
      const evidence = store.create('evidence', {
        engagementId: sensor.engagementId,
        name: `Kernel capture · ${sensor.name}`,
        format: 'kernel-capture',
        raw,
        sha256: digest(raw),
        findingCount: 0,
      });
      const record = store.create('kernelCapture', {
        engagementId: sensor.engagementId,
        sensorId: sensor.id,
        permitId: permit.id,
        evidenceId: evidence.id,
        startedAt: capture.startedAt,
        finishedAt: capture.finishedAt,
        eventCount: capture.events.length,
        counts,
        counters: capture.counters,
        programSha256: capture.programSha256,
        kernel: capture.host.kernel,
        stopReason: capture.stopReason,
      });
      store.put('kernelPermit', { ...permit, state: 'consumed' });
      store.put('sensor', { ...sensor, lastCaptureAt: new Date(capture.finishedAt).toISOString() });
      store.audit(
        req.actor,
        'kernel.capture_imported',
        `${record.id} ${evidence.sha256} ${record.eventCount} events`,
      );
      return record;
    });
    res.status(201).json(result);
  });
  app.get('/api/kernel/captures/:id', (req, res) => {
    const record = store.get('kernelCapture', z.string().uuid().parse(req.params.id));
    if (!record) throw new PolicyError('Capture not found.', 404);
    const evidence = store.get('evidence', record.evidenceId);
    const sensor = store.get('sensor', record.sensorId);
    if (!evidence || !sensor) throw new PolicyError('Capture evidence unavailable.', 404);
    const capture = captureSchema.parse(
      verifyEnvelope(envelopeSchema.parse(JSON.parse(evidence.raw)), sensor.publicKey),
    );
    res.json({ record, capture });
  });
}
