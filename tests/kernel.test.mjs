import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { createApp } from '../server/app.mts';
import { Store } from '../server/store.mts';
import {
  generateAuthority,
  authorityPublic,
  signEnvelope,
  verifyEnvelope,
  permitSchema,
} from '../server/kernel.mts';

async function fixture(t) {
  const store = new Store(':memory:', 'kernel-test-audit');
  const authority = generateAuthority(),
    sensorKey = generateAuthority();
  const adminKey = 'admin-'.repeat(8),
    viewerKey = 'viewer-'.repeat(8);
  const runtime = createApp({ store, adminKey, viewerKey, kernelAuthority: authority });
  const server = runtime.app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  t.after(async () => {
    runtime.shutdown();
    await new Promise((r) => server.close(r));
    store.close();
  });
  let cookie = '';
  const request = (route, body, method = body === undefined ? 'GET' : 'POST') =>
    new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: server.address().port,
          path: route,
          method,
          headers: {
            Host: '127.0.0.1:4173',
            'Content-Type': 'application/json',
            'X-Rudy-Request': '1',
            Cookie: cookie,
          },
        },
        (res) => {
          if (res.headers['set-cookie']) cookie = res.headers['set-cookie'][0].split(';')[0];
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString();
            let data;
            try {
              data = JSON.parse(raw);
            } catch {
              data = raw;
            }
            resolve({ status: res.statusCode, data });
          });
        },
      );
      req.on('error', reject);
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  const login = (key = adminKey) => request('/api/session', { key });
  await login();
  const engagement = store.create('engagement', {
    name: 'Kernel test',
    client: 'Fixture',
    objective: 'Authorized kernel telemetry integration test',
    status: 'active',
  });
  const enrollment = {
    schema: 'rudy.sensor-enrollment.v1',
    hostId: 'a'.repeat(64),
    bootId: crypto.randomUUID(),
    hostname: 'fixture.test',
    kernel: 'fixture-kernel',
    architecture: 'x86_64',
    publicKey: authorityPublic(sensorKey),
  };
  const sensorBody = {
    engagementId: engagement.id,
    name: 'Test sensor',
    uid: 1000,
    enrollment,
    authorized: true,
  };
  const s = await request('/api/kernel/sensors', sensorBody);
  assert.equal(s.status, 201);
  const sensor = s.data;
  const p = await request(`/api/kernel/sensors/${sensor.id}/permit`, {
    maxDurationSeconds: 30,
    maxEvents: 10,
    authorized: true,
  });
  assert.equal(p.status, 201);
  const scope = permitSchema.parse(verifyEnvelope(p.data, authorityPublic(authority)));
  const capture = {
    schema: 'rudy.kernel-capture.v1',
    agentVersion: '0.2.0',
    permit: p.data,
    host: {
      hostId: enrollment.hostId,
      bootId: enrollment.bootId,
      hostname: enrollment.hostname,
      kernel: enrollment.kernel,
      architecture: 'x86_64',
    },
    startedAt: scope.issuedAt,
    finishedAt: scope.issuedAt + 1000,
    hooks: ['sched/sched_process_exec', 'sched/sched_process_exit', 'syscalls/sys_enter_connect'],
    programSha256: 'f'.repeat(64),
    readerUid: 65534,
    noNewPrivileges: true,
    stopReason: 'duration_elapsed',
    counters: { seen: 1, emitted: 1, ringDropped: 0, budgetDropped: 0, decodeErrors: 0 },
    events: [
      {
        timestampNs: '99999999999999999',
        cgroupId: '18446744073709551615',
        pid: 42,
        tid: 42,
        uid: 1000,
        comm: 'fixture',
        kind: 'process_exec',
      },
    ],
  };
  const upload = (value = capture, key = sensorKey) =>
    request('/api/kernel/captures', { sensorId: sensor.id, artifact: signEnvelope(value, key) });
  return {
    request,
    store,
    authority,
    sensorKey,
    sensorBody,
    sensor,
    scope,
    capture,
    upload,
    login,
    viewerKey,
  };
}
test('kernel permit binds one host, boot, key, UID and finite budget', async (t) => {
  const f = await fixture(t);
  assert.equal(f.scope.hostId, f.sensor.hostId);
  assert.equal(f.scope.bootId, f.sensor.bootId);
  assert.equal(f.scope.publicKey, f.sensor.publicKey);
  assert.equal(f.scope.uid, 1000);
  assert.equal(f.scope.expiresAt - f.scope.issuedAt, 900000);
  for (const body of [
    { maxEvents: 10001, maxDurationSeconds: 30, authorized: true },
    { maxEvents: 1, maxDurationSeconds: 301, authorized: true },
    { maxEvents: 1, maxDurationSeconds: 30, authorized: false },
  ])
    assert.equal((await f.request(`/api/kernel/sensors/${f.sensor.id}/permit`, body)).status, 400);
  assert.equal((await f.request('/api/kernel/sensors', f.sensorBody)).status, 409);
  assert.equal(
    (
      await f.request('/api/kernel/sensors', {
        ...f.sensorBody,
        enrollment: { ...f.sensorBody.enrollment, privateKey: 'do-not-upload-private-keys' },
      })
    ).status,
    400,
  );
});
test('kernel ingestion verifies both signatures and atomically prevents replay', async (t) => {
  const f = await fixture(t);
  const results = await Promise.all([f.upload(), f.upload()]);
  assert.deepEqual(results.map((r) => r.status).sort(), [201, 403]);
  const record = results.find((r) => r.status === 201).data;
  assert.equal(f.store.get('kernelPermit', f.scope.id).state, 'consumed');
  assert.equal(f.store.list('kernelCapture').length, 1);
  assert.equal(f.store.list('evidence').length, 1);
  assert(f.store.integrity().valid);
  const detail = await f.request(`/api/kernel/captures/${record.id}`);
  assert.equal(detail.status, 200);
  assert.equal(detail.data.capture.events[0].timestampNs, '99999999999999999');
  assert.equal((await f.request('/api/kernel')).data.captures[0].eventCount, 1);
});
test('forged sensor signatures and modified authority permits cannot become evidence', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.upload(f.capture, generateAuthority())).status, 403);
  const forged = structuredClone(f.capture);
  forged.permit = signEnvelope({ ...f.scope, uid: 0 }, f.sensorKey);
  assert.equal((await f.upload(forged)).status, 403);
  const tampered = signEnvelope(f.capture, f.sensorKey);
  tampered.payload = Buffer.from(JSON.stringify({ ...f.capture, readerUid: 0 })).toString(
    'base64url',
  );
  assert.equal(
    (await f.request('/api/kernel/captures', { sensorId: f.sensor.id, artifact: tampered })).status,
    403,
  );
  assert.equal(f.store.list('evidence').length, 0);
});
test('signed but out-of-scope capture metadata is rejected', async (t) => {
  const f = await fixture(t);
  const mutations = [
    (c) => {
      c.host.hostId = 'b'.repeat(64);
    },
    (c) => {
      c.host.bootId = crypto.randomUUID();
    },
    (c) => {
      c.events[0].uid = 0;
    },
    (c) => {
      c.startedAt = f.scope.issuedAt - 1;
    },
    (c) => {
      c.finishedAt = f.scope.expiresAt + 6000;
    },
    (c) => {
      c.counters.emitted = 2;
    },
    (c) => {
      c.counters.seen = 0;
    },
    (c) => {
      c.events = Array(11).fill(c.events[0]);
      c.counters.seen = 11;
      c.counters.emitted = 11;
    },
    (c) => {
      c.readerUid = 0;
    },
    (c) => {
      c.noNewPrivileges = false;
    },
    (c) => {
      c.hooks = ['arbitrary/kprobe'];
    },
  ];
  for (const mutate of mutations) {
    const bad = structuredClone(f.capture);
    mutate(bad);
    const result = await f.upload(bad);
    assert([400, 403].includes(result.status), JSON.stringify(result));
  }
  assert.equal(f.store.list('evidence').length, 0);
  assert.equal(f.store.get('kernelPermit', f.scope.id).state, 'issued');
});
test('revoking a sensor blocks outstanding permits and artifact ingestion', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request(`/api/kernel/sensors/${f.sensor.id}/revoke`, {})).status, 200);
  assert.equal((await f.upload()).status, 403);
  assert.equal(f.store.get('kernelPermit', f.scope.id).state, 'revoked');
  assert.equal(
    (
      await f.request(`/api/kernel/sensors/${f.sensor.id}/permit`, {
        maxDurationSeconds: 3,
        maxEvents: 10,
        authorized: true,
      })
    ).status,
    403,
  );
});
test('viewer can review kernel evidence but cannot enroll, authorize, revoke or import', async (t) => {
  const f = await fixture(t);
  await f.login(f.viewerKey);
  assert.equal((await f.request('/api/kernel')).status, 200);
  assert.equal((await f.request('/api/kernel/authority')).status, 200);
  assert.equal((await f.request('/api/kernel/sensors', f.sensorBody)).status, 403);
  assert.equal(
    (
      await f.request(`/api/kernel/sensors/${f.sensor.id}/permit`, {
        maxDurationSeconds: 3,
        maxEvents: 1,
        authorized: true,
      })
    ).status,
    403,
  );
  assert.equal((await f.request(`/api/kernel/sensors/${f.sensor.id}/revoke`, {})).status, 403);
  assert.equal((await f.upload()).status, 403);
});
