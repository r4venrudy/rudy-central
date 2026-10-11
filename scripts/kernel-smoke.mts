// Runs only on an ephemeral, owned Linux CI runner. All traffic is loopback.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { spawn, execFileSync } from 'node:child_process';
import { Store } from '../server/store.mts';
import { createApp } from '../server/app.mts';
import {
  authorityPublic,
  generateAuthority,
  captureSchema,
  verifyEnvelope,
} from '../server/kernel.mts';

assert.equal(process.platform, 'linux');
const binary = path.resolve('native/target/release/rudy-agent');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'rudy-kernel-ci-'));
const keyFile = path.join(temp, 'sensor.key'),
  authorityFile = path.join(temp, 'authority.pub');
const enrollment = JSON.parse(
  execFileSync(binary, ['enroll', '--key-file', keyFile], { encoding: 'utf8' }),
);
const authority = generateAuthority();
fs.writeFileSync(authorityFile, authorityPublic(authority), { mode: 0o600 });
const store = new Store(':memory:', 'ci-' + crypto.randomUUID()),
  adminKey = crypto.randomBytes(32).toString('hex');
const runtime = createApp({ store, adminKey, kernelAuthority: authority });
const server = runtime.app.listen(0, '127.0.0.1');
await new Promise<void>((r) => server.once('listening', r));
const address = server.address();
assert(address && typeof address !== 'string');
let cookie = '';
async function request(route: string, method = 'GET', body?: unknown) {
  return new Promise<{ status: number; data: any }>((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: address!.port,
        path: route,
        method,
        headers: {
          Host: '127.0.0.1:4173',
          'X-Rudy-Request': '1',
          'Content-Type': 'application/json',
          Cookie: cookie,
        },
      },
      (res) => {
        if (res.headers['set-cookie']) cookie = res.headers['set-cookie'][0].split(';')[0];
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({ status: res.statusCode!, data: JSON.parse(Buffer.concat(chunks).toString()) }),
        );
      },
    );
    req.on('error', reject);
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
try {
  assert.equal((await request('/api/session', 'POST', { key: adminKey })).status, 200);
  const engagement = await request('/api/engagements', 'POST', {
    name: 'Linux kernel CI',
    client: 'Owned ephemeral runner',
    objective: 'Validate real kernel events through the authorization and evidence pipeline.',
  });
  assert.equal(engagement.status, 201);
  const sensor = await request('/api/kernel/sensors', 'POST', {
    engagementId: engagement.data.id,
    name: 'CI host',
    uid: os.userInfo().uid,
    enrollment,
    authorized: true,
  });
  assert.equal(sensor.status, 201);
  const captures = [];
  for (const [index, maxEvents] of [1000, 2].entries()) {
    const permitResult = await request(`/api/kernel/sensors/${sensor.data.id}/permit`, 'POST', {
      maxDurationSeconds: 3,
      maxEvents,
      authorized: true,
    });
    assert.equal(permitResult.status, 201, JSON.stringify(permitResult.data));
    const permitFile = path.join(temp, `permit-${index}.json`),
      out = path.join(temp, `capture-${index}.json`);
    fs.writeFileSync(permitFile, JSON.stringify(permitResult.data), { mode: 0o600 });
    const child = spawn(
      'sudo',
      [
        '-n',
        binary,
        'capture',
        '--key-file',
        keyFile,
        '--authority',
        authorityFile,
        '--permit',
        permitFile,
        '--out',
        out,
        '--seconds',
        '3',
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let stderr = '',
      stdout = '';
    child.stderr.on('data', (b) => {
      stderr += b.toString();
    });
    child.stdout.on('data', (b) => {
      stdout += b.toString();
    });
    const finished = new Promise<number | null>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Attach timeout: ${stderr}`)), 15000);
      const check = setInterval(() => {
        if (stderr.includes('RUDY_KERNEL_ATTACHED')) {
          clearTimeout(timer);
          clearInterval(check);
          resolve();
        }
      }, 20);
      finished
        .then((code) => {
          clearTimeout(timer);
          clearInterval(check);
          if (!stderr.includes('RUDY_KERNEL_ATTACHED'))
            reject(new Error(`Capture exited ${code}: ${stderr}`));
        })
        .catch(reject);
    });
    const tcp = net.createServer((s) => s.end());
    tcp.listen(0, '127.0.0.1');
    await new Promise<void>((r) => tcp.once('listening', r));
    const tcpAddress = tcp.address();
    assert(tcpAddress && typeof tcpAddress !== 'string');
    await new Promise<void>((resolve, reject) => {
      const client = net.connect(tcpAddress.port, '127.0.0.1');
      client.on('close', () => resolve());
      client.on('error', reject);
      client.resume();
    });
    await new Promise<void>((r) => tcp.close(() => r()));
    for (let i = 0; i < 10; i++) execFileSync('/usr/bin/true');
    assert.equal(await finished, 0, stderr);
    const artifact = JSON.parse(
      execFileSync('sudo', ['-n', 'cat', out], { encoding: 'utf8', maxBuffer: 5000000 }),
    );
    const capture = captureSchema.parse(verifyEnvelope(artifact, enrollment.publicKey));
    assert.equal(capture.readerUid, 65534);
    assert.equal(capture.noNewPrivileges, true);
    assert(capture.events.every((e) => e.uid === os.userInfo().uid));
    if (index === 0)
      for (const kind of ['process_exec', 'process_exit', 'connect_attempt'])
        assert(
          capture.events.some((e) => e.kind === kind),
          `Missing real ${kind}`,
        );
    else {
      assert.equal(capture.events.length, 2);
      assert(capture.counters.budgetDropped > 0);
    }
    const imported = await request('/api/kernel/captures', 'POST', {
      sensorId: sensor.data.id,
      artifact,
    });
    assert.equal(imported.status, 201, JSON.stringify(imported.data));
    const detail = await request(`/api/kernel/captures/${imported.data.id}`);
    assert.equal(detail.status, 200);
    assert.equal(detail.data.capture.events.length, capture.events.length);
    assert.equal(
      (await request('/api/kernel/captures', 'POST', { sensorId: sensor.data.id, artifact }))
        .status,
      403,
    );
    const replay = spawn(
      'sudo',
      [
        '-n',
        binary,
        'capture',
        '--key-file',
        keyFile,
        '--authority',
        authorityFile,
        '--permit',
        permitFile,
        '--out',
        out + '.replay',
        '--seconds',
        '3',
      ],
      { stdio: 'ignore' },
    );
    assert.notEqual(
      await new Promise((r) => replay.once('close', r)),
      0,
      'Consumed permit was replayed locally',
    );
    captures.push({
      events: capture.events.length,
      counters: capture.counters,
      programSha256: capture.programSha256,
      kernel: capture.host.kernel,
      readerUid: capture.readerUid,
      summary: JSON.parse(stdout.trim()),
    });
    if (index === 0) await new Promise((r) => setTimeout(r, 10000));
  }
  assert(store.integrity().valid);
  const summary = {
    schema: 'rudy.kernel-ci.v1',
    validatedAt: new Date().toISOString(),
    realKernel: true,
    apiRoundTrip: true,
    signatureVerification: true,
    localReplayRejected: true,
    duplicateImportRejected: true,
    captures,
    audit: store.integrity(),
  };
  fs.mkdirSync('work', { recursive: true });
  fs.writeFileSync('work/kernel-validation.json', JSON.stringify(summary, null, 2));
  console.log(JSON.stringify(summary, null, 2));
} finally {
  runtime.shutdown();
  await new Promise<void>((r) => server.close(() => r()));
  store.close();
}
