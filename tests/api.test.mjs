import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Store } from '../server/store.mts';
import { createApp } from '../server/app.mts';
const adminKey = 'a'.repeat(40),
  viewerKey = 'v'.repeat(40);
async function fixture(t, overrides = {}) {
  const store = new Store(':memory:', 'test-audit-key');
  let proofs = 0,
    requests = 0;
  const runtime = createApp({
    store,
    adminKey,
    viewerKey,
    proof: async () => {
      proofs++;
    },
    get: async () => {
      requests++;
      return { status: 200, headers: {}, tls: {}, bytes: 12, ip: '8.8.8.8' };
    },
    ...overrides,
  });
  const server = runtime.app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  t.after(async () => {
    runtime.shutdown();
    for (let i = 0; i < 100 && runtime.active.size; i++)
      await new Promise((r) => setTimeout(r, 10));
    await new Promise((resolve) => server.close(resolve));
    store.close();
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';
  const request = async (path, method = 'GET', body, extra = {}) => {
    return new Promise((resolve, reject) => {
      const req = http.request(
        base + path,
        {
          method,
          headers: {
            Host: '127.0.0.1:4173',
            'X-Rudy-Request': '1',
            'Content-Type': 'application/json',
            Cookie: cookie,
            ...extra,
          },
        },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString();
            let data;
            try {
              data = JSON.parse(text);
            } catch {
              data = text;
            }
            resolve({
              status: res.statusCode,
              data,
              headers: {
                get: (name) => {
                  const value = res.headers[name.toLowerCase()];
                  return Array.isArray(value) ? value.join('; ') : value || null;
                },
              },
            });
          });
        },
      );
      req.on('error', reject);
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  };
  const login = async (key = adminKey) => {
    const r = await request('/api/session', 'POST', { key });
    cookie = r.headers.get('set-cookie')?.split(';')[0] || '';
    return r;
  };
  const engagement = async () => {
    const r = await request('/api/engagements', 'POST', {
      name: 'Assessment',
      client: 'Test organization',
      objective: 'Authorized integration test fixture',
    });
    assert.equal(r.status, 201);
    return r.data;
  };
  const asset = async (engagementId) => {
    const r = await request('/api/assets', 'POST', {
      engagementId,
      name: 'Portal',
      origin: 'https://example.com',
      method: 'dns',
      authorized: true,
    });
    assert.equal(r.status, 201);
    return r.data;
  };
  return {
    store,
    request,
    login,
    engagement,
    asset,
    runtime,
    counters: () => ({ proofs, requests }),
  };
}
test('authentication, host validation, origin validation, and CSRF gates', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/state')).status, 401);
  assert.equal(
    (await f.request('/api/health', 'GET', undefined, { Host: 'evil.test' })).status,
    403,
  );
  assert.equal(
    (await f.request('/api/session', 'POST', { key: adminKey }, { Origin: 'https://evil.test' }))
      .status,
    403,
  );
  assert.equal(
    (await f.request('/api/session', 'POST', { key: adminKey }, { 'X-Rudy-Request': '' })).status,
    403,
  );
  assert.equal((await f.login('wrong')).status, 401);
  const login = await f.login();
  assert.equal(login.status, 200);
  assert.match(login.headers.get('set-cookie'), /HttpOnly/);
  assert.match(login.headers.get('set-cookie'), /SameSite=Strict/);
  assert.equal((await f.request('/api/state')).status, 200);
  await f.request('/api/session', 'DELETE');
  assert.equal((await f.request('/api/state')).status, 401);
});
test('viewer cannot mutate engagements, controls, findings or scope', async (t) => {
  const f = await fixture(t);
  await f.login(viewerKey);
  assert.equal((await f.request('/api/state')).data.role, 'viewer');
  for (const path of [
    '/api/engagements',
    '/api/assets',
    '/api/runs',
    '/api/imports',
    '/api/controls',
  ])
    assert.equal((await f.request(path, 'POST', {})).status, 403, path);
});
test('unsigned scope is rejected before any target request', async (t) => {
  const f = await fixture(t);
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  assert.equal(
    (
      await f.request('/api/runs', 'POST', {
        assetId: a.id,
        profile: 'web-baseline',
        authorized: true,
      })
    ).status,
    403,
  );
  assert.deepEqual(f.counters(), { proofs: 0, requests: 0 });
  assert.equal(
    (
      await f.request('/api/runs', 'POST', {
        assetId: a.id,
        profile: 'arbitrary-command',
        authorized: true,
      })
    ).status,
    400,
  );
});
test('verified assessment persists evidence, findings, and audit; export and triage work', async (t) => {
  const f = await fixture(t);
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  assert.equal((await f.request(`/api/assets/${a.id}/verify`, 'POST', {})).status, 200);
  const run = await f.request('/api/runs', 'POST', {
    assetId: a.id,
    profile: 'web-baseline',
    authorized: true,
  });
  assert.equal(run.status, 202);
  for (let i = 0; i < 50 && f.runtime.active.size; i++) await new Promise((r) => setTimeout(r, 10));
  const state = (await f.request('/api/state')).data;
  assert.equal(state.runs[0].state, 'completed');
  assert.equal(state.findings.length, 4);
  assert.equal(state.evidence.length, 1);
  assert.equal(state.integrity.valid, true);
  assert.deepEqual(f.counters(), { proofs: 2, requests: 1 });
  assert.equal(state.assets[0].signature, undefined);
  const finding = state.findings[0];
  assert.equal(
    (
      await f.request(`/api/findings/${finding.id}`, 'PATCH', {
        status: 'resolved',
        owner: 'analyst',
        notes: 'Verified fixed',
      })
    ).data.status,
    'resolved',
  );
  const report = await f.request(`/api/reports/${e.id}?format=json`);
  assert.equal(report.status, 200);
  assert.equal(report.data.findings.length, 4);
  assert.ok(report.headers.get('content-disposition').includes('attachment'));
  assert.equal((await f.request(`/api/evidence/${state.evidence[0].id}`)).status, 200);
  assert.equal(
    (
      await f.request('/api/runs', 'POST', {
        assetId: a.id,
        profile: 'web-baseline',
        authorized: true,
      })
    ).status,
    429,
  );
  await f.request(`/api/assets/${a.id}/revoke`, 'POST', {});
  assert.equal(
    (
      await f.request('/api/runs', 'POST', {
        assetId: a.id,
        profile: 'web-baseline',
        authorized: true,
      })
    ).status,
    403,
  );
});
test('expired ownership challenges and expired permits cannot be renewed or run', async (t) => {
  const f = await fixture(t);
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  f.store.put('asset', { ...f.store.get('asset', a.id), challengeExpiresAt: Date.now() - 1 });
  assert.equal((await f.request(`/api/assets/${a.id}/verify`, 'POST', {})).status, 403);
  assert.equal(f.counters().proofs, 0);
});
test('proof removal blocks assessment without making a baseline request', async (t) => {
  let fail = false;
  const f = await fixture(t, {
    proof: async () => {
      if (fail) throw new Error('Proof removed.');
    },
  });
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  await f.request(`/api/assets/${a.id}/verify`, 'POST', {});
  fail = true;
  await f.request('/api/runs', 'POST', {
    assetId: a.id,
    profile: 'web-baseline',
    authorized: true,
  });
  for (let i = 0; i < 50 && f.runtime.active.size; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(f.store.list('run')[0].state, 'failed');
  assert.equal(f.counters().requests, 0);
});
test('revocation during proof prevents permit issuance', async (t) => {
  let release;
  const f = await fixture(t, {
    proof: () =>
      new Promise((r) => {
        release = r;
      }),
  });
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  const checking = f.request(`/api/assets/${a.id}/verify`, 'POST', {});
  for (let i = 0; i < 50 && !release; i++) await new Promise((r) => setTimeout(r, 5));
  await f.request(`/api/assets/${a.id}/revoke`, 'POST', {});
  release();
  assert.equal((await checking).status, 403);
  assert.equal(f.store.get('asset', a.id).state, 'revoked');
});
test('revocation during a running request cancels run and prevents evidence persistence', async (t) => {
  let release;
  const f = await fixture(t, {
    get: () =>
      new Promise((r) => {
        release = () => r({ status: 200, headers: {}, tls: {} });
      }),
  });
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  await f.request(`/api/assets/${a.id}/verify`, 'POST', {});
  await f.request('/api/runs', 'POST', {
    assetId: a.id,
    profile: 'web-baseline',
    authorized: true,
  });
  for (let i = 0; i < 50 && !release; i++) await new Promise((r) => setTimeout(r, 5));
  await f.request(`/api/assets/${a.id}/revoke`, 'POST', {});
  release();
  for (let i = 0; i < 50 && f.runtime.active.size; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(f.store.list('run')[0].state, 'cancelled');
  assert.equal(f.store.list('evidence').length, 0);
  assert.equal(f.store.list('finding').length, 0);
});
test('redirects are recorded as incomplete, without baseline findings', async (t) => {
  const f = await fixture(t, {
    get: async () => ({ status: 302, headers: { location: 'https://other.test' }, tls: {} }),
  });
  await f.login();
  const e = await f.engagement(),
    a = await f.asset(e.id);
  await f.request(`/api/assets/${a.id}/verify`, 'POST', {});
  await f.request('/api/runs', 'POST', {
    assetId: a.id,
    profile: 'web-baseline',
    authorized: true,
  });
  for (let i = 0; i < 50 && f.runtime.active.size; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(f.store.list('run')[0].state, 'failed');
  assert.equal(f.store.list('finding').length, 0);
});
test('imports are bounded, deduplicated, and isolated from demo data', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/demo')).data.demo, true);
  await f.login();
  const e = await f.engagement();
  assert.equal((await f.request('/api/state')).data.findings.length, 0);
  const body = {
    engagementId: e.id,
    name: 'manual.json',
    format: 'normalized',
    content: JSON.stringify({
      findings: [
        { title: 'Finding', severity: 'high', evidence: '<script>not executable</script>' },
      ],
    }),
  };
  assert.equal((await f.request('/api/imports', 'POST', body)).status, 201);
  assert.equal((await f.request('/api/imports', 'POST', body)).status, 409);
  assert.equal(f.store.list('finding').length, 1);
  assert.equal(f.store.integrity().valid, true);
  const html = (await f.request(`/api/reports/${e.id}`)).data;
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<script>'));
});
test('controls persist implementation reviews', async (t) => {
  const f = await fixture(t);
  await f.login();
  const e = await f.engagement();
  const result = await f.request('/api/controls', 'POST', {
    engagementId: e.id,
    name: 'Access review',
    description: 'Review privileged accounts',
    status: 'review',
  });
  assert.equal(result.status, 201);
  assert.equal(
    (
      await f.request(`/api/controls/${result.data.id}`, 'PATCH', {
        status: 'implemented',
        notes: 'Evidence reviewed',
      })
    ).data.status,
    'implemented',
  );
});
