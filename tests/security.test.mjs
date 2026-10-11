import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeOrigin,
  isPublicAddress,
  resolvePublic,
  assertPermit,
  checkProof,
  sign,
  baselineFindings,
} from '../server/security.mjs';
import { parseEvidence } from '../server/importers.mjs';
import { reportHtml } from '../server/reports.mjs';
import { Store } from '../server/store.mjs';
import { catalog, domains } from '../server/catalog.mjs';

test('scope normalization accepts only exact public HTTPS DNS origins', () => {
  assert.equal(normalizeOrigin('https://EXAMPLE.COM:443/'), 'https://example.com');
  for (const value of [
    'http://example.com',
    'https://example.com/path',
    'https://example.com/?x=1',
    'https://u:p@example.com',
    'https://example.com/#x',
    'https://127.0.0.1',
    'https://[::1]',
    'https://localhost',
    'https://*.example.com',
    'https://example.com:8443',
    'https://example.com.',
    'https://2130706433',
    'https://0x7f000001',
    'https://example_com.test',
  ])
    assert.throws(() => normalizeOrigin(value), undefined, value);
});
test('private, mapped, local, multicast, and reserved addresses are denied', () => {
  for (const address of [
    '127.0.0.1',
    '10.2.3.4',
    '172.16.1.1',
    '192.168.1.2',
    '169.254.169.254',
    '100.64.0.1',
    '192.0.2.1',
    '198.51.100.1',
    '203.0.113.2',
    '0.0.0.0',
    '224.0.0.1',
    '240.1.1.1',
    '::1',
    '::',
    'fc00::1',
    'fe80::1',
    'ff02::1',
    '2001:db8::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
  ])
    assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
});
test('mixed DNS answers fail closed', async () => {
  await assert.rejects(
    resolvePublic('example.com', async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]),
    /blocked/,
  );
  await assert.rejects(
    resolvePublic('example.com', async () => []),
    /blocked/,
  );
});
test('signed permits bind asset, origin, capability, state, and expiry', () => {
  const key = 'test-signing-key',
    permit = {
      assetId: '1',
      origin: 'https://example.com',
      expiresAt: Date.now() + 10000,
      capabilities: ['web-baseline'],
    };
  const asset = {
    id: '1',
    origin: permit.origin,
    state: 'verified',
    permit,
    signature: sign(permit, key),
  };
  assert.doesNotThrow(() => assertPermit(asset, key));
  for (const modified of [
    { ...asset, state: 'revoked' },
    { ...asset, origin: 'https://other.test' },
    { ...asset, id: '2' },
    { ...asset, permit: { ...permit, expiresAt: Date.now() + 999999 } },
    { ...asset, signature: 'tampered' },
  ])
    assert.throws(() => assertPermit(modified, key));
  assert.throws(() => assertPermit(asset, key, Date.now() + 20000));
});
test('ownership proof requires exact token and never accepts a redirect', async () => {
  const asset = { id: 'abc', origin: 'https://example.com', challenge: 'token', method: 'https' },
    expected = 'rudy-central-verification=abc.token';
  assert.equal(
    await checkProof(asset, {
      get: async (origin, path) => {
        assert.equal(origin, asset.origin);
        assert.equal(path, '/.well-known/rudy-central/abc.txt');
        return { status: 200, body: expected };
      },
    }),
    true,
  );
  await assert.rejects(checkProof(asset, { get: async () => ({ status: 302, body: expected }) }));
  await assert.rejects(
    checkProof(asset, { get: async () => ({ status: 200, body: expected + 'extra' }) }),
  );
  assert.equal(
    await checkProof(
      { ...asset, method: 'dns' },
      {
        resolveTxt: async (name) => {
          assert.equal(name, '_rudy-central.example.com');
          return [['rudy-central-verification=', 'abc.token']];
        },
      },
    ),
    true,
  );
  await assert.rejects(
    checkProof({ ...asset, method: 'dns' }, { resolveTxt: async () => [['other']] }),
  );
});
test('baseline preserves caveats and never records cookie values', () => {
  const findings = baselineFindings(
    { headers: { 'set-cookie': ['session=very-secret-value; Path=/'] }, tls: {} },
    'https://example.com',
  );
  assert.equal(findings.length, 7);
  assert.equal(JSON.stringify(findings).includes('very-secret-value'), false);
  assert.match(findings[0].description, /not proof/);
  const safe = baselineFindings(
    {
      headers: {
        'strict-transport-security': 'max-age=31536000',
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'set-cookie': ['session=secret; Secure; HttpOnly; SameSite=Strict'],
      },
      tls: {},
    },
    'https://example.com',
  );
  assert.equal(safe.length, 0);
});
test('all supported evidence formats normalize severity and source', () => {
  const cases = [
    [
      'sarif',
      {
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'Scanner',
                rules: [{ id: 'X', properties: { 'security-severity': '9.1' } }],
              },
            },
            results: [{ ruleId: 'X', message: { text: 'Test' } }],
          },
        ],
      },
      'critical',
    ],
    [
      'semgrep',
      {
        results: [{ check_id: 'x', path: 'a.ts', extra: { severity: 'WARNING', message: 'Test' } }],
      },
      'medium',
    ],
    [
      'nuclei',
      [
        {
          'template-id': 'x',
          info: { name: 'Finding', severity: 'high' },
          'matched-at': 'https://u:p@example.com/path?token=secret',
        },
      ],
      'high',
    ],
    [
      'trivy',
      {
        Results: [
          {
            Target: 'image',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-example', PkgName: 'package', Severity: 'CRITICAL' },
            ],
          },
        ],
      },
      'critical',
    ],
    [
      'prowler',
      [{ status_code: 'FAIL', severity: 'High', finding_info: { title: 'Cloud finding' } }],
      'high',
    ],
    ['normalized', { findings: [{ title: 'Manual', severity: 'low' }] }, 'low'],
    [
      'linux-snapshot',
      {
        schema: 'rudy.linux-snapshot.v1',
        host: { name: 'host' },
        checks: [{ id: 'x', title: 'Review', status: 'review' }],
      },
      'low',
    ],
  ];
  for (const [format, object, expected] of cases) {
    const findings = parseEvidence(format, JSON.stringify(object));
    assert.equal(findings.length, 1, format);
    assert.equal(findings[0].severity, expected, format);
    assert.ok(findings[0].source);
    assert.equal(findings[0].status, 'open');
    assert.equal(JSON.stringify(findings).includes('token=secret'), false);
  }
});
test('malformed and excessive artifacts are rejected', () => {
  assert.throws(() => parseEvidence('sarif', '{}'));
  assert.throws(() => parseEvidence('normalized', '{bad'));
  assert.throws(() =>
    parseEvidence(
      'normalized',
      JSON.stringify(Array.from({ length: 501 }, () => ({ title: 'x', severity: 'low' }))),
    ),
  );
  const line = JSON.stringify({ 'template-id': 'one', info: { name: 'A', severity: 'low' } });
  assert.equal(parseEvidence('nuclei', line + '\n' + line).length, 2);
});
test('reports escape untrusted evidence and enforce a no-script policy', () => {
  const html = reportHtml(
    { name: '<script>x</script>', client: 'x', objective: 'x' },
    [
      {
        title: '<img src=x onerror=alert(1)>',
        evidence: '</pre><script>bad</script>',
        notes: '<b>x</b>',
      },
    ],
    [],
    {},
  );
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(html.includes("default-src 'none'"));
});
test('audit chain detects changes and database transactions roll back', () => {
  const store = new Store(':memory:', 'audit-key');
  store.audit('tester', 'first', 'detail');
  store.audit('tester', 'second', 'detail');
  assert.equal(store.integrity().valid, true);
  assert.throws(() =>
    store.transaction(() => {
      store.create('test', { value: 1 });
      throw new Error('rollback');
    }),
  );
  assert.equal(store.list('test').length, 0);
  store.db.prepare('UPDATE audit SET data=? WHERE seq=1').run(
    JSON.stringify({
      time: 'forged',
      actor: 'tester',
      action: 'first',
      detail: 'modified',
      previous: 'genesis',
    }),
  );
  assert.equal(store.integrity().valid, false);
  store.close();
});
test('catalog covers ten requested domains and does not claim executable integrations', () => {
  assert.equal(domains.length, 10);
  assert.ok(catalog.length >= 85);
  assert.equal(new Set(catalog.map((t) => t.id)).size, catalog.length);
  for (const name of [
    'Metasploit',
    'Cobalt Strike',
    'Burp Suite',
    'Nuclei',
    'Hashcat',
    'Pacu',
    'Wazuh',
    'Volatility',
    'Ghidra',
    'OpenSSL',
    'Vanta',
    'Okta',
  ])
    assert.ok(
      catalog.some((t) => t.name === name),
      name,
    );
  assert.ok(catalog.every((t) => t.execution === 'No executable bundled'));
});
