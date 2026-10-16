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
} from '../server/security.mts';
import { parseEvidence } from '../server/importers.mjs';
import { reportHtml } from '../server/reports.mts';
import { Store } from '../server/store.mts';
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
  const none = baselineFindings(
    { headers: { 'set-cookie': ['t=1; HttpOnly; SameSite=None'] }, tls: {} },
    'https://example.com',
  );
  assert.ok(none.some((f) => f.title === 'Cookie t is rejected by browsers'));
  const sniff = (value) =>
    baselineFindings(
      { headers: { 'x-content-type-options': value }, tls: {} },
      'https://example.com',
    )
      .map((f) => f.evidence)
      .some((e) => e.startsWith('x-content-type-options'));
  assert.equal(sniff('nosniff, nosniff'), false);
  assert.equal(sniff(' NoSniff'), false);
  assert.equal(sniff('nosnif'), true);
  const disabled = baselineFindings(
    {
      headers: {
        'strict-transport-security': 'max-age=0',
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
      },
      tls: {},
    },
    'https://example.com',
  );
  assert.deepEqual(
    disabled.map((f) => f.title),
    ['Strict transport security is missing'],
  );
  for (const headers of [
    { 'x-frame-options': 'ALLOW-FROM https://partner.example' },
    { 'content-security-policy': "default-src 'self'; frame-ancestors *" },
  ])
    assert.ok(
      baselineFindings({ headers, tls: {} }, 'https://example.com').some(
        (f) => f.title === 'Framing policy is missing',
      ),
    );
  assert.ok(
    !baselineFindings(
      { headers: { 'x-frame-options': ' sameorigin, SAMEORIGIN ' }, tls: {} },
      'https://example.com',
    ).some((f) => f.title === 'Framing policy is missing'),
  );
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
test('SARIF rules are found by index and in tool extensions', () => {
  const [row] = parseEvidence(
    'sarif',
    JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: { name: 'CodeQL', rules: [] },
            extensions: [
              {
                name: 'codeql/js-queries',
                rules: [
                  { id: 'js/a', shortDescription: { text: 'Other rule' } },
                  {
                    id: 'js/sql-injection',
                    shortDescription: { text: 'Database query built from user input' },
                    properties: { 'security-severity': '8.8' },
                  },
                ],
              },
            ],
          },
          results: [
            {
              ruleId: 'js/sql-injection',
              rule: { id: 'js/sql-injection', index: 1, toolComponent: { index: 0 } },
              message: { text: 'Query depends on a user-provided value.' },
            },
          ],
        },
      ],
    }),
  );
  assert.equal(row.title, 'Database query built from user input');
  assert.equal(row.severity, 'high');
  assert.equal(row.ruleId, 'js/sql-injection');
});
test('SARIF passes and suppressed results are skipped and the default level is warning', () => {
  const rows = parseEvidence(
    'sarif',
    JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'Scanner', rules: [{ id: 'R1' }] } },
          results: [
            { ruleId: 'R1', message: { text: 'no level' } },
            { ruleId: 'R1', kind: 'pass', message: { text: 'passed' } },
            { ruleId: 'R1', message: { text: 'waived' }, suppressions: [{ kind: 'external' }] },
            {
              ruleId: 'R1',
              message: { text: 'rejected waiver' },
              suppressions: [{ kind: 'external', status: 'rejected' }],
            },
          ],
        },
      ],
    }),
  );
  assert.deepEqual(
    rows.map((r) => [r.description, r.severity]),
    [
      ['no level', 'medium'],
      ['rejected waiver', 'medium'],
    ],
  );
});
test('Trivy secrets are imported without the matched value', () => {
  const [row] = parseEvidence(
    'trivy',
    JSON.stringify({
      Results: [
        {
          Target: 'config/.env',
          Secrets: [
            {
              RuleID: 'aws-access-key-id',
              Category: 'AWS',
              Severity: 'CRITICAL',
              Title: 'AWS Access Key ID',
              StartLine: 3,
              EndLine: 3,
              Match: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
            },
          ],
        },
      ],
    }),
  );
  assert.equal(row.severity, 'critical');
  assert.equal(row.asset, 'config/.env');
  assert.match(row.description, /line 3/);
  assert.equal(JSON.stringify(row).includes('AKIAIOSFODNN7EXAMPLE'), false);
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
test('reports list findings most severe first with counts', () => {
  const html = reportHtml(
    { name: 'n', client: 'c', objective: 'o' },
    ['low', 'critical', 'medium', 'critical'].map((severity, i) => ({
      title: `finding-${i}-${severity}`,
      severity,
    })),
    [],
    {},
  );
  const order = [...html.matchAll(/finding-\d-(\w+)/g)].map((m) => m[1]);
  assert.deepEqual(order, ['critical', 'critical', 'medium', 'low']);
  assert.ok(html.includes('2 critical · 1 medium · 1 low'));
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
