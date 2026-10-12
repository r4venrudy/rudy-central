import test from 'node:test';
import assert from 'node:assert/strict';
import { convertEvidence } from '../scripts/evidence-convert.mjs';
import { parseEvidence } from '../server/importers.mjs';

test('SDK conversion rejects untrusted executable selection and oversize input', () => {
  assert.throws(
    () => convertEvidence('native', 'test', '{}', 'relative-binary'),
    /absolute trusted/,
  );
  assert.throws(
    () => convertEvidence('native', 'test', ' '.repeat(4 * 1024 * 1024 + 1), process.execPath),
    /4 MiB/,
  );
});

test(
  'real SDK normalizes, redacts and produces an importable Central report',
  { skip: !process.env.RUDY_EVIDENCE_CLI },
  () => {
    const raw = JSON.stringify({
      results: [
        {
          check_id: 'TEST',
          path: 'src/main.cpp',
          start: { line: 10 },
          extra: { severity: 'WARNING', message: 'Review token=synthetic_secret' },
        },
      ],
    });
    const converted = convertEvidence('semgrep', 'repo:fixture', raw);
    assert.equal(converted.findings.length, 1);
    assert.ok(!JSON.stringify(converted).includes('synthetic_secret'));
    const findings = parseEvidence('normalized', JSON.stringify(converted));
    assert.equal(findings[0].severity, 'medium');
    assert.equal(findings[0].asset, 'src/main.cpp');
    const metadata = JSON.parse(findings[0].evidence);
    assert.equal(metadata.scope, 'repo:fixture');
    assert.match(metadata.fingerprint, /^blake3:[0-9a-f]{64}$/);
    assert.equal(findings[0].confidence, 'Imported — requires validation');
  },
);

test(
  'real SDK rejects malformed/duplicate-key input and Central limit overflow',
  { skip: !process.env.RUDY_EVIDENCE_CLI },
  () => {
    assert.throws(
      () => convertEvidence('native', 'test', '{"findings":[],"findings":[]}'),
      /conversion failed/,
    );
    assert.throws(
      () => convertEvidence('bundle', 'test', '{"schema":"rudy-evidence/v1","findings":[]}'),
      /conversion failed/,
    );
    const findings = Array.from({ length: 501 }, (_, i) => ({
      producer: 'test',
      rule_id: 'RULE',
      title: 'Test',
      severity: 'medium',
      asset: { kind: 'file', id: `${i}.cpp` },
    }));
    assert.throws(
      () => convertEvidence('native', 'test', JSON.stringify({ findings })),
      /500 findings/,
    );
  },
);
