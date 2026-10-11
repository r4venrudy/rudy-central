import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { parseEvidence } from '../server/importers.mjs';
test('posture collector is explicit about platform support', () => {
  const result = spawnSync(process.execPath, ['sensors/linux-snapshot.mjs'], { encoding: 'utf8' });
  if (process.platform === 'linux') {
    assert.equal(result.status, 0, result.stderr);
    const snapshot = JSON.parse(result.stdout);
    assert.equal(snapshot.schema, 'rudy.linux-snapshot.v1');
    assert.equal(snapshot.collector.network, 'none');
    assert.equal(snapshot.checks.length, 5);
    assert.ok(Array.isArray(parseEvidence('linux-snapshot', result.stdout)));
  } else {
    assert.equal(result.status, 1);
    assert.match(result.stderr, /requires Linux/);
    assert.equal(result.stdout, '');
  }
});
