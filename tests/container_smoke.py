"""Check the production container without network access or real workspace data."""
import json
import subprocess
import sys
import uuid

image = sys.argv[1]
name = "rudy-package-smoke-" + uuid.uuid4().hex

def docker(*args, timeout=60):
    result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr or "Container command failed")
    return result.stdout

probe = r"""
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
assert.equal(process.getuid(), 1000);
for (const path of ['/app/.git', '/app/.env', '/app/native', '/app/node_modules/typescript']) {
  assert.equal(fs.existsSync(path), false, path);
}
function request(path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get({hostname: '127.0.0.1', port: 4173, path,
      headers: {Host: '127.0.0.1:4173', ...headers}}, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({status: res.statusCode, body}));
    });
    req.setTimeout(1500, () => req.destroy(new Error('Probe timeout')));
    req.on('error', reject);
  });
}
(async () => {
  let health;
  for (let attempt = 0; attempt < 60; attempt++) {
    try { health = await request('/api/health'); if (health.status === 200) break; }
    catch {}
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.equal(health?.status, 200);
  assert.equal(JSON.parse(health.body).ok, true);
  const page = await request('/');
  assert.equal(page.status, 200);
  const asset = page.body.match(/src="(\/assets\/[^\"]+\.js)"/);
  assert.ok(asset, 'Compiled UI asset missing');
  assert.equal((await request(asset[1])).status, 200);
  assert.equal((await request('/api/projects')).status, 401);
  assert.equal((await request('/api/health', {Host: 'untrusted.invalid'})).status, 403);
  assert.equal((await request('/api/health', {Origin: 'https://untrusted.invalid'})).status, 403);
  console.log('Production image passed health, UI, authorization, host and origin checks.');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
"""

try:
    docker("run", "--detach", "--name", name, "--network", "none", "--read-only",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
           "--tmpfs", "/app/.data:rw,uid=1000,gid=1000,mode=0700", image)
    print(docker("exec", name, "node", "-e", probe).strip())
    docker("stop", "--time", "10", name)
    state = json.loads(docker("inspect", name))[0]["State"]
    assert state["ExitCode"] == 0, "Service did not shut down cleanly"
finally:
    subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30)
