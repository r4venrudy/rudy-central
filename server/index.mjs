import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { createApp } from './app.mjs';
import { randomToken } from './security.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const data = process.env.RUDY_DATA_DIR || path.join(root, '.data');
fs.mkdirSync(data, { recursive: true, mode: 0o700 });
function secret(name, env) {
  if (env) {
    if (env.length < 32) throw new Error(`${name} must contain at least 32 characters.`);
    return env;
  }
  const file = path.join(data, name);
  if (!fs.existsSync(file)) fs.writeFileSync(file, randomToken(), { mode: 0o600, flag: 'wx' });
  return fs.readFileSync(file, 'utf8').trim();
}
const adminKey = secret('admin-key', process.env.RUDY_ADMIN_KEY),
  auditKey = secret('audit-key'),
  permitKey = secret('permit-key');
const viewerKey = process.env.RUDY_VIEWER_KEY;
if (viewerKey && (viewerKey.length < 32 || viewerKey === adminKey))
  throw new Error('Viewer key must be distinct and at least 32 characters.');
const port = Number(process.env.PORT || 4173),
  host = process.env.HOST || '127.0.0.1',
  publicOrigin = process.env.RUDY_PUBLIC_ORIGIN;
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT.');
if (
  !['127.0.0.1', '::1', 'localhost'].includes(host) &&
  !(
    process.env.RUDY_ALLOW_REMOTE === '1' &&
    publicOrigin?.startsWith('https://') &&
    process.env.RUDY_SECURE_COOKIE === '1'
  )
)
  throw new Error(
    'Remote binding requires an HTTPS reverse proxy, RUDY_PUBLIC_ORIGIN, RUDY_SECURE_COOKIE=1, and RUDY_ALLOW_REMOTE=1.',
  );
const store = new Store(path.join(data, 'rudy.sqlite'), auditKey);
if (!store.integrity().valid)
  throw new Error(
    'Audit integrity verification failed. Preserve the data and investigate before starting.',
  );
for (const run of store.list('run'))
  if (run.state === 'running')
    store.put('run', {
      ...run,
      state: 'interrupted',
      error: 'Service restarted before completion.',
      finishedAt: new Date().toISOString(),
    });
store.audit('service', 'service.started', 'Rudy Central 0.1.0');
const runtime = createApp({
  store,
  adminKey,
  viewerKey,
  permitKey,
  port,
  publicOrigin,
  secureCookie: process.env.RUDY_SECURE_COOKIE === '1',
  dist: path.join(root, 'dist'),
});
const server = runtime.app.listen(port, host, () => {
  console.log(`Rudy Central: http://${host}:${port}`);
  console.log(
    process.env.RUDY_ADMIN_KEY
      ? 'Workspace key: supplied through RUDY_ADMIN_KEY (not printed).'
      : `Workspace key file: ${path.join(data, 'admin-key')}`,
  );
  console.log(
    'Demo mode is synthetic. Connect with your workspace key to manage real assessments.',
  );
});
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    runtime.shutdown();
    server.close(() => {
      const timer = setInterval(() => {
        if (!runtime.active.size) {
          clearInterval(timer);
          store.audit('service', 'service.stopped', 'Graceful shutdown');
          store.close();
          process.exit(0);
        }
      }, 100);
    });
    setTimeout(() => process.exit(1), 12000).unref();
  });
