import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { z } from 'zod';
import { catalog, domains, nativeChecks } from './catalog.mjs';
import { demoState } from './demo.mjs';
import {
  PolicyError,
  randomToken,
  digest,
  equal,
  sign,
  normalizeOrigin,
  assertPermit,
  checkProof,
  boundedGet,
  baselineFindings,
} from './security.mts';
import { parseEvidence } from './importers.mjs';
import { reportHtml } from './reports.mts';
import type { ErrorRequestHandler } from 'express';
import type { Store } from './store.mts';
import type { Asset, RecordKind, Records } from './models.mts';
import { generateAuthority, mountKernelRoutes } from './kernel.mts';
type AppOptions = {
  store: Store;
  adminKey: string;
  viewerKey?: string;
  port?: number;
  publicOrigin?: string;
  secureCookie?: boolean;
  dist?: string;
  proof?: typeof checkProof;
  get?: typeof boundedGet;
  permitKey?: string;
  kernelAuthority?: crypto.KeyObject;
};

const short = z.string().trim().min(1).max(240);
const id = z.string().uuid();
export function createApp({
  store,
  adminKey,
  viewerKey,
  port = 4173,
  publicOrigin,
  secureCookie = false,
  dist = path.resolve('dist'),
  proof = checkProof,
  get = boundedGet,
  permitKey = adminKey,
  kernelAuthority = generateAuthority(),
}: AppOptions) {
  const app = express(),
    sessions = new Map<string, { role: 'operator' | 'viewer'; expiresAt: number }>(),
    rates = new Map<string, { since: number; count: number }>(),
    active = new Map<string, { controller: AbortController; assetId: string }>(),
    verifying = new Set<string>();
  app.disable('x-powered-by');
  const trustedOrigins = new Set([
    `http://127.0.0.1:${port}`,
    `http://localhost:${port}`,
    ...(publicOrigin ? [publicOrigin] : []),
  ]);
  const trustedHosts = new Set([...trustedOrigins].map((o) => new URL(o).host));
  const rate = (bucket: string, max: number) => {
    const now = Date.now(),
      key = bucket;
    let r = rates.get(key);
    if (!r || now - r.since > 60000) {
      r = { since: now, count: 0 };
      rates.set(key, r);
    }
    if (++r.count > max) throw new PolicyError('Too many requests. Retry in one minute.', 429);
    if (rates.size > 2000) for (const [k, v] of rates) if (now - v.since > 60000) rates.delete(k);
  };
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    });
    if (!trustedHosts.has(req.headers.host || ''))
      return res.status(403).json({ error: 'Untrusted Host header.' });
    if (req.headers.origin && !trustedOrigins.has(req.headers.origin))
      return res.status(403).json({ error: 'Untrusted request origin.' });
    if (req.path.startsWith('/api')) res.set('Cache-Control', 'no-store');
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.get('x-rudy-request') !== '1')
      return res.status(403).json({ error: 'Missing request integrity header.' });
    next();
  });
  app.use(express.json({ limit: '5mb', strict: true }));
  app.get('/api/health', (_req, res) => res.json({ ok: true }));
  app.get('/api/demo', (_req, res) => res.json(demoState()));
  app.post('/api/session', (req, res) => {
    rate(`login:${req.ip}`, 8);
    const body = z.object({ key: z.string().min(1).max(512) }).parse(req.body);
    const role = equal(body.key, adminKey)
      ? 'operator'
      : viewerKey && equal(body.key, viewerKey)
        ? 'viewer'
        : null;
    if (!role) {
      store.audit('anonymous', 'session.denied', 'Invalid workspace key');
      throw new PolicyError('Invalid workspace key.', 401);
    }
    for (const [k, v] of sessions) if (v.expiresAt < Date.now()) sessions.delete(k);
    if (sessions.size >= 100) throw new PolicyError('Session capacity reached.', 429);
    const token = randomToken();
    sessions.set(digest(token), { role, expiresAt: Date.now() + 8 * 3600000 });
    res.cookie('rudy_session', token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookie,
      path: '/',
      maxAge: 8 * 3600000,
    });
    store.audit(role, 'session.opened', 'Workspace session');
    res.json({ role });
  });
  app.use('/api', (req, res, next) => {
    const token = (req.headers.cookie || '')
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith('rudy_session='))
      ?.slice(13);
    const session = token ? sessions.get(digest(token)) : null;
    if (!session || session.expiresAt < Date.now())
      return res.status(401).json({ error: 'Connect to your workspace to continue.' });
    req.actor = session.role;
    req.sessionId = digest(token!);
    if (
      !['GET', 'HEAD'].includes(req.method) &&
      req.actor !== 'operator' &&
      req.path !== '/session'
    )
      return res.status(403).json({ error: 'A viewer cannot modify the workspace.' });
    rate(`api:${req.sessionId}`, 120);
    next();
  });
  const mustGet = <K extends RecordKind>(kind: K, value: unknown): Records[K] => {
    const row = store.get(kind, id.parse(value));
    if (!row) throw new PolicyError(`${kind} not found.`, 404);
    return row;
  };
  const safeAsset = (asset: Asset) => ({
    ...asset,
    signature: undefined,
    permit: asset.permit ? { ...asset.permit } : null,
  });
  mountKernelRoutes(app, store, kernelAuthority);
  app.delete('/api/session', (req, res) => {
    sessions.delete(req.sessionId);
    res.clearCookie('rudy_session', { path: '/' });
    res.json({ ok: true });
  });
  app.get('/api/state', (req, res) =>
    res.json({
      demo: false,
      role: req.actor,
      catalog,
      domains,
      nativeChecks,
      engagements: store.list('engagement'),
      assets: store.list('asset').map(safeAsset),
      findings: store.list('finding'),
      runs: store.list('run'),
      evidence: store.list('evidence').map(({ raw, ...e }) => e),
      controls: store.list('control'),
      audit: store.auditRows(),
      integrity: store.integrity(),
      policy: {
        version: '1.0',
        capabilities: ['web-baseline'],
        maxConcurrentRuns: 1,
        maxRequestsPerRun: 2,
        permitHours: 24,
        publicHttpsOnly: true,
        kernel:
          'Rust host agent and three bounded Linux eBPF tracepoints. Enroll a host and issue a signed capture permit in Kernel telemetry.',
      },
    }),
  );
  app.post('/api/engagements', (req, res) => {
    const body = z
      .object({ name: short, client: short, objective: z.string().trim().min(10).max(4000) })
      .strict()
      .parse(req.body);
    const row = store.transaction(() => {
      const row = store.create('engagement', { ...body, status: 'active' });
      store.audit(req.actor, 'engagement.created', row.id);
      return row;
    });
    res.status(201).json(row);
  });
  app.post('/api/assets', (req, res) => {
    const body = z
      .object({
        engagementId: id,
        name: short,
        origin: z.string().max(512),
        method: z.enum(['dns', 'https']),
        authorized: z.literal(true),
      })
      .strict()
      .parse(req.body);
    mustGet('engagement', body.engagementId);
    const origin = normalizeOrigin(body.origin);
    if (
      store
        .list('asset')
        .some(
          (a) =>
            a.engagementId === body.engagementId && a.origin === origin && a.state !== 'revoked',
        )
    )
      throw new PolicyError('This origin is already in this engagement.');
    const row = store.transaction(() => {
      const row = store.create('asset', {
        ...body,
        origin,
        state: 'pending',
        challenge: randomToken(),
        challengeExpiresAt: Date.now() + 30 * 60000,
        permit: null,
        authorizedBy: req.actor,
      });
      store.audit(req.actor, 'scope.requested', `${row.id} ${origin}`);
      return row;
    });
    res.status(201).json(safeAsset(row));
  });
  app.post('/api/assets/:id/verify', async (req, res) => {
    rate(`verify:${req.sessionId}`, 10);
    const asset = mustGet('asset', req.params.id);
    if (verifying.has(asset.id)) throw new PolicyError('Verification is already in progress.', 409);
    if (asset.state === 'revoked')
      throw new PolicyError(
        'Revoked scope cannot be reactivated. Create a new authorization.',
        403,
      );
    if (asset.state === 'pending' && asset.challengeExpiresAt < Date.now())
      throw new PolicyError('Challenge expired. Revoke and create a new authorization.', 403);
    if (asset.state === 'verified' && (asset.permit?.expiresAt ?? 0) < Date.now())
      throw new PolicyError('Authorization expired. Revoke and create a new authorization.', 403);
    verifying.add(asset.id);
    try {
      await proof(asset);
      if (mustGet('asset', asset.id).state === 'revoked')
        throw new PolicyError('Scope was revoked during verification.', 403);
      const permit = {
        assetId: asset.id,
        origin: asset.origin,
        engagementId: asset.engagementId,
        issuedAt: Date.now(),
        expiresAt: Date.now() + 24 * 3600000,
        capabilities: ['web-baseline'],
        requestBudget: 2,
      };
      const result = store.transaction(() => {
        const row = store.put('asset', {
          ...asset,
          state: 'verified',
          verifiedAt: new Date().toISOString(),
          permit,
          signature: sign(permit, permitKey),
        });
        store.audit(req.actor, 'scope.verified', `${asset.id} ${asset.origin}`);
        return row;
      });
      res.json(safeAsset(result));
    } catch (error) {
      store.audit(req.actor, 'scope.verification_failed', asset.id);
      throw error;
    } finally {
      verifying.delete(asset.id);
    }
  });
  app.post('/api/assets/:id/revoke', (req, res) => {
    const asset = mustGet('asset', req.params.id);
    const result = store.transaction(() => {
      const row = store.put('asset', { ...asset, state: 'revoked', permit: null, signature: null });
      store.audit(req.actor, 'scope.revoked', asset.id);
      return row;
    });
    for (const entry of active.values()) if (entry.assetId === asset.id) entry.controller.abort();
    res.json(safeAsset(result));
  });
  app.post('/api/runs', (req, res) => {
    const body = z
      .object({ assetId: id, profile: z.literal('web-baseline'), authorized: z.literal(true) })
      .strict()
      .parse(req.body);
    const asset = mustGet('asset', body.assetId);
    assertPermit(asset, permitKey);
    if (active.size)
      throw new PolicyError('One assessment is already running. Wait or cancel it.', 409);
    if (
      store
        .list('run')
        .some((r) => r.assetId === asset.id && Date.now() - Date.parse(r.createdAt) < 60000)
    )
      throw new PolicyError('This asset has a one-minute assessment cooldown.', 429);
    const run = store.transaction(() => {
      const row = store.create('run', {
        engagementId: asset.engagementId,
        assetId: asset.id,
        name: 'Web security baseline',
        target: asset.origin,
        state: 'running',
        findingCount: 0,
        steps: ['Scope permit accepted'],
      });
      store.audit(req.actor, 'run.started', `${row.id} ${asset.origin}`);
      return row;
    });
    const controller = new AbortController();
    active.set(run.id, { controller, assetId: asset.id });
    res.status(202).json(run);
    setImmediate(async () => {
      try {
        await proof(asset, { signal: controller.signal });
        assertPermit(mustGet('asset', asset.id), permitKey);
        if (controller.signal.aborted) throw new PolicyError('Run cancelled.');
        const response = await get(asset.origin, '/', { signal: controller.signal });
        assertPermit(mustGet('asset', asset.id), permitKey);
        if (controller.signal.aborted) throw new PolicyError('Run cancelled.');
        if (response.status >= 300 && response.status < 400)
          throw new PolicyError(
            'Target returned a redirect. Redirect following is disabled; authorize the destination separately.',
          );
        if (response.status < 200 || response.status >= 300)
          throw new PolicyError(`Target returned HTTP ${response.status}; baseline incomplete.`);
        const findings = baselineFindings(response, asset.origin);
        const raw = JSON.stringify(
          {
            origin: asset.origin,
            status: response.status,
            ip: response.ip,
            tls: response.tls,
            bytes: response.bytes,
            observations: findings.map((f) => ({ title: f.title, evidence: f.evidence })),
          },
          null,
          2,
        );
        store.transaction(() => {
          const evidence = store.create('evidence', {
            engagementId: asset.engagementId,
            name: `Web baseline · ${asset.origin}`,
            format: 'native',
            sha256: digest(raw),
            raw,
            findingCount: findings.length,
            runId: run.id,
          });
          for (const finding of findings)
            store.create('finding', {
              ...finding,
              engagementId: asset.engagementId,
              evidenceId: evidence.id,
              runId: run.id,
            });
          store.put('run', {
            ...run,
            state: 'completed',
            finishedAt: new Date().toISOString(),
            findingCount: findings.length,
            steps: [
              'Signed permit accepted',
              'Ownership proof revalidated',
              'DNS validated and socket pinned',
              'One bounded HTTPS response assessed',
              'Evidence saved',
            ],
          });
          store.audit('engine', 'run.completed', run.id);
        });
      } catch (error) {
        const cancelled = controller.signal.aborted;
        store.transaction(() => {
          store.put('run', {
            ...run,
            state: cancelled ? 'cancelled' : 'failed',
            error: cancelled
              ? 'Run cancelled or scope revoked.'
              : error instanceof Error
                ? error.message
                : 'Assessment failed.',
            finishedAt: new Date().toISOString(),
          });
          store.audit('engine', cancelled ? 'run.cancelled' : 'run.failed', run.id);
        });
      } finally {
        active.delete(run.id);
      }
    });
  });
  app.post('/api/runs/:id/cancel', (req, res) => {
    mustGet('run', req.params.id);
    const entry = active.get(id.parse(req.params.id));
    if (!entry) throw new PolicyError('Run is no longer active.', 409);
    entry.controller.abort();
    store.audit(req.actor, 'run.cancel_requested', id.parse(req.params.id));
    res.json({ ok: true });
  });
  app.post('/api/imports', (req, res) => {
    const body = z
      .object({
        engagementId: id,
        name: short,
        format: z.enum([
          'sarif',
          'semgrep',
          'nuclei',
          'trivy',
          'prowler',
          'normalized',
          'linux-snapshot',
        ]),
        content: z.string().min(1).max(4000000),
      })
      .strict()
      .parse(req.body);
    mustGet('engagement', body.engagementId);
    const findings = parseEvidence(body.format, body.content),
      sha256 = digest(body.content);
    if (
      store
        .list('evidence')
        .some((e) => e.engagementId === body.engagementId && e.sha256 === sha256)
    )
      throw new PolicyError('This exact artifact has already been imported.', 409);
    const row = store.transaction(() => {
      const e = store.create('evidence', {
        engagementId: body.engagementId,
        name: body.name,
        format: body.format,
        sha256,
        raw: body.content,
        findingCount: findings.length,
      });
      for (const finding of findings)
        store.create('finding', { ...finding, engagementId: body.engagementId, evidenceId: e.id });
      store.audit(req.actor, 'evidence.imported', `${e.id} ${sha256}`);
      return e;
    });
    const { raw, ...metadata } = row;
    res.status(201).json(metadata);
  });
  app.patch('/api/findings/:id', (req, res) => {
    const row = mustGet('finding', req.params.id);
    const body = z
      .object({
        status: z
          .enum(['open', 'in_progress', 'resolved', 'accepted', 'false_positive'])
          .optional(),
        notes: z.string().max(8000).optional(),
        owner: z.string().max(120).optional(),
      })
      .strict()
      .parse(req.body);
    const updated = store.transaction(() => {
      const result = store.put('finding', { ...row, ...body, updatedAt: new Date().toISOString() });
      store.audit(req.actor, 'finding.updated', `${row.id} ${body.status || row.status}`);
      return result;
    });
    res.json(updated);
  });
  app.post('/api/controls', (req, res) => {
    const body = z
      .object({
        name: short,
        description: z.string().max(2000),
        status: z.enum(['review', 'implemented', 'gap']),
        engagementId: id,
      })
      .strict()
      .parse(req.body);
    mustGet('engagement', body.engagementId);
    const row = store.transaction(() => {
      const r = store.create('control', body);
      store.audit(req.actor, 'control.created', r.id);
      return r;
    });
    res.status(201).json(row);
  });
  app.patch('/api/controls/:id', (req, res) => {
    const row = mustGet('control', req.params.id);
    const body = z
      .object({ status: z.enum(['review', 'implemented', 'gap']), notes: z.string().max(4000) })
      .strict()
      .parse(req.body);
    const result = store.transaction(() => {
      const r = store.put('control', { ...row, ...body });
      store.audit(req.actor, 'control.updated', r.id);
      return r;
    });
    res.json(result);
  });
  app.get('/api/evidence/:id', (req, res) => {
    const e = mustGet('evidence', req.params.id);
    store.audit(req.actor, 'evidence.exported', e.id);
    res
      .set({
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="rudy-evidence-${e.id}.json"`,
      })
      .send(e.raw);
  });
  app.get('/api/reports/:id', (req, res) => {
    const engagement = mustGet('engagement', req.params.id),
      findings = store.list('finding').filter((f) => f.engagementId === engagement.id),
      evidence = store
        .list('evidence')
        .filter((e) => e.engagementId === engagement.id)
        .map(({ raw, ...e }) => e);
    store.audit(req.actor, 'report.exported', engagement.id);
    const integrity = store.integrity();
    if (req.query.format === 'json') {
      res
        .set('Content-Disposition', `attachment; filename="rudy-report-${engagement.id}.json"`)
        .json({ engagement, findings, evidence, integrity });
    } else
      res
        .set({
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Disposition': `attachment; filename="rudy-report-${engagement.id}.html"`,
        })
        .send(reportHtml(engagement, findings, evidence, integrity));
  });
  app.get('/api/audit/export', (req, res) => {
    res
      .set('Content-Disposition', 'attachment; filename="rudy-audit.json"')
      .json({ checkpoint: store.integrity(), recentEntries: store.auditRows() });
  });
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Unknown API route.' }));
  app.use(express.static(dist, { dotfiles: 'deny', index: 'index.html' }));
  app.get('/{*path}', (_req, res) => res.sendFile(path.join(dist, 'index.html')));
  const errorHandler: ErrorRequestHandler = (error, req, res, _next) => {
    const status = error instanceof z.ZodError ? 400 : error.status || 500;
    res.status(status).json({
      error:
        error instanceof z.ZodError
          ? 'Invalid input: ' +
            error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join(';')
          : status >= 500
            ? 'An internal operation failed. Review local service logs.'
            : error.message,
    });
    if (status >= 500) console.error('Request failed:', error.message);
  };
  app.use(errorHandler);
  return {
    app,
    shutdown: () => {
      for (const value of active.values()) value.controller.abort();
      sessions.clear();
    },
    active,
  };
}
