import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import ipaddr from 'ipaddr.js';
import type { LookupAddress } from 'node:dns';
import type { IncomingHttpHeaders } from 'node:http';
import type { TLSSocket } from 'node:tls';
import type { Asset, FindingInput } from './models.mts';
export type Resolver = (
  hostname: string,
  options: { all: true; verbatim: true },
) => Promise<LookupAddress[]>;
export type ResponseSnapshot = {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
  bytes: number;
  ip: string;
  tls: {
    protocol?: string | null;
    cipher?: string;
    validTo?: string | null;
    issuer?: string | string[] | null;
  };
};
export type GetOptions = { signal?: AbortSignal; resolver?: Resolver; maxBytes?: number };
export type BoundedGetter = (
  origin: string,
  path?: string,
  options?: GetOptions,
) => Promise<ResponseSnapshot>;

export class PolicyError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}
export const randomToken = () => crypto.randomBytes(32).toString('base64url');
export const digest = (value: string | Buffer) =>
  crypto.createHash('sha256').update(value).digest('hex');
export const equal = (a: unknown, b: unknown) =>
  typeof a === 'string' &&
  typeof b === 'string' &&
  crypto.timingSafeEqual(Buffer.from(digest(a), 'hex'), Buffer.from(digest(b), 'hex'));
export const sign = (value: unknown, key: string) =>
  crypto.createHmac('sha256', key).update(JSON.stringify(value)).digest('hex');
export async function withDeadline<T>(
  operation: Promise<T>,
  milliseconds: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new PolicyError(message)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export function normalizeOrigin(input: string) {
  let u;
  try {
    u = new URL(input);
  } catch {
    throw new PolicyError('Enter a valid HTTPS origin.');
  }
  if (
    u.protocol !== 'https:' ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    (u.pathname !== '/' && u.pathname !== '')
  )
    throw new PolicyError(
      'Scope must be an exact HTTPS origin, without credentials, path, query, or fragment.',
    );
  if (u.port && u.port !== '443')
    throw new PolicyError('This release permits HTTPS on port 443 only.');
  if (
    net.isIP(u.hostname.replace(/^\[|\]$/g, '')) ||
    u.hostname.endsWith('.') ||
    !u.hostname.includes('.') ||
    u.hostname.length > 253 ||
    !u.hostname.split('.').every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(l))
  )
    throw new PolicyError(
      'A public DNS hostname is required. IP literals, wildcards, and local hosts are outside this release’s scope.',
    );
  return u.origin;
}
export function isPublicAddress(address: string) {
  try {
    const p = ipaddr.process(address);
    return p.range() === 'unicast';
  } catch {
    return false;
  }
}
export async function resolvePublic(hostname: string, resolver: Resolver = dns.lookup) {
  const addresses = await withDeadline(
    resolver(hostname, { all: true, verbatim: true }),
    7000,
    'DNS resolution timed out.',
  );
  if (!addresses.length || addresses.some((a) => !isPublicAddress(a.address)))
    throw new PolicyError(
      'Target resolves to a private, reserved, or local address. Request blocked.',
      403,
    );
  return addresses;
}

// Resolve once, validate every answer, and pin the socket to that answer. Never follow redirects.
export async function boundedGet(
  origin: string,
  path = '/',
  { signal, resolver = dns.lookup, maxBytes = 262144 }: GetOptions = {},
): Promise<ResponseSnapshot> {
  const normalized = normalizeOrigin(origin),
    u = new URL(normalized);
  if (!path.startsWith('/') || path.startsWith('//'))
    throw new PolicyError('Invalid request path.');
  const addresses = await resolvePublic(u.hostname, resolver);
  if (signal?.aborted) throw new PolicyError('Run cancelled.', 409);
  const pinned = addresses[0];
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: u.hostname,
        port: 443,
        path,
        method: 'GET',
        servername: u.hostname,
        rejectUnauthorized: true,
        signal,
        lookup: (_host, opts, cb) =>
          opts?.all ? cb(null, [pinned]) : cb(null, pinned.address, pinned.family),
        headers: {
          'User-Agent': 'RudyCentral/0.1 authorized-assessment',
          Accept: 'text/plain, text/html;q=0.8',
          'Accept-Encoding': 'identity',
        },
        timeout: 7000,
        maxHeaderSize: 32768,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        const socket = res.socket as TLSSocket;
        const cert = socket.getPeerCertificate?.() || {};
        const tls = {
          protocol: socket.getProtocol?.(),
          cipher: socket.getCipher?.()?.name,
          validTo: cert.valid_to || null,
          issuer: cert.issuer?.O || null,
        };
        res.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > maxBytes) {
            req.destroy(new PolicyError('Response exceeds the assessment byte budget.'));
          } else chunks.push(chunk);
        });
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            bytes,
            ip: pinned.address,
            tls,
          }),
        );
        res.on('error', reject);
      },
    );
    const deadline = setTimeout(
      () => req.destroy(new PolicyError('Request exceeded the 10-second wall-clock budget.')),
      10000,
    );
    req.on('timeout', () => req.destroy(new PolicyError('Target request timed out.')));
    req.on('error', reject);
    req.on('close', () => clearTimeout(deadline));
    req.end();
  });
}

export function assertPermit(asset: Asset, key: string, now = Date.now()) {
  if (
    asset.state !== 'verified' ||
    !asset.permit ||
    !equal(asset.signature, sign(asset.permit, key))
  )
    throw new PolicyError('No valid signed scope permit. Verify ownership before running.', 403);
  if (
    asset.permit.origin !== asset.origin ||
    asset.permit.assetId !== asset.id ||
    asset.permit.expiresAt <= now ||
    !asset.permit.capabilities.includes('web-baseline')
  )
    throw new PolicyError('Scope permit is expired or mismatched.', 403);
}
export async function checkProof(
  asset: Asset,
  {
    get = boundedGet,
    resolveTxt = dns.resolveTxt,
    signal,
  }: { get?: BoundedGetter; resolveTxt?: typeof dns.resolveTxt; signal?: AbortSignal } = {},
) {
  const expected = `rudy-central-verification=${asset.id}.${asset.challenge}`;
  if (asset.method === 'dns') {
    // DNS-only challenge does not send any request to the prospective target.
    const records = await withDeadline(
      resolveTxt(`_rudy-central.${new URL(asset.origin).hostname}`),
      7000,
      'DNS proof lookup timed out.',
    );
    if (!records.some((parts) => equal(parts.join(''), expected)))
      throw new PolicyError('DNS proof was not found or did not match.', 403);
  } else {
    const result = await get(asset.origin, `/.well-known/rudy-central/${asset.id}.txt`, {
      maxBytes: 4096,
      signal,
    });
    if (result.status !== 200 || !equal(result.body.trim(), expected))
      throw new PolicyError(
        'HTTPS proof did not match. Serve the exact token with status 200; redirects are not accepted.',
        403,
      );
  }
  return true;
}

export function baselineFindings(response: ResponseSnapshot, origin: string): FindingInput[] {
  const findings: FindingInput[] = [];
  const add = (
    title: string,
    severity: string,
    description: string,
    remediation: string,
    evidence: string,
  ) =>
    findings.push({
      title,
      severity,
      description,
      remediation,
      evidence,
      asset: origin,
      source: 'Rudy native',
      category: 'Web configuration',
      confidence: 'Observed',
      status: 'open',
    });
  const h = response.headers;
  const hsts = String(h['strict-transport-security'] || '');
  // max-age=0 tells browsers to drop the policy, so it is reported like a missing header
  const hstsAge = /(?:^|;)\s*max-age\s*=\s*"?(\d+)/i.exec(hsts);
  if (!hstsAge || Number(hstsAge[1]) === 0)
    add(
      'Strict transport security is missing',
      'medium',
      'The sampled HTTPS response does not advertise HSTS. This is a configuration observation, not proof of an exploitable attack.',
      'After validating HTTPS coverage, configure an appropriate Strict-Transport-Security policy.',
      hsts
        ? `strict-transport-security: ${hsts.slice(0, 120)} (disabled or invalid)`
        : 'strict-transport-security: absent',
    );
  if (!h['content-security-policy'])
    add(
      'Content security policy is missing',
      'medium',
      'The sampled response has no enforcing CSP. Applicability depends on whether this origin serves browser content.',
      'Design and test a restrictive CSP for browser-facing content.',
      'content-security-policy: absent',
    );
  // Fetch spec: only the first value counts, and a repeated header arrives as "nosniff, nosniff"
  if (
    String(h['x-content-type-options'] || '')
      .split(',')[0]
      .trim()
      .toLowerCase() !== 'nosniff'
  )
    add(
      'Content-type sniffing is not disabled',
      'low',
      'The sampled response does not set X-Content-Type-Options to nosniff.',
      'Return X-Content-Type-Options: nosniff with correct MIME types.',
      `x-content-type-options: ${h['x-content-type-options'] || 'absent'}`,
    );
  // ALLOW-FROM and other X-Frame-Options values are ignored by current browsers, and
  // "frame-ancestors *" allows every embedder, so neither restricts framing
  // Node joins repeated headers with ", "; per the HTML standard a single distinct value must be
  // DENY/SAMEORIGIN, and conflicting values that include a known one block framing
  const xfo = new Set(
    String(h['x-frame-options'] || '')
      .split(',')
      .map((v) => v.trim().toUpperCase()),
  );
  const xfoBlocks =
    xfo.size === 1
      ? xfo.has('DENY') || xfo.has('SAMEORIGIN')
      : ['DENY', 'SAMEORIGIN', 'ALLOWALL'].some((v) => xfo.has(v));
  const cspBlocksFraming = String(h['content-security-policy'] || '')
    .split(',')
    .some((policy) => {
      const ancestors = policy
        .split(';')
        .map((directive) =>
          directive.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '').split(/[\t\n\f\r ]+/),
        )
        .find(([name]) => name.toLowerCase() === 'frame-ancestors');
      // Empty source lists deny all ancestors. Duplicate directives use the first
      // occurrence; separately enforced policies can each restrict framing.
      return ancestors !== undefined && !ancestors.slice(1).includes('*');
    });
  if (!xfoBlocks && !cspBlocksFraming)
    add(
      'Framing policy is missing',
      'low',
      'No frame-ancestors directive or X-Frame-Options header was observed.',
      'Define a frame-ancestors policy appropriate for allowed embedding.',
      'No anti-framing response policy observed.',
    );
  for (const cookie of h['set-cookie'] || []) {
    const name = cookie.split('=')[0];
    for (const flag of ['Secure', 'HttpOnly', 'SameSite'])
      if (!new RegExp(`;\\s*${flag}(?:[=;]|$)`, 'i').test(cookie))
        add(
          `Cookie ${name.slice(0, 60)} lacks ${flag}`,
          'low',
          `The sampled Set-Cookie omits ${flag}. Review whether this is a sensitive session cookie before treating it as a vulnerability.`,
          `Review cookie purpose and configure ${flag} where applicable.`,
          `Cookie name: ${name.slice(0, 60)}; value redacted.`,
        );
    // browsers refuse to store a SameSite=None cookie that is not also Secure
    if (
      /;\s*SameSite\s*=\s*None\s*(?:;|$)/i.test(cookie) &&
      !/;\s*Secure\s*(?:[=;]|$)/i.test(cookie)
    )
      add(
        `Cookie ${name.slice(0, 60)} is rejected by browsers`,
        'low',
        'The sampled Set-Cookie sets SameSite=None without Secure, so current browsers do not store it.',
        'Add Secure, or choose Lax or Strict if cross-site delivery is not needed.',
        `Cookie name: ${name.slice(0, 60)}; value redacted.`,
      );
  }
  if (response.tls?.validTo && Date.parse(response.tls.validTo) - Date.now() < 30 * 86400000)
    add(
      'TLS certificate expires within 30 days',
      'low',
      'The peer certificate observed on this connection is approaching expiration.',
      'Verify automated renewal and certificate deployment.',
      `Expiry: ${response.tls.validTo}`,
    );
  return findings;
}
