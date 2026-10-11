# Security model

Rudy Central is an authorized-assessment workbench. Scope enforcement is a product control, not proof of legal permission and not protection against a person who modifies the source or controls its host.

## Trust boundaries

- Browser inputs, imported evidence, DNS, and target responses are untrusted.
- The local operator controls the workspace. A viewer may read and export its evidence, but cannot change scope or start work.
- Workspace and cryptographic keys are trusted server-side files. Local host administrators are outside the protection boundary.
- Demo records are a separate synthetic response, never copied into the real database.
- The server does not execute shell commands, import supplied code, launch user-selected binaries, or forward arbitrary HTTP requests.

## Target authorization

An operator records an authorization assertion and an exact HTTPS DNS origin. A cryptographically random challenge is bound to the asset ID. Pending challenges expire after 30 minutes. Successful DNS TXT or HTTPS proof produces an HMAC-signed permit for that asset, origin, engagement, capability, and a 24-hour expiry. The only runnable capability is `web-baseline`.

The web engine verifies the permit and rechecks the proof before each run, rechecks scope before the baseline request and before saving evidence, and aborts active requests on revocation. Revoked authorizations cannot be reactivated. A verification in flight cannot undo a concurrent revocation. Removing a proof prevents later assessments, subject to DNS caching. Kernel capture has a separate host-bound Ed25519 protocol described below.

Ownership of DNS or a web origin does not prove authority over a hosting provider, shared IP, cloud account, related subdomains, or adjacent network. The release does not infer any of that scope. Written authorization remains an operator responsibility. A malicious administrator can patch these checks; a source-available local application cannot prevent that.

## Request isolation

- HTTPS port 443 only, no credentials/path/query/fragment in the origin.
- DNS hostnames only. IP literals, wildcards, single-label names, reserved and private addresses are denied.
- Every resolved answer must be public. The socket uses a validated address while preserving TLS hostname verification and SNI.
- No redirects, crawling, recursive discovery, credential attacks, exploit execution, or lateral movement adapters.
- One active run, a one-minute per-asset cooldown, one baseline request plus at most one HTTPS proof request.
- DNS/proof deadlines and bounded response bytes. The maximum native response is 256 KiB, proof response 4 KiB, and headers 32 KiB.
- Proof verification and logins are rate limited. There is no externally exposed arbitrary-proxy endpoint.

## Application protections

Session cookies are HttpOnly, SameSite=Strict, and expire after eight hours. HTTPS deployments must use Secure cookies. Request integrity headers, strict Host and Origin allowlists, and absence of CORS permission protect the loopback service from browser cross-origin use and DNS rebinding. Operator and viewer keys must be distinct. Tokens are high-entropy bearer credentials, not passwords selected by the user.

Imported artifacts are bounded to 4 MB and 500 normalized findings, stored as inert content, and deduplicated by SHA-256 within an engagement. Imported observations require analyst validation. React escapes screen text; report output independently HTML-escapes every field and uses a restrictive CSP. Native evidence never stores cookie values or page bodies. Original imported evidence is retained verbatim and **can contain secrets**: review before importing and limit access to the workspace.

SQLite queries are parameterized. SQLite and key files are local, not encrypted by the application. Use OS filesystem permissions and encrypted storage. On Windows, POSIX mode bits do not establish Windows ACL isolation; restrict the workspace folder's ACLs. Do not place sensitive data in a broadly shared/synced directory.

## Audit limits

Each event includes the previous digest and an HMAC. Startup verifies the chain. This detects changes without the audit key; it does not prevent an administrator with the key from rewriting history. Without an external trusted checkpoint, tail truncation is not detectable. Export and anchor checkpoints independently. The UI/export shows the latest 250 records; integrity verification covers the stored chain.

## Deployment limits

This release is single-workspace. It has no tenant boundary, federated identity, individual user accountability, MFA, encrypted database, outbound firewall worker sandbox, or distributed execution service. Operator/viewer are shared role keys. Do not market it as a production multi-tenant platform.

The kernel sensor is validated on one Linux x86_64 CI kernel, not a broad production compatibility matrix. Container/service examples still require deployment validation. Rootkits, stealth, disabling defenses, persistence mechanisms, and arbitrary remote execution are outside the product's implemented capabilities.

## Kernel collection boundary

The separately invoked Rust agent loads three fixed eBPF tracepoints. A workspace Ed25519 permit binds host ID, boot ID, sensor key, one real UID, a maximum 15-minute authorization window, at most 300 seconds of observation and at most 10,000 candidate events. The agent uses a separately trusted authority public key; it does not trust a key inside a submitted permit. A local exclusive journal prevents accidental permit replay. A host owner can remove that journal, so the server independently enforces one accepted artifact per issued permit.

The eBPF producer filters UID, excludes the agent's thread group, enforces a monotonic deadline and event budget, and writes to a bounded one-MiB ring buffer. Counters expose ring loss, budget suppression and decode failure. Rust loads an embedded object only, attaches all required hooks, removes supplementary groups, changes UID/GID to 65534 and sets no_new_privs. The process retains only already opened handles needed for this workflow, but does not claim a complete seccomp or filesystem sandbox. No host settings or defenses are disabled to make capture succeed.

Capture artifacts are signed by the enrolled sensor key. The API checks both signatures, the original issued permit, host/boot/key/UID, time window, exact schema, counters and replay state before atomically persisting evidence. Raw kernel events do not automatically become vulnerability findings. They include process names and IDs and can still be sensitive. Only approved users should access evidence.

Revocation blocks future permits and imports immediately. It cannot interrupt a disconnected agent holding an existing permit; that agent's kernel deadline remains the stop mechanism. Host signatures and reported object hashes do not attest an uncompromised kernel or binary. An administrator with the host/key can forge observations, modify source, change clocks or replace the trust anchor. Kernel sensor source, binary dependencies, supported environments and limitations are documented in [KERNEL.md](docs/KERNEL.md).

## Reporting defects

Use the private repository's security reporting channel if enabled, or contact the repository owner privately. Do not include credentials, live sensitive evidence, or exploit material in a public issue. Reproduce defects against a local test fixture or an explicitly authorized lab.
