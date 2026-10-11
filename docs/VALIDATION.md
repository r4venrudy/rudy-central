# Validation record

Development validation performed on 2026-10-11 on Windows with Node 24.14.1.

## Passed locally

- TypeScript checking and optimized production build.
- 33 Node tests: API authentication/roles, Host and Origin enforcement, request integrity header, signed/exact/expired scope, private/mapped/mixed DNS rejection, pinned TLS transport, no redirect following, response byte limits, deadlines, proof removal, verification/revocation races, cancellation, imports, duplicate artifacts, report escaping, controls, and audit tampering. Kernel tests additionally cover permit binding, resource limits, forged sensor/authority signatures, time/host/UID mismatches, counter inconsistency, concurrent duplicate acceptance, revoked sensors, and viewer restrictions.
- Rust 1.99.0 Windows GNU build, three native tests (multiple rejection cases each), and Clippy with warnings denied. The Rust tests exercise signature/scope/expiry/budget checks and byte-safe kernel ABI decoding, including 64-bit precision. They do not load Linux programs on Windows.
- Package audit: zero reported vulnerabilities at validation time; this is a time-specific dependency result, not a security certification.
- Browser workflow against an isolated local test database: connect, create engagement, import normalized file, review SHA-256, resolve a finding with owner/notes, and download HTML report.
- Browser rejection of an IP-literal asset before any target request.
- Tool search, capability dialog, severity filtering, desktop layout, and 390-pixel mobile layout/navigation; no document-level horizontal overflow observed.
- Real workspace and synthetic demonstration remain separate.
- Browser validation of the new kernel workflow against a separate test database: enrollment, permit issuance/download, signed fixture upload, 31-event detail view, pagination, sensor revocation and disabled permit controls. Synthetic fixtures were used for browser testing; the Linux runner supplied the real-kernel proof below. No browser console errors were observed. The kernel page fits a 390-pixel mobile viewport without document-level horizontal overflow.

## Verification boundaries

Network tests use injected DNS and HTTPS fixtures, not third-party targets. No real Internet assessment was performed. Linux posture tests execute collection on Linux CI and verify explicit refusal on other platforms. Linux kernel loading is validated separately on an ephemeral GitHub runner; WSL and Docker were unavailable on the Windows development host.

The Dockerfile, actual Internet proof/assessment flow, and direct HTTPS reverse-proxy deployment require target-environment validation. Commercial tools and external product APIs were not executed or connected.

## Real kernel verification

[Run 38159530194](https://github.com/r4venrudy/rudy-central/actions/runs/38159530194) passed on 2026-10-11 at commit `edfbbb686cb6256393832cfb8f666255e8df063e`. Ubuntu 24.04, kernel `6.17.0-1022-azure`, Rust 1.99.0. Native Clippy, tests, release build, and the actual kernel smoke test passed. This initial proof precedes subsequent UI/documentation refinements; use the newest commit's Actions result for a release decision.

- Three eBPF programs loaded and attached; locally generated exec, exit and loopback connect activity produced **21 decoded events**, with zero ring loss or decode errors.
- Reader UID was **65534** after root was dropped; `no_new_privs` was set.
- A second capture with a **2-event permit** emitted exactly 2 and reported **19 budget-suppressed events**.
- Both signed artifacts passed the real authenticated API and were retrievable through the capture-detail route.
- Replay of the local permit and duplicate artifact imports were rejected. Audit integrity remained valid.
- The smoke test uses an isolated in-memory database and an ephemeral sensor key, not user targets or production credentials.

This verifies a bounded prototype on one kernel, not production scalability, comprehensive threat detection, or compatibility with every Linux environment.

[Run 38160082971](https://github.com/r4venrudy/rudy-central/actions/runs/38160082971) also passed for the integrated UI/API and agent packaging at commit `f649f0d`. It includes all 33 Node tests on Ubuntu and Windows, the actual kernel test, and the downloadable `rudy-agent-linux-x86_64` artifact.

GitHub Actions is configured for Ubuntu and Windows; its run status is authoritative for remote CI. Check the repository Actions tab for the commit you intend to deploy.
