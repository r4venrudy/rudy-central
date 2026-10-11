# Validation record

Development validation performed on 2026-10-11 on Windows with Node 24.14.1.

## Passed locally

- TypeScript checking and optimized production build.
- 27 automated tests: API authentication/roles, Host and Origin enforcement, request integrity header, signed/exact/expired scope, private/mapped/mixed DNS rejection, pinned TLS transport, no redirect following, response byte limits, deadlines, proof removal, verification/revocation races, cancellation, imports, duplicate artifacts, report escaping, controls, and audit tampering.
- Package audit: zero reported vulnerabilities at validation time; this is a time-specific dependency result, not a security certification.
- Browser workflow against an isolated local test database: connect, create engagement, import normalized file, review SHA-256, resolve a finding with owner/notes, and download HTML report.
- Browser rejection of an IP-literal asset before any target request.
- Tool search, capability dialog, severity filtering, desktop layout, and 390-pixel mobile layout/navigation; no document-level horizontal overflow observed.
- Real workspace and synthetic demonstration remain separate.

## Verification boundaries

Network tests use injected DNS and HTTPS fixtures, not third-party targets. No real Internet assessment was performed. Linux posture tests execute collection on Linux CI and verify explicit refusal on other platforms. Windows development cannot validate Linux kernel/eBPF loading. WSL and Docker were unavailable on the development host.

The optional bpftrace source, Dockerfile, actual Internet proof/assessment flow, and direct HTTPS reverse-proxy deployment require target-environment validation. Commercial tools and external product APIs were not executed or connected.

GitHub Actions is configured for Ubuntu and Windows; its run status is authoritative for remote CI. Check the repository Actions tab for the commit you intend to deploy.
