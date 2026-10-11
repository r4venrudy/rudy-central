# Full-platform release plan

The owner's requested scope is larger than v0.2. This file separates delivered capabilities from the remaining platform backlog.

## Delivered: authorized workbench

Responsive UI, local persistence, engagements, exact-origin proof, signed scope, bounded web baseline, evidence import, triage, HTML/JSON reports, controls, audit chain, full named-tool registry, and an offline Linux posture collector.

## Delivered in 0.2: Rust and Linux eBPF

Rust CLI and core policy, eight read-only Linux posture checks, embedded helper-based eBPF probes, bounded kernel producer, privilege-dropped userspace reader, host enrollment, Ed25519 authorization and evidence, local/server replay checks, revocation, metadata event explorer, Linux load/capture/API smoke test, and packaged CI executable. The critical API/policy/persistence modules now use strict TypeScript. The first three probes do not require CO-RE relocations; no arbitrary kernel structures are read.

## Next: validated Linux distribution

- Package and exercise the service on selected Ubuntu/Debian versions; document install, upgrade, backup, and rollback.
- Validate the native transport against owner-controlled Internet fixtures, including TLS rotation, split DNS, DNS rebinding attempts, redirects, slow bodies, and cancelled requests.
- Add integration fixtures from actual approved product versions for every importer.
- Add quotas, pagination, retention/export/delete workflows, and integrity checks for stored evidence at read time.
- Replace shared role keys with individual identities, MFA/SSO, recovery, and per-user attribution before collaborative production use.

Acceptance: supported-platform CI, reproducible package, authenticated UI tests, bounded-network adversarial tests, and independent review. No claim of kernel protection at this phase.

## Next: isolated tool runners

- Implement Nmap inventory and authenticated vulnerability-scanner result ingestion using fixed profiles and exact authorized IP/port scopes.
- Run tools in constrained workers with no ambient host privileges, pinned binaries/images, resource budgets, outbound firewall rules, and signed job permits.
- Add AppSec, SCA, cloud posture, IAM, detection, and DFIR connectors individually; require least-privilege vendor credentials and explicit data handling contracts.
- Build importers for versioned native export formats rather than claiming every catalog item supports SARIF.

Acceptance for each adapter: declared license, version pin, exact authorization mechanism, sandbox/egress boundary, cancellation, result schema, golden fixtures, negative tests, and truthful UI availability.

## Next: broader kernel validation and continuous telemetry

- Expand the Linux/kernel/architecture compatibility matrix, crash tests, overload tests, and measured overhead/soak testing.
- Signed release distribution, reproducible toolchain packaging, key rotation, explicit upgrades and rollback.
- Authenticated continuous transport and online revocation; the current artifact workflow is offline and bounded.
- Independent review of privileged startup and host identity; remote attestation if the product later needs that stronger guarantee.
- Kernel lockdown, BTF availability, capability support, and degraded-mode testing on actual Linux hosts.

Acceptance: independent review, repeatable multi-kernel tests, crash/overload exercises, documented operational limits, signed releases, and verified lifecycle behavior. Current real CI validation covers one Linux kernel and deliberately exercises local process and loopback traffic only.

## Later: professional deployment

Multi-tenant authorization, separated evidence stores, customer-controlled encryption, distributed scheduling, asset inventory synchronization, approval workflows, immutable external audit anchoring, signed reports, risk scoring with validated business context, SIEM/SOAR integrations, and control-framework mappings reviewed by qualified owners.

Commercial tools such as Cobalt Strike, Nessus, Burp editions, Wiz, Orca, IDA Pro, FTK, and EnCase require separate licenses and supported integration agreements where applicable. Third-party product code is not being reimplemented or redistributed by adding a registry entry.
