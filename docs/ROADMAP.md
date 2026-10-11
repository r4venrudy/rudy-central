# Full-platform release plan

The owner's requested scope is larger than v0.1. This file is a delivery backlog, not a claim that unfinished capabilities exist.

## Delivered: authorized workbench

Responsive UI, local persistence, engagements, exact-origin proof, signed scope, bounded web baseline, evidence import, triage, HTML/JSON reports, controls, audit chain, full named-tool registry, and an offline Linux posture collector.

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

## Next: kernel observability sensor

- Linux eBPF CO-RE sensor with narrow, documented telemetry; no stealth, exploitation, or interference with defenses.
- Separate explicit privileged installation, supported kernel matrix, signed artifacts, measurable overhead, bounded buffers and event rates.
- Authenticated local transport, host enrollment/revocation, event schema, privacy review, and uninstall behavior.
- Kernel lockdown, BTF availability, capability support, and degraded-mode testing on actual Linux hosts.

Acceptance: independently reviewed sensor, repeatable Linux tests, crash/overload exercises, least-privilege deployment, signed releases, and verified uninstall. The included bpftrace counter is only a minimal observability example.

## Later: professional deployment

Multi-tenant authorization, separated evidence stores, customer-controlled encryption, distributed scheduling, asset inventory synchronization, approval workflows, immutable external audit anchoring, signed reports, risk scoring with validated business context, SIEM/SOAR integrations, and control-framework mappings reviewed by qualified owners.

Commercial tools such as Cobalt Strike, Nessus, Burp editions, Wiz, Orca, IDA Pro, FTK, and EnCase require separate licenses and supported integration agreements where applicable. Third-party product code is not being reimplemented or redistributed by adding a registry entry.
