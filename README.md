# Rudy Central

A professional, local-first security workbench for **authorized assessment, evidence, and remediation**. Linux engine, responsive browser UI, private GitHub source.

**Version 0.1.0 is a working foundation, not the completed full-scope platform.** It includes an enforced web-authorization workflow, a bounded native web baseline, seven evidence formats, finding triage, printable reports, controls, an audit chain, and a registry of 88 tools and references across ten disciplines. Registry entries do not mean those products are bundled or directly executable. Commercial licenses are not included.

## Start locally

Requires **Node.js 24.14+** and npm. Node's built-in SQLite API is experimental in the tested runtime; the application uses a small isolated storage module.

```sh
git clone https://github.com/r4venrudy/rudy-central.git
cd rudy-central
npm ci
npm run build
npm test
npm start
```

Open **http://127.0.0.1:4173**. The initial screen is an explicitly labeled synthetic demonstration. Select **Connect workspace** and use the key generated in `.data/admin-key`. For example, read it locally with `cat .data/admin-key` on Linux or `Get-Content .data/admin-key` in PowerShell. Do not send it to another service or commit it. Your connected workspace starts empty.

The server binds to loopback by default. To use a Linux engine from Windows, keep it bound to loopback and use an SSH tunnel:

```sh
ssh -L 4173:127.0.0.1:4173 your-user@your-linux-host
```

Then open the same localhost URL on Windows. An HTTPS reverse proxy is required for direct network exposure; see [deployment](docs/DEPLOYMENT.md).

## Working capabilities

| Area              | Implemented                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Workspace         | Operator and viewer sessions, local SQLite persistence, engagement filtering                                                 |
| Authorization     | DNS TXT or HTTPS challenge, 30-minute pending challenge, signed 24-hour exact-origin permit, revalidation, revocation        |
| Native assessment | One HTTPS response; HSTS, CSP, content-type sniffing, framing, cookie flags, certificate expiry observations                 |
| Network boundary  | Public DNS origins on port 443; every answer checked; DNS pinned to socket; no redirects; bounded bytes and time             |
| Evidence          | SARIF 2.1.0 subset, Semgrep JSON, Nuclei JSON/JSONL, Trivy JSON, Prowler OCSF JSON, normalized JSON, Rudy Linux snapshots    |
| Finding workflow  | Severity filtering, detail/evidence inspection, owner, notes, remediation status                                             |
| Reports           | Downloadable HTML with print/PDF layout and JSON; evidence register and audit checkpoint                                     |
| Controls          | Per-engagement control records with review, implementation, and gap status                                                   |
| Audit             | HMAC-linked actions, integrity verification on startup, exported checkpoints                                                 |
| Linux posture     | Offline, unprivileged collection of selected kernel hardening settings                                                       |
| Tool library      | All tools named in the supplied scope, plus Trivy, Grype, Syft, Gitleaks, Checkov, kube-bench, Falco, Timesketch, testssl.sh |

## Run your first assessment

1. Connect to the real workspace and create an engagement with its objective and authorization reference.
2. Add an exact HTTPS origin you are authorized to assess. This release excludes IP literals, private networks, wildcard scopes, and nonstandard ports.
3. Publish the generated DNS TXT record or HTTPS text file. Verify ownership from the asset dialog.
4. Keep the proof published. Start the **Web security baseline** within your authorized testing window.
5. Review observations and evidence, import other authorized tool exports, triage findings, and export the report.

For evidence-only work, an engagement is sufficient: importing a file sends no assessment traffic. Sample exports are in [`examples/`](examples/). Do not mistake the sample fixtures for real results.

## Kernel boundary

The control plane never runs as root, loads a driver, executes submitted shell commands, or launches a privileged tool. The offline Linux collector is functional source with Linux CI coverage. The optional [`process-count.bt`](sensors/process-count.bt) is a small, bounded eBPF tracepoint example, not a packaged kernel sensor. It has not been validated on the Windows development host.

A signed and independently installed Linux sensor, kernel compatibility matrix, event transport, attestation, and lifecycle management remain separate release work. See [architecture](docs/ARCHITECTURE.md) and [roadmap](docs/ROADMAP.md).

## Development and verification

```sh
npm run check
npm run format:check
npm audit
```

For Vite development, start the API with `RUDY_PUBLIC_ORIGIN=http://127.0.0.1:5173` and run `npm run dev` in another terminal. This explicitly trusts that local development origin. Production runs serve the compiled frontend and API from the same origin.

Tests use in-memory databases and injected transport fixtures. They do **not** scan Internet targets. GitHub Actions runs builds and tests on Ubuntu and Windows, plus an unprivileged posture snapshot on Ubuntu. eBPF execution and a real authorized Internet target require separate operator validation.

## Security and coverage documents

- [Security model and limitations](SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Tool coverage and integration contracts](docs/TOOL-COVERAGE.md)
- [Deployment and key handling](docs/DEPLOYMENT.md)
- [Evidence formats](docs/EVIDENCE.md)
- [Release roadmap](docs/ROADMAP.md)
- [Verification record](docs/VALIDATION.md)

No project license has been selected. Keep the repository private until the owner chooses its distribution and licensing terms. Third-party software keeps its own license.
