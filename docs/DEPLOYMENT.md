# Deployment

## Preferred first deployment: loopback + SSH

Install Node 24.14 or later on a supported Linux distribution, clone the public repository, then `npm ci && npm run build && npm test`. Start with `npm start` under an unprivileged dedicated account. The browser/API never requires sudo. The separate Rust kernel agent is built and invoked according to [KERNEL.md](KERNEL.md); do not run the web service as root.

Bind to `127.0.0.1:4173` and forward that port with SSH when accessing it from Windows. Avoid exposing an unauthenticated HTTP transport to the network.

## Direct HTTPS reverse proxy

Provision your own certificate and reverse proxy. Pass these settings through a service environment file readable only by the service account:

```ini
HOST=127.0.0.1
PORT=4173
RUDY_PUBLIC_ORIGIN=https://security.your-domain.example
RUDY_SECURE_COOKIE=1
RUDY_DATA_DIR=/var/lib/rudy-central
```

Preserve the original public Host header. The origin and host must match `RUDY_PUBLIC_ORIGIN` exactly. The app does not enable Express `trust proxy`; login throttling behind a shared proxy is consequently conservative and shared. Do not accept arbitrary forwarded host/origin headers.

For a container that must bind internally to `0.0.0.0`, set `RUDY_ALLOW_REMOTE=1`, a real HTTPS `RUDY_PUBLIC_ORIGIN`, and `RUDY_SECURE_COOKIE=1`. Place it on a private container network behind the HTTPS proxy. Do not publish its raw HTTP port to untrusted clients.

## Private GitHub package

The private Linux amd64 image contains the web UI and API. It does not contain or load the privileged kernel agent, and it does not bundle the native Rudy Evidence executable. The package workflow runs the application tests during the image build, then checks the compiled UI, API health, authorization and Host/Origin enforcement in an offline container with a read-only root filesystem. Publication is restricted to the original repository and an absent or private package; source visibility is independent of package visibility. The workflow verifies package privacy before and after publishing and never changes package visibility.

Sign in to `ghcr.io` using your own GitHub account with access to this private package. See [GitHub's container authentication instructions](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-to-the-container-registry). Never commit a token or put it directly in a command argument.

On a Linux Docker host, use host networking to retain the default `127.0.0.1:4173` listener:

```sh
docker pull ghcr.io/r4venrudy/rudy-central:latest
docker volume create rudy-central-data
docker run --detach --name rudy-central \
  --network host --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 256 \
  --mount type=volume,source=rudy-central-data,target=/app/.data \
  ghcr.io/r4venrudy/rudy-central:latest
```

Open `http://127.0.0.1:4173` on that host, or use an SSH tunnel from Windows. This example is for Linux host networking; it is not a Docker Desktop port-mapping recipe. Keys and the database live in the named volume, writable by UID 1000. Retrieve the generated role key privately from `/app/.data/admin-key` using your container administration tools, and keep it out of logs, screenshots and shared terminals. The Linux snapshot module sees the container's environment; host-level collection still uses the separate documented agent.

Tags are `latest` and `sha-<full-commit>`. Pin the package digest for an exact image. The container recipe uses Node 24 and lockfile-based dependency installation. To build the same recipe from source:

```sh
docker build -t rudy-central:0.2.0 .
```

## Persistent state

`.data/` contains the database, workspace role key, audit key, web permit key, and `kernel-authority.pem` Ed25519 signing key. These are excluded from Git and from the Docker build context. Use an encrypted volume and restrict OS access. Keep backups of the database **and the matching cryptographic keys**. Stop the application or use a proper SQLite online backup approach; do not casually copy only the main database file while WAL writes are active. Replacing the kernel authority breaks verification of previously issued permits; preserve it for existing evidence. Do not replace it casually to rotate a browser session.

Role keys can be supplied as `RUDY_ADMIN_KEY` and optional `RUDY_VIEWER_KEY` (each at least 32 random characters and distinct). If an environment key is used, it overrides the generated `admin-key` file. Never put a key in a browser URL, shell history, source file, screenshot, or issue. Change the configured key and restart the service to invalidate all sessions. Restarts also invalidate in-memory sessions automatically. Treat suspected key compromise as a workspace security incident.

Use an independent system for audit checkpoints. Local administrators can modify local files. No automatic outbound telemetry, analytics, or cloud persistence is configured.

## Development

The production server serves compiled UI files. Rebuild after frontend changes. For Vite HMR, explicitly trust the local development origin through `RUDY_PUBLIC_ORIGIN=http://127.0.0.1:5173`; run the API and `npm run dev` in separate shells. Never use that development configuration for remote exposure.
