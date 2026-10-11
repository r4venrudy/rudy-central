# Deployment

## Preferred first deployment: loopback + SSH

Install Node 24.14 or later on a supported Linux distribution, clone the private repository using your own GitHub access, then `npm ci && npm run build && npm test`. Start with `npm start` under an unprivileged dedicated account. This application does not require sudo or a kernel driver.

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

For a container that must bind internally to `0.0.0.0`, set `RUDY_ALLOW_REMOTE=1`, a real HTTPS `RUDY_PUBLIC_ORIGIN`, and `RUDY_SECURE_COOKIE=1`. Place it on a private container network behind the HTTPS proxy. Do not publish its raw HTTP port to untrusted clients. The included Dockerfile is an example and was not executed on the Windows development host.

```sh
docker build -t rudy-central:0.1.0 .
```

## Persistent state

`.data/` contains the database, workspace role key, audit key, and permit key. These are excluded from Git and from the Docker build context. Use an encrypted volume and restrict OS access. Keep backups of the database **and the matching cryptographic keys**. Stop the application or use a proper SQLite online backup approach; do not casually copy only the main database file while WAL writes are active.

Role keys can be supplied as `RUDY_ADMIN_KEY` and optional `RUDY_VIEWER_KEY` (each at least 32 random characters and distinct). If an environment key is used, it overrides the generated `admin-key` file. Never put a key in a browser URL, shell history, source file, screenshot, or issue. Change the configured key and restart the service to invalidate all sessions. Restarts also invalidate in-memory sessions automatically. Treat suspected key compromise as a workspace security incident.

Use an independent system for audit checkpoints. Local administrators can modify local files. No automatic outbound telemetry, analytics, or cloud persistence is configured.

## Development

The production server serves compiled UI files. Rebuild after frontend changes. For Vite HMR, explicitly trust the local development origin through `RUDY_PUBLIC_ORIGIN=http://127.0.0.1:5173`; run the API and `npm run dev` in separate shells. Never use that development configuration for remote exposure.
