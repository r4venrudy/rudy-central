# Linux kernel sensor

Rudy Agent 0.2.0 is a Rust userspace agent with three embedded eBPF programs written in restricted C and loaded through libbpf. Kernel code only uses helper-derived metadata, so these hooks do not depend on arbitrary kernel structure layouts or CO-RE field relocation. The embedded object is compiled at build time; the CLI cannot load a user-supplied object or attach an arbitrary probe.

## Supported and tested

- Build target: Linux x86_64; Ubuntu 24.04 build dependencies below.
- Real load/capture/API validation: Ubuntu GitHub-hosted runner, kernel **6.17.0-1022-azure**, 2026-10-11. [Passing initial kernel run](https://github.com/r4venrudy/rudy-central/actions/runs/38159530194).
- Core permit and event decoder tests also run on Windows. Windows cannot load Linux probes.
- Kernel needs BPF ring buffers (introduced in Linux 5.8), BPF syscall and tracing support, and all three named tracepoints. Version alone does not guarantee compatibility. Lockdown, container capability restrictions, disabled tracepoints, and host policy may prevent capture. `doctor` is diagnostic; only a successful capture confirms support.
- ARM64, WSL, alternate distributions, containerized capture, older kernels, and production overhead/soak behavior are not validated in this release.

## Build

```sh
sudo apt-get update
sudo apt-get install -y clang libbpf-dev libelf-dev zlib1g-dev pkg-config
cargo build --locked --release --manifest-path native/Cargo.toml --features kernel
./native/target/release/rudy-agent doctor
```

Use Rust stable from its official distribution. This package currently declares Rust 1.85 as its minimum; validation used 1.99.0. Building from Cargo.lock pins dependencies, not the whole OS/toolchain. The executable embeds the eBPF object and dynamically depends on the system's libelf/zlib/libc. GitHub Actions also packages the tested executable, checksum, and validation report as **rudy-agent-linux-x86_64** under each successful run. Artifact checksums detect accidental change; this is not an independently signed release distribution.

## Enroll and capture

1. Create a private working directory on the authorized Linux host. Keep key files and output out of shared directories. Run enrollment **without sudo**:

   ```sh
   mkdir -m 700 rudy-sensor
   cd rudy-sensor
   /path/to/rudy-agent enroll --key-file sensor.key > enrollment.json
   ```

2. In Rudy Central, create an engagement. Open **Kernel telemetry → Enroll host**. Paste `enrollment.json`, name the host, select the engagement, and set the exact Linux UID to observe (`id -u` for your user). UID 0 observes root-owned processes and requires explicit authorization for that scope. Host identity is a product-specific hash of `/etc/machine-id`, plus the current boot ID. Enrollment after reboot requires a new key/record; revoke the old record.

3. Issue a capture permit in the UI. Download `capture-permit.json` and `rudy-authority.pub`. Copy them to the host through your authenticated channel. Verify the authority public key against your trusted workspace before using it; a public key supplied by an untrusted party is not an authority. The agent never obtains trust from the permit itself.

   ```sh
   chmod 600 sensor.key capture-permit.json rudy-authority.pub
   sudo /path/to/rudy-agent capture \
     --key-file sensor.key \
     --authority rudy-authority.pub \
     --permit capture-permit.json \
     --out capture.json --seconds 30
   ```

   Set `--seconds` at or below your permit duration. A permit expires in 15 minutes; initialization must leave enough time for the requested capture. Capture requires root for loading and attaching. Immediately after attachment, the reader removes supplementary groups, drops to UID/GID 65534 and sets `no_new_privs`. Existing ring-buffer/map handles and an already opened output descriptor are retained. It does not run subprocesses, use the network, or change sysctls. It is not a general-purpose OS sandbox.

4. The output is root-owned and mode 0600. Transfer it securely with administrative access. One local method for creating a private user-owned copy is:

   ```sh
   umask 077
   sudo cat capture.json > capture-for-import.json
   ```

   In **Import capture**, select the enrolled sensor and this JSON file. The API checks the sensor signature, authority signature, original issued permit, host/boot/key/UID, timestamps, budgets and counters. An accepted artifact is stored as evidence with a SHA-256 digest, and its permit is atomically marked consumed. Inspect the events in the explorer or export the original signed envelope from Evidence.

## Events and collection limits

| Hook                         | Event             | Meaning                                                                      |
| ---------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| `sched/sched_process_exec`   | `process_exec`    | A process successfully replaced its program image                            |
| `sched/sched_process_exit`   | `process_exit`    | A thread exits; PID identifies its thread group, TID its thread              |
| `syscalls/sys_enter_connect` | `connect_attempt` | A connect syscall was entered, regardless of later outcome or address family |

Each 48-byte event carries monotonic nanoseconds, cgroup ID, PID, TID, real UID, kind, and the kernel's 16-byte command field. No command arguments, paths, environment, file content, socket addresses, packet payload, or credentials are collected. The command field can be truncated and is not a trustworthy executable identity. Monotonic time is not UTC. 64-bit IDs/timestamps are serialized as decimal strings to preserve precision in JavaScript.

- One explicitly selected UID; no all-users wildcard. The agent's own thread group is excluded.
- One MiB ring buffer; at most 10,000 candidate events and 300 seconds per capture.
- UID, monotonic deadline, and event budget are checked in eBPF before emitting data. The deadline stops emission even if userspace stops polling.
- `seen = emitted + ringDropped + budgetDropped`; `emitted = decoded events + decodeErrors`. The reader and server both reject inconsistent accounting. Event loss is reported, never silently interpreted as no activity.
- The event budget counts matching candidates, including a ring-buffer reservation that fails. Once exhausted, later matches increment `budgetDropped` without emitting.
- SIGINT/SIGTERM requests stop collection and produces a partial signed capture with `operator_signal` when graceful completion is possible. No links or maps are pinned. Closing process handles detaches probes; SIGKILL or a crash may leave an incomplete, invalid output file.
- The local `.used-<permit-id>` journal is created exclusively before a load attempt. Failed attempts also consume that permit; request another after diagnosing failure. Do not remove journals to reuse permits.

## Trust limits

This is host observability, not a kernel exploitation engine, rootkit detector, or preventive IPS. It does not block syscalls, inspect other machines, or establish whether a process is malicious. The app keeps telemetry separate from vulnerability findings; an analyst must interpret it.

The sensor key proves possession of an enrolled key. It does **not** attest that a host is uncompromised, prove legal ownership, enforce an immutable binary, or prevent a host administrator from forging events, deleting journals, replacing keys, modifying the program, or changing the clock. The object hash records what the agent reports loading; it is not hardware attestation.

Offline capture has explicit revocation limits: revoking the sensor blocks new permits and future imports immediately, but cannot interrupt an offline agent that already holds a valid permit. That agent stops at its kernel deadline. An expired permit can be imported later if the recorded capture occurred entirely inside its authorized window and the sensor/permit have not been revoked or consumed.

The native agent is installed and invoked separately from the browser/API. Never run the web server as root or expose a generic sudo command endpoint. No service, boot hook, driver install, firewall change, or automatic kernel-module persistence is created. Removing the standalone binary and its private working directory after preserving needed evidence removes the installation; no persistent BPF links need cleanup.

## References

- [Linux eBPF userspace API](https://docs.kernel.org/userspace-api/ebpf/index.html)
- [Kernel BPF ring-buffer design](https://docs.kernel.org/bpf/ringbuf.html)
- [libbpf-rs loader and ring-buffer API](https://docs.rs/libbpf-rs/0.26.2/libbpf_rs/)
