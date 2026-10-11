use anyhow::{Context, Result, ensure};
use libbpf_rs::{MapCore, MapFlags, ObjectBuilder, RingBufferBuilder};
use rudy_agent::{
    Capture, Counters, Envelope, HOOKS, Identity, Permit, VERSION, decode_event, now_ms, sha256,
};
use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/telemetry.bpf.o"));
fn monotonic_ns() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid writable timespec; CLOCK_MONOTONIC matches bpf_ktime_get_ns.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0,
        "Cannot read monotonic clock"
    );
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}
fn drop_privileges() -> Result<()> {
    // SAFETY: fixed identity, empty supplementary group list. Called after all
    // privileged handles are acquired; no threads or subprocesses are created.
    unsafe {
        ensure!(
            libc::geteuid() == 0,
            "Use sudo for capture; the reader drops to UID/GID 65534 after attach"
        );
        ensure!(
            libc::setgroups(0, std::ptr::null()) == 0,
            "Cannot drop supplementary groups"
        );
        ensure!(
            libc::setgid(65534) == 0 && libc::setuid(65534) == 0,
            "Cannot drop root identity"
        );
        ensure!(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
            "Cannot set no_new_privs"
        );
        ensure!(
            libc::getuid() == 65534 && libc::geteuid() == 65534,
            "Privilege drop failed"
        );
    }
    Ok(())
}
pub fn capture(
    permit: &Permit,
    envelope: Envelope,
    host: Identity,
    seconds: u32,
) -> Result<Capture> {
    let started_at = now_ms();
    // SAFETY: read-only effective-UID query, before loading anything.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Capture requires sudo and will drop root after attach"
    );
    let object = ObjectBuilder::default()
        .open_memory(OBJECT)?
        .load()
        .context("Kernel verifier rejected the embedded sensor or BPF permission is unavailable")?;
    let mut policy = Vec::with_capacity(24);
    policy.extend_from_slice(&(monotonic_ns()? + u64::from(seconds) * 1_000_000_000).to_le_bytes());
    policy.extend_from_slice(&permit.uid.to_le_bytes());
    policy.extend_from_slice(&permit.max_events.to_le_bytes());
    policy.extend_from_slice(&std::process::id().to_le_bytes());
    policy.extend_from_slice(&0u32.to_le_bytes());
    object
        .maps()
        .find(|m| m.name() == "capture_policy")
        .context("Missing policy map")?
        .update(&0u32.to_le_bytes(), &policy, MapFlags::ANY)?;
    // Keep every link alive until capture ends. An error unwinds and detaches all
    // previously attached probes. No map/link is pinned into bpffs.
    let mut links = Vec::new();
    for program in object.progs_mut() {
        links.push(
            program
                .attach()
                .context("Cannot attach required tracepoint")?,
        );
    }
    ensure!(
        links.len() == HOOKS.len(),
        "Unexpected embedded program count"
    );
    let events = RefCell::new(Vec::new());
    let decode_errors = RefCell::new(0u64);
    let event_map = object
        .maps()
        .find(|m| m.name() == "events")
        .context("Missing event map")?;
    let stats_map = object
        .maps()
        .find(|m| m.name() == "capture_stats")
        .context("Missing stats map")?;
    let mut builder = RingBufferBuilder::new();
    builder.add(&event_map, |bytes| {
        match decode_event(bytes) {
            Ok(event)
                if event.uid == permit.uid
                    && events.borrow().len() < permit.max_events as usize =>
            {
                events.borrow_mut().push(event)
            }
            _ => *decode_errors.borrow_mut() += 1,
        }
        0
    })?;
    let ring = builder.build()?;
    let stopped = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
    drop_privileges()?;
    // Test harness waits for this exact point: all probes attached, reader unprivileged.
    eprintln!("RUDY_KERNEL_ATTACHED reader_uid=65534 hooks=3");
    let timer = Instant::now();
    let mut stop_reason = "duration_elapsed";
    while timer.elapsed() < Duration::from_secs(u64::from(seconds)) && now_ms() < permit.expires_at
    {
        if stopped.load(Ordering::Relaxed) {
            stop_reason = "operator_signal";
            break;
        }
        if let Err(error) = ring.poll(Duration::from_millis(50)) {
            if !stopped.load(Ordering::Relaxed) {
                return Err(error.into());
            }
        }
    }
    // Detach before draining so producer counters and consumed data are final.
    drop(links);
    ring.consume()?;
    let raw_stats = stats_map
        .lookup(&0u32.to_le_bytes(), MapFlags::ANY)?
        .context("Missing capture counters")?;
    ensure!(raw_stats.len() == 32, "Unexpected counter ABI");
    let read = |i| u64::from_le_bytes(raw_stats[i..i + 8].try_into().unwrap());
    let counters = Counters {
        seen: read(0),
        emitted: read(8),
        ring_dropped: read(16),
        budget_dropped: read(24),
        decode_errors: *decode_errors.borrow(),
    };
    drop(ring);
    let captured = events.into_inner();
    ensure!(
        counters.seen == counters.emitted + counters.ring_dropped + counters.budget_dropped,
        "Kernel counter accounting mismatch"
    );
    ensure!(
        counters.emitted == captured.len() as u64 + counters.decode_errors,
        "Ring-buffer accounting mismatch"
    );
    Ok(Capture {
        schema: "rudy.kernel-capture.v1".into(),
        agent_version: VERSION.into(),
        permit: envelope,
        host,
        started_at,
        finished_at: now_ms(),
        hooks: HOOKS.iter().map(|s| s.to_string()).collect(),
        program_sha256: sha256(OBJECT),
        reader_uid: 65534,
        no_new_privileges: true,
        stop_reason: stop_reason.into(),
        counters,
        events: captured,
    })
}
