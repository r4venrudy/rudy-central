use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use rudy_agent::{Envelope, VERSION, identity, now_ms, read_bounded, sign_json, validate_permit};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
#[cfg(all(target_os = "linux", feature = "kernel"))]
mod kernel;

#[derive(Parser)]
#[command(
    version,
    about = "Rudy Central: bounded, authorized Linux kernel observation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Inspect platform and build support without loading kernel programs.
    Doctor,
    /// Generate a local sensor key. Prints public enrollment data, never the secret.
    Enroll {
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Read eight Linux hardening settings without root or network access.
    Posture,
    /// Capture three fixed tracepoints using a workspace-issued, host-bound permit.
    Capture {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        authority: PathBuf,
        #[arg(long)]
        permit: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 30)]
        seconds: u32,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SensorKey {
    schema: String,
    private_key: String,
}
fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).with_context(|| {
        format!(
            "Cannot create {} (files are never overwritten)",
            path.display()
        )
    })
}
fn secure_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Key and authority paths must not be symlinks"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            std::fs::metadata(path)?.permissions().mode() & 0o022 == 0,
            "Key and authority files must not be group/world writable"
        );
    }
    read_bounded(path, limit)
}
fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("rudy-agent: {error:#}");
        std::process::exit(1);
    }
}
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Doctor => {
            let kernel_compiled = cfg!(all(target_os = "linux", feature = "kernel"));
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema":"rudy.agent-doctor.v1", "version":VERSION, "platform":std::env::consts::OS,
                    "architecture":std::env::consts::ARCH, "kernelCompiled":kernel_compiled,
                    "kernel":std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|v|v.trim().to_string()),
                    "btfAvailable":Path::new("/sys/kernel/btf/vmlinux").exists(),
                    "tracefsAvailable":Path::new("/sys/kernel/tracing/events").exists() || Path::new("/sys/kernel/debug/tracing/events").exists(),
                    "hooks":rudy_agent::HOOKS, "network":"none", "maxEvents":10000,"maxDurationSeconds":300,
                    "readiness":"Only a successful authorized capture confirms kernel compatibility and permissions."
                }))?
            );
        }
        Command::Enroll { key_file } => {
            let host = identity()?;
            let key = SigningKey::generate(&mut OsRng);
            let state = SensorKey {
                schema: "rudy.sensor-key.v1".into(),
                private_key: hex::encode(key.to_bytes()),
            };
            let mut file = create_private(&key_file)?;
            file.write_all(&serde_json::to_vec(&state)?)?;
            file.sync_all()?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"schema":"rudy.sensor-enrollment.v1","hostId":host.host_id,"bootId":host.boot_id,"hostname":host.hostname,"kernel":host.kernel,"architecture":host.architecture,"publicKey":hex::encode(key.verifying_key().to_bytes())})
                )?
            );
        }
        Command::Posture => println!("{}", serde_json::to_string_pretty(&rudy_agent::posture()?)?),
        Command::Capture {
            key_file,
            authority,
            permit,
            out,
            seconds,
        } => {
            ensure!(
                cfg!(all(target_os = "linux", feature = "kernel")),
                "Capture requires the Linux x86_64 build with --features kernel"
            );
            let host = identity()?;
            let state: SensorKey = serde_json::from_slice(&secure_read(&key_file, 4096)?)?;
            ensure!(
                state.schema == "rudy.sensor-key.v1",
                "Invalid sensor key schema"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    std::fs::metadata(&key_file)?.permissions().mode() & 0o077 == 0,
                    "Sensor key must be private (chmod 600)"
                );
            }
            let seed: [u8; 32] = hex::decode(state.private_key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid sensor seed length"))?;
            let key = SigningKey::from_bytes(&seed);
            let authority = String::from_utf8(secure_read(&authority, 256)?)?;
            let envelope: Envelope = serde_json::from_slice(&read_bounded(&permit, 16384)?)?;
            let p = validate_permit(
                &envelope,
                authority.trim(),
                &host,
                &hex::encode(key.verifying_key().to_bytes()),
                now_ms(),
            )?;
            ensure!(
                seconds > 0
                    && seconds <= p.max_duration_seconds
                    && now_ms() + u64::from(seconds) * 1000 <= p.expires_at,
                "Capture duration exceeds permit or remaining lifetime"
            );
            // A one-shot journal consumes the permit before loading, including failed attempts.
            let mut used = create_private(&key_file.with_extension(format!("used-{}", p.id)))?;
            used.write_all(p.id.as_bytes())?;
            used.sync_all()?;
            let mut output = create_private(&out)?;
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            {
                let capture = kernel::capture(&p, envelope, host, seconds)?;
                let signed = sign_json(&capture, &key)?;
                output.write_all(&serde_json::to_vec_pretty(&signed)?)?;
                output.write_all(b"\n")?;
                output.sync_all()?;
                println!(
                    "{}",
                    serde_json::json!({"saved":out,"events":capture.events.len(),"counters":capture.counters,"stopReason":capture.stop_reason,"readerUid":capture.reader_uid})
                );
            }
            #[cfg(not(all(target_os = "linux", feature = "kernel")))]
            {
                let _ = (&mut output, key, envelope, sign_json::<serde_json::Value>);
            }
        }
    }
    Ok(())
}
