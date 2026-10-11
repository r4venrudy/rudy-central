use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const HOOKS: [&str; 3] = [
    "sched/sched_process_exec",
    "sched/sched_process_exit",
    "syscalls/sys_enter_connect",
];
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "Input exceeds byte limit");
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Envelope {
    pub payload: String,
    pub signature: String,
}
pub fn sign_json<T: Serialize>(value: &T, key: &SigningKey) -> Result<Envelope> {
    let bytes = serde_json::to_vec(value)?;
    Ok(Envelope {
        payload: URL_SAFE_NO_PAD.encode(&bytes),
        signature: URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()),
    })
}
pub fn verify_envelope(envelope: &Envelope, public_key: &str, max_bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        envelope.payload.len() <= max_bytes * 4 / 3 + 4,
        "Signed payload too large"
    );
    let key: [u8; 32] = hex::decode(public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
    let bytes = URL_SAFE_NO_PAD.decode(&envelope.payload)?;
    ensure!(bytes.len() <= max_bytes, "Signed payload too large");
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(&envelope.signature)?)?;
    VerifyingKey::from_bytes(&key)?
        .verify_strict(&bytes, &signature)
        .context("Invalid Ed25519 signature")?;
    Ok(bytes)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Permit {
    pub schema: String,
    pub id: String,
    pub sensor_id: String,
    pub engagement_id: String,
    pub host_id: String,
    pub boot_id: String,
    pub public_key: String,
    pub uid: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_duration_seconds: u32,
    pub max_events: u32,
}
pub fn validate_permit(
    envelope: &Envelope,
    authority: &str,
    host: &Identity,
    public_key: &str,
    now: u64,
) -> Result<Permit> {
    let p: Permit = serde_json::from_slice(&verify_envelope(envelope, authority, 8192)?)?;
    ensure!(
        p.schema == "rudy.kernel-permit.v1",
        "Unsupported permit schema"
    );
    ensure!(
        p.host_id == host.host_id && p.boot_id == host.boot_id && p.public_key == public_key,
        "Permit is for a different host, boot, or sensor key"
    );
    ensure!(
        p.issued_at <= now
            && p.expires_at > now
            && p.expires_at > p.issued_at
            && p.expires_at - p.issued_at <= 900_000,
        "Permit expired, future-dated, or exceeds 15 minutes"
    );
    ensure!(
        (1..=300).contains(&p.max_duration_seconds) && (1..=10_000).contains(&p.max_events),
        "Permit exceeds capture limits"
    );
    ensure!(
        p.id.len() == 36 && p.id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "Invalid permit ID"
    );
    ensure!(
        !p.sensor_id.is_empty() && !p.engagement_id.is_empty(),
        "Missing permit scope"
    );
    Ok(p)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub host_id: String,
    pub boot_id: String,
    pub hostname: String,
    pub kernel: String,
    pub architecture: String,
}
pub fn identity() -> Result<Identity> {
    ensure!(cfg!(target_os = "linux"), "Host identity requires Linux");
    let read = |p: &str| -> Result<String> {
        Ok(String::from_utf8(read_bounded(Path::new(p), 4096)?)?
            .trim()
            .to_string())
    };
    let machine_id = read("/etc/machine-id")?;
    ensure!(
        machine_id.len() == 32 && machine_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid machine-id"
    );
    Ok(Identity {
        host_id: sha256(format!("rudy-central-host-v1:{machine_id}").as_bytes()),
        boot_id: read("/proc/sys/kernel/random/boot_id")?,
        hostname: read("/proc/sys/kernel/hostname")?,
        kernel: read("/proc/sys/kernel/osrelease")?,
        architecture: std::env::consts::ARCH.into(),
    })
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub timestamp_ns: String,
    pub cgroup_id: String,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub kind: String,
    pub comm: String,
}
// Decode each field explicitly: no casting untrusted bytes into aligned structs.
pub fn decode_event(bytes: &[u8]) -> Result<Event> {
    ensure!(bytes.len() == 48, "Unexpected kernel event ABI");
    let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    let u64_at = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
    let kind = match u32_at(28) {
        1 => "process_exec",
        2 => "process_exit",
        3 => "connect_attempt",
        _ => bail!("Unknown kernel event kind"),
    };
    let end = bytes[32..48].iter().position(|b| *b == 0).unwrap_or(16);
    let comm = String::from_utf8_lossy(&bytes[32..32 + end])
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect();
    Ok(Event {
        timestamp_ns: u64_at(0).to_string(),
        cgroup_id: u64_at(8).to_string(),
        pid: u32_at(16),
        tid: u32_at(20),
        uid: u32_at(24),
        kind: kind.into(),
        comm,
    })
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counters {
    pub seen: u64,
    pub emitted: u64,
    pub ring_dropped: u64,
    pub budget_dropped: u64,
    pub decode_errors: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    pub schema: String,
    pub agent_version: String,
    pub permit: Envelope,
    pub host: Identity,
    pub started_at: u64,
    pub finished_at: u64,
    pub hooks: Vec<String>,
    pub program_sha256: String,
    pub reader_uid: u32,
    pub no_new_privileges: bool,
    pub stop_reason: String,
    pub counters: Counters,
    pub events: Vec<Event>,
}

pub fn posture() -> Result<serde_json::Value> {
    let host = identity()?;
    let specs = [
        ("kptr_restrict", "/proc/sys/kernel/kptr_restrict", 1),
        ("dmesg_restrict", "/proc/sys/kernel/dmesg_restrict", 1),
        ("ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope", 1),
        (
            "unprivileged_bpf_disabled",
            "/proc/sys/kernel/unprivileged_bpf_disabled",
            1,
        ),
        (
            "randomize_va_space",
            "/proc/sys/kernel/randomize_va_space",
            2,
        ),
        ("protected_hardlinks", "/proc/sys/fs/protected_hardlinks", 1),
        ("protected_symlinks", "/proc/sys/fs/protected_symlinks", 1),
        (
            "perf_event_paranoid",
            "/proc/sys/kernel/perf_event_paranoid",
            2,
        ),
    ];
    let checks: Vec<_> = specs.iter().map(|(id, path, min)| {
        let value = read_bounded(Path::new(path), 128).ok().and_then(|v| String::from_utf8(v).ok()).and_then(|v| v.trim().parse::<i32>().ok());
        serde_json::json!({"id":id,"title":format!("Review Linux {id} policy"),"status":match value { None => "unavailable",Some(v) if v >= *min => "observed",_ => "review"},"severity":"low","description":"Read-only host configuration observation. Applicability depends on workload requirements.","remediation":format!("Review distribution guidance and application compatibility before changing {path}."),"evidence":format!("{path}: {}",value.map(|v|v.to_string()).unwrap_or_else(||"unavailable".into()))})
    }).collect();
    Ok(
        serde_json::json!({"schema":"rudy.linux-snapshot.v1","collector":{"version":VERSION,"runtime":"Rust","network":"none"},"host":{"name":host.hostname,"kernel":host.kernel,"architecture":host.architecture,"platform":"linux"},"checks":checks}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (SigningKey, Identity, Permit) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let host = Identity {
            host_id: "a".repeat(64),
            boot_id: "boot".into(),
            hostname: "fixture".into(),
            kernel: "fixture".into(),
            architecture: "x86_64".into(),
        };
        let p = Permit {
            schema: "rudy.kernel-permit.v1".into(),
            id: "00000000-0000-4000-8000-000000000000".into(),
            sensor_id: "sensor".into(),
            engagement_id: "engagement".into(),
            host_id: host.host_id.clone(),
            boot_id: host.boot_id.clone(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            uid: 1000,
            issued_at: 100,
            expires_at: 10000,
            max_duration_seconds: 3,
            max_events: 10,
        };
        (key, host, p)
    }
    #[test]
    fn signed_permit_rejects_tampering_scope_and_time() {
        let (key, host, mut p) = setup();
        let public = p.public_key.clone();
        let envelope = sign_json(&p, &key).unwrap();
        assert!(validate_permit(&envelope, &public, &host, &public, 101).is_ok());
        assert!(validate_permit(&envelope, &public, &host, &public, 10000).is_err());
        assert!(validate_permit(&envelope, &public, &host, &public, 99).is_err());
        p.host_id = "another-host".into();
        assert!(
            validate_permit(&sign_json(&p, &key).unwrap(), &public, &host, &public, 101).is_err()
        );
        let mut forged = envelope.clone();
        forged.payload.push('A');
        assert!(verify_envelope(&forged, &public, 8192).is_err());
        assert!(
            verify_envelope(
                &envelope,
                &hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()),
                8192
            )
            .is_err()
        );
    }
    #[test]
    fn permit_has_hard_resource_limits_and_rejects_unknown_fields() {
        let (key, host, mut p) = setup();
        let public = p.public_key.clone();
        for limit in [0, 10001, u32::MAX] {
            p.max_events = limit;
            assert!(
                validate_permit(&sign_json(&p, &key).unwrap(), &public, &host, &public, 101)
                    .is_err()
            );
        }
        p.max_events = 10;
        p.max_duration_seconds = 301;
        assert!(
            validate_permit(&sign_json(&p, &key).unwrap(), &public, &host, &public, 101).is_err()
        );
        let mut value = serde_json::to_value(p).unwrap();
        value["command"] = serde_json::json!("arbitrary");
        assert!(
            validate_permit(
                &sign_json(&value, &key).unwrap(),
                &public,
                &host,
                &public,
                101
            )
            .is_err()
        );
    }
    #[test]
    fn kernel_abi_is_length_checked_and_preserves_u64_precision() {
        let mut b = [0u8; 48];
        b[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        b[28..32].copy_from_slice(&3u32.to_le_bytes());
        b[32..37].copy_from_slice(b"hello");
        let event = decode_event(&b).unwrap();
        assert_eq!(event.timestamp_ns, u64::MAX.to_string());
        assert_eq!(event.kind, "connect_attempt");
        assert_eq!(event.comm, "hello");
        assert!(decode_event(&b[..47]).is_err());
        b[28] = 99;
        assert!(decode_event(&b).is_err());
    }
}
