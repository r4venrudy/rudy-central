use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=bpf/telemetry.bpf.c");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var_os("CARGO_FEATURE_KERNEL").is_none()
    {
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    assert_eq!(
        arch, "x86_64",
        "Kernel capture is currently validated for Linux x86_64"
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("telemetry.bpf.o");
    let status = Command::new(env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into()))
        .args([
            "-g",
            "-O2",
            "-target",
            "bpfel",
            "-Wall",
            "-Werror",
            "-I/usr/include/x86_64-linux-gnu",
            "-c",
            "bpf/telemetry.bpf.c",
            "-o",
        ])
        .arg(output)
        .status()
        .expect("Install clang, libbpf-dev, libelf-dev, zlib1g-dev and pkg-config");
    assert!(status.success(), "eBPF compilation failed");
}
