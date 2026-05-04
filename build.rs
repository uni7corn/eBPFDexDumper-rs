use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let bpf_source = manifest_dir.join("bpf/bpf.c");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let object = out_dir.join("bpf_arm64_bpfel.o");

    println!("cargo:rerun-if-changed={}", bpf_source.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("bpf/header.h").display()
    );
    println!("cargo:rerun-if-env-changed=CLANG");
    rerun_dir(&manifest_dir.join("headers"));
    rerun_dir(&manifest_dir.join("vmlinux/arm64"));

    let clang = find_bpf_clang();

    let output = Command::new(&clang)
        .arg("-target")
        .arg("bpfel")
        .arg("-D__TARGET_ARCH_arm64")
        .arg("-O2")
        .arg("-g")
        .arg("-c")
        .arg(&bpf_source)
        .arg("-o")
        .arg(&object)
        .arg("-I")
        .arg(manifest_dir.join("bpf"))
        .arg("-I")
        .arg(manifest_dir.join("headers"))
        .arg("-I")
        .arg(manifest_dir.join("vmlinux/arm64"))
        .output()
        .expect("failed to execute clang");

    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        panic!(
            "failed to compile {} with {}",
            bpf_source.display(),
            clang.display()
        );
    }
}

fn find_bpf_clang() -> PathBuf {
    let mut candidates = Vec::new();
    if let Some(clang) = env::var_os("CLANG") {
        candidates.push(PathBuf::from(clang));
    }
    candidates.extend([
        PathBuf::from("/opt/homebrew/opt/llvm/bin/clang"),
        PathBuf::from("/usr/local/opt/llvm/bin/clang"),
        PathBuf::from("clang"),
        PathBuf::from("clang-21"),
        PathBuf::from("clang-20"),
        PathBuf::from("clang-19"),
        PathBuf::from("clang-18"),
        PathBuf::from("clang-17"),
    ]);

    for candidate in candidates {
        if supports_bpf_target(&candidate) {
            return candidate;
        }
    }

    panic!(
        "no clang with BPF target support found; install LLVM clang and set CLANG=/path/to/clang"
    );
}

fn supports_bpf_target(clang: &Path) -> bool {
    let Ok(output) = Command::new(clang)
        .arg("-print-targets")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim_start().starts_with("bpfel"))
}

fn rerun_dir(path: &Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}
