# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2021 project that builds the `eBPFDexDumper` binary from `src/main.rs`.
Core logic lives in `src/`: `dump.rs` handles runtime dumping, `fix.rs` repairs DEX
files, `art.rs` resolves ART offsets, `dex.rs` covers DEX parsing/checksums, and
`platform.rs` contains platform helpers. The eBPF program is `bpf.c`; shared C/BPF
headers are in `headers/`; generated or bundled kernel headers are in `vmlinux/`;
minimal BTF assets are in `assets/`. Release packaging scripts live under `scripts/`.

## Build, Test, and Development Commands

- `cargo build`: build the host binary for local development.
- `cargo fmt --check`: verify Rust formatting before committing.
- `cargo test --locked`: run the inline unit tests with the checked-in lockfile.
- `sh build_android.sh`: build the Android ARM64 release binary at
  `target/aarch64-linux-android/release/eBPFDexDumper`.
- `./scripts/package-release.sh`: rebuild Android ARM64 and write release artifacts
  to `dist/`.

For eBPF builds on macOS, use LLVM clang, for example
`export CLANG=/opt/homebrew/opt/llvm/bin/clang`. Android builds require an NDK via
`ANDROID_NDK_HOME` or `NDK_HOME` unless `cargo ndk` is installed.

## Coding Style & Naming Conventions

Use standard `rustfmt` output and Rust 2021 idioms. Prefer 4-space indentation,
`snake_case` for modules/functions, `PascalCase` for types, and
`SCREAMING_SNAKE_CASE` for constants. Keep changes scoped to the existing modules
and avoid unrelated refactors, especially around eBPF loading, ART symbol handling,
and DEX repair behavior. Do not commit generated directories such as `target/`,
`dist/`, or local OS metadata.

## Testing Guidelines

Tests are currently inline Rust unit tests in files such as `src/dex.rs`,
`src/fix.rs`, `src/art.rs`, and `src/platform.rs`. Add new tests beside the code
they exercise using descriptive names, for example
`rejects_invalid_dex_checksum`. Run `cargo test --locked` for logic changes, and
also run `sh build_android.sh` when touching `bpf.c`, `headers/`, `vmlinux/`,
`assets/`, `build.rs`, or Android packaging paths.

## Commit & Pull Request Guidelines

The current history uses short imperative commit subjects such as
`Fix embedded BTF asset paths`. Keep subjects concise and focused. Pull requests
should describe the behavior change, list validation commands run, and call out
Android/eBPF compatibility impact. Link related issues when available. For
user-facing behavior or release changes, update `README.md`, `CONTRIBUTING.md`,
or packaging scripts in the same PR.

## Security & Configuration Tips

This project is for authorized Android reverse engineering and security research.
Avoid adding examples that bypass authorization, target third-party devices, or
expose sensitive data. Keep documentation claims tied to behavior that is actually
implemented and tested.
