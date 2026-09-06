# eBPFDexDumper-rs

[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Downloads](https://img.shields.io/github/downloads/chinleez/eBPFDexDumper-rs/total)](https://github.com/chinleez/eBPFDexDumper-rs/releases)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

[中文](../README.md) | English

Capture real DEX files from rooted Android ARM64 devices, restore executed method bytecode into dumped files. Also supports native .so memory dumps and JNI name recovery.

## Quick start

```bash
# Build Android ARM64 binary
sh build_android.sh

# Push to device and run
adb push target/aarch64-linux-android/release/eBPFDexDumper /data/local/tmp/
adb shell su -c '/data/local/tmp/eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

The default `full` mode auto-repairs DEX on exit into `repair/`. The standalone `fix` command still writes its combined output into `final/`.

## Notes

- Captures are isolated by process and named `dex_<pid>_<begin>_<size>.dex` (hexadecimal). Older filenames remain supported. Use a fresh output directory per session.
- `repair` preserves inputs, checks structure and checksums, and returns nonzero on failure. These checks are not full ART bytecode verification.
- Normal shutdown drains event queues, including JNI. A second stop signal interrupts draining.
- JNI discovery can select an incorrect offset on API 35. Use `--register-natives-offset` with an offset verified for the current `libart.so`.

[Validation and limitations](DEFENSIVE_VALIDATION.md) · [Build and contribution guide](../CONTRIBUTING.md) (Chinese)

## Subcommands

| Command | Purpose |
|---------|---------|
| `dump` | Capture DEX + method bytecode |
| `fix` | Restore bytecode into DEX |
| `repair` | Fix header/format/missing code_items |
| `dumpso` | Capture native .so from memory |
| `fixso` | Repair .so segment offsets |
| `offsets` | Inspect ART layout |

## Probe modes

| Mode | Probes | Performance |
|------|--------|-------------|
| `full` (default) | Interpreter + lifecycle + libc | UI lag |
| `lifecycle` | Lifecycle only | No impact |
| `maps-only` | No uprobes | No impact |

## Project skill

One-click run:

```bash
./skills/android-dex-dump/scripts/run_dump.sh /path/to/app.apk
```

## License

GPL-3.0-or-later
