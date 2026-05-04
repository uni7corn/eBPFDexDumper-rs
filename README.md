# eBPFDexDumper-rs

[![CI](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml)
[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

中文 | [English](docs/README_EN.md)

请先阅读 [中文说明](docs/README.md) 或 [English README](docs/README_EN.md)。

## 目录

- `bpf/`: eBPF 程序和共享头文件。
- `src/`: Rust 用户态实现。
- `headers/`: BPF helper 头文件。
- `vmlinux/`: ARM64 内核头文件。
- `assets/`: BTF 资源。
- `scripts/`: 打包脚本。
