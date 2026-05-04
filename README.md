# eBPFDexDumper-rs

[![CI](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/ci.yml)
[![Release](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml/badge.svg)](https://github.com/chinleez/eBPFDexDumper-rs/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/chinleez/eBPFDexDumper-rs)](https://github.com/chinleez/eBPFDexDumper-rs/releases/latest)

中文 | [English](README_EN.md)

面向 Android ARM64 的 eBPF DEX dump 工具。用于在已 root 设备上通过 eBPF/uProbe 捕获
ART 运行时中的 DEX，记录执行过的方法字节码，并可将字节码回填到已 dump 的 DEX。

## 功能

- `dump`：通过 ART 入口、DexFile 注册/构造、CodeItem 反扫、maps 扫描和 native buffer 扫描捕获 DEX。
- `fix`：把记录到的方法字节码回填到 DEX，输出到 `fix/` 目录。
- `offsets`：从 `libart.so` 定位 hook 目标，必要时可手动指定 ART layout。

## 环境

- 编译：Rust stable、LLVM clang、Android NDK。
- 运行：Android ARM64、root、内核支持 eBPF、可访问 ART `libart.so`。
- macOS 建议使用 LLVM clang：

```bash
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang
```

## 编译

```bash
cargo build
sh build_android.sh
```

Android 产物：

```text
target/aarch64-linux-android/release/eBPFDexDumper
```

## 使用

```bash
./eBPFDexDumper --help

su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
su -c './eBPFDexDumper dump -u 10123 -o /data/local/tmp/dex_out'

./eBPFDexDumper fix -d /data/local/tmp/dex_out
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so --json
```

常用选项：

- `--pid <PID>`：在 UID/包名基础上进一步限制目标进程。
- `--no-clean-oat`：不清理 OAT。
- `--no-auto-fix`：dump 后不自动修复。
- `--debug-layout`：打印 ART layout 诊断事件。
- `--no-code-item-fallback` / `--no-maps-scan` / `--no-native-buffer-scan`：关闭对应兜底路径。
- `--libc <PATH>`：指定 bionic libc 路径。
- `--art-layout <LIST>`：手动指定 ART 字段偏移。

`--art-layout` 顺序：

```text
ShadowFrame.method,ArtMethod.declaring_class,ArtMethod.dex_method_index,ArtMethod.data,Class.dex_cache,DexCache.dex_file,DexFile.begin,DexHeader.file_size,CodeItem.insns_size,CodeItem.insns
```

## 打包

```bash
./scripts/package-release.sh
```

输出到 `dist/`：

- `eBPFDexDumper_android_arm64`
- `eBPFDexDumper_android_arm64.sha256`
- `eBPFDexDumper_android_arm64.tar.gz`

## 说明

默认 ART layout 按 Android 13+ 常见布局处理；ROM 偏移不一致时使用 `--art-layout`。
如果目标只在 native 层短暂解密碎片化方法体，内存中不保留连续合法 DEX，需要按壳适配。

## 许可证

`GPL-3.0-or-later`。仓库内 Linux BPF helper 头文件的 BSD-2-Clause 许可证位于
`headers/LICENSE.BSD-2-Clause`。

请只在你有权分析的设备、应用和数据上使用本项目。

## 参考

本项目参考了 [LLeavesG/eBPFDexDumper](https://github.com/LLeavesG/eBPFDexDumper) 的部分实现逻辑。
