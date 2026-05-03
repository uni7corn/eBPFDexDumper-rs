# eBPFDexDumper-rs

`eBPFDexDumper-rs` 是面向 Android ARM64 的 eBPF DEX dump 工具，用于在已 root
设备上通过 eBPF/uProbe 捕获 ART 运行时中的 DEX 信息，重建内存 DEX，并记录执行过
的方法字节码，随后可把记录到的字节码回填到已 dump 的 DEX 文件中。

本仓库是独立 Rust 项目，已经包含编译 eBPF 程序所需的 `bpf.c`、头文件、
ARM64 `vmlinux.h` 和最小 BTF 资源。

## 功能

- 支持 Android ARM64 设备上的 `dump` 命令。
- 通过 eBPF ring buffer 接收 DEX、方法和读取失败事件。
- 分块重建 DEX，并在 eBPF 分块读取失败时自动使用 `process_vm_readv` 兜底。
- 导出方法字节码 JSON，用于后续 DEX 修复。
- 支持 `fix` 命令，将记录到的方法字节码回填到 DEX，并输出到 `fix/` 目录。
- 支持从 `libart.so` 中自动定位 ART `Execute`、`ExecuteNterpImpl` 和
  `VerifyClass` 偏移。
- 支持 GitHub Actions CI 和 Android ARM64 Release 打包。

## 环境要求

编译环境：

- Rust stable 工具链。
- 支持 BPF target 的 LLVM clang。
- Android ARM64 Release 构建需要 Android NDK。

设备运行环境：

- Android ARM64。
- root 权限。
- 内核支持 eBPF。
- 可访问 ART `libart.so`，默认路径通常是
  `/apex/com.android.art/lib64/libart.so`。

macOS 自带的 Apple clang 通常不包含 BPF 后端，建议安装 LLVM：

```bash
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang
```

如果没有设置 `CLANG`，构建脚本会优先尝试 Homebrew LLVM clang，然后再尝试系统
`clang`。

## 编译

本机编译：

```bash
cargo build
```

Android ARM64 Release 编译：

```bash
sh build_android.sh
```

生成的 Android 可执行文件路径：

```text
target/aarch64-linux-android/release/eBPFDexDumper
```

`build_android.sh` 会优先使用 `cargo ndk`。如果没有安装 `cargo ndk`，脚本会回退到
`cargo build --target aarch64-linux-android --release`，并通过 `ANDROID_NDK_HOME` 或
`NDK_HOME` 查找 Android linker。

## 使用

查看帮助：

```bash
./eBPFDexDumper --help
```

按包名 dump：

```bash
su -c './eBPFDexDumper dump -n com.example.app -o /data/local/tmp/dex_out'
```

按 UID dump：

```bash
su -c './eBPFDexDumper dump -u 10123 -o /data/local/tmp/dex_out'
```

禁用 OAT 清理或自动修复：

```bash
su -c './eBPFDexDumper dump -n com.example.app --no-clean-oat --no-auto-fix'
```

修复已有 dump 目录：

```bash
./eBPFDexDumper fix -d /data/local/tmp/dex_out
```

单独定位 ART 偏移：

```bash
./eBPFDexDumper offsets -l /apex/com.android.art/lib64/libart.so
```

## 常见日志

运行时如果看到类似日志：

```text
eBPF read failed at offset ...; using process_vm_readv fallback
Dex file saved to ...
```

这通常不是 dump 失败。它表示 eBPF 分块读取某个 DEX offset 时失败，用户态随后使用
`process_vm_readv` 兜底读取。如果后面出现 `Dex file saved`，说明最终 DEX 已经保存。

如果只看到 `process_vm_readv failed`，才需要继续检查目标进程权限、SELinux、root
环境或目标进程是否已经退出。

## Release 打包

本地生成与 GitHub Release 一致的 Android ARM64 产物：

```bash
./scripts/package-release.sh
```

产物会写入 `dist/`：

- `eBPFDexDumper_android_arm64`
- `eBPFDexDumper_android_arm64.sha256`
- `eBPFDexDumper_android_arm64.tar.gz`

## GitHub Actions

仓库内已经包含两个工作流：

- `.github/workflows/ci.yml`：检查格式、运行测试，并验证 Android ARM64 构建。
- `.github/workflows/release.yml`：在推送 `v*` tag 或手动触发时，构建并上传
  Android ARM64 Release 产物。

发布新版本：

```bash
git tag v0.1.0
git push origin v0.1.0
```

也可以在 GitHub Actions 页面手动运行 Release workflow，并填写 tag。

## 许可证

本项目使用 `GPL-3.0-or-later` 许可证。仓库内打包的 Linux BPF helper 头文件带有
独立的 BSD-2-Clause 许可证文件，位于 `headers/LICENSE.BSD-2-Clause`。

请只在你有权分析的设备、应用和数据上使用本项目。
