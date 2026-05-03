# 贡献指南

感谢你关注 `eBPFDexDumper-rs`。这个项目的目标是提供稳定、可维护、可发布的
Android eBPF DEX dump 工具。

## 开发环境

建议准备以下工具：

- Rust stable 工具链。
- 支持 BPF target 的 LLVM clang。
- Android NDK，用于 Android ARM64 Release 构建。

macOS 自带的 Apple clang 通常不能编译 eBPF，建议安装 Homebrew LLVM：

```bash
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang
```

## 提交前检查

提交改动前建议执行：

```bash
cargo fmt --check
cargo test --locked
sh build_android.sh
```

Android Release 可执行文件会生成在：

```text
target/aarch64-linux-android/release/eBPFDexDumper
```

如果只改了文档，也至少确认 Markdown 内容准确，不要写超过当前实现能力的功能描述。

## 打包

本地复现 GitHub Release 产物：

```bash
./scripts/package-release.sh
```

生成文件位于 `dist/`。

## 代码要求

- 保持 `dump`、`fix`、`offsets` 的命令行为稳定。
- 优先使用已有模块和数据结构，不做无关重构。
- 涉及 eBPF、ART 偏移、DEX 修复逻辑的改动，需要尽量补充或更新测试。
- 不提交 `target/`、`dist/`、`.DS_Store` 等本地生成文件。

## 安全边界

请不要提交用于绕过授权、攻击第三方设备或泄露敏感数据的示例。项目只面向授权的
Android 逆向分析和安全研究场景。
