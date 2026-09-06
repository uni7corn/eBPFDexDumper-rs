# 贡献指南

## 环境

需要 Rust stable、支持 BPF target 的 LLVM clang 和 Android NDK（CI 使用 r27c）。

```bash
# macOS
brew install llvm
export CLANG=/opt/homebrew/opt/llvm/bin/clang

rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/android-sdk/ndk/27.2.12479018
```

混用 Homebrew Rust 与 rustup 时，可设置 `RUSTC="$(rustup which rustc)"`。

## 检查

```bash
cargo fmt --check
cargo test --locked
sh build_android.sh
```

Android 二进制：`target/aarch64-linux-android/release/eBPFDexDumper`。
采集、BPF 或退出流程改动还需设备测试，见[验证记录](docs/DEFENSIVE_VALIDATION.md)。

## 发布

```bash
./scripts/package-release.sh
```

产物在 `dist/`。推送新 `v*` 标签触发 Release，也支持对标签手动运行；不要移动旧标签。

工作流仅用 `run`，兼容 owner-only Actions 策略；依赖 Ubuntu runner 的 Git、
rustup、sdkmanager 和 gh。修改工作流后运行 `actionlint`。

## 提交要求

- 沿用现有结构，只改相关代码，并补充测试。
- 不提交 `target/`、`dist/`、`.DS_Store` 等生成文件。
- 文档只描述已实现、已验证的行为。
- 示例仅用于授权测试，不包含第三方敏感数据。
