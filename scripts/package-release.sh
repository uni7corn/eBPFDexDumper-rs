#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${project_dir}/dist"
binary_name="eBPFDexDumper"
artifact_name="eBPFDexDumper_android_arm64"

cd "${project_dir}"
rm -rf "${dist_dir}"
mkdir -p "${dist_dir}"

./build_android.sh

binary_path="${project_dir}/target/aarch64-linux-android/release/${binary_name}"
if [[ ! -x "${binary_path}" ]]; then
  echo "missing release binary: ${binary_path}" >&2
  exit 1
fi

cp "${binary_path}" "${dist_dir}/${artifact_name}"
chmod +x "${dist_dir}/${artifact_name}"

(
  cd "${dist_dir}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${artifact_name}" > "${artifact_name}.sha256"
  else
    shasum -a 256 "${artifact_name}" > "${artifact_name}.sha256"
  fi
  tar -czf "${artifact_name}.tar.gz" "${artifact_name}" "${artifact_name}.sha256"
)

echo "${dist_dir}/${artifact_name}.tar.gz"
