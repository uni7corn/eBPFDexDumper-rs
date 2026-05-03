use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn lookup_uid_by_package_name(pkg: &str) -> Result<u32> {
    if let Ok(contents) = fs::read_to_string("/data/system/packages.list") {
        if let Some(uid) = parse_packages_list_for_pkg(&contents, pkg) {
            return Ok(uid);
        }
    }

    if let Ok(output) = run_shell("cmd package list packages -U") {
        if let Some(uid) = parse_cmd_package_list_for_pkg(&output, pkg) {
            return Ok(uid);
        }
    }

    if let Ok(output) = run_shell(&format!("dumpsys package {pkg} | grep -m1 userId=")) {
        if let Some(uid) = parse_dumpsys_user_id(&output) {
            return Ok(uid);
        }
    }

    anyhow::bail!("failed to resolve uid for package {pkg:?}")
}

pub fn lookup_packages_by_uid(uid: u32) -> Result<Vec<String>> {
    if let Ok(contents) = fs::read_to_string("/data/system/packages.list") {
        let packages = parse_packages_list_for_uid(&contents, uid);
        if !packages.is_empty() {
            return Ok(packages);
        }
    }

    if let Ok(output) = run_shell("cmd package list packages -U") {
        let packages = parse_cmd_package_list_for_uid(&output, uid);
        if !packages.is_empty() {
            return Ok(packages);
        }
    }

    anyhow::bail!("no packages found for uid {uid}")
}

pub fn remove_oat_dirs_for_package(pkg: &str) {
    match pm_paths_for_package(pkg) {
        Ok(paths) => {
            let mut seen = Vec::<PathBuf>::new();
            for apk_path in paths {
                let Some(base_dir) = apk_path.parent() else {
                    continue;
                };
                if base_dir == Path::new("/") {
                    continue;
                }
                let oat_dir = base_dir.join("oat");
                if seen.iter().any(|p| p == &oat_dir) {
                    continue;
                }
                seen.push(oat_dir.clone());
                match fs::metadata(&oat_dir) {
                    Ok(metadata) if metadata.is_dir() => match fs::remove_dir_all(&oat_dir) {
                        Ok(()) => println!("[oat-clean] removed {}", oat_dir.display()),
                        Err(err) => {
                            println!("[oat-clean] failed to remove {}: {err}", oat_dir.display())
                        }
                    },
                    _ => println!("[oat-clean] skip, not found: {}", oat_dir.display()),
                }
            }
        }
        Err(err) => println!("[oat-clean] pm path error for {pkg}: {err:#}"),
    }
}

pub fn remove_oat_dirs_by_uid(uid: u32) {
    match lookup_packages_by_uid(uid) {
        Ok(packages) => {
            for pkg in packages {
                remove_oat_dirs_for_package(&pkg);
            }
        }
        Err(err) => println!("[oat-clean] resolve packages by uid {uid} failed: {err:#}"),
    }
}

fn pm_paths_for_package(pkg: &str) -> Result<Vec<PathBuf>> {
    let output = run_shell(&format!("pm path {pkg}"))
        .with_context(|| format!("pm path failed for {pkg}"))?;
    let paths: Vec<PathBuf> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("package:"))
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .collect();

    if paths.is_empty() {
        anyhow::bail!("no package paths reported for {pkg}");
    }
    Ok(paths)
}

fn run_shell(script: &str) -> Result<String> {
    let output = Command::new("/system/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .with_context(|| format!("failed to run shell command: {script}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "shell command failed ({script}): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_packages_list_for_pkg(contents: &str, pkg: &str) -> Option<u32> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let uid = fields.next()?;
        (name == pkg).then(|| uid.parse().ok()).flatten()
    })
}

fn parse_packages_list_for_uid(contents: &str, uid: u32) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let parsed_uid: u32 = fields.next()?.parse().ok()?;
            (parsed_uid == uid).then(|| name.to_string())
        })
        .collect()
}

fn parse_cmd_package_list_for_pkg(contents: &str, pkg: &str) -> Option<u32> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("package:") || !line.contains("uid:") {
            return None;
        }
        let mut package_name = None;
        let mut uid = None;
        for part in line.split_whitespace() {
            if let Some(value) = part.strip_prefix("package:") {
                package_name = Some(value);
            } else if let Some(value) = part.strip_prefix("uid:") {
                uid = value.parse::<u32>().ok();
            }
        }
        (package_name == Some(pkg)).then_some(uid).flatten()
    })
}

fn parse_cmd_package_list_for_uid(contents: &str, uid: u32) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("package:") || !line.contains("uid:") {
                return None;
            }
            let mut package_name = None;
            let mut parsed_uid = None;
            for part in line.split_whitespace() {
                if let Some(value) = part.strip_prefix("package:") {
                    package_name = Some(value.to_string());
                } else if let Some(value) = part.strip_prefix("uid:") {
                    parsed_uid = value.parse::<u32>().ok();
                }
            }
            (parsed_uid == Some(uid)).then_some(package_name).flatten()
        })
        .collect()
}

fn parse_dumpsys_user_id(contents: &str) -> Option<u32> {
    let start = contents.find("userId=")? + "userId=".len();
    let suffix = &contents[start..];
    let digits: String = suffix.chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_list_uid() {
        let data = "com.example.app 10244 0 /data/user/0/com.example.app\n";
        assert_eq!(
            parse_packages_list_for_pkg(data, "com.example.app"),
            Some(10244)
        );
        assert_eq!(
            parse_packages_list_for_uid(data, 10244),
            vec!["com.example.app"]
        );
    }

    #[test]
    fn parses_cmd_package_output() {
        let data = "package:com.example.one uid:10001\npackage:com.example.two uid:10002\n";
        assert_eq!(
            parse_cmd_package_list_for_pkg(data, "com.example.two"),
            Some(10002)
        );
        assert_eq!(
            parse_cmd_package_list_for_uid(data, 10001),
            vec!["com.example.one"]
        );
    }

    #[test]
    fn parses_dumpsys_user_id() {
        assert_eq!(parse_dumpsys_user_id("  userId=10342\n"), Some(10342));
        assert_eq!(parse_dumpsys_user_id("missing"), None);
    }
}
