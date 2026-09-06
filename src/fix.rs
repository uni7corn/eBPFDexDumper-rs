use crate::dex::{read_uleb128, DexParser, DEX_HEADER_SIZE};
use adler2::Adler32;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MethodCodeRecord {
    pub name: String,
    pub method_idx: u32,
    pub code: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixStats {
    pub applied: usize,
    pub skipped: usize,
    pub length_mismatch: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FixOptions {
    /// If true, accept records whose hex-decoded length differs from the DEX
    /// header's `insns_size * 2`. The mismatched bytes are truncated or
    /// zero-padded — semantically dangerous but useful when the DEX header is
    /// known stale. Off by default because padding can corrupt the bytecode
    /// stream / payload alignment.
    pub force_mismatch: bool,

    /// Skip identical DEX/record pairs without deleting any input files.
    pub dedup: bool,
}

/// One non-abstract / non-native method whose bytecode we did not capture.
/// Surfaced after a fix pass so the user can tell what coverage gaps remain.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MissedMethod {
    pub method_idx: u32,
    pub code_off: u32,
    /// Pretty-printed Java-style signature, when the DEX id tables resolve.
    /// Best-effort: packers sometimes corrupt string tables, in which case we
    /// emit the method index alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Coverage of one DEX file's bytecode after fix has applied all records.
/// `total_methods` counts methods whose `code_off != 0` in the DEX
/// (abstract/native methods are excluded — there's no bytecode to capture).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CoverageReport {
    pub total_methods: usize,
    pub captured_methods: usize,
    pub missed_methods: Vec<MissedMethod>,
}

impl CoverageReport {
    pub fn ratio(&self) -> f64 {
        if self.total_methods == 0 {
            1.0
        } else {
            self.captured_methods as f64 / self.total_methods as f64
        }
    }
}

/// Combined result of fixing one DEX: bytecode-write stats plus coverage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FixOutcome {
    pub stats: FixStats,
    pub coverage: CoverageReport,
}

pub fn fix_dex_directory(output_dir: &Path) -> Result<()> {
    fix_dex_directory_with(output_dir, FixOptions::default())
}

pub fn fix_dex_directory_with(output_dir: &Path, options: FixOptions) -> Result<()> {
    let pairs = find_pairs(output_dir)?;
    let dex_files = find_root_dex_files(output_dir)?;
    if dex_files.is_empty() {
        anyhow::bail!("no dex_*.dex found in {}", output_dir.display());
    }

    let fix_dir = output_dir.join("fix");
    let final_dir = output_dir.join("final");
    fs::create_dir_all(&fix_dir)
        .with_context(|| format!("failed to create {}", fix_dir.display()))?;
    fs::create_dir_all(&final_dir)
        .with_context(|| format!("failed to create {}", final_dir.display()))?;

    let mut failures = 0;
    for (base, dex_path) in dex_files {
        if !crate::shutdown::keep_finalizing() {
            anyhow::bail!("fix interrupted; remaining files left as-is");
        }
        let final_path = final_dir.join(format!("{base}.dex"));
        let display_name = dex_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        match pairs.get(&base) {
            Some(json_path) => {
                let out_path = fix_dir.join(format!("{base}_fix.dex"));
                match fix_one_dex(&dex_path, json_path, &out_path, options) {
                    Ok(outcome) => {
                        println!(
                            "Applied: {}, Skipped: {}, LengthMismatch: {} for {display_name}",
                            outcome.stats.applied,
                            outcome.stats.skipped,
                            outcome.stats.length_mismatch,
                        );
                        let coverage = &outcome.coverage;
                        println!(
                            "Coverage: {}/{} methods ({:.2}%), {} missed for {display_name}",
                            coverage.captured_methods,
                            coverage.total_methods,
                            coverage.ratio() * 100.0,
                            coverage.missed_methods.len(),
                        );
                        copy_file(&out_path, &final_path)?;
                        if !coverage.missed_methods.is_empty() {
                            let missed_path = final_dir.join(format!("{base}_missed.json"));
                            if let Err(err) = write_coverage_report(&missed_path, coverage) {
                                failures += 1;
                                eprintln!(
                                    "[!] failed to write coverage report {}: {err:#}",
                                    missed_path.display()
                                );
                            } else {
                                println!("[+] Missed {}", missed_path.display());
                            }
                        }
                        println!("[+] Wrote {}", out_path.display());
                        println!("[+] Final {}", final_path.display());
                    }
                    Err(err) => {
                        failures += 1;
                        println!("[!] Fix failed for {}: {err:#}", dex_path.display());
                        copy_file(&dex_path, &final_path)?;
                        println!("[+] Final fallback {}", final_path.display());
                    }
                }
            }
            None => {
                copy_file(&dex_path, &final_path)?;
                println!("[+] Final original {}", final_path.display());
            }
        }
    }

    anyhow::ensure!(
        failures == 0,
        "{failures} fix/report failure(s); fallback copies are not repaired outputs"
    );
    Ok(())
}

fn write_coverage_report(path: &Path, coverage: &CoverageReport) -> Result<()> {
    let file =
        fs::File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    serde_json::to_writer_pretty(file, coverage)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn fix_one_dex(
    dex_path: &Path,
    json_path: &Path,
    out_path: &Path,
    options: FixOptions,
) -> Result<FixOutcome> {
    let mut dex_bytes =
        fs::read(dex_path).with_context(|| format!("failed to read {}", dex_path.display()))?;
    let outcome = fix_one_dex_bytes_from_json_file(&mut dex_bytes, json_path, options)?;
    fs::write(out_path, &dex_bytes)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    Ok(outcome)
}

pub fn fix_one_dex_bytes_from_json_file(
    dex_bytes: &mut [u8],
    json_path: &Path,
    options: FixOptions,
) -> Result<FixOutcome> {
    let parser = DexParser::new(dex_bytes)?;
    let method2off = build_method_code_off_map(&parser)?;
    let records = read_records(json_path)?;
    let coverage = compute_coverage(&parser, &method2off, &records);
    // `parser`'s immutable borrow of `dex_bytes` ends here under NLL, so the
    // next line's `&mut dex_bytes` is allowed.
    let _ = parser;
    let stats = apply_records_to_dex(dex_bytes, &method2off, &records, options)?;
    recalc_dex_header(dex_bytes);
    Ok(FixOutcome { stats, coverage })
}

/// Compute method-coverage statistics for a DEX given the records we captured
/// for it. Counts every method whose `code_off != 0` (i.e. has bytecode in the
/// DEX) and reports which method indices were missing from the records.
pub fn compute_coverage(
    parser: &DexParser<'_>,
    method2off: &HashMap<u32, u32>,
    records: &[MethodCodeRecord],
) -> CoverageReport {
    let captured: HashSet<u32> = records.iter().map(|r| r.method_idx).collect();
    let mut missed = Vec::new();
    let mut total = 0usize;
    for (&method_idx, &code_off) in method2off {
        if code_off == 0 {
            continue;
        }
        total += 1;
        if !captured.contains(&method_idx) {
            let signature = parser
                .get_method_info(method_idx)
                .ok()
                .map(|info| info.pretty_method());
            missed.push(MissedMethod {
                method_idx,
                code_off,
                signature,
            });
        }
    }
    missed.sort_by_key(|m| m.method_idx);
    CoverageReport {
        total_methods: total,
        captured_methods: total.saturating_sub(missed.len()),
        missed_methods: missed,
    }
}

pub fn apply_records_to_dex(
    dex_bytes: &mut [u8],
    method2off: &HashMap<u32, u32>,
    records: &[MethodCodeRecord],
    options: FixOptions,
) -> Result<FixStats> {
    let mut stats = FixStats::default();
    for record in records {
        let Some(&code_off) = method2off.get(&record.method_idx) else {
            stats.skipped += 1;
            continue;
        };
        if code_off == 0 || code_off as usize + 0x10 > dex_bytes.len() {
            stats.skipped += 1;
            continue;
        }

        let code_off = code_off as usize;
        let insns_units = le32(&dex_bytes[code_off + 0x0c..]) as usize;
        let expected_len = insns_units.saturating_mul(2);
        let code_bytes = match hex::decode(&record.code) {
            Ok(code_bytes) => code_bytes,
            Err(_) => {
                stats.skipped += 1;
                continue;
            }
        };
        let insns_start = code_off + 0x10;
        let insns_end = insns_start.saturating_add(expected_len);
        if insns_end > dex_bytes.len() {
            stats.skipped += 1;
            continue;
        }
        if code_bytes.len() != expected_len {
            stats.length_mismatch += 1;
            if !options.force_mismatch {
                stats.skipped += 1;
                continue;
            }
        }
        let write_len = expected_len.min(code_bytes.len());
        dex_bytes[insns_start..insns_start + write_len].copy_from_slice(&code_bytes[..write_len]);
        if write_len < expected_len {
            dex_bytes[insns_start + write_len..insns_end].fill(0);
        }
        stats.applied += 1;
    }
    Ok(stats)
}

pub fn build_method_code_off_map(parser: &DexParser<'_>) -> Result<HashMap<u32, u32>> {
    let mut result = HashMap::new();
    let data = parser.data();
    let header = parser.header();
    const CLASS_DEF_SIZE: usize = 32;

    for idx in 0..header.class_defs_size {
        let off = header.class_defs_off as usize + idx as usize * CLASS_DEF_SIZE;
        let class_def = data
            .get(off..off + CLASS_DEF_SIZE)
            .context("class_def out of bounds")?;
        let class_data_off = le32(&class_def[24..]);
        if class_data_off == 0 {
            continue;
        }

        let mut pos = class_data_off as usize;
        let (static_fields_size, next) = read_uleb128(data, pos)?;
        pos = next;
        let (instance_fields_size, next) = read_uleb128(data, pos)?;
        pos = next;
        let (direct_methods_size, next) = read_uleb128(data, pos)?;
        pos = next;
        let (virtual_methods_size, next) = read_uleb128(data, pos)?;
        pos = next;

        skip_fields(data, &mut pos, static_fields_size)?;
        skip_fields(data, &mut pos, instance_fields_size)?;
        read_methods(data, &mut pos, direct_methods_size, &mut result)?;
        read_methods(data, &mut pos, virtual_methods_size, &mut result)?;
    }

    Ok(result)
}

pub fn recalc_dex_header(dex: &mut [u8]) {
    if dex.len() < 32 {
        return;
    }

    let mut sha1 = Sha1::new();
    sha1.update(&dex[32..]);
    let sig = sha1.finalize();
    dex[12..32].copy_from_slice(&sig);

    let mut adler = Adler32::new();
    adler.write_slice(&dex[12..]);
    let sum = adler.checksum();
    dex[8] = sum as u8;
    dex[9] = (sum >> 8) as u8;
    dex[10] = (sum >> 16) as u8;
    dex[11] = (sum >> 24) as u8;
}

fn read_records(json_path: &Path) -> Result<Vec<MethodCodeRecord>> {
    let file = fs::File::open(json_path)
        .with_context(|| format!("failed to open {}", json_path.display()))?;
    serde_json::from_reader(file)
        .with_context(|| format!("failed to parse {}", json_path.display()))
}

fn find_pairs(output_dir: &Path) -> Result<HashMap<String, PathBuf>> {
    // JSON sidecars are written at the root of the output dir. Scanning only
    // the top level (matching find_root_dex_files) keeps us from re-ingesting
    // historical artefacts in fix/ / final/ / native_elf/ etc. on a second
    // run.
    let mut pairs = HashMap::new();
    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("failed to read {}", output_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(base) = dex_code_json_base(&name) {
            pairs.insert(base, entry.path());
        }
    }
    Ok(pairs)
}

fn find_root_dex_files(output_dir: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut dex_files = HashMap::new();
    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("failed to read {}", output_dir.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(base) = dex_file_base(&name) {
            dex_files.insert(base, entry.path());
        }
    }
    Ok(dex_files)
}

fn dex_code_json_base(name: &str) -> Option<String> {
    if !name.starts_with("dex_") || !name.ends_with("_code.json") {
        return None;
    }
    let stem = name.strip_suffix("_code.json")?;
    dex_file_base(&format!("{stem}.dex"))
}

fn dex_file_base(name: &str) -> Option<String> {
    if !name.starts_with("dex_") || !name.ends_with(".dex") {
        return None;
    }
    let stem = name.strip_suffix(".dex")?;
    // Legacy begin/size, process-qualified pid/begin/size, or quarantined
    // pid/begin/content-hash/size. All identity fields are hexadecimal.
    let parts: Vec<_> = stem.strip_prefix("dex_")?.split('_').collect();
    if (2..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        Some(stem.to_string())
    } else {
        None
    }
}

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    fs::copy(src, dst)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))?;
    Ok(())
}

fn skip_fields(data: &[u8], pos: &mut usize, count: u32) -> Result<()> {
    for _ in 0..count {
        let (_, next) = read_uleb128(data, *pos)?;
        *pos = next;
        let (_, next) = read_uleb128(data, *pos)?;
        *pos = next;
    }
    Ok(())
}

fn read_methods(
    data: &[u8],
    pos: &mut usize,
    count: u32,
    result: &mut HashMap<u32, u32>,
) -> Result<()> {
    let mut last_method = 0u32;
    for _ in 0..count {
        let (diff, next) = read_uleb128(data, *pos)?;
        *pos = next;
        last_method = last_method.saturating_add(diff);
        let (_, next) = read_uleb128(data, *pos)?;
        *pos = next;
        let (code_off, next) = read_uleb128(data, *pos)?;
        *pos = next;
        result.insert(last_method, code_off);
    }
    Ok(())
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[0..4].try_into().expect("slice length"))
}

// ---------------------------------------------------------------------------
// Structural repair
// ---------------------------------------------------------------------------

const CLASS_DEF_SIZE: usize = 32;
const CODE_ITEM_HEADER_SIZE: usize = 0x10;
/// `TYPE_MAP_LIST`. Map types above it are data-section items; those below are
/// the header and the id tables.
const MAP_TYPE_MAP_LIST: u16 = 0x1000;

const HDR_FILE_SIZE: usize = 0x20;
const HDR_MAP_OFF: usize = 0x34;
const HDR_DATA_SIZE: usize = 0x68;
const HDR_DATA_OFF: usize = 0x6c;

const ACC_STATIC: u32 = 0x0008;
const ACC_NATIVE: u32 = 0x0100;
const ACC_ABSTRACT: u32 = 0x0400;

/// What a repair pass changed in one DEX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepairStats {
    /// `file_size`, `data_off` or `data_size` disagreed with the real layout.
    pub header_fixed: bool,
    /// The map list was out of order or not at the end of the file.
    pub map_rebuilt: bool,
    /// Records written into a `code_item` that was still intact.
    pub inline_applied: usize,
    /// Methods given a freshly synthesized `code_item`.
    pub appended: usize,
    /// Methods with a record we could not turn into a `code_item`.
    pub append_failed: usize,
    /// Methods with no usable `code_item` and no record to rebuild one from.
    pub unrecovered: usize,
    /// Format fields (debug_info_off, tries_size, interfaces_off, etc.) fixed.
    pub format_fixed: bool,
    /// Bounded structural and checksum checks, not ART bytecode verification.
    pub validation_passed: bool,
    /// Methods whose bytecode record could not be decoded.
    pub bytecode_decode_failed: usize,
}

impl RepairStats {
    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.inline_applied > 0 {
            parts.push(format!("{} methods written in place", self.inline_applied));
        }
        if self.appended > 0 {
            parts.push(format!("{} code_items rebuilt", self.appended));
        }
        if self.append_failed > 0 {
            parts.push(format!("{} unusable records", self.append_failed));
        }
        if self.bytecode_decode_failed > 0 {
            parts.push(format!(
                "{} bytecode decode failures",
                self.bytecode_decode_failed
            ));
        }
        if self.unrecovered > 0 {
            parts.push(format!("{} methods still without code", self.unrecovered));
        }
        if self.header_fixed {
            parts.push("header bounds fixed".to_string());
        }
        if self.format_fixed {
            parts.push("format fields fixed".to_string());
        }
        if self.validation_passed {
            parts.push("structure/checksums OK (not ART verification)".to_string());
        } else if self.format_fixed
            || self.header_fixed
            || self.map_rebuilt
            || self.inline_applied > 0
            || self.appended > 0
        {
            parts.push("validation FAILED".to_string());
        }
        if self.map_rebuilt {
            parts.push("map rebuilt".to_string());
        }
        if parts.is_empty() {
            return "no change".to_string();
        }
        parts.join(", ")
    }
}

/// Skip only identical DEX and bytecode-record inputs; retain all originals.
fn dedup_dex_files(dex_files: &[(String, PathBuf)], records_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut seen = HashSet::new();
    let mut retained = Vec::new();
    for (base, path) in dex_files {
        let Ok(bytes) = fs::read(path) else {
            retained.push((base.clone(), path.clone()));
            continue;
        };
        let records_path = records_dir.join(format!("{base}_code.json"));
        let records = match fs::read(&records_path) {
            Ok(records) => Some(records),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => {
                retained.push((base.clone(), path.clone()));
                continue;
            }
        };
        let identity = (
            Sha1::digest(&bytes).to_vec(),
            records
                .as_ref()
                .map(|records| Sha1::digest(records).to_vec()),
        );
        if seen.insert(identity) {
            retained.push((base.clone(), path.clone()));
        } else {
            println!("[=] Duplicate input {base}: skipped; original retained");
        }
    }
    retained
}

/// Repair every `dex_*.dex` under `dex_dir`, writing results to `dex_dir/repair`.
///
/// [`fix_dex_directory_with`] only overwrites bytecode inside `code_item`s that
/// are already intact, which is all a well-formed dump needs. This pass also
/// rebuilds what a packer tears down: header bounds, the map list, and the
/// `code_item`s of methods whose code was stripped from the file and only ever
/// existed in memory. It subsumes the in-place path, so the output needs no
/// second `fix` run.
pub fn repair_directory(
    dex_dir: &Path,
    code_records_dir: Option<&Path>,
    options: FixOptions,
) -> Result<()> {
    let records_dir = code_records_dir.unwrap_or(dex_dir);
    let dex_files = find_root_dex_files(dex_dir)?;
    anyhow::ensure!(
        !dex_files.is_empty(),
        "no dex_*.dex found in {}",
        dex_dir.display()
    );
    let mut dex_files: Vec<_> = dex_files.into_iter().collect();
    dex_files.sort();
    if options.dedup {
        dex_files = dedup_dex_files(&dex_files, records_dir);
    }
    let repair_dir = dex_dir.join("repair");
    fs::create_dir_all(&repair_dir)?;
    let mut written = 0;
    let mut failures = Vec::new();
    // Bound peak memory: each repair may relocate most of its input.
    for (base, dex_path) in &dex_files {
        anyhow::ensure!(
            crate::shutdown::keep_finalizing(),
            "repair interrupted after {written} output(s)"
        );
        let result = (|| -> Result<RepairStats> {
            let json_path = records_dir.join(format!("{base}_code.json"));
            let records = match fs::read(&json_path) {
                Ok(bytes) => Some(
                    serde_json::from_slice::<Vec<MethodCodeRecord>>(&bytes)
                        .with_context(|| format!("invalid {}", json_path.display()))?,
                ),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(err).with_context(|| format!("read {}", json_path.display()))
                }
            };
            let mut bytes = fs::read(dex_path)?;
            let stats = repair_one_dex(&mut bytes, records.as_deref(), options)?;
            anyhow::ensure!(
                stats.append_failed == 0,
                "{} unusable method capture(s)",
                stats.append_failed
            );
            atomic_write(&repair_dir.join(format!("{base}.dex")), &bytes)?;
            Ok(stats)
        })();
        match result {
            Ok(stats) => {
                written += 1;
                println!("[+] {base}: {}", stats.summary());
            }
            Err(err) => {
                eprintln!("[!] {base}: {err:#}");
                failures.push(format!("{base}: {err:#}"));
            }
        }
    }
    println!(
        "[+] Repair complete: {written}/{} files written -> {}; {} failed",
        dex_files.len(),
        repair_dir.display(),
        failures.len()
    );
    anyhow::ensure!(
        failures.is_empty(),
        "{} repair failure(s): {}",
        failures.len(),
        failures.join("; ")
    );
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.with_context(|| format!("write {}", path.display()))
}

/// Repair one DEX buffer in place, reporting what changed.
fn repair_one_dex(
    dex_bytes: &mut Vec<u8>,
    records: Option<&[MethodCodeRecord]>,
    options: FixOptions,
) -> Result<RepairStats> {
    let mut stats = RepairStats::default();
    DexParser::new(dex_bytes)?;
    // Reject unreadable tables before any in-place edits or relocation.
    validate_id_bounds(dex_bytes)?;
    read_map_entries(dex_bytes)?;

    // Bytecode first: both halves of it append to the file, and the map has to
    // come after everything else.
    // Always run restore_bytecode, even without records, to zero out bad code_offs.
    let bytecode_records: &[MethodCodeRecord] = records.unwrap_or(&[]);
    let relocated = restore_bytecode(dex_bytes, bytecode_records, options, &mut stats)?;
    stats.format_fixed = fix_format_fields(dex_bytes);
    stats.map_rebuilt = rebuild_map(dex_bytes, relocated.as_deref())?;
    // Header bounds last, once the file has reached its final length.
    stats.header_fixed = fix_header_bounds(dex_bytes);

    recalc_dex_header(dex_bytes);
    validate_repaired_dex(dex_bytes)?;
    stats.validation_passed = true;
    Ok(stats)
}

/// Put every captured method body back: in place where the `code_item`
/// survived, as a freshly appended one where it did not.
///
/// Structural failures propagate; unusable individual captures are counted.
fn restore_bytecode(
    dex_bytes: &mut Vec<u8>,
    records: &[MethodCodeRecord],
    options: FixOptions,
    stats: &mut RepairStats,
) -> Result<Option<Vec<MapEntry>>> {
    let method2off = {
        let parser = match DexParser::new(dex_bytes) {
            Ok(parser) => parser,
            Err(err) => {
                eprintln!("[!] {err}");
                return Err(err.into());
            }
        };
        match build_method_code_off_map(&parser) {
            Ok(map) => map,
            Err(err) => {
                eprintln!("[!] class_data unreadable, skipping bytecode restore: {err:#}");
                return Err(err);
            }
        }
    };

    // Deliberately never force here. In `fix`, --force-mismatch truncates or
    // zero-pads a capture into a code_item that disagrees about its length,
    // because rewriting in place is all `fix` can do. Repair has a better
    // answer for that case — build a correctly sized code_item — so the
    // in-place pass is left to handle only exact fits, and everything else
    // falls through to append_missing_code_items below. That also keeps the
    // two passes disjoint no matter how the flag is set.
    let exact_fits = FixOptions {
        force_mismatch: false,
        dedup: false,
    };
    match apply_records_to_dex(dex_bytes, &method2off, records, exact_fits) {
        Ok(applied) => stats.inline_applied = applied.applied,
        Err(err) => eprintln!("[!] in-place bytecode write failed: {err:#}"),
    }

    match append_missing_code_items(dex_bytes, records, options) {
        Ok(outcome) => {
            stats.appended = outcome.appended;
            stats.append_failed = outcome.failed;
            stats.unrecovered = outcome.unrecovered;
            if let Some(reason) = outcome.first_failure {
                eprintln!("[!] {} record(s) unusable, first: {reason}", outcome.failed);
            }
            Ok(outcome.relocated)
        }
        Err(err) => Err(err.context("code_item rebuild failed")),
    }
}

#[derive(Debug, Default)]
struct AppendOutcome {
    appended: usize,
    failed: usize,
    unrecovered: usize,
    first_failure: Option<String>,
    relocated: Option<Vec<MapEntry>>,
}

/// Give every method whose `code_item` the packer stripped a new one, built
/// from its captured bytecode and appended at the end of the file.
///
/// `code_off` lives in `class_data_item` as a ULEB128 and a new offset rarely
/// encodes to the same width, so the whole `class_data_item` is re-encoded and
/// appended as well; only `class_def.class_data_off`, a fixed-width `u32`, is
/// patched in place. Retired mapped sections are zeroed after all copies;
/// ART requires the gaps between remaining sections to contain zero padding.
///
/// When any item changes, relocate all live code and class data into two
/// contiguous runs and return their replacement map entries.
fn append_missing_code_items(
    dex_bytes: &mut Vec<u8>,
    records: &[MethodCodeRecord],
    options: FixOptions,
) -> Result<AppendOutcome> {
    let mut outcome = AppendOutcome::default();
    let by_method: HashMap<u32, &MethodCodeRecord> = records
        .iter()
        .map(|record| (record.method_idx, record))
        .collect();

    // Plan every edit while the parser holds its immutable borrow, then apply
    // them once it is gone.
    let mut planned: Vec<(usize, ClassData)> = Vec::new();
    let mut needs_relocation = false;
    {
        let parser = DexParser::new(dex_bytes)?;
        let header = parser.header();
        for class_idx in 0..header.class_defs_size {
            // Offsets only grow, so the first one past the end means the rest
            // are too. Stopping here also keeps a corrupt class_defs_size from
            // spinning us through billions of empty iterations.
            let class_def = (header.class_defs_off as usize)
                .checked_add(class_idx as usize * CLASS_DEF_SIZE)
                .and_then(|off| Some((off, off.checked_add(CLASS_DEF_SIZE)?)))
                .and_then(|(off, end)| Some((off, dex_bytes.get(off..end)?)));
            let Some((class_def_off, class_def)) = class_def else {
                break;
            };
            let class_data_off = le32(&class_def[24..]);
            if class_data_off == 0 {
                continue;
            }
            let mut class_data = parse_class_data(dex_bytes, class_data_off)?;

            let mut touched = false;
            for method in class_data.methods_mut() {
                // Abstract and native methods have no bytecode to begin with,
                // so a zero code_off is correct for them.
                if method.access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0 {
                    continue;
                }
                let on_disk = code_item_insns_len(dex_bytes, method.code_off);
                if on_disk.is_some() {
                    code_item_end(dex_bytes, method.code_off)?;
                }
                let Some(record) = by_method.get(&method.method_idx) else {
                    // Nothing captured for it. Only worth reporting when the
                    // DEX has no body for it either.
                    if on_disk.is_none() {
                        outcome.unrecovered += 1;
                        method.code_off = 0;
                        touched = true;
                    }
                    continue;
                };
                // The in-place pass already wrote every capture that fits its
                // code_item exactly; those are the only ones it accepts, so
                // anything else is ours. A code_item that disagrees about its
                // length is itself the corrupt part: the capture's size came
                // from the *live* code_item ART was executing.
                if on_disk == Some(record.code.len() / 2) {
                    continue;
                }
                match synthesize_code_item(
                    &parser,
                    method.method_idx,
                    method.access_flags,
                    record,
                    options,
                ) {
                    Ok(code_item) => {
                        method.pending_code = Some(code_item);
                        touched = true;
                    }
                    Err(err) => {
                        outcome.failed += 1;
                        outcome.first_failure.get_or_insert_with(|| {
                            format!("method_idx {}: {err:#}", method.method_idx)
                        });
                    }
                }
            }
            if touched {
                needs_relocation = true;
            }
            planned.push((class_def_off, class_data));
        }
    }

    if !needs_relocation {
        return Ok(outcome);
    }
    let original_len = dex_bytes.len();
    let original_map = read_map_entries(dex_bytes)?;
    let mut retired = Vec::new();
    for entry in original_map
        .iter()
        .filter(|entry| matches!(entry.typ, 0x2000 | 0x2001))
    {
        let start = entry.off as usize;
        let end = original_map
            .iter()
            .filter(|next| next.off > entry.off)
            .map(|next| next.off as usize)
            .min()
            .unwrap_or(original_len);
        anyhow::ensure!(
            start >= DEX_HEADER_SIZE && start < end && end <= original_len,
            "invalid retired section bounds"
        );
        retired.push(start..end);
    }
    let mut code_map = MapEntry {
        typ: 0x2001,
        size: 0,
        off: 0,
    };
    for (_, class_data) in &mut planned {
        for method in class_data.methods_mut() {
            let code_item = if let Some(code) = method.pending_code.take() {
                outcome.appended += 1;
                code
            } else if method.code_off != 0 {
                let end = code_item_end(dex_bytes, method.code_off)?;
                dex_bytes[method.code_off as usize..end].to_vec()
            } else {
                continue;
            };
            align_to(dex_bytes, 4);
            let new_off = u32::try_from(dex_bytes.len())
                .context("DEX grew past 4 GiB while rebuilding code items")?;
            if code_map.size == 0 {
                code_map.off = new_off;
            }
            code_map.size += 1;
            method.code_off = new_off;
            dex_bytes.extend_from_slice(&code_item);
        }
    }
    let class_map = MapEntry {
        typ: 0x2000,
        size: u32::try_from(planned.len())?,
        off: u32::try_from(dex_bytes.len())?,
    };
    for (class_def_off, class_data) in planned {
        let encoded = encode_class_data(&class_data);
        let class_data_off = u32::try_from(dex_bytes.len())
            .context("DEX grew past 4 GiB while rebuilding class data")?;
        dex_bytes.extend_from_slice(&encoded);
        dex_bytes[class_def_off + 24..class_def_off + 28]
            .copy_from_slice(&class_data_off.to_le_bytes());
    }
    for range in retired {
        dex_bytes[range].fill(0);
    }
    outcome.relocated = Some(vec![code_map, class_map]);
    Ok(outcome)
}

/// Wrap captured `insns` in a standalone `code_item`.
///
/// The dumper records the instruction bytes and nothing else (see
/// `read_method_bytecode` in `bpf/bpf.c`), so the header has to be
/// reconstructed: `ins_size` from the method signature, `registers_size` and
/// `outs_size` by walking the stream. Exception handlers cannot be recovered —
/// they sit past `insns` in the original item and were never captured — so
/// `tries_size` is always zero and any `try`/`catch` the method had is lost.
fn synthesize_code_item(
    parser: &DexParser<'_>,
    method_idx: u32,
    access_flags: u32,
    record: &MethodCodeRecord,
    options: FixOptions,
) -> Result<Vec<u8>> {
    let insns = hex::decode(&record.code).context("bytecode is not valid hex")?;
    if insns.is_empty() {
        anyhow::bail!("record carries no bytecode");
    }
    if insns.len() % 2 != 0 {
        anyhow::bail!(
            "bytecode is {} bytes, not a whole number of code units",
            insns.len()
        );
    }

    let scan = match crate::bytecode::scan_insns(&insns) {
        Ok(scan) => scan,
        // A capture the eBPF side had to clamp stops decoding partway through.
        // Without --force-mismatch, drop the method rather than emit a header
        // whose register window is a guess.
        Err(partial) if options.force_mismatch => partial.scan,
        Err(partial) => return Err(anyhow::anyhow!("{}", partial.error)),
    };

    let ins_size = incoming_words(parser, method_idx, access_flags)?;
    // Parameters occupy the top `ins_size` registers, so the window has to
    // cover them even when the body never reads one.
    let registers_size = scan.registers_used.max(ins_size);
    let insns_units = u32::try_from(insns.len() / 2)
        .context("bytecode is longer than a code_item can address")?;

    let mut item = Vec::with_capacity(CODE_ITEM_HEADER_SIZE + insns.len());
    item.extend_from_slice(&registers_size.to_le_bytes());
    item.extend_from_slice(&ins_size.to_le_bytes());
    item.extend_from_slice(&scan.outs_size.to_le_bytes());
    item.extend_from_slice(&0u16.to_le_bytes()); // tries_size
    item.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
    item.extend_from_slice(&insns_units.to_le_bytes());
    item.extend_from_slice(&insns);
    Ok(item)
}

/// Registers the caller passes in: one per parameter, two for `long` and
/// `double`, plus `this` unless the method is static.
fn incoming_words(parser: &DexParser<'_>, method_idx: u32, access_flags: u32) -> Result<u16> {
    let info = parser.get_method_info(method_idx)?;
    let mut words = u32::from(access_flags & ACC_STATIC == 0);
    for parameter in &info.parameters {
        words += if parameter == "J" || parameter == "D" {
            2
        } else {
            1
        };
    }
    u16::try_from(words).context("signature needs more than 65535 registers")
}

/// Length in bytes of the `insns` array of the `code_item` at `code_off`, when
/// one is wholly inside the file. `None` means there is nothing usable there —
/// a nulled offset, one pointing past the end, or a declared `insns_size` that
/// runs off the end.
///
/// These are exactly the conditions [`apply_records_to_dex`] uses to skip a
/// method, so comparing the result against a capture's length tells us whether
/// the in-place pass has already dealt with it.
fn code_item_insns_len(dex_bytes: &[u8], code_off: u32) -> Option<usize> {
    if code_off == 0 {
        return None;
    }
    let off = code_off as usize;
    let header = dex_bytes.get(off..off.checked_add(CODE_ITEM_HEADER_SIZE)?)?;
    let insns_bytes = (le32(&header[0x0c..]) as usize).checked_mul(2)?;
    let end = off
        .checked_add(CODE_ITEM_HEADER_SIZE)?
        .checked_add(insns_bytes)?;
    (end <= dex_bytes.len()).then_some(insns_bytes)
}

/// One `encoded_field` of a `class_data_item`.
#[derive(Clone, Debug)]
struct EncodedField {
    field_idx: u32,
    access_flags: u32,
}

/// One `encoded_method` of a `class_data_item`.
#[derive(Clone, Debug)]
struct EncodedMethod {
    method_idx: u32,
    access_flags: u32,
    code_off: u32,
    /// A `code_item` to append for this method, when the packer left the DEX
    /// without a usable one. Filled in while planning, consumed while writing.
    pending_code: Option<Vec<u8>>,
}

/// A parsed `class_data_item`, ready to be re-encoded after `code_off` edits.
#[derive(Clone, Debug)]
struct ClassData {
    static_fields: Vec<EncodedField>,
    instance_fields: Vec<EncodedField>,
    direct_methods: Vec<EncodedMethod>,
    virtual_methods: Vec<EncodedMethod>,
}

impl ClassData {
    fn methods_mut(&mut self) -> impl Iterator<Item = &mut EncodedMethod> {
        self.direct_methods
            .iter_mut()
            .chain(self.virtual_methods.iter_mut())
    }
}

fn take_uleb(data: &[u8], pos: &mut usize) -> Result<u32> {
    let (value, next) = read_uleb128(data, *pos)?;
    *pos = next;
    Ok(value)
}

fn read_encoded_fields(data: &[u8], pos: &mut usize, count: u32) -> Result<Vec<EncodedField>> {
    // `count` comes straight off disk, so grow on demand rather than reserving
    // up front — a corrupt count would otherwise ask for gigabytes.
    let mut fields = Vec::new();
    let mut field_idx = 0u32;
    for _ in 0..count {
        field_idx = field_idx.saturating_add(take_uleb(data, pos)?);
        let access_flags = take_uleb(data, pos)?;
        fields.push(EncodedField {
            field_idx,
            access_flags,
        });
    }
    Ok(fields)
}

fn read_encoded_methods(data: &[u8], pos: &mut usize, count: u32) -> Result<Vec<EncodedMethod>> {
    let mut methods = Vec::new();
    let mut method_idx = 0u32;
    for _ in 0..count {
        method_idx = method_idx.saturating_add(take_uleb(data, pos)?);
        let access_flags = take_uleb(data, pos)?;
        let code_off = take_uleb(data, pos)?;
        methods.push(EncodedMethod {
            method_idx,
            access_flags,
            code_off,
            pending_code: None,
        });
    }
    Ok(methods)
}

fn parse_class_data(dex_bytes: &[u8], class_data_off: u32) -> Result<ClassData> {
    Ok(parse_class_data_end(dex_bytes, class_data_off)?.0)
}

fn parse_class_data_end(dex_bytes: &[u8], class_data_off: u32) -> Result<(ClassData, usize)> {
    let mut pos = class_data_off as usize;
    let static_count = take_uleb(dex_bytes, &mut pos)?;
    let instance_count = take_uleb(dex_bytes, &mut pos)?;
    let direct_count = take_uleb(dex_bytes, &mut pos)?;
    let virtual_count = take_uleb(dex_bytes, &mut pos)?;

    let class = ClassData {
        static_fields: read_encoded_fields(dex_bytes, &mut pos, static_count)?,
        instance_fields: read_encoded_fields(dex_bytes, &mut pos, instance_count)?,
        direct_methods: read_encoded_methods(dex_bytes, &mut pos, direct_count)?,
        virtual_methods: read_encoded_methods(dex_bytes, &mut pos, virtual_count)?,
    };
    Ok((class, pos))
}

/// Re-encode a `class_data_item`. Indices are stored as deltas and each of the
/// four lists restarts its delta at zero.
fn encode_class_data(class_data: &ClassData) -> Vec<u8> {
    let mut buf = Vec::new();
    push_uleb(&mut buf, class_data.static_fields.len() as u32);
    push_uleb(&mut buf, class_data.instance_fields.len() as u32);
    push_uleb(&mut buf, class_data.direct_methods.len() as u32);
    push_uleb(&mut buf, class_data.virtual_methods.len() as u32);

    for fields in [&class_data.static_fields, &class_data.instance_fields] {
        let mut previous = 0u32;
        for field in fields {
            push_uleb(&mut buf, field.field_idx.saturating_sub(previous));
            push_uleb(&mut buf, field.access_flags);
            previous = field.field_idx;
        }
    }
    for methods in [&class_data.direct_methods, &class_data.virtual_methods] {
        let mut previous = 0u32;
        for method in methods {
            push_uleb(&mut buf, method.method_idx.saturating_sub(previous));
            push_uleb(&mut buf, method.access_flags);
            push_uleb(&mut buf, method.code_off);
            previous = method.method_idx;
        }
    }
    buf
}

fn push_uleb(buf: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            return;
        }
    }
}

/// Pad `buf` with zeros until its length is a multiple of `align`.
fn align_to(buf: &mut Vec<u8>, align: usize) {
    let remainder = buf.len() % align;
    if remainder != 0 {
        buf.resize(buf.len() + (align - remainder), 0);
    }
}

/// Little-endian `u32` at `off`, or `None` when it would read past the end.
fn read_u32_at(data: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    data.get(off..end).map(le32)
}

/// Sort the map list by offset and move it to the end of the file.
///
/// Returns false when the map is already in shape, or when `map_off` does not
/// point at a readable table — a packer that aims it into nowhere leaves
/// nothing to rebuild from, and inventing a map wholesale would be guesswork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MapEntry {
    typ: u16,
    size: u32,
    off: u32,
}

fn read_map_entries(bytes: &[u8]) -> Result<Vec<MapEntry>> {
    let off = read_u32_at(bytes, HDR_MAP_OFF).context("missing map_off")? as usize;
    anyhow::ensure!(
        off >= DEX_HEADER_SIZE && off.is_multiple_of(4),
        "invalid map_off"
    );
    let count = read_u32_at(bytes, off).context("unreadable map list")? as usize;
    let end = off
        .checked_add(4)
        .and_then(|p| count.checked_mul(12).and_then(|n| p.checked_add(n)))
        .context("map list overflow")?;
    anyhow::ensure!(count != 0 && end <= bytes.len(), "map list out of bounds");
    let mut types = HashSet::new();
    let mut entries = Vec::new();
    for i in 0..count {
        let at = off + 4 + i * 12;
        let entry = MapEntry {
            typ: u16::from_le_bytes([bytes[at], bytes[at + 1]]),
            size: le32(&bytes[at + 4..]),
            off: le32(&bytes[at + 8..]),
        };
        anyhow::ensure!(
            types.insert(entry.typ),
            "duplicate map type 0x{:x}",
            entry.typ
        );
        anyhow::ensure!(
            entry.size != 0 && (entry.off as usize) < bytes.len(),
            "map item out of bounds"
        );
        entries.push(entry);
    }
    Ok(entries)
}

fn rebuild_map(dex_bytes: &mut Vec<u8>, relocated: Option<&[MapEntry]>) -> Result<bool> {
    let mut entries = read_map_entries(dex_bytes)?;
    let old_map_off = le32(&dex_bytes[HDR_MAP_OFF..]) as usize;
    let old_map_end = old_map_off + 4 + entries.len() * 12;
    anyhow::ensure!(
        !entries.iter().any(|entry| entry.typ != MAP_TYPE_MAP_LIST
            && (old_map_off..old_map_end).contains(&(entry.off as usize))),
        "map overlaps another section"
    );
    if let Some(replacements) = relocated {
        for replacement in replacements {
            entries.retain(|entry| entry.typ != replacement.typ);
            if replacement.size != 0 {
                entries.push(*replacement);
            }
        }
    }
    let map_off = le32(&dex_bytes[HDR_MAP_OFF..]);
    let ordered = entries.windows(2).all(|pair| pair[0].off < pair[1].off);
    let last = entries.last().is_some_and(|entry| {
        entry.typ == MAP_TYPE_MAP_LIST && entry.off == map_off && entry.size == 1
    });
    if relocated.is_none()
        && ordered
        && last
        && map_off as usize + 4 + entries.len() * 12 == dex_bytes.len()
    {
        return Ok(false);
    }
    align_to(dex_bytes, 4);
    let new_off = u32::try_from(dex_bytes.len())?;
    entries.retain(|entry| entry.typ != MAP_TYPE_MAP_LIST);
    entries.push(MapEntry {
        typ: MAP_TYPE_MAP_LIST,
        size: 1,
        off: new_off,
    });
    entries.sort_by_key(|entry| entry.off);
    dex_bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        dex_bytes.extend_from_slice(&entry.typ.to_le_bytes());
        dex_bytes.extend_from_slice(&0u16.to_le_bytes());
        dex_bytes.extend_from_slice(&entry.size.to_le_bytes());
        dex_bytes.extend_from_slice(&entry.off.to_le_bytes());
    }
    dex_bytes[HDR_MAP_OFF..HDR_MAP_OFF + 4].copy_from_slice(&new_off.to_le_bytes());
    dex_bytes[old_map_off..old_map_end].fill(0);
    Ok(true)
}

/// Locate the complete code_item, including padding, tries and handlers.
fn code_item_end(bytes: &[u8], off: u32) -> Result<usize> {
    let start = off as usize;
    anyhow::ensure!(off != 0 && off.is_multiple_of(4), "unaligned code_item");
    let insns_len = code_item_insns_len(bytes, off).context("code_item out of bounds")?;
    let insns_units = insns_len / 2;
    let mut pos = start + CODE_ITEM_HEADER_SIZE + insns_len;
    let tries = u16::from_le_bytes([bytes[start + 6], bytes[start + 7]]) as usize;
    if tries == 0 {
        return Ok(pos);
    }
    pos = pos.checked_add(3).context("code_item overflow")? & !3;
    let tries_start = pos;
    pos = pos.checked_add(tries * 8).context("try table overflow")?;
    anyhow::ensure!(pos < bytes.len(), "try table out of bounds");
    let handlers_start = pos;
    let count = take_uleb(bytes, &mut pos)?;
    let mut handler_offsets = HashSet::new();
    for _ in 0..count {
        handler_offsets.insert(pos - handlers_start);
        let size = take_sleb(bytes, &mut pos)?;
        for _ in 0..size.unsigned_abs() {
            take_uleb(bytes, &mut pos)?; // type_idx is checked separately by ART.
            let addr = take_uleb(bytes, &mut pos)?;
            anyhow::ensure!(
                (addr as usize) < insns_units,
                "handler address out of bounds"
            );
        }
        if size <= 0 {
            let addr = take_uleb(bytes, &mut pos)?;
            anyhow::ensure!(
                (addr as usize) < insns_units,
                "catch-all address out of bounds"
            );
        }
    }
    for i in 0..tries {
        let at = tries_start + i * 8;
        let begin = le32(&bytes[at..]) as usize;
        let count = u16::from_le_bytes([bytes[at + 4], bytes[at + 5]]) as usize;
        let handler = u16::from_le_bytes([bytes[at + 6], bytes[at + 7]]) as usize;
        anyhow::ensure!(
            begin + count <= insns_units && handler_offsets.contains(&handler),
            "invalid try item"
        );
    }
    Ok(pos)
}

fn take_sleb(bytes: &[u8], pos: &mut usize) -> Result<i32> {
    let mut value = 0i64;
    for i in 0..5 {
        let byte = *bytes.get(*pos).context("truncated SLEB128")?;
        *pos += 1;
        value |= i64::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 {
                value |= !0i64 << ((i + 1) * 7);
            }
            return i32::try_from(value).context("SLEB128 overflow");
        }
    }
    anyhow::bail!("invalid SLEB128")
}

fn validate_id_bounds(bytes: &[u8]) -> Result<()> {
    let header = crate::dex::DexHeader::parse(bytes)?;
    anyhow::ensure!(
        header.header_size == DEX_HEADER_SIZE as u32,
        "unsupported DEX header size"
    );
    anyhow::ensure!(
        header.endian_tag == 0x1234_5678,
        "unsupported DEX endian tag"
    );
    let mut spans = Vec::new();
    for (count, off, width) in [
        (header.string_ids_size, header.string_ids_off, 4usize),
        (header.type_ids_size, header.type_ids_off, 4),
        (header.proto_ids_size, header.proto_ids_off, 12),
        (header.field_ids_size, header.field_ids_off, 8),
        (header.method_ids_size, header.method_ids_off, 8),
        (
            header.class_defs_size,
            header.class_defs_off,
            CLASS_DEF_SIZE,
        ),
    ] {
        if count == 0 {
            continue;
        }
        let end = (off as usize)
            .checked_add(
                (count as usize)
                    .checked_mul(width)
                    .context("id table overflow")?,
            )
            .context("id table overflow")?;
        anyhow::ensure!(
            off as usize >= DEX_HEADER_SIZE && off % 4 == 0 && end <= bytes.len(),
            "id table out of bounds"
        );
        spans.push((off as usize, end));
    }
    spans.sort_unstable();
    anyhow::ensure!(
        spans.windows(2).all(|p| p[0].1 <= p[1].0),
        "overlapping id tables"
    );
    Ok(())
}

/// These checks cover repaired structures, not full bytecode semantics.
fn validate_repaired_dex(bytes: &[u8]) -> Result<()> {
    validate_id_bounds(bytes)?;
    let parser = DexParser::new(bytes)?;
    let header = parser.header();
    anyhow::ensure!(
        header.file_size as usize == bytes.len(),
        "file_size mismatch"
    );
    anyhow::ensure!(
        header.data_off as usize >= DEX_HEADER_SIZE
            && header.data_off as usize + header.data_size as usize == bytes.len(),
        "data bounds mismatch"
    );
    anyhow::ensure!(
        header.signature.as_slice() == Sha1::digest(&bytes[32..]).as_slice(),
        "signature mismatch"
    );
    let mut adler = Adler32::new();
    adler.write_slice(&bytes[12..]);
    anyhow::ensure!(header.checksum == adler.checksum(), "checksum mismatch");
    let entries = read_map_entries(bytes)?;
    anyhow::ensure!(
        entries.windows(2).all(|p| p[0].off < p[1].off),
        "unordered map"
    );
    anyhow::ensure!(
        entries
            .iter()
            .any(|e| e.typ == MAP_TYPE_MAP_LIST && e.off == header.map_off && e.size == 1),
        "map self-entry mismatch"
    );
    let mut classes = HashSet::new();
    let mut codes = HashSet::new();
    for i in 0..header.class_defs_size as usize {
        let at = header.class_defs_off as usize + i * CLASS_DEF_SIZE;
        let off = le32(&bytes[at + 24..]);
        if off == 0 {
            continue;
        }
        classes.insert(off);
        let mut class = parse_class_data(bytes, off)?;
        for method in class.methods_mut() {
            anyhow::ensure!(
                method.method_idx < header.method_ids_size,
                "method index out of bounds"
            );
            if method.code_off != 0 {
                code_item_end(bytes, method.code_off)?;
                codes.insert(method.code_off);
            }
        }
    }
    for (typ, offsets) in [(0x2000, classes), (0x2001, codes)] {
        if let Some(entry) = entries.iter().find(|entry| entry.typ == typ) {
            anyhow::ensure!(
                entry.size as usize == offsets.len() && offsets.iter().min() == Some(&entry.off),
                "live item/map mismatch for 0x{typ:x}"
            );
            let mut ordered: Vec<_> = offsets.into_iter().collect();
            ordered.sort_unstable();
            let mut pos = entry.off as usize;
            for off in ordered {
                if typ == 0x2001 {
                    pos = (pos + 3) & !3;
                }
                anyhow::ensure!(off as usize == pos, "noncontiguous map run for 0x{typ:x}");
                pos = if typ == 0x2001 {
                    code_item_end(bytes, off)?
                } else {
                    parse_class_data_end(bytes, off)?.1
                };
            }
            let next = entries
                .iter()
                .filter(|other| other.off > entry.off)
                .map(|other| other.off as usize)
                .min()
                .unwrap_or(bytes.len());
            anyhow::ensure!(pos <= next, "overlapping map run for 0x{typ:x}");
        } else {
            anyhow::ensure!(offsets.is_empty(), "missing live item map for 0x{typ:x}");
        }
    }
    Ok(())
}

/// Bring `file_size`, `data_off` and `data_size` back in line with the real
/// layout. `data_off` is derived from where `class_defs` ends, which is where
/// the data section starts in a well-formed DEX.
fn fix_header_bounds(dex_bytes: &mut [u8]) -> bool {
    let Ok(header) = crate::dex::DexHeader::parse(dex_bytes) else {
        return false;
    };
    let tables_end = [
        (header.string_ids_off, header.string_ids_size, 4usize),
        (header.type_ids_off, header.type_ids_size, 4),
        (header.proto_ids_off, header.proto_ids_size, 12),
        (header.field_ids_off, header.field_ids_size, 8),
        (header.method_ids_off, header.method_ids_size, 8),
        (
            header.class_defs_off,
            header.class_defs_size,
            CLASS_DEF_SIZE,
        ),
    ]
    .into_iter()
    .filter(|(_, count, _)| *count != 0)
    .map(|(off, count, width)| {
        (off as usize).saturating_add((count as usize).saturating_mul(width))
    })
    .max()
    .unwrap_or(DEX_HEADER_SIZE);
    let Some(data_off) = tables_end.checked_add(3).map(|end| end & !3) else {
        return false;
    };
    // A class_defs table claiming to end past EOF tells us nothing usable.
    if data_off > dex_bytes.len() {
        return false;
    }
    let (Ok(file_size), Ok(data_off), Ok(data_size)) = (
        u32::try_from(dex_bytes.len()),
        u32::try_from(data_off),
        u32::try_from(dex_bytes.len() - data_off),
    ) else {
        return false;
    };

    let mut changed = false;
    for (offset, value) in [
        (HDR_FILE_SIZE, file_size),
        (HDR_DATA_SIZE, data_size),
        (HDR_DATA_OFF, data_off),
    ] {
        if dex_bytes[offset..offset + 4] != value.to_le_bytes() {
            dex_bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            changed = true;
        }
    }
    changed
}

/// Fix general DEX format issues: zero out fields that point past the end of
/// the file. Packer-stripped data (debug info, annotations, try/catch, etc.)
/// often leaves stale offsets that crash analysis tools. Setting them to 0 is
/// always valid — the DEX spec defines 0 as "absent" for every field here.
fn fix_format_fields(dex_bytes: &mut [u8]) -> bool {
    let len = dex_bytes.len();
    let Ok(header) = crate::dex::DexHeader::parse(dex_bytes) else {
        return false;
    };
    let mut changed = false;

    // --- class_def fields ---
    for i in 0..header.class_defs_size {
        let Some(off) = (header.class_defs_off as usize).checked_add(i as usize * 32) else {
            break;
        };
        if off + 32 > len {
            break;
        }
        let interfaces_off = le32(&dex_bytes[off + 0x0c..]);
        let annotations_off = le32(&dex_bytes[off + 0x14..]);
        let static_values_off = le32(&dex_bytes[off + 0x1c..]);
        if interfaces_off != 0 && interfaces_off as usize >= len {
            dex_bytes[off + 0x0c..off + 0x10].copy_from_slice(&0u32.to_le_bytes());
            changed = true;
        }
        if annotations_off != 0 && annotations_off as usize >= len {
            dex_bytes[off + 0x14..off + 0x18].copy_from_slice(&0u32.to_le_bytes());
            changed = true;
        }
        if static_values_off != 0 && static_values_off as usize >= len {
            dex_bytes[off + 0x1c..off + 0x20].copy_from_slice(&0u32.to_le_bytes());
            changed = true;
        }
    }

    // --- code_item fields ---
    for i in 0..header.class_defs_size {
        let Some(cd_off) = (header.class_defs_off as usize).checked_add(i as usize * 32) else {
            break;
        };
        if cd_off + 32 > len {
            break;
        }
        let class_data_off = le32(&dex_bytes[cd_off + 24..]);
        if class_data_off == 0 || class_data_off as usize >= len {
            continue;
        }
        let Ok(mut class_data) = parse_class_data(dex_bytes, class_data_off) else {
            continue;
        };
        for method in class_data.methods_mut() {
            let co = method.code_off as usize;
            if co == 0 || co + 0x10 > len {
                continue;
            }
            // debug_info_off @ +0x08
            let dio = le32(&dex_bytes[co + 0x08..]);
            if dio != 0 && dio as usize >= len {
                dex_bytes[co + 0x08..co + 0x0c].copy_from_slice(&0u32.to_le_bytes());
                changed = true;
            }
            // tries_size @ +0x06
            let tries = u16::from_le_bytes([dex_bytes[co + 0x06], dex_bytes[co + 0x07]]);
            if tries > 0 {
                let insns_units = le32(&dex_bytes[co + 0x0c..]) as usize;
                let insns_bytes = insns_units.saturating_mul(2);
                let try_data_off = co + 0x10 + insns_bytes;
                let try_data_off = try_data_off.saturating_add(3) & !3;
                let try_end = try_data_off.saturating_add(tries as usize * 8);
                if try_end > len {
                    dex_bytes[co + 0x06..co + 0x08].copy_from_slice(&0u16.to_le_bytes());
                    changed = true;
                }
            }
        }
    }

    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_code_json_base() {
        assert_eq!(
            dex_code_json_base("dex_1234_abcd_code.json").as_deref(),
            Some("dex_1234_abcd")
        );
        assert!(dex_code_json_base("dex_1234_nope_code.json").is_none());
        assert!(dex_code_json_base("not_dex_1234_abcd_code.json").is_none());
    }

    #[test]
    fn parses_dex_file_base() {
        assert_eq!(
            dex_file_base("dex_1234_abcd.dex").as_deref(),
            Some("dex_1234_abcd")
        );
        assert!(dex_file_base("dex_1234_nope.dex").is_none());
        assert!(dex_file_base("dex_1234_abcd_fix.dex").is_none());
        assert!(dex_file_base("not_dex_1234_abcd.dex").is_none());
    }

    #[test]
    fn fix_directory_writes_final_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let fixed_base = "dex_1000_b0";
        let original_base = "dex_2000_b0";

        let fixed_dex_path = dir.path().join(format!("{fixed_base}.dex"));
        let original_dex_path = dir.path().join(format!("{original_base}.dex"));
        let json_path = dir.path().join(format!("{fixed_base}_code.json"));

        fs::write(&fixed_dex_path, minimal_dex_with_code_item()).unwrap();
        fs::write(&original_dex_path, minimal_dex_with_code_item()).unwrap();
        fs::write(
            &json_path,
            r#"[{"name":"void Lx;.m()","method_idx":0,"code":"01020304"}]"#,
        )
        .unwrap();

        fix_dex_directory(dir.path()).unwrap();

        let fixed_final =
            fs::read(dir.path().join("final").join(format!("{fixed_base}.dex"))).unwrap();
        let original_final = fs::read(
            dir.path()
                .join("final")
                .join(format!("{original_base}.dex")),
        )
        .unwrap();
        let fixed_copy =
            fs::read(dir.path().join("fix").join(format!("{fixed_base}_fix.dex"))).unwrap();

        assert_eq!(&fixed_final[0xa0..0xa4], &[1, 2, 3, 4]);
        assert_eq!(fixed_final, fixed_copy);
        assert_eq!(original_final, fs::read(original_dex_path).unwrap());
    }

    #[test]
    fn coverage_reports_missed_methods() {
        let dex = minimal_dex_with_code_item();
        let parser = DexParser::new(&dex).unwrap();
        let map = build_method_code_off_map(&parser).unwrap();

        // No records — the lone method with code_off should appear as missed.
        let report = compute_coverage(&parser, &map, &[]);
        assert_eq!(report.total_methods, 1);
        assert_eq!(report.captured_methods, 0);
        assert_eq!(report.missed_methods.len(), 1);
        assert_eq!(report.missed_methods[0].method_idx, 0);
        assert_eq!(report.missed_methods[0].code_off, 0x90);
        // The fixture has zero string/method ids, so signature resolution
        // should fail gracefully and emit None.
        assert_eq!(report.missed_methods[0].signature, None);

        // With a record covering method_idx 0, coverage hits 100%.
        let records = vec![MethodCodeRecord {
            name: "void Lx;.m()".to_string(),
            method_idx: 0,
            code: "01020304".to_string(),
        }];
        let report = compute_coverage(&parser, &map, &records);
        assert_eq!(report.total_methods, 1);
        assert_eq!(report.captured_methods, 1);
        assert!(report.missed_methods.is_empty());
        assert_eq!(report.ratio(), 1.0);
    }

    #[test]
    fn fix_directory_writes_missed_report_only_when_needed() {
        let dir = tempfile::tempdir().unwrap();
        let base = "dex_4000_b0";

        let dex_path = dir.path().join(format!("{base}.dex"));
        let json_path = dir.path().join(format!("{base}_code.json"));
        fs::write(&dex_path, minimal_dex_with_code_item()).unwrap();
        // Empty records → 1 method, 0 captured, 1 missed → missed.json must
        // be produced.
        fs::write(&json_path, "[]").unwrap();

        fix_dex_directory(dir.path()).unwrap();

        let missed_path = dir.path().join("final").join(format!("{base}_missed.json"));
        let raw = fs::read_to_string(&missed_path).unwrap();
        let report: CoverageReport = serde_json::from_str(&raw).unwrap();
        assert_eq!(report.total_methods, 1);
        assert_eq!(report.captured_methods, 0);
        assert_eq!(report.missed_methods.len(), 1);
        assert_eq!(report.missed_methods[0].method_idx, 0);
    }

    #[test]
    fn fix_directory_skips_missed_report_at_full_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let base = "dex_5000_b0";

        let dex_path = dir.path().join(format!("{base}.dex"));
        let json_path = dir.path().join(format!("{base}_code.json"));
        fs::write(&dex_path, minimal_dex_with_code_item()).unwrap();
        fs::write(
            &json_path,
            r#"[{"name":"void Lx;.m()","method_idx":0,"code":"01020304"}]"#,
        )
        .unwrap();

        fix_dex_directory(dir.path()).unwrap();

        let missed_path = dir.path().join("final").join(format!("{base}_missed.json"));
        assert!(
            !missed_path.exists(),
            "no missed.json should be written at 100% coverage"
        );
    }

    #[test]
    fn fix_ignores_json_in_derived_subdirs() {
        // Re-running fix against an output dir that already has fix/ and
        // final/ subdirs from a previous pass must not re-ingest the JSON
        // sidecars from those subdirs.
        let dir = tempfile::tempdir().unwrap();
        let base = "dex_3000_b0";

        let dex_path = dir.path().join(format!("{base}.dex"));
        fs::write(&dex_path, minimal_dex_with_code_item()).unwrap();

        // Stale JSON nested under fix/ that must be ignored.
        let stale_dir = dir.path().join("fix");
        fs::create_dir_all(&stale_dir).unwrap();
        fs::write(
            stale_dir.join(format!("{base}_code.json")),
            r#"[{"name":"void Lx;.m()","method_idx":0,"code":"deadbeef"}]"#,
        )
        .unwrap();

        // No JSON at root → fix must treat the DEX as unchanged.
        fix_dex_directory(dir.path()).unwrap();

        let final_bytes = fs::read(dir.path().join("final").join(format!("{base}.dex"))).unwrap();
        // The original DEX bytecode region is zero; if the stale JSON had
        // been picked up, bytes at 0xa0..0xa4 would be 0xde 0xad 0xbe 0xef.
        assert_eq!(&final_bytes[0xa0..0xa4], &[0, 0, 0, 0]);
    }

    #[test]
    fn applies_code_record_and_recalculates_header() {
        let mut dex = minimal_dex_with_code_item();
        let parser = DexParser::new(&dex).unwrap();
        let map = build_method_code_off_map(&parser).unwrap();
        assert_eq!(map.get(&0), Some(&0x90));

        let records = vec![MethodCodeRecord {
            name: "void Lx;.m()".to_string(),
            method_idx: 0,
            code: "01020304".to_string(),
        }];
        let stats = apply_records_to_dex(&mut dex, &map, &records, FixOptions::default()).unwrap();
        assert_eq!(
            stats,
            FixStats {
                applied: 1,
                skipped: 0,
                length_mismatch: 0
            }
        );
        assert_eq!(&dex[0xa0..0xa4], &[1, 2, 3, 4]);

        recalc_dex_header(&mut dex);
        assert_ne!(&dex[12..32], &[0u8; 20]);
        assert_ne!(&dex[8..12], &[0u8; 4]);
    }

    #[test]
    fn length_mismatch_skipped_by_default() {
        let mut dex = minimal_dex_with_code_item();
        let parser = DexParser::new(&dex).unwrap();
        let map = build_method_code_off_map(&parser).unwrap();

        // Record carries 6 bytes but code_item.insns_size says 2 units = 4 bytes.
        let records = vec![MethodCodeRecord {
            name: "void Lx;.m()".to_string(),
            method_idx: 0,
            code: "010203040506".to_string(),
        }];
        let stats = apply_records_to_dex(&mut dex, &map, &records, FixOptions::default()).unwrap();
        assert_eq!(
            stats,
            FixStats {
                applied: 0,
                skipped: 1,
                length_mismatch: 1
            }
        );
        // The bytecode region should be untouched (still zero from the fixture).
        assert_eq!(&dex[0xa0..0xa4], &[0, 0, 0, 0]);
    }

    #[test]
    fn length_mismatch_applied_with_force_flag() {
        let mut dex = minimal_dex_with_code_item();
        let parser = DexParser::new(&dex).unwrap();
        let map = build_method_code_off_map(&parser).unwrap();

        let records = vec![MethodCodeRecord {
            name: "void Lx;.m()".to_string(),
            method_idx: 0,
            code: "010203040506".to_string(),
        }];
        let opts = FixOptions {
            force_mismatch: true,
            dedup: false,
        };
        let stats = apply_records_to_dex(&mut dex, &map, &records, opts).unwrap();
        assert_eq!(
            stats,
            FixStats {
                applied: 1,
                skipped: 0,
                length_mismatch: 1
            }
        );
        // 4 bytes were written (truncated to expected_len).
        assert_eq!(&dex[0xa0..0xa4], &[1, 2, 3, 4]);
    }

    fn minimal_dex_with_code_item() -> Vec<u8> {
        let mut dex = vec![0u8; 0xb0];
        let dex_len = dex.len() as u32;
        dex[0..8].copy_from_slice(b"dex\n035\0");
        put_u32(&mut dex, 32, dex_len);
        put_u32(&mut dex, 36, DEX_HEADER_SIZE as u32);
        put_u32(&mut dex, 96, 1);
        put_u32(&mut dex, 100, 0x70);

        // class_def_item.class_data_off at +24.
        put_u32(&mut dex, 0x70 + 24, 0x80);

        // class_data_item: 0 static, 0 instance, 1 direct, 0 virtual.
        dex[0x80] = 0;
        dex[0x81] = 0;
        dex[0x82] = 1;
        dex[0x83] = 0;
        // encoded_method: method_idx_diff=0, access_flags=0, code_off=0x90.
        dex[0x84] = 0;
        dex[0x85] = 0;
        dex[0x86] = 0x90 | 0x80;
        dex[0x87] = 0x01;

        // code_item.insns_size at +0x0c. Two code units = four bytes.
        put_u32(&mut dex, 0x90 + 0x0c, 2);
        dex
    }

    fn put_u32(data: &mut [u8], off: usize, value: u32) {
        data[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    // -- repair -------------------------------------------------------------

    /// `const/4 v9, #0 ; return-void` — touches v9, so a correct header has to
    /// declare at least ten registers.
    const V9_BODY: &str = "12090e00";

    fn record(code: &str) -> Vec<MethodCodeRecord> {
        vec![MethodCodeRecord {
            name: "void Lx;.a(long)".to_string(),
            method_idx: 0,
            code: code.to_string(),
        }]
    }

    /// A DEX with real id tables, one class, and one public instance method
    /// `Lx;.a(J)V` whose `code_off` is whatever the caller asks for.
    ///
    /// The signature matters: `this` plus a `long` means `ins_size` must come
    /// out as 3, which only happens if the proto is actually resolved.
    fn dex_with_method(code_off: u32) -> Vec<u8> {
        const STRINGS: [&str; 4] = ["V", "Lx;", "a", "J"];
        let string_ids_off = DEX_HEADER_SIZE;
        let type_ids_off = string_ids_off + STRINGS.len() * 4;
        let proto_ids_off = type_ids_off + 3 * 4;
        let method_ids_off = proto_ids_off + 12;
        let class_defs_off = method_ids_off + 8;

        let mut dex = vec![0u8; class_defs_off + CLASS_DEF_SIZE];
        dex[0..8].copy_from_slice(b"dex\n035\0");

        // type_list holding the single `J` parameter; 4-byte aligned.
        let type_list_off = dex.len();
        dex.extend_from_slice(&1u32.to_le_bytes());
        dex.extend_from_slice(&2u16.to_le_bytes()); // type_ids[2] == "J"

        let mut string_data_offs = Vec::new();
        for text in STRINGS {
            string_data_offs.push(dex.len() as u32);
            dex.push(text.len() as u8); // utf16_size, single-byte ULEB128 here
            dex.extend_from_slice(text.as_bytes());
            dex.push(0);
        }

        let class_data_off = dex.len();
        dex.extend_from_slice(&[0, 0, 1, 0]); // static, instance, direct, virtual
        dex.push(0); // method_idx_diff
        dex.push(0x01); // access_flags: public, non-static
        push_uleb(&mut dex, code_off);

        align_to(&mut dex, 4);
        let map_off = dex.len();
        dex.extend_from_slice(&2u32.to_le_bytes());
        dex.extend_from_slice(&0x2000u16.to_le_bytes());
        dex.extend_from_slice(&0u16.to_le_bytes());
        dex.extend_from_slice(&1u32.to_le_bytes());
        dex.extend_from_slice(&(class_data_off as u32).to_le_bytes());
        dex.extend_from_slice(&MAP_TYPE_MAP_LIST.to_le_bytes());
        dex.extend_from_slice(&0u16.to_le_bytes());
        dex.extend_from_slice(&1u32.to_le_bytes());
        dex.extend_from_slice(&(map_off as u32).to_le_bytes());

        for (i, off) in string_data_offs.iter().enumerate() {
            put_u32(&mut dex, string_ids_off + i * 4, *off);
        }
        for (i, string_idx) in [0u32, 1, 3].iter().enumerate() {
            put_u32(&mut dex, type_ids_off + i * 4, *string_idx);
        }
        put_u32(&mut dex, proto_ids_off, 0); // shorty_idx
        put_u32(&mut dex, proto_ids_off + 4, 0); // return_type_idx -> V
        put_u32(&mut dex, proto_ids_off + 8, type_list_off as u32);
        dex[method_ids_off..method_ids_off + 2].copy_from_slice(&1u16.to_le_bytes()); // class Lx;
        dex[method_ids_off + 2..method_ids_off + 4].copy_from_slice(&0u16.to_le_bytes());
        put_u32(&mut dex, method_ids_off + 4, 2); // name_idx -> "a"
        put_u32(&mut dex, class_defs_off, 1); // class_idx -> Lx;
        put_u32(&mut dex, class_defs_off + 24, class_data_off as u32);

        let file_size = dex.len() as u32;
        put_u32(&mut dex, HDR_FILE_SIZE, file_size);
        put_u32(&mut dex, 0x24, DEX_HEADER_SIZE as u32);
        put_u32(&mut dex, 0x28, 0x1234_5678);
        put_u32(&mut dex, HDR_MAP_OFF, map_off as u32);
        put_u32(&mut dex, 0x38, STRINGS.len() as u32);
        put_u32(&mut dex, 0x3c, string_ids_off as u32);
        put_u32(&mut dex, 0x40, 3);
        put_u32(&mut dex, 0x44, type_ids_off as u32);
        put_u32(&mut dex, 0x48, 1);
        put_u32(&mut dex, 0x4c, proto_ids_off as u32);
        put_u32(&mut dex, 0x58, 1);
        put_u32(&mut dex, 0x5c, method_ids_off as u32);
        put_u32(&mut dex, 0x60, 1);
        put_u32(&mut dex, 0x64, class_defs_off as u32);
        dex
    }

    /// A DEX whose lone method points at a real, in-bounds `code_item`
    /// declaring `insns_units` code units of (zeroed) bytecode.
    fn dex_with_intact_code_item(insns_units: u32) -> (Vec<u8>, u32) {
        let mut dex = dex_with_method(0);
        align_to(&mut dex, 4);
        let code_off = dex.len() as u32;
        let mut item = vec![0u8; CODE_ITEM_HEADER_SIZE];
        item[0..2].copy_from_slice(&10u16.to_le_bytes()); // registers_size
        item[12..16].copy_from_slice(&insns_units.to_le_bytes());
        item.resize(CODE_ITEM_HEADER_SIZE + insns_units as usize * 2, 0);
        dex.extend_from_slice(&item);

        let class_data_off = le32(&dex[0xa0 + 24..]);
        let mut class_data = parse_class_data(&dex, class_data_off).unwrap();
        class_data.direct_methods[0].code_off = code_off;
        let encoded = encode_class_data(&class_data);
        let new_off = dex.len() as u32;
        dex.extend_from_slice(&encoded);
        put_u32(&mut dex, 0xa0 + 24, new_off);
        rebuild_map(
            &mut dex,
            Some(&[
                MapEntry {
                    typ: 0x2001,
                    size: 1,
                    off: code_off,
                },
                MapEntry {
                    typ: 0x2000,
                    size: 1,
                    off: new_off,
                },
            ]),
        )
        .unwrap();
        (dex, code_off)
    }

    /// Follow class_def -> class_data to read the lone method's `code_off`.
    fn method_code_off(dex: &[u8]) -> u32 {
        let header = crate::dex::DexHeader::parse(dex).unwrap();
        let class_data_off = le32(&dex[header.class_defs_off as usize + 24..]);
        parse_class_data(dex, class_data_off)
            .unwrap()
            .direct_methods[0]
            .code_off
    }

    fn assert_recovered_body(dex: &[u8]) {
        let code_off = method_code_off(dex);
        assert_ne!(code_off, 0, "method should have been given a code_item");
        assert_eq!(code_off % 4, 0, "code_item must be 4-byte aligned");

        let item = &dex[code_off as usize..];
        // The body reads v9, so the window has to span v0..=v9.
        assert_eq!(u16::from_le_bytes(item[0..2].try_into().unwrap()), 10);
        // `this` plus one long parameter.
        assert_eq!(u16::from_le_bytes(item[2..4].try_into().unwrap()), 3);
        assert_eq!(u16::from_le_bytes(item[4..6].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(item[6..8].try_into().unwrap()), 0);
        assert_eq!(le32(&item[12..]), 2, "insns_size in code units");
        assert_eq!(&item[16..20], &[0x12, 0x09, 0x0e, 0x00]);
    }

    #[test]
    fn repair_rebuilds_a_code_item_the_packer_nulled() {
        let mut dex = dex_with_method(0);
        let stats =
            repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).unwrap();
        assert_eq!(stats.appended, 1);
        assert_eq!(stats.inline_applied, 0);
        assert_eq!(stats.append_failed, 0);
        assert_recovered_body(&dex);
    }

    #[test]
    fn repair_rebuilds_a_code_item_pointing_out_of_bounds() {
        let mut dex = dex_with_method(0x7fff_ffff);
        let stats =
            repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).unwrap();
        assert_eq!(stats.appended, 1);
        assert_recovered_body(&dex);
    }

    #[test]
    fn repair_reports_methods_it_has_no_record_for() {
        let mut dex = dex_with_method(0);
        let stats = repair_one_dex(&mut dex, Some(&record("")), FixOptions::default()).unwrap();
        assert_eq!(stats.appended, 0);
        assert_eq!(stats.append_failed, 1, "empty record cannot be synthesized");
        assert_eq!(method_code_off(&dex), 0, "code_off must stay untouched");
    }

    #[test]
    fn repair_refuses_bytecode_that_does_not_decode() {
        // return-void, then 0x73 — an opcode the DEX spec leaves unused.
        let mut dex = dex_with_method(0);
        let stats =
            repair_one_dex(&mut dex, Some(&record("0e007300")), FixOptions::default()).unwrap();
        assert_eq!(stats.appended, 0);
        assert_eq!(stats.append_failed, 1);
        assert_eq!(method_code_off(&dex), 0);
    }

    #[test]
    fn force_mismatch_rebuilds_from_a_clamped_capture() {
        let mut dex = dex_with_method(0);
        let options = FixOptions {
            force_mismatch: true,
            dedup: false,
        };
        let stats = repair_one_dex(&mut dex, Some(&record("0e007300")), options).unwrap();
        assert_eq!(stats.appended, 1);
        let item = &dex[method_code_off(&dex) as usize..];
        // The walk stopped before naming a register, so the parameter window
        // alone decides registers_size.
        assert_eq!(u16::from_le_bytes(item[0..2].try_into().unwrap()), 3);
    }

    #[test]
    fn repair_leaves_an_intact_code_item_to_the_in_place_path() {
        let (mut dex, code_off) = dex_with_intact_code_item(2);
        let stats =
            repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).unwrap();
        assert_eq!(stats.inline_applied, 1, "fix's path should have taken it");
        assert_eq!(stats.appended, 0, "and it must not be appended twice");
        assert_eq!(method_code_off(&dex), code_off);
        assert_eq!(
            &dex[code_off as usize + 16..code_off as usize + 20],
            &[0x12, 0x09, 0x0e, 0x00]
        );
    }

    #[test]
    fn repair_rebuilds_when_the_on_disk_insns_size_is_stale() {
        // The code_item claims two code units; the capture carries four. The
        // capture is ground truth — the eBPF side reads insns_size off the
        // *live* code_item — so the on-disk header is the stale one and the
        // method has to be rebuilt rather than dropped.
        let (mut dex, stale_off) = dex_with_intact_code_item(2);
        // const/4 v9 ; const/4 v8 ; return-void ; nop
        let body = record("120912080e000000");
        let stats = repair_one_dex(&mut dex, Some(&body), FixOptions::default()).unwrap();

        assert_eq!(stats.inline_applied, 0, "it does not fit the old item");
        assert_eq!(stats.appended, 1, "so it must get a new one");
        let code_off = method_code_off(&dex);
        assert_ne!(code_off, stale_off, "code_off must move to the new item");
        let item = &dex[code_off as usize..];
        assert_eq!(le32(&item[12..]), 4, "insns_size follows the capture");
        assert_eq!(
            &item[16..24],
            &[0x12, 0x09, 0x12, 0x08, 0x0e, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn force_mismatch_does_not_divert_a_stale_code_item_in_place() {
        // `fix` would take the flag as licence to truncate or pad the capture
        // into the old item. Repair must still rebuild instead, or the method
        // gets handled twice and the in-place copy is silently wrong.
        let (mut dex, stale_off) = dex_with_intact_code_item(2);
        let options = FixOptions {
            force_mismatch: true,
            dedup: false,
        };
        let stats = repair_one_dex(&mut dex, Some(&record("120912080e000000")), options).unwrap();
        assert_eq!(stats.inline_applied, 0);
        assert_eq!(stats.appended, 1);
        assert_ne!(method_code_off(&dex), stale_off);
    }

    #[test]
    fn repair_ignores_abstract_and_native_methods() {
        let mut dex = dex_with_method(0);
        // Rewrite access_flags to ACC_PUBLIC | ACC_ABSTRACT.
        let class_data_off = le32(&dex[0xa0 + 24..]) as usize;
        dex[class_data_off + 5] = 0x01 | 0x04; // ULEB128 for 0x0400 >> 7 is two bytes
        let mut class_data = parse_class_data(&dex, class_data_off as u32).unwrap();
        class_data.direct_methods[0].access_flags = 0x0401;
        let encoded = encode_class_data(&class_data);
        let new_off = dex.len() as u32;
        dex.extend_from_slice(&encoded);
        put_u32(&mut dex, 0xa0 + 24, new_off);

        rebuild_map(
            &mut dex,
            Some(&[MapEntry {
                typ: 0x2000,
                size: 1,
                off: new_off,
            }]),
        )
        .unwrap();
        let stats =
            repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).unwrap();
        assert_eq!(stats.appended, 0);
        assert_eq!(
            stats.unrecovered, 0,
            "abstract methods are not missing code"
        );
    }

    #[test]
    fn repair_moves_the_map_list_to_the_end() {
        let mut dex = dex_with_method(0);
        repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).unwrap();

        let map_off = le32(&dex[HDR_MAP_OFF..]) as usize;
        let count = le32(&dex[map_off..]) as usize;
        assert_eq!(map_off + 4 + count * 12, dex.len(), "map must end the file");
        let mut offsets: Vec<u32> = (0..count)
            .map(|i| le32(&dex[map_off + 4 + i * 12 + 8..]))
            .collect();
        assert!(offsets.iter().all(|&off| off <= map_off as u32));
        let sorted = {
            offsets.sort_unstable();
            offsets.clone()
        };
        let actual: Vec<u32> = (0..count)
            .map(|i| le32(&dex[map_off + 4 + i * 12 + 8..]))
            .collect();
        assert_eq!(actual, sorted, "entries must be in offset order");
    }

    #[test]
    fn repair_fixes_header_bounds() {
        let mut dex = dex_with_method(0);
        put_u32(&mut dex, HDR_DATA_OFF, 0xdead);
        put_u32(&mut dex, HDR_DATA_SIZE, 0xbeef);
        let stats = repair_one_dex(&mut dex, None, FixOptions::default()).unwrap();
        assert!(stats.header_fixed);
        // class_defs sit at 0xa0 and are 32 bytes, so the data section is 0xc0.
        assert_eq!(le32(&dex[HDR_DATA_OFF..]), 0xc0);
        assert_eq!(le32(&dex[HDR_DATA_SIZE..]), dex.len() as u32 - 0xc0);
        assert_eq!(le32(&dex[HDR_FILE_SIZE..]), dex.len() as u32);
    }

    #[test]
    fn repair_rejects_an_unreadable_map_before_mutation() {
        let mut dex = dex_with_method(0);
        put_u32(&mut dex, HDR_MAP_OFF, 0);
        let original = dex.clone();
        assert!(repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).is_err());
        assert_eq!(dex, original);
    }

    #[test]
    fn repair_rejects_class_defs_pointing_past_the_end() {
        let mut dex = dex_with_method(0);
        put_u32(&mut dex, 0x64, 0x10_0000);
        let original = dex.clone();
        assert!(repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).is_err());
        assert_eq!(dex, original);
    }

    #[test]
    fn repair_directory_writes_into_the_repair_subdir() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("dex_1000_b0.dex"), dex_with_method(0)).unwrap();
        fs::write(
            dir.path().join("dex_1000_b0_code.json"),
            format!(r#"[{{"name":"void Lx;.a(long)","method_idx":0,"code":"{V9_BODY}"}}]"#),
        )
        .unwrap();

        repair_directory(dir.path(), None, FixOptions::default()).unwrap();

        let out = fs::read(dir.path().join("repair").join("dex_1000_b0.dex")).unwrap();
        assert_recovered_body(&out);
    }

    #[test]
    fn accepts_process_and_quarantine_names_alongside_legacy_names() {
        for base in ["dex_1000_70", "dex_65_1000_70", "dex_65_1000_aabbcc_70"] {
            assert_eq!(dex_file_base(&format!("{base}.dex")).as_deref(), Some(base));
            assert_eq!(
                dex_code_json_base(&format!("{base}_code.json")).as_deref(),
                Some(base)
            );
        }
        assert!(dex_file_base("dex_65__70.dex").is_none());
    }

    #[test]
    fn dedup_preserves_equal_size_distinct_dexes_and_distinct_records() {
        let dir = tempfile::tempdir().unwrap();
        let inputs: Vec<_> = (1..=4)
            .map(|i| {
                let base = format!("dex_{i}_70");
                let path = dir.path().join(format!("{base}.dex"));
                fs::write(
                    &path,
                    if i == 2 {
                        b"different".as_slice()
                    } else {
                        b"identical".as_slice()
                    },
                )
                .unwrap();
                (base, path)
            })
            .collect();
        fs::write(dir.path().join("dex_3_70_code.json"), "[]").unwrap();
        let kept = dedup_dex_files(&inputs, dir.path());
        assert_eq!(kept.len(), 3);
        assert!(inputs.iter().all(|(_, path)| path.is_file()));
    }

    #[test]
    fn repair_returns_error_but_keeps_successful_outputs_and_originals() {
        let dir = tempfile::tempdir().unwrap();
        let good = dex_with_method(0);
        fs::write(dir.path().join("dex_1_70.dex"), &good).unwrap();
        fs::write(dir.path().join("dex_2_70.dex"), b"invalid").unwrap();
        let result = repair_directory(dir.path(), None, FixOptions::default());
        assert!(result.is_err());
        assert!(dir.path().join("repair/dex_1_70.dex").is_file());
        assert!(!dir.path().join("repair/dex_2_70.dex").exists());
        assert_eq!(fs::read(dir.path().join("dex_1_70.dex")).unwrap(), good);
    }

    #[test]
    fn malformed_records_do_not_replace_previous_output() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("dex_1_70.dex"), dex_with_method(0)).unwrap();
        fs::write(dir.path().join("dex_1_70_code.json"), "not json").unwrap();
        fs::create_dir(dir.path().join("repair")).unwrap();
        let output = dir.path().join("repair/dex_1_70.dex");
        fs::write(&output, b"previous").unwrap();
        assert!(repair_directory(dir.path(), None, FixOptions::default()).is_err());
        assert_eq!(fs::read(output).unwrap(), b"previous");
    }

    #[test]
    fn output_write_failure_is_not_reported_as_success() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("dex_1_70.dex"), dex_with_method(0)).unwrap();
        fs::create_dir_all(dir.path().join("repair/dex_1_70.dex")).unwrap();
        assert!(repair_directory(dir.path(), None, FixOptions::default()).is_err());
        assert_eq!(fs::read_dir(dir.path().join("repair")).unwrap().count(), 1);
    }

    #[test]
    fn structural_validation_rejects_bad_checksums_and_map_counts() {
        let mut dex = dex_with_method(0);
        repair_one_dex(&mut dex, Some(&record(V9_BODY)), FixOptions::default()).unwrap();
        validate_repaired_dex(&dex).unwrap();
        let mut bad = dex.clone();
        bad[8] ^= 1;
        assert!(validate_repaired_dex(&bad)
            .unwrap_err()
            .to_string()
            .contains("checksum"));
        let mut bad = dex.clone();
        bad[12] ^= 1;
        assert!(validate_repaired_dex(&bad)
            .unwrap_err()
            .to_string()
            .contains("signature"));
        let map = le32(&dex[HDR_MAP_OFF..]) as usize;
        let entries = read_map_entries(&dex).unwrap();
        let index = entries.iter().position(|e| e.typ == 0x2001).unwrap();
        put_u32(&mut dex, map + 4 + index * 12 + 4, 99);
        recalc_dex_header(&mut dex);
        assert!(validate_repaired_dex(&dex)
            .unwrap_err()
            .to_string()
            .contains("map mismatch"));
    }

    #[test]
    fn fix_fallback_keeps_original_but_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let original = minimal_dex_with_code_item();
        fs::write(dir.path().join("dex_1_70.dex"), &original).unwrap();
        fs::write(dir.path().join("dex_1_70_code.json"), "invalid").unwrap();
        assert!(fix_dex_directory(dir.path()).is_err());
        assert_eq!(
            fs::read(dir.path().join("final/dex_1_70.dex")).unwrap(),
            original
        );
    }

    #[test]
    fn full_code_item_length_preserves_handlers_and_rejects_truncation() {
        let mut bytes = vec![0; 4];
        let start = bytes.len() as u32;
        bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0]);
        bytes.extend_from_slice(&[0x12, 0, 0x0e, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0, 2, 0, 1, 0]);
        // One handler, catch-all only, at code-unit address one.
        bytes.extend_from_slice(&[1, 0, 1]);
        assert_eq!(code_item_end(&bytes, start).unwrap(), bytes.len());
        bytes.pop();
        assert!(code_item_end(&bytes, start).is_err());
    }

    #[test]
    fn relocation_groups_all_classes_and_preserves_intact_try_handlers() {
        // Two classes and methods, sharing a void/no-argument prototype.
        let mut dex = vec![0; 0xec];
        dex[..8].copy_from_slice(b"dex\n035\0");
        put_u32(&mut dex, 0x24, 0x70);
        put_u32(&mut dex, 0x28, 0x1234_5678);
        for (size_at, count, off) in [
            (0x38, 5, 0x70),
            (0x40, 3, 0x84),
            (0x48, 1, 0x90),
            (0x58, 2, 0x9c),
            (0x60, 2, 0xac),
        ] {
            put_u32(&mut dex, size_at, count);
            put_u32(&mut dex, size_at + 4, off);
        }
        for (i, text) in ["V", "Lx;", "Ly;", "a", "b"].iter().enumerate() {
            let off = dex.len() as u32;
            put_u32(&mut dex, 0x70 + i * 4, off);
            dex.push(text.len() as u8);
            dex.extend_from_slice(text.as_bytes());
            dex.push(0);
        }
        for i in 0..3 {
            put_u32(&mut dex, 0x84 + i * 4, i as u32);
        }
        for i in 0..2 {
            dex[0x9c + i * 8..0x9e + i * 8].copy_from_slice(&(i as u16 + 1).to_le_bytes());
            put_u32(&mut dex, 0xa0 + i * 8, i as u32 + 3);
            put_u32(&mut dex, 0xac + i * 32, i as u32 + 1);
        }
        align_to(&mut dex, 4);
        let intact_off = dex.len() as u32;
        let intact = [
            1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0x12, 0, 0x0e, 0, 0, 0, 0, 0, 2, 0, 1,
            0, 1, 0, 1,
        ];
        dex.extend_from_slice(&intact);
        let debug_off = dex.len() as u32;
        let debug_data = [1, 0, 0];
        dex.extend_from_slice(&debug_data);
        let class_start = dex.len() as u32;
        for i in 0..2 {
            let off = dex.len() as u32;
            put_u32(&mut dex, 0xac + i * 32 + 24, off);
            dex.extend_from_slice(&[0, 0, 1, 0, i as u8, 9]);
            push_uleb(&mut dex, if i == 0 { 0 } else { intact_off });
        }
        align_to(&mut dex, 4);
        let map_off = dex.len() as u32;
        put_u32(&mut dex, HDR_MAP_OFF, map_off);
        dex.extend_from_slice(&4u32.to_le_bytes());
        for entry in [
            MapEntry {
                typ: 0x2001,
                size: 1,
                off: intact_off,
            },
            MapEntry {
                typ: 0x2003,
                size: 1,
                off: debug_off,
            },
            MapEntry {
                typ: 0x2000,
                size: 2,
                off: class_start,
            },
            MapEntry {
                typ: MAP_TYPE_MAP_LIST,
                size: 1,
                off: map_off,
            },
        ] {
            dex.extend_from_slice(&entry.typ.to_le_bytes());
            dex.extend_from_slice(&0u16.to_le_bytes());
            dex.extend_from_slice(&entry.size.to_le_bytes());
            dex.extend_from_slice(&entry.off.to_le_bytes());
        }
        let original_len = dex.len();
        let stats = repair_one_dex(&mut dex, Some(&record("0e00")), FixOptions::default()).unwrap();
        assert!(dex[intact_off as usize..debug_off as usize]
            .iter()
            .all(|&byte| byte == 0));
        assert_eq!(&dex[debug_off as usize..class_start as usize], &debug_data);
        assert!(dex[class_start as usize..original_len]
            .iter()
            .all(|&byte| byte == 0));
        assert_eq!(stats.appended, 1);
        let entries = read_map_entries(&dex).unwrap();
        assert_eq!(entries.iter().find(|e| e.typ == 0x2001).unwrap().size, 2);
        assert_eq!(entries.iter().find(|e| e.typ == 0x2000).unwrap().size, 2);
        let class_off = le32(&dex[0xcc + 24..]);
        let class = parse_class_data(&dex, class_off).unwrap();
        let off = class.direct_methods[0].code_off;
        assert_ne!(off, intact_off);
        assert_eq!(
            &dex[off as usize..code_item_end(&dex, off).unwrap()],
            &intact
        );
        validate_repaired_dex(&dex).unwrap();
    }

    #[test]
    fn moving_map_zeros_the_retired_table() {
        let mut dex = dex_with_method(0);
        let old_off = le32(&dex[HDR_MAP_OFF..]) as usize;
        let old_end = dex.len();
        dex.extend_from_slice(&[0; 4]);
        assert!(rebuild_map(&mut dex, None).unwrap());
        assert!(dex[old_off..old_end].iter().all(|&byte| byte == 0));
        assert!(read_map_entries(&dex).is_ok());
    }
}
