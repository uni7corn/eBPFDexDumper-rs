use crate::dex::{read_uleb128, DexParser};
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

    for (base, dex_path) in dex_files {
        if !crate::shutdown::keep_finalizing() {
            eprintln!("[!] auto-fix aborted by user; remaining files left as-is");
            break;
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
    let mut parts = stem.split('_');
    if parts.next()? != "dex" {
        return None;
    }
    let begin = parts.next()?;
    let size = parts.next()?;
    if parts.next().is_some() || begin.is_empty() || size.is_empty() {
        return None;
    }
    if begin.bytes().all(|b| b.is_ascii_hexdigit()) && size.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(stem.to_string())
    } else {
        None
    }
}

fn dex_file_base(name: &str) -> Option<String> {
    if !name.starts_with("dex_") || !name.ends_with(".dex") {
        return None;
    }
    let stem = name.strip_suffix(".dex")?;
    let mut parts = stem.split('_');
    if parts.next()? != "dex" {
        return None;
    }
    let begin = parts.next()?;
    let size = parts.next()?;
    if parts.next().is_some() || begin.is_empty() || size.is_empty() {
        return None;
    }
    if begin.bytes().all(|b| b.is_ascii_hexdigit()) && size.bytes().all(|b| b.is_ascii_hexdigit()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::DEX_HEADER_SIZE;

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
}
