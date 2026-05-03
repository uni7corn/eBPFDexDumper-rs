use anyhow::{Context, Result};
use goblin::elf::{program_header, Elf};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtOffsets {
    pub execute: u64,
    pub execute_nterp: u64,
    pub verify_class: u64,
}

pub fn find_art_offsets(
    libart_path: &Path,
    manual_execute_offset: Option<u64>,
    manual_nterp_offset: Option<u64>,
) -> Result<ArtOffsets> {
    let bytes = fs::read(libart_path)
        .with_context(|| format!("failed to read {}", libart_path.display()))?;
    let elf = Elf::parse(&bytes).context("failed to parse ELF")?;
    let sym_map = parse_libart_symbols(&elf);

    let mut execute = manual_execute_offset.unwrap_or(0);
    let mut execute_nterp = manual_nterp_offset.unwrap_or(0);
    let mut verify_class = 0;

    for (name, value) in sym_map {
        if execute == 0
            && name.contains("3art")
            && name.contains("11interpreter")
            && name.contains("7Execute")
        {
            execute = value;
            continue;
        }
        if execute_nterp == 0 && name == "ExecuteNterpImpl" {
            execute_nterp = value;
            continue;
        }
        if verify_class == 0
            && name.contains("3art")
            && name.contains("8verifier")
            && name.contains("13ClassVerifier")
            && name.contains("11VerifyClass")
        {
            verify_class = value;
        }
    }

    if execute == 0 {
        match find_execute_by_interpreting_string(&elf, &bytes) {
            Ok(addr) => {
                execute = addr;
                println!("[+] Execute found by 'Interpreting ' string at 0x{execute:x}");
            }
            Err(err) => println!("[-] Execute not found by symbol or string reference: {err:#}"),
        }
    }

    if execute_nterp == 0 {
        let nterp_sig = [
            0xf0, 0x0b, 0x40, 0xd1, 0x1f, 0x02, 0x40, 0xb9, 0xff, 0x83, 0x02, 0xd1, 0xe8, 0x27,
            0x00, 0x6d, 0xea, 0x2f, 0x01, 0x6d, 0xec, 0x37, 0x02, 0x6d, 0xee, 0x3f, 0x03, 0x6d,
            0xf3, 0x53, 0x04, 0xa9, 0xf5, 0x5b, 0x05, 0xa9, 0xf7, 0x63, 0x06, 0xa9, 0xf9, 0x6b,
            0x07, 0xa9, 0xfb, 0x73, 0x08, 0xa9, 0xfd, 0x7b, 0x09, 0xa9, 0x16, 0x08, 0x40, 0xf9,
        ];
        match find_pattern_uaddrs(&elf, &bytes, &nterp_sig) {
            Ok(addrs) if !addrs.is_empty() => {
                execute_nterp = addrs[0];
                if addrs.len() > 1 {
                    println!(
                        "[!] ExecuteNterpImpl signature matched {} sites; using first: 0x{execute_nterp:x}",
                        addrs.len()
                    );
                } else {
                    println!("[+] ExecuteNterpImpl found by signature at 0x{execute_nterp:x}");
                }
            }
            Ok(_) => println!("[-] ExecuteNterpImpl not found by symbol or signature"),
            Err(err) => println!("[-] ExecuteNterpImpl not found by symbol or signature: {err:#}"),
        }
    }

    if execute == 0 || execute_nterp == 0 || verify_class == 0 {
        anyhow::bail!(
            "failed to parse libart.so offsets (Execute={execute:x}, Nterp={execute_nterp:x}, VerifyClass={verify_class:x})"
        );
    }

    Ok(ArtOffsets {
        execute,
        execute_nterp,
        verify_class,
    })
}

pub fn parse_libart_symbols(elf: &Elf<'_>) -> HashMap<String, u64> {
    let mut out = HashMap::new();

    for sym in elf.syms.iter() {
        if sym.st_value == 0 {
            continue;
        }
        if let Some(name) = elf
            .strtab
            .get_at(sym.st_name)
            .filter(|name| is_target_art_symbol(name))
        {
            out.insert(name.to_string(), sym.st_value);
        }
    }

    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 {
            continue;
        }
        if let Some(name) = elf
            .dynstrtab
            .get_at(sym.st_name)
            .filter(|name| is_target_art_symbol(name))
        {
            out.insert(name.to_string(), sym.st_value);
        }
    }

    out
}

fn is_target_art_symbol(name: &str) -> bool {
    (name.contains("3art") && name.contains("11interpreter") && name.contains("7Execute"))
        || name == "ExecuteNterpImpl"
        || (name.contains("3art")
            && name.contains("8verifier")
            && name.contains("13ClassVerifier")
            && name.contains("11VerifyClass"))
}

pub fn find_pattern_uaddrs(elf: &Elf<'_>, bytes: &[u8], pattern: &[u8]) -> Result<Vec<u64>> {
    if pattern.is_empty() {
        anyhow::bail!("pattern is empty");
    }

    let mut addrs = Vec::new();
    let mut seen = BTreeSet::new();
    for ph in executable_load_segments(elf) {
        let data = segment_data(bytes, ph)?;
        if data.len() < pattern.len() {
            continue;
        }
        let mut off = 0usize;
        while off + pattern.len() <= data.len() {
            let Some(idx) = find_subslice(&data[off..], pattern) else {
                break;
            };
            let seg_off = off + idx;
            let uaddr = ph.p_vaddr + seg_off as u64;
            if seen.insert(uaddr) {
                addrs.push(uaddr);
            }
            off = seg_off + 1;
        }
    }

    if addrs.is_empty() {
        anyhow::bail!("pattern not found");
    }
    Ok(addrs)
}

fn find_execute_by_interpreting_string(elf: &Elf<'_>, bytes: &[u8]) -> Result<u64> {
    let str_addr = find_string_in_elf(elf, bytes, b"Interpreting ")
        .context("failed to find 'Interpreting ' string")?;
    println!("[+] Found 'Interpreting ' string at 0x{str_addr:x}");

    let (code_vaddr, code_data) = executable_load_segments(elf)
        .find_map(|ph| segment_data(bytes, ph).ok().map(|data| (ph.p_vaddr, data)))
        .context("code segment not found")?;

    let mut ref_addrs = Vec::new();
    for i in (0..code_data.len().saturating_sub(8)).step_by(4) {
        let pc = code_vaddr + i as u64;
        let inst = read_inst(code_data, i);
        if (inst & 0x9f00_0000) == 0x9000_0000 {
            let immlo = (inst >> 29) & 0x3;
            let immhi = (inst >> 5) & 0x7ffff;
            let mut imm = (((immhi << 2) | immlo) as i64) << 12;
            if (imm & (1 << 32)) != 0 {
                imm |= !0i64 << 33;
            }
            let page_addr = (pc & !0xfff).wrapping_add(imm as u64);
            let next_inst = read_inst(code_data, i + 4);
            if (next_inst & 0xffc0_0000) == 0x9100_0000 {
                let imm12 = (next_inst >> 10) & 0xfff;
                if page_addr + imm12 as u64 == str_addr {
                    ref_addrs.push(pc);
                }
            }
        }

        if (inst & 0x9f00_0000) == 0x1000_0000 {
            let immlo = (inst >> 29) & 0x3;
            let immhi = (inst >> 5) & 0x7ffff;
            let mut imm = ((immhi << 2) | immlo) as i64;
            if (imm & (1 << 20)) != 0 {
                imm |= !0i64 << 21;
            }
            if pc.wrapping_add(imm as u64) == str_addr {
                ref_addrs.push(pc);
            }
        }
    }

    if ref_addrs.is_empty() {
        anyhow::bail!("no code references to 'Interpreting ' string found");
    }
    println!(
        "[+] Found {} references to 'Interpreting ' string",
        ref_addrs.len()
    );

    for ref_addr in ref_addrs {
        let Some(func_addr) = find_function_entry(code_data, code_vaddr, ref_addr) else {
            continue;
        };
        if check_for_6th_parameter(code_data, code_vaddr, func_addr) {
            println!("[+] Execute function found at 0x{func_addr:x} (6 parameters, uses W5)");
            return Ok(func_addr);
        }
    }

    anyhow::bail!("Execute function not found (no 6-parameter function found)")
}

fn find_string_in_elf(elf: &Elf<'_>, bytes: &[u8], target: &[u8]) -> Result<u64> {
    for ph in elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == program_header::PT_LOAD)
    {
        let data = segment_data(bytes, ph)?;
        if let Some(idx) = find_subslice(data, target) {
            return Ok(ph.p_vaddr + idx as u64);
        }
    }
    anyhow::bail!("string {:?} not found", String::from_utf8_lossy(target))
}

fn find_function_entry(code_data: &[u8], code_vaddr: u64, ref_addr: u64) -> Option<u64> {
    if ref_addr < code_vaddr {
        return None;
    }
    let start_off = (ref_addr - code_vaddr) as usize;
    let max_search = start_off.min(0x2000);
    let mut off = start_off;
    while off >= start_off - max_search {
        if off + 4 > code_data.len() {
            return None;
        }
        let inst = read_inst(code_data, off);
        if (inst & 0xffc0_03ff) == 0xd100_03ff {
            let imm12 = (inst >> 10) & 0xfff;
            if (0x20..=0x400).contains(&imm12) {
                return Some(code_vaddr + off as u64);
            }
        }
        if (inst & 0xffc0_7fff) == 0xa980_7bfd {
            return Some(code_vaddr + off as u64);
        }
        if off < 4 {
            break;
        }
        off -= 4;
    }
    None
}

fn check_for_6th_parameter(code_data: &[u8], code_vaddr: u64, func_addr: u64) -> bool {
    if func_addr < code_vaddr {
        return false;
    }
    let start_off = (func_addr - code_vaddr) as usize;
    let check_len = (code_data.len().saturating_sub(start_off)).min(200);
    for off in (start_off..start_off + check_len).step_by(4) {
        if off + 4 > code_data.len() {
            break;
        }
        let inst = read_inst(code_data, off);
        if (inst & 0x7f00_0000) == 0x3600_0000 || (inst & 0x7f00_0000) == 0x3700_0000 {
            let rt = inst & 0x1f;
            let b5 = (inst >> 31) & 1;
            if rt == 5 && b5 == 0 {
                return true;
            }
        }
    }
    false
}

fn executable_load_segments<'a>(
    elf: &'a Elf<'a>,
) -> impl Iterator<Item = &'a goblin::elf::program_header::ProgramHeader> + 'a {
    elf.program_headers.iter().filter(|ph| {
        ph.p_type == program_header::PT_LOAD && (ph.p_flags & program_header::PF_X) != 0
    })
}

fn segment_data<'a>(
    bytes: &'a [u8],
    ph: &goblin::elf::program_header::ProgramHeader,
) -> Result<&'a [u8]> {
    let start = ph.p_offset as usize;
    let end = start
        .checked_add(ph.p_filesz as usize)
        .context("segment size overflow")?;
    bytes
        .get(start..end)
        .with_context(|| format!("segment out of bounds at file offset 0x{:x}", ph.p_offset))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_inst(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().expect("instruction slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_function_entry_from_sub_sp_prologue() {
        let mut code = vec![0u8; 0x100];
        let prologue = 0xd100_83ffu32;
        code[0x20..0x24].copy_from_slice(&prologue.to_le_bytes());
        assert_eq!(find_function_entry(&code, 0x1000, 0x1060), Some(0x1020));
    }

    #[test]
    fn detects_w5_tbz_or_tbnz() {
        let mut code = vec![0u8; 0x100];
        let tbnz_w5 = 0x3700_0005u32;
        code[0x10..0x14].copy_from_slice(&tbnz_w5.to_le_bytes());
        assert!(check_for_6th_parameter(&code, 0x1000, 0x1000));
    }

    #[test]
    fn finds_overlapping_subslice() {
        assert_eq!(find_subslice(b"aaaab", b"aab"), Some(2));
    }
}
