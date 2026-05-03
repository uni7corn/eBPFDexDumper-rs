use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct DumpConfig {
    pub uid: u32,
    pub package_name: Option<String>,
    pub libart: PathBuf,
    pub out: PathBuf,
    pub trace: bool,
    pub auto_fix: bool,
    pub execute_offset: Option<u64>,
    pub nterp_offset: Option<u64>,
    pub runtime_layout: Option<crate::art::ArtRuntimeLayout>,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod imp {
    use super::DumpConfig;
    use crate::{art, dex::DexParser, fix};
    use anyhow::{Context, Result};
    use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, RingBuf};
    use aya::programs::{ProgramError, UProbe};
    use aya::{include_bytes_aligned, Btf, EbpfLoader, Pod};
    use object::Endianness;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, RwLock};
    use std::thread;
    use std::time::Duration;

    const BPF_OBJECT: &[u8] =
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bpf_arm64_bpfel.o"));
    const DEX_CHUNK_HEADER_SIZE: usize = 24;
    const METHOD_EVENT_HEADER_SIZE: usize = 40;
    const READ_FAILURE_HEADER_SIZE: usize = 24;
    static RUNNING: AtomicBool = AtomicBool::new(true);

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct BpfConfig {
        uid: u32,
        pid: i32,
    }

    unsafe impl Pod for BpfConfig {}

    unsafe impl Pod for art::ArtRuntimeLayout {}

    #[derive(Clone, Debug, Serialize)]
    struct MethodCodeRecord {
        name: String,
        method_idx: u32,
        code: String,
    }

    #[derive(Default)]
    struct DumpState {
        output_dir: PathBuf,
        trace: bool,
        dex_cache: RwLock<HashMap<u64, Vec<u8>>>,
        dex_sizes: RwLock<HashMap<u64, u32>>,
        pending_dex: RwLock<HashMap<u64, DexRecvState>>,
        method_records: RwLock<HashMap<u64, Vec<MethodCodeRecord>>>,
        method_sig_cache: RwLock<HashMap<(u64, u32), String>>,
    }

    #[derive(Clone, Debug)]
    struct DexRecvState {
        total: u32,
        recv: u32,
        buf: Vec<u8>,
    }

    impl DumpState {
        fn new(output_dir: PathBuf, trace: bool) -> Self {
            Self {
                output_dir,
                trace,
                dex_cache: RwLock::new(HashMap::new()),
                dex_sizes: RwLock::new(HashMap::new()),
                pending_dex: RwLock::new(HashMap::new()),
                method_records: RwLock::new(HashMap::new()),
                method_sig_cache: RwLock::new(HashMap::new()),
            }
        }

        fn handle_dex_event(&self, data: &[u8]) {
            let Some(evt) = DexEvent::parse(data) else {
                eprintln!("Dex event too short: {} bytes", data.len());
                return;
            };
            self.dex_sizes.write().unwrap().insert(evt.begin, evt.size);
        }

        fn handle_dex_chunk(&self, data: &[u8]) {
            let Some(hdr) = DexChunkEvent::parse(data) else {
                eprintln!("Dex chunk event too short: {} bytes", data.len());
                return;
            };
            let payload_start = DEX_CHUNK_HEADER_SIZE;
            let payload_end = payload_start.saturating_add(hdr.data_len as usize);
            let Some(payload) = data.get(payload_start..payload_end) else {
                eprintln!("Dex chunk payload out of bounds: {} bytes", data.len());
                return;
            };

            let maybe_complete = {
                let mut pending = self.pending_dex.write().unwrap();
                let state = pending.entry(hdr.begin).or_insert_with(|| {
                    self.dex_sizes.write().unwrap().insert(hdr.begin, hdr.size);
                    DexRecvState {
                        total: hdr.size,
                        recv: 0,
                        buf: vec![0; hdr.size as usize],
                    }
                });

                let end = hdr.offset.saturating_add(hdr.data_len);
                if end as usize <= state.buf.len() {
                    state.buf[hdr.offset as usize..end as usize].copy_from_slice(payload);
                    if state.recv < end {
                        state.recv = end;
                    }
                }

                if state.recv >= state.total {
                    pending
                        .remove(&hdr.begin)
                        .map(|state| (hdr.begin, hdr.size, state.buf))
                } else {
                    None
                }
            };

            if let Some((begin, size, bytes)) = maybe_complete {
                self.save_dex(begin, size, bytes);
            }
        }

        fn handle_method_event(&self, data: &[u8]) {
            let Some(hdr) = MethodEvent::parse(data) else {
                return;
            };
            let bytecode = if hdr.codeitem_size > 0 {
                data.get(
                    METHOD_EVENT_HEADER_SIZE..METHOD_EVENT_HEADER_SIZE + hdr.codeitem_size as usize,
                )
                .unwrap_or_default()
            } else {
                &[]
            };

            let method_name = self.method_name(hdr.begin, hdr.method_index);

            if self.trace {
                if hdr.codeitem_size > 0 {
                    println!(
                        "{} (pid={}, dex=0x{:x}, method_idx={}, art_method=0x{:x}, bytecode_size={})",
                        method_name,
                        hdr.pid,
                        hdr.begin,
                        hdr.method_index,
                        hdr.art_method_ptr,
                        hdr.codeitem_size
                    );
                } else {
                    println!(
                        "{} (pid={}, dex=0x{:x}, method_idx={}, art_method=0x{:x})",
                        method_name, hdr.pid, hdr.begin, hdr.method_index, hdr.art_method_ptr
                    );
                }
            }

            if !bytecode.is_empty() {
                let record = MethodCodeRecord {
                    name: method_name,
                    method_idx: hdr.method_index,
                    code: hex::encode(bytecode),
                };
                self.method_records
                    .write()
                    .unwrap()
                    .entry(hdr.begin)
                    .or_default()
                    .push(record);
            }
        }

        fn handle_read_failure(&self, data: &[u8]) {
            let Some(evt) = ReadFailureEvent::parse(data) else {
                eprintln!("Read failure event too short: {} bytes", data.len());
                return;
            };
            eprintln!(
                "eBPF read failed at offset {} for dex 0x{:x} (pid={}); using process_vm_readv fallback",
                evt.failed_offset, evt.begin, evt.pid
            );
            match read_remote_mem(evt.pid, evt.begin, evt.size) {
                Ok(bytes) => {
                    self.pending_dex.write().unwrap().remove(&evt.begin);
                    self.save_dex(evt.begin, evt.size, bytes);
                }
                Err(err) => eprintln!("process_vm_readv failed for dex 0x{:x}: {err:#}", evt.begin),
            }
        }

        fn save_dex(&self, begin: u64, size: u32, bytes: Vec<u8>) {
            if let Err(err) = DexParser::new(&bytes) {
                eprintln!("Failed to parse dumped dex 0x{begin:x}: {err}");
            }
            self.dex_cache.write().unwrap().insert(begin, bytes.clone());
            self.dex_sizes.write().unwrap().insert(begin, size);

            let file_name = self.output_dir.join(format!("dex_{begin:x}_{size:x}.dex"));
            match fs::write(&file_name, &bytes) {
                Ok(()) => println!(
                    "Dex file saved to {}, size {}",
                    file_name.display(),
                    bytes.len()
                ),
                Err(err) => eprintln!("Write dexData failed for {}: {err}", file_name.display()),
            }
        }

        fn method_name(&self, begin: u64, method_idx: u32) -> String {
            if let Some(cached) = self
                .method_sig_cache
                .read()
                .unwrap()
                .get(&(begin, method_idx))
                .cloned()
            {
                return cached;
            }

            let name = self
                .dex_cache
                .read()
                .unwrap()
                .get(&begin)
                .and_then(|dex| DexParser::new(dex).ok())
                .and_then(|parser| parser.get_method_info(method_idx).ok())
                .map(|method| method.pretty_method())
                .unwrap_or_else(|| format!("method_idx_{method_idx}"));

            self.method_sig_cache
                .write()
                .unwrap()
                .insert((begin, method_idx), name.clone());
            name
        }

        fn flush_json(&self) -> Result<()> {
            let mut records_by_dex = self.method_records.write().unwrap();
            let records_by_dex = std::mem::take(&mut *records_by_dex);

            let sizes = self.dex_sizes.read().unwrap().clone();
            for (begin, records) in records_by_dex {
                if records.is_empty() {
                    continue;
                }
                let size =
                    sizes
                        .get(&begin)
                        .copied()
                        .or_else(|| {
                            self.dex_cache.read().unwrap().get(&begin).and_then(|dex| {
                                DexParser::new(dex).ok().map(|p| p.header().file_size)
                            })
                        })
                        .unwrap_or(0);
                let file_name = self
                    .output_dir
                    .join(format!("dex_{begin:x}_{size:x}_code.json"));
                let file = fs::File::create(&file_name)
                    .with_context(|| format!("failed to create {}", file_name.display()))?;
                serde_json::to_writer_pretty(file, &records)
                    .with_context(|| format!("failed to write {}", file_name.display()))?;
                println!(
                    "Saved code records to {} ({} entries)",
                    file_name.display(),
                    records.len()
                );
            }
            Ok(())
        }
    }

    pub fn run(config: DumpConfig) -> Result<()> {
        fs::create_dir_all(&config.out).with_context(|| {
            format!("failed to create output directory {}", config.out.display())
        })?;

        let targets =
            art::find_art_offsets(&config.libart, config.execute_offset, config.nterp_offset)
                .with_context(|| {
                    format!(
                        "failed to locate ART hook targets in {}",
                        config.libart.display()
                    )
                })?;
        print_target("Execute", targets.execute);
        print_target("ExecuteNterpImpl", targets.execute_nterp);
        print_target(
            "ExecuteNterpWithClinitImpl",
            targets.execute_nterp_with_clinit,
        );
        print_target("VerifyClass", targets.verify_class);
        println!(
            "[+] nterp_op_invoke_* pattern targets: {}",
            targets.nterp_invoke_addrs.len()
        );
        let runtime_layout = match config.runtime_layout {
            Some(layout) => layout,
            None => art::resolve_runtime_layout(&config.libart).with_context(|| {
                format!(
                    "failed to resolve ART layout for {}",
                    config.libart.display()
                )
            })?,
        };
        println!("[+] ART runtime layout: {}", runtime_layout.summary());

        let asset_btf = load_asset_btf();
        let mut loader = EbpfLoader::new();
        if let Some(btf) = asset_btf.as_ref() {
            loader.btf(Some(btf));
        }
        bump_memlock_rlimit();
        let mut ebpf = loader
            .load(BPF_OBJECT)
            .context("failed to load eBPF object")?;

        let mut config_map: AyaHashMap<&mut MapData, u32, BpfConfig> =
            AyaHashMap::try_from(ebpf.map_mut("config_map").context("config_map not found")?)?;
        config_map.insert(
            0,
            BpfConfig {
                uid: config.uid,
                pid: 0,
            },
            0,
        )?;
        let mut layout_map: AyaArray<&mut MapData, art::ArtRuntimeLayout> = AyaArray::try_from(
            ebpf.map_mut("art_layout_map")
                .context("art_layout_map not found")?,
        )?;
        layout_map.set(0, runtime_layout, 0)?;
        println!("[+] Filtering on uid {}", config.uid);

        let mut attached_main = 0usize;
        if let Some(target) = targets.execute {
            attach_uprobe(
                &mut ebpf,
                "uprobe_libart_execute",
                &config.libart,
                target.addr,
            )
            .context("failed to attach Execute uprobe")?;
            attached_main += 1;
        }
        if let Some(target) = targets.execute_nterp {
            attach_uprobe(
                &mut ebpf,
                "uprobe_libart_executeNterpImpl",
                &config.libart,
                target.addr,
            )
            .context("failed to attach ExecuteNterpImpl uprobe")?;
            attached_main += 1;
        }
        if let Some(target) = targets.execute_nterp_with_clinit {
            attach_uprobe(
                &mut ebpf,
                "uprobe_libart_executeNterpImpl",
                &config.libart,
                target.addr,
            )
            .context("failed to attach ExecuteNterpWithClinitImpl uprobe")?;
            attached_main += 1;
        }
        if attached_main == 0 {
            anyhow::bail!("no ART main entry uprobe was attached");
        }

        for target in targets.nterp_invoke_addrs {
            if let Err(err) = attach_uprobe(
                &mut ebpf,
                "uprobe_libart_nterpOpInvoke",
                &config.libart,
                target.addr,
            ) {
                eprintln!(
                    "[-] failed to attach nterp_op_invoke_* at 0x{:x}: {err:#}",
                    target.addr
                );
            }
        }

        let state = Arc::new(DumpState::new(config.out.clone(), config.trace));
        RUNNING.store(true, Ordering::SeqCst);
        install_signal_handlers();

        let mut events =
            RingBuf::try_from(ebpf.take_map("events").context("events map not found")?)?;
        let mut method_events = RingBuf::try_from(
            ebpf.take_map("method_events")
                .context("method_events map not found")?,
        )?;
        let mut dex_chunks = RingBuf::try_from(
            ebpf.take_map("dex_chunks")
                .context("dex_chunks map not found")?,
        )?;
        let mut read_failures = RingBuf::try_from(
            ebpf.take_map("read_failures")
                .context("read_failures map not found")?,
        )?;

        println!("eBPF DexDumper started successfully");
        while RUNNING.load(Ordering::SeqCst) {
            drain_ring(&mut events, |data| state.handle_dex_event(data));
            drain_ring(&mut method_events, |data| state.handle_method_event(data));
            drain_ring(&mut dex_chunks, |data| state.handle_dex_chunk(data));
            drain_ring(&mut read_failures, |data| state.handle_read_failure(data));
            thread::sleep(Duration::from_millis(50));
        }

        println!("Stopping eBPF DexDumper");
        drain_ring(&mut events, |data| state.handle_dex_event(data));
        drain_ring(&mut method_events, |data| state.handle_method_event(data));
        drain_ring(&mut dex_chunks, |data| state.handle_dex_chunk(data));
        drain_ring(&mut read_failures, |data| state.handle_read_failure(data));
        state.flush_json()?;
        if config.auto_fix {
            println!("[+] Auto-fixing DEX files...");
            if let Err(err) = fix::fix_dex_directory(&config.out) {
                eprintln!("[!] Auto-fix failed: {err:#}");
            }
        }
        println!("DexDumper stopped");
        Ok(())
    }

    fn attach_uprobe(
        ebpf: &mut aya::Ebpf,
        program_name: &str,
        target: &std::path::Path,
        offset: u64,
    ) -> Result<()> {
        let program: &mut UProbe = ebpf
            .program_mut(program_name)
            .with_context(|| format!("{program_name} not found"))?
            .try_into()?;
        match program.load() {
            Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
            Err(err) => return Err(err.into()),
        }
        program.attach(None, offset, target, None)?;
        Ok(())
    }

    fn drain_ring<T: std::borrow::Borrow<MapData>, F: FnMut(&[u8])>(
        ring: &mut RingBuf<T>,
        mut handler: F,
    ) {
        while let Some(item) = ring.next() {
            handler(&item);
        }
    }

    fn print_target(name: &str, target: Option<art::ResolvedTarget>) {
        match target {
            Some(target) => println!("[+] {name}: 0x{:x} ({})", target.addr, target.source),
            None => println!("[-] {name}: not found"),
        }
    }

    fn load_asset_btf() -> Option<Btf> {
        if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return None;
        }

        let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let asset = if release.contains("rockchip") {
            include_bytes!("../assets/rock5b-5.10-arm64_min.btf").as_slice()
        } else {
            include_bytes!("../assets/a12-5.10-arm64_min.btf").as_slice()
        };

        match Btf::parse(asset, Endianness::Little) {
            Ok(btf) => {
                if release.contains("rockchip") {
                    println!("[+] Loaded BTF spec from rock5b-5.10-arm64_min.btf");
                } else {
                    println!("[+] Loaded BTF spec from a12-5.10-arm64_min.btf");
                }
                Some(btf)
            }
            Err(err) => {
                eprintln!("[!] Failed to parse embedded BTF spec: {err}");
                None
            }
        }
    }

    fn bump_memlock_rlimit() {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            eprintln!(
                "[!] Failed to raise RLIMIT_MEMLOCK: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    fn install_signal_handlers() {
        unsafe {
            libc::signal(libc::SIGINT, signal_handler as *const () as usize);
            libc::signal(libc::SIGTERM, signal_handler as *const () as usize);
            libc::signal(libc::SIGHUP, signal_handler as *const () as usize);
            libc::signal(libc::SIGQUIT, signal_handler as *const () as usize);
        }
    }

    extern "C" fn signal_handler(_: libc::c_int) {
        RUNNING.store(false, Ordering::SeqCst);
    }

    #[derive(Clone, Copy, Debug)]
    struct DexEvent {
        begin: u64,
        size: u32,
    }

    impl DexEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            Some(Self {
                begin: le64(data, 0)?,
                size: le32(data, 12)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct DexChunkEvent {
        begin: u64,
        size: u32,
        offset: u32,
        data_len: u32,
    }

    impl DexChunkEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < DEX_CHUNK_HEADER_SIZE {
                return None;
            }
            Some(Self {
                begin: le64(data, 0)?,
                size: le32(data, 12)?,
                offset: le32(data, 16)?,
                data_len: le32(data, 20)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct MethodEvent {
        begin: u64,
        pid: u32,
        art_method_ptr: u64,
        method_index: u32,
        codeitem_size: u32,
    }

    impl MethodEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < METHOD_EVENT_HEADER_SIZE {
                return None;
            }
            Some(Self {
                begin: le64(data, 0)?,
                pid: le32(data, 8)?,
                art_method_ptr: le64(data, 24)?,
                method_index: le32(data, 32)?,
                codeitem_size: le32(data, 36)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct ReadFailureEvent {
        begin: u64,
        pid: u32,
        size: u32,
        failed_offset: u32,
    }

    impl ReadFailureEvent {
        fn parse(data: &[u8]) -> Option<Self> {
            if data.len() < READ_FAILURE_HEADER_SIZE {
                return None;
            }
            Some(Self {
                begin: le64(data, 0)?,
                pid: le32(data, 8)?,
                size: le32(data, 12)?,
                failed_offset: le32(data, 16)?,
            })
        }
    }

    fn read_remote_mem(pid: u32, remote_addr: u64, len: u32) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len as usize];
        let mut local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut remote = libc::iovec {
            iov_base: remote_addr as usize as *mut libc::c_void,
            iov_len: len as usize,
        };

        let read = unsafe {
            libc::syscall(
                libc::SYS_process_vm_readv,
                pid as libc::pid_t,
                &mut local,
                1usize,
                &mut remote,
                1usize,
                0usize,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("process_vm_readv");
        }
        let read = read as usize;
        if read < buf.len() {
            eprintln!(
                "process_vm_readv partial read: expected {}, got {read}",
                buf.len()
            );
            buf.truncate(read);
        }
        Ok(buf)
    }

    fn le32(data: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    fn le64(data: &[u8], offset: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            data.get(offset..offset + 8)?.try_into().ok()?,
        ))
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod imp {
    use super::DumpConfig;
    use crate::art;
    use anyhow::{Context, Result};
    use std::fs;

    pub fn run(config: DumpConfig) -> Result<()> {
        fs::create_dir_all(&config.out).with_context(|| {
            format!("failed to create output directory {}", config.out.display())
        })?;
        let targets =
            art::find_art_offsets(&config.libart, config.execute_offset, config.nterp_offset)
                .with_context(|| {
                    format!(
                        "failed to locate ART hook targets in {}",
                        config.libart.display()
                    )
                })?;
        print_target("Execute", targets.execute);
        print_target("ExecuteNterpImpl", targets.execute_nterp);
        print_target(
            "ExecuteNterpWithClinitImpl",
            targets.execute_nterp_with_clinit,
        );
        print_target("VerifyClass", targets.verify_class);
        println!(
            "[+] nterp_op_invoke_* pattern targets: {}",
            targets.nterp_invoke_addrs.len()
        );
        let runtime_layout = match config.runtime_layout {
            Some(layout) => layout,
            None => art::resolve_runtime_layout(&config.libart).with_context(|| {
                format!(
                    "failed to resolve ART layout for {}",
                    config.libart.display()
                )
            })?,
        };
        println!("[+] ART runtime layout: {}", runtime_layout.summary());
        println!("[+] Filtering on uid {}", config.uid);
        let _ = (config.package_name, config.trace, config.auto_fix);
        anyhow::bail!("live dump is available only when built for Linux/Android")
    }

    fn print_target(name: &str, target: Option<art::ResolvedTarget>) {
        match target {
            Some(target) => println!("[+] {name}: 0x{:x} ({})", target.addr, target.source),
            None => println!("[-] {name}: not found"),
        }
    }
}

pub use imp::run;
