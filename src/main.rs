use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use ebpf_dex_dumper_rs::{art, dump, fix, platform};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "eBPFDexDumper",
    about = "Android eBPF DEX dumper",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start eBPF-based DEX dumper.
    Dump(DumpArgs),
    /// Fix dumped DEX files in a directory.
    Fix(FixArgs),
    /// Locate ART interpreter offsets in a libart.so ELF.
    Offsets(OffsetsArgs),
}

#[derive(Debug, Parser)]
struct DumpArgs {
    /// Filter by Android UID. Use either --uid or --name.
    #[arg(short, long)]
    uid: Option<u32>,

    /// Android package name used to derive UID.
    #[arg(short, long)]
    name: Option<String>,

    /// Path to libart.so on target device.
    #[arg(short, long, default_value = "/apex/com.android.art/lib64/libart.so")]
    libart: PathBuf,

    /// Output directory on target device.
    #[arg(
        short,
        long,
        alias = "output",
        default_value = "/data/local/tmp/dex_out"
    )]
    out: PathBuf,

    /// Print executed methods while dumping.
    #[arg(short, long)]
    trace: bool,

    /// Remove /data/app/.../oat folders of target app(s) before dumping.
    #[arg(short = 'c', long, default_value_t = true)]
    clean_oat: bool,

    /// Automatically fix DEX files after dumping.
    #[arg(short = 'f', long, default_value_t = true)]
    auto_fix: bool,

    /// Disable automatic oat cleaning.
    #[arg(long)]
    no_clean_oat: bool,

    /// Disable automatic DEX fixing.
    #[arg(long)]
    no_auto_fix: bool,

    /// Manual offset for art::interpreter::Execute, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    execute_offset: Option<u64>,

    /// Manual offset for ExecuteNterpImpl, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    nterp_offset: Option<u64>,
}

#[derive(Debug, Parser)]
struct FixArgs {
    /// Directory containing dumped DEX files.
    #[arg(short, long)]
    dir: PathBuf,
}

#[derive(Debug, Parser)]
struct OffsetsArgs {
    /// Path to libart.so.
    #[arg(short, long)]
    libart: PathBuf,

    /// Manual offset for art::interpreter::Execute, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    execute_offset: Option<u64>,

    /// Manual offset for ExecuteNterpImpl, decimal or 0x-prefixed hex.
    #[arg(long, value_parser = parse_u64)]
    nterp_offset: Option<u64>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
        Some(Command::Fix(args)) => fix::fix_dex_directory(&args.dir),
        Some(Command::Offsets(args)) => {
            let offsets =
                art::find_art_offsets(&args.libart, args.execute_offset, args.nterp_offset)
                    .with_context(|| format!("failed to parse {}", args.libart.display()))?;
            println!("Execute: 0x{:x}", offsets.execute);
            println!("ExecuteNterpImpl: 0x{:x}", offsets.execute_nterp);
            println!("VerifyClass: 0x{:x}", offsets.verify_class);
            Ok(())
        }
        Some(Command::Dump(args)) => {
            let clean_oat = args.clean_oat && !args.no_clean_oat;
            let auto_fix = args.auto_fix && !args.no_auto_fix;
            let uid = match (args.uid, args.name.as_deref()) {
                (Some(uid), _) if uid != 0 => uid,
                (_, Some(pkg)) => {
                    let uid = platform::lookup_uid_by_package_name(pkg)?;
                    println!("[+] Resolved UID {uid} from package {pkg:?}");
                    uid
                }
                _ => anyhow::bail!("either --uid or --name must be provided"),
            };

            if clean_oat {
                if let Some(pkg) = args.name.as_deref() {
                    platform::remove_oat_dirs_for_package(pkg);
                } else {
                    platform::remove_oat_dirs_by_uid(uid);
                }
            }

            let config = dump::DumpConfig {
                uid,
                package_name: args.name,
                libart: args.libart,
                out: args.out,
                trace: args.trace,
                auto_fix,
                execute_offset: args.execute_offset,
                nterp_offset: args.nterp_offset,
            };
            dump::run(config)
        }
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        s.parse::<u64>().map_err(|err| err.to_string())
    }
}
