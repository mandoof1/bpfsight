use bpfsight::{detect, db_stats, install_ctrlc, run_until, Options};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "bpfsight", version, about = "eBPF host sensor: exec/fork/connect/accept/open/cred/module")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Capture events and run detections until Ctrl-C or --duration.
    Run {
        #[arg(long, default_value = "bpfsight.sqlite")]
        db: PathBuf,
        /// append every event as JSONL
        #[arg(long)]
        jsonl: Option<PathBuf>,
        /// append matched detections as JSONL
        #[arg(long)]
        alerts: Option<PathBuf>,
        /// directory of sigma-style .yml rules
        #[arg(long)]
        rules_dir: Option<PathBuf>,
        #[arg(long)]
        iocs: Option<PathBuf>,
        /// stop after N seconds
        #[arg(long)]
        duration: Option<u64>,
        /// do not print alerts to stdout
        #[arg(long)]
        quiet: bool,
    },
    /// Print capture statistics from a .sqlite file written by `run`.
    Stats {
        #[arg(long, default_value = "bpfsight.sqlite")]
        db: PathBuf,
    },
    /// List built-in detection rules.
    Rules,
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { db, jsonl, alerts, rules_dir, iocs, duration, quiet } => {
            let opts = Options {
                db: db.clone(),
                jsonl,
                alerts_jsonl: alerts,
                rules_dir,
                iocs,
                quiet,
            };
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            install_ctrlc(&stop);
            match run_until(&opts, &stop, duration.map(Duration::from_secs), |d| {
                if !quiet {
                    println!("[{}] {:<22} {}", d.severity, d.rule, d.detail);
                }
            }) {
                Ok(s) => {
                    println!(
                        "events: {} submitted: {} ring-full: {} drops: {} alerts: {}",
                        s.events, s.kernel_submitted, s.ring_full, s.seq_drops, s.alerts
                    );
                    for (k, n) in &s.by_kind {
                        println!("  {k:<10} {n}");
                    }
                    println!("db: {}", db.display());
                }
                Err(e) => {
                    eprintln!("bpfsight: {e}");
                    std::process::exit(2);
                }
            }
        }
        Cmd::Stats { db } => match db_stats(&db) {
            Ok(s) => print!("{s}"),
            Err(e) => {
                eprintln!("bpfsight: {e}");
                std::process::exit(2);
            }
        },
        Cmd::Rules => {
            for r in detect::builtins() {
                println!("{:<7} {:<24} {}", r.severity, r.id, r.title);
            }
        }
    }
}
