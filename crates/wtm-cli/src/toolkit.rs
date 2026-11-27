//! CLI subcommands for disk cleanup, risk scanning, Windows tweaks, and repair.

use std::process::ExitCode;

use clap::Subcommand;
use wtm_core::repair::{self, DnsProvider, RepairAction};
use wtm_core::risk;
use wtm_core::tasks;
use wtm_core::tweaks;
use wtm_core::{Sampler, cleanup, format_bytes};

#[derive(Subcommand)]
pub enum RiskCommand {
    /// Scan running processes, startup entries, services, risky folders, and policies
    Scan {
        #[arg(long)]
        json: bool,
    },
    /// Scan a specific file with Microsoft Defender (MpCmdRun.exe)
    Defender { path: String },
}

#[derive(Subcommand)]
pub enum TweakCommand {
    /// List available tweaks and their current status
    List {
        #[arg(long)]
        json: bool,
    },
    /// Apply a tweak by ID (saves previous values for rollback)
    Apply { id: String },
    /// Revert a tweak by ID using its saved backup
    Undo { id: String },
}

#[derive(Subcommand)]
pub enum RepairCommand {
    /// Show network adapters, IPv4/IPv6, gateway, DHCP/manual mode, and DNS servers
    NetInfo {
        #[arg(long)]
        json: bool,
    },
    /// Flush the Windows DNS resolver cache (ipconfig /flushdns)
    FlushDns,
    /// Release and renew DHCP IP leases (ipconfig /release + /renew)
    RenewIp,
    /// Run System File Checker (sfc /scannow)
    Sfc,
    /// Run DISM image health restore
    Dism,
    /// Flush DNS and reset Winsock / IP stack
    NetReset,
    /// Force Windows Time synchronization
    TimeSync,
    /// Set active network adapter DNS (auto, cloudflare, quad9, google, adguard, opendns)
    Dns { provider: String },
    /// Create a Windows System Restore Point
    RestorePoint,
}

#[derive(Subcommand)]
pub enum TaskCommand {
    /// List scheduled tasks
    List {
        #[arg(long)]
        microsoft: bool,
        #[arg(long)]
        json: bool,
    },
    /// Enable a scheduled task by full path
    Enable { path: String },
    /// Disable a scheduled task by full path
    Disable { path: String },
}

pub fn run_clean(apply: bool, ram: bool, categories: Vec<String>, json: bool) -> ExitCode {
    if ram {
        let mut sampler = Sampler::new();
        let procs = sampler.sample().map(|s| s.processes).unwrap_or_default();
        let report = cleanup::trim_system_memory(&procs);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
        } else {
            println!(
                "Before: {} / {} | After: {} / {} | Freed: {} ({} trimmed, {} skipped)",
                format_bytes(report.before_used_bytes as f64),
                format_bytes(report.total_bytes as f64),
                format_bytes(report.after_used_bytes as f64),
                format_bytes(report.total_bytes as f64),
                format_bytes(report.freed_bytes as f64),
                report.trimmed_processes,
                report.skipped_processes,
            );
            for d in report.details.iter().take(15) {
                println!(
                    "  {:<28} ({:>6})  {} -> {}  (-{})",
                    d.name,
                    d.pid,
                    format_bytes(d.before_bytes as f64),
                    format_bytes(d.after_bytes as f64),
                    format_bytes(d.freed_bytes as f64),
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    let mut cats = cleanup::default_categories();
    cleanup::scan_categories(&mut cats);

    if !apply {
        if json {
            let summaries: Vec<_> = cats.iter().map(cleanup::CleanupCategory::summary).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&summaries).unwrap_or_default()
            );
        } else {
            for c in &cats {
                println!(
                    "{:<10} {:>10} ({} files) - {}",
                    c.id,
                    format_bytes(c.bytes as f64),
                    c.files,
                    c.name
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    let selected: Vec<String> = if categories.is_empty() {
        cats.iter()
            .filter(|c| c.default_enabled)
            .map(|c| c.id.to_owned())
            .collect()
    } else {
        categories
    };
    let (freed, files, skipped) = cleanup::clean_categories(&mut cats, &selected);
    if json {
        println!(
            "{}",
            serde_json::json!({ "freed_bytes": freed, "freed_files": files, "skipped": skipped })
        );
    } else {
        println!(
            "Freed {} across {files} file(s) ({skipped} skipped).",
            format_bytes(freed as f64)
        );
    }
    ExitCode::SUCCESS
}

pub fn run_risk(cmd: RiskCommand) -> ExitCode {
    match cmd {
        RiskCommand::Scan { json } => {
            let mut sampler = Sampler::new();
            let procs = sampler.sample().map(|s| s.processes).unwrap_or_default();
            let findings = risk::scan_risks(&procs);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&findings).unwrap_or_default()
                );
            } else if findings.is_empty() {
                println!("No suspicious items found.");
            } else {
                for f in &findings {
                    println!(
                        "[{}] {} ({}) - {}\n  {}",
                        f.level.label(),
                        f.name,
                        f.kinds_summary(),
                        f.reason,
                        f.path
                    );
                }
            }
            ExitCode::SUCCESS
        }
        RiskCommand::Defender { path } => {
            let (threat, msg) = risk::defender_scan_file(&path);
            println!("{msg}");
            if threat == Some(true) {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

pub fn run_tweaks(cmd: TweakCommand) -> ExitCode {
    match cmd {
        TweakCommand::List { json } => {
            let states = tweaks::list_states();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&states).unwrap_or_default()
                );
            } else {
                for t in &states {
                    let status = if t.applied { "applied" } else { "default" };
                    println!("{:<22} [{}] {}", t.id, status, t.name);
                }
            }
            ExitCode::SUCCESS
        }
        TweakCommand::Apply { id } => match tweaks::apply_tweak(&id) {
            Ok(()) => {
                println!("Applied tweak '{id}'.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TweakCommand::Undo { id } => match tweaks::undo_tweak(&id) {
            Ok(()) => {
                println!("Reverted tweak '{id}'.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

pub fn run_repair(cmd: RepairCommand) -> ExitCode {
    let action = match cmd {
        RepairCommand::NetInfo { json } => match repair::list_network_adapters() {
            Ok(adapters) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&adapters).unwrap_or_default()
                    );
                } else {
                    for a in &adapters {
                        let ip_mode = if a.dhcp_enabled { "DHCP" } else { "Manual" };
                        let dns_mode = if a.dns_dhcp { "DHCP" } else { "Manual" };
                        println!(
                            "{} [{}] ({}) | IP({ip_mode}): {} | GW: {} | DNS({dns_mode}): {}",
                            a.name,
                            a.status,
                            a.link_speed,
                            a.ipv4.join(", "),
                            a.gateway,
                            a.dns_servers.join(", ")
                        );
                    }
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        },
        RepairCommand::FlushDns => RepairAction::FlushDns,
        RepairCommand::RenewIp => RepairAction::RenewIp,
        RepairCommand::Sfc => RepairAction::SfcScan,
        RepairCommand::Dism => RepairAction::DismRestoreHealth,
        RepairCommand::NetReset => RepairAction::NetworkReset,
        RepairCommand::TimeSync => RepairAction::TimeSync,
        RepairCommand::Dns { provider } => match DnsProvider::parse(&provider) {
            Some(p) => RepairAction::SetDns(p),
            None => {
                eprintln!(
                    "Unknown DNS provider '{provider}'. Expected: auto, cloudflare, quad9, google, adguard, opendns."
                );
                return ExitCode::FAILURE;
            }
        },
        RepairCommand::RestorePoint => RepairAction::CreateRestorePoint,
    };
    match repair::run_repair(action) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_tasks(cmd: TaskCommand) -> ExitCode {
    match cmd {
        TaskCommand::List { microsoft, json } => match tasks::list_tasks() {
            Ok(list) => {
                let filtered: Vec<_> = list
                    .into_iter()
                    .filter(|t| microsoft || !t.is_microsoft)
                    .collect();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&filtered).unwrap_or_default()
                    );
                } else {
                    for t in &filtered {
                        let st = if t.enabled { "enabled" } else { "disabled" };
                        println!("[{st}] {} ({})", t.name, t.path);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TaskCommand::Enable { path } => match tasks::set_task_enabled(&path, true) {
            Ok(()) => {
                println!("Enabled task '{path}'.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        TaskCommand::Disable { path } => match tasks::set_task_enabled(&path, false) {
            Ok(()) => {
                println!("Disabled task '{path}'.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
