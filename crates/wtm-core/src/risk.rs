//! Contextual risk assessment, unified security scan (processes, startup,
//! services, scheduled tasks, suspicious files, critical settings),
//! Microsoft Defender integration, and safe quarantine.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use crate::control::ProcessRef;
use crate::startup::{self, StartupEntry};
use crate::{ProcessInfo, Signature, StartType};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

const SYSTEM_PROCESS_NAMES: &[&str] = &[
    "svchost",
    "lsass",
    "csrss",
    "winlogon",
    "services",
    "smss",
    "explorer",
    "dwm",
    "taskhostw",
    "conhost",
    "rundll32",
    "spoolsv",
    "wininit",
    "sihost",
    "ctfmon",
    "dllhost",
    "runtimebroker",
];

const RISKY_LOCATIONS: &[&str] = &[
    r"\appdata\local\temp\",
    r"\windows\temp\",
    r"\downloads\",
    r"\users\public\",
    r"\appdata\roaming\",
    r"\$recycle.bin\",
];

const EXE_EXTS: &[&str] = &["exe", "scr", "com", "pif"];
const SCRIPT_EXTS: &[&str] = &["vbs", "vbe", "js", "jse", "wsf", "bat", "cmd", "ps1", "hta"];
const DOC_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "zip", "rar", "mp4",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Unknown,
    Safe,
    Unsigned,
    Suspicious,
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Safe => "Signed",
            Self::Unsigned => "Unsigned",
            Self::Suspicious => "Suspicious",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskOrigin {
    Process {
        pid: u32,
        create_time: i64,
        name: String,
    },
    Startup(StartupEntry),
    Service {
        name: String,
    },
    ScheduledTask {
        path: String,
    },
    File,
    SystemSetting {
        tool: String,
        args: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub key: String,
    pub level: RiskLevel,
    pub name: String,
    pub reason: String,
    pub path: String,
    pub origins: Vec<RiskOrigin>,
    pub defender_verdict: Option<(Option<bool>, String)>,
}

impl RiskFinding {
    pub fn kinds_summary(&self) -> String {
        let mut kinds = Vec::new();
        for o in &self.origins {
            let label = match o {
                RiskOrigin::Process { .. } => "Running",
                RiskOrigin::Startup(_) => "Startup",
                RiskOrigin::Service { .. } => "Service",
                RiskOrigin::ScheduledTask { .. } => "Scheduled task",
                RiskOrigin::File => "File",
                RiskOrigin::SystemSetting { .. } => "System setting",
            };
            if !kinds.contains(&label) {
                kinds.push(label);
            }
        }
        kinds.join(" · ")
    }

    pub fn can_quarantine(&self) -> bool {
        is_removable_target(&self.path)
    }

    pub fn pids(&self) -> Vec<ProcessRef> {
        self.origins
            .iter()
            .filter_map(|o| match o {
                RiskOrigin::Process {
                    pid,
                    create_time,
                    name,
                } => Some(ProcessRef {
                    pid: *pid,
                    create_time: *create_time,
                    name: name.clone(),
                }),
                _ => None,
            })
            .collect()
    }
}

fn windir_lower() -> String {
    std::env::var("WINDIR")
        .unwrap_or_else(|_| r"C:\Windows".into())
        .to_lowercase()
}

fn is_self_path(path: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Some(dir) = exe.parent() else {
        return false;
    };
    path.to_lowercase()
        .starts_with(&dir.to_string_lossy().to_lowercase())
}

fn is_removable_target(path: &str) -> bool {
    if path.is_empty() || is_self_path(path) {
        return false;
    }
    let lower = path.to_lowercase();
    if lower.starts_with(&windir_lower()) {
        return false;
    }
    Path::new(path).is_file()
}

/// Evaluates the contextual risk of a process executable given its name, path,
/// and Authenticode/catalog signature.
pub fn assess_process_risk(
    name: &str,
    exe_path: &str,
    sig: Option<&Signature>,
) -> (RiskLevel, String) {
    if exe_path.is_empty() {
        return (RiskLevel::Unknown, String::new());
    }
    if is_self_path(exe_path) {
        return (RiskLevel::Safe, "RustWTM".into());
    }
    let stem = name.strip_suffix(".exe").unwrap_or(name).to_lowercase();
    let lower = exe_path.to_lowercase();
    if SYSTEM_PROCESS_NAMES.contains(&stem.as_str()) && !lower.starts_with(&windir_lower()) {
        return (
            RiskLevel::Suspicious,
            "Imitates a Windows system process name outside the Windows directory".into(),
        );
    }

    let Some(sig) = sig else {
        return (RiskLevel::Unknown, "Checking signature…".into());
    };

    match sig {
        Signature::Signed { signer, catalog } => {
            let label = match (signer, catalog) {
                (Some(s), _) => s.clone(),
                (None, true) => "Microsoft Windows (catalog)".into(),
                (None, false) => "Signed".into(),
            };
            (RiskLevel::Safe, label)
        }
        Signature::Invalid(reason) => (
            RiskLevel::Suspicious,
            format!("Invalid or untrusted signature ({reason})"),
        ),
        Signature::Unsigned => {
            if RISKY_LOCATIONS.iter().any(|loc| lower.contains(loc)) {
                (
                    RiskLevel::Suspicious,
                    "Unsigned executable running from a high-risk location".into(),
                )
            } else {
                (RiskLevel::Unsigned, "Unsigned executable".into())
            }
        }
    }
}

/// Extracts an executable path from a command line or service binary path.
pub fn extract_exe_path(cmd: &str) -> Option<String> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else if let Some(idx) = trimmed.to_lowercase().find(".exe") {
        &trimmed[..idx + 4]
    } else {
        trimmed.split_whitespace().next().unwrap_or("")
    };
    let expanded = expand_env_vars(candidate);
    if Path::new(&expanded).is_file() {
        Some(expanded)
    } else {
        None
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut out = input.to_owned();
    for var in [
        "SystemRoot",
        "WINDIR",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "USERPROFILE",
    ] {
        if let Ok(val) = std::env::var(var) {
            let pat = format!("%{var}%");
            if let Some(pos) = out.to_lowercase().find(&pat.to_lowercase()) {
                out.replace_range(pos..pos + pat.len(), &val);
            }
        }
    }
    out
}

fn push_finding(
    out: &mut Vec<RiskFinding>,
    key: &str,
    level: RiskLevel,
    name: &str,
    reason: &str,
    path: &str,
    origin: RiskOrigin,
) {
    let k = key.to_lowercase();
    if let Some(existing) = out.iter_mut().find(|f| f.key == k) {
        if level > existing.level {
            existing.level = level;
            existing.reason = reason.to_owned();
        }
        existing.origins.push(origin);
    } else {
        out.push(RiskFinding {
            key: k,
            level,
            name: name.to_owned(),
            reason: reason.to_owned(),
            path: path.to_owned(),
            origins: vec![origin],
            defender_verdict: None,
        });
    }
}

fn parse_csv_row(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                cols.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    cols.push(cur);
    cols
}

fn file_ext_lower(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

fn has_double_extension(p: &Path) -> bool {
    let stem = p.file_stem().map(PathBuf::from).unwrap_or_default();
    DOC_EXTS.contains(&file_ext_lower(&stem).as_str())
}

fn walk_executables(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    if out.len() >= 4000 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let Ok(md) = entry.metadata() else {
            continue;
        };
        if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            continue;
        }
        let path = entry.path();
        if md.is_dir() {
            if depth > 0 {
                walk_executables(&path, depth - 1, out);
            }
        } else {
            let ext = file_ext_lower(&path);
            if EXE_EXTS.contains(&ext.as_str()) || SCRIPT_EXTS.contains(&ext.as_str()) {
                out.push(path);
            }
        }
    }
}

/// Runs a unified risk scan across running processes, startup entries,
/// services, scheduled tasks, risky folders, and critical security settings.
pub fn scan_risks(processes: &[ProcessInfo]) -> Vec<RiskFinding> {
    let mut findings = Vec::new();
    let mut sig_cache: HashMap<String, Signature> = HashMap::new();
    let mut cached_sig = |path: &str| -> Signature {
        if let Some(s) = sig_cache.get(path) {
            return s.clone();
        }
        let s = crate::signature(path);
        sig_cache.insert(path.to_owned(), s.clone());
        s
    };

    // 1. Running processes
    for p in processes {
        let pref = ProcessRef::from(p);
        let Ok(exe_path) = crate::control::image_path(&pref) else {
            continue;
        };
        if exe_path.is_empty() {
            continue;
        }
        let sig = cached_sig(&exe_path);
        let (level, reason) = assess_process_risk(&p.name, &exe_path, Some(&sig));
        if matches!(level, RiskLevel::Suspicious | RiskLevel::Unsigned) {
            push_finding(
                &mut findings,
                &exe_path,
                level,
                &p.name,
                &reason,
                &exe_path,
                RiskOrigin::Process {
                    pid: p.pid,
                    create_time: p.create_time,
                    name: p.name.clone(),
                },
            );
        }
    }

    // 2. Startup entries
    for entry in startup::list_startup().into_iter().filter(|e| e.enabled) {
        let Some(exe) = extract_exe_path(&entry.command) else {
            continue;
        };
        let sig = cached_sig(&exe);
        let name = Path::new(&exe)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| entry.name.clone());
        let (level, reason) = assess_process_risk(&name, &exe, Some(&sig));
        if matches!(level, RiskLevel::Suspicious | RiskLevel::Unsigned) {
            let entry_name = entry.name.clone();
            push_finding(
                &mut findings,
                &exe,
                level,
                &entry_name,
                &format!("Startup entry: {reason}"),
                &exe,
                RiskOrigin::Startup(entry),
            );
        }
    }

    // 3. Non-Microsoft services with suspicious binaries
    if let Ok(services) = crate::list_services() {
        for svc in services {
            if let Some(exe) = svc.binary_path.as_deref().and_then(extract_exe_path) {
                let sig = cached_sig(&exe);
                let name = Path::new(&exe)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| svc.name.clone());
                let (level, reason) = assess_process_risk(&name, &exe, Some(&sig));
                if level == RiskLevel::Suspicious {
                    push_finding(
                        &mut findings,
                        &exe,
                        level,
                        &svc.display_name,
                        &format!("Service ({}): {reason}", svc.name),
                        &exe,
                        RiskOrigin::Service { name: svc.name },
                    );
                }
            }
        }
    }

    // 3b. Non-Microsoft scheduled tasks with suspicious or unsigned executables
    if let Ok(out) = Command::new("schtasks")
        .args(["/Query", "/FO", "CSV", "/NH", "/V"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let cols = parse_csv_row(line);
            // TaskName is col 1, Task To Run is col 8 in verbose CSV output.
            let Some(task_path) = cols.get(1) else {
                continue;
            };
            if task_path.starts_with(r"\Microsoft\") || task_path == "TaskName" {
                continue;
            }
            let Some(cmd) = cols.get(8) else {
                continue;
            };
            let Some(exe) = extract_exe_path(cmd) else {
                continue;
            };
            let sig = cached_sig(&exe);
            let name = Path::new(&exe)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| task_path.clone());
            let (level, reason) = assess_process_risk(&name, &exe, Some(&sig));
            if matches!(level, RiskLevel::Suspicious | RiskLevel::Unsigned) {
                push_finding(
                    &mut findings,
                    &exe,
                    level,
                    &name,
                    &format!("Scheduled task ({task_path}): {reason}"),
                    &exe,
                    RiskOrigin::ScheduledTask {
                        path: task_path.clone(),
                    },
                );
            }
        }
    }

    // 4. Risky folders (double extensions & scripts in Temp / Downloads / Public)
    let mut scan_dirs: Vec<(PathBuf, u32, &str, bool)> = Vec::new();
    if let Ok(t) = std::env::var("TEMP") {
        scan_dirs.push((PathBuf::from(t), 2, "in Temp folder", false));
    }
    if let Ok(up) = std::env::var("USERPROFILE") {
        scan_dirs.push((
            PathBuf::from(&up).join("Downloads"),
            1,
            "in Downloads folder",
            false,
        ));
    }
    scan_dirs.push((
        PathBuf::from(r"C:\Users\Public"),
        2,
        "in Public folder",
        true,
    ));

    let mut seen_files = HashSet::new();
    for (dir, depth, where_label, flag_unsigned_exe) in scan_dirs {
        let mut files = Vec::new();
        walk_executables(&dir, depth, &mut files);
        for file in files {
            let s = file.to_string_lossy().into_owned();
            if !seen_files.insert(s.to_lowercase()) || is_self_path(&s) {
                continue;
            }
            let ext = file_ext_lower(&file);
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            if has_double_extension(&file) {
                push_finding(
                    &mut findings,
                    &s,
                    RiskLevel::Suspicious,
                    &name,
                    &format!("Double-extension executable {where_label}"),
                    &s,
                    RiskOrigin::File,
                );
            } else if SCRIPT_EXTS.contains(&ext.as_str()) {
                push_finding(
                    &mut findings,
                    &s,
                    RiskLevel::Unsigned,
                    &name,
                    &format!("Script file {where_label}"),
                    &s,
                    RiskOrigin::File,
                );
            } else if flag_unsigned_exe && EXE_EXTS.contains(&ext.as_str()) {
                let sig = cached_sig(&s);
                if matches!(sig, Signature::Unsigned | Signature::Invalid(_)) {
                    push_finding(
                        &mut findings,
                        &s,
                        RiskLevel::Suspicious,
                        &name,
                        &format!("Unsigned executable {where_label}"),
                        &s,
                        RiskOrigin::File,
                    );
                }
            }
        }
    }

    // 5. Critical Windows security settings
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(k) =
        hklm.open_subkey_with_flags(r"SOFTWARE\Policies\Microsoft\Windows Defender", KEY_READ)
        && k.get_value::<u32, _>("DisableAntiSpyware").ok() == Some(1)
    {
        push_finding(
            &mut findings,
            "setting:defender_disabled",
            RiskLevel::Suspicious,
            "Microsoft Defender disabled via policy",
            "DisableAntiSpyware policy is set to 1",
            "",
            RiskOrigin::SystemSetting {
                tool: "windowsdefender:".into(),
                args: String::new(),
            },
        );
    }
    if let Ok(k) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        KEY_READ,
    ) && k.get_value::<u32, _>("EnableLUA").ok() == Some(0)
    {
        push_finding(
            &mut findings,
            "setting:uac_disabled",
            RiskLevel::Suspicious,
            "User Account Control (UAC) is disabled",
            "EnableLUA is set to 0",
            "",
            RiskOrigin::SystemSetting {
                tool: "UserAccountControlSettings.exe".into(),
                args: String::new(),
            },
        );
    }

    findings.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.name.cmp(&b.name)));
    findings
}

fn mpcmdrun_path() -> Option<PathBuf> {
    let pf = std::env::var("ProgramFiles").ok()?;
    let p = Path::new(&pf).join(r"Windows Defender\MpCmdRun.exe");
    p.is_file().then_some(p)
}

/// Scans a single file with Microsoft Defender (`MpCmdRun.exe`).
/// Returns `(Some(true) = threat, Some(false) = clean, None = unavailable)` and a message.
pub fn defender_scan_file(path: &str) -> (Option<bool>, String) {
    let Some(mp) = mpcmdrun_path() else {
        return (None, "Microsoft Defender (MpCmdRun.exe) not found".into());
    };
    let Ok(out) = Command::new(mp)
        .args([
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            path,
            "-DisableRemediation",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return (None, "Could not launch Microsoft Defender".into());
    };
    let text = String::from_utf8_lossy(&out.stdout);
    match out.status.code() {
        Some(0) => (Some(false), "Defender: clean".into()),
        Some(2) => {
            let threat = text
                .lines()
                .find(|l| {
                    l.trim_start().starts_with("Threat")
                        && l.contains(':')
                        && !l.contains("information")
                })
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_else(|| "Threat detected".into());
            (Some(true), format!("Defender: {threat}"))
        }
        _ => (
            None,
            "Defender could not scan this file (it may be disabled or managed by another AV)"
                .into(),
        ),
    }
}

/// Runs a Microsoft Defender quick scan (`-ScanType 1`).
pub fn defender_quick_scan() -> Result<String, String> {
    let mp = mpcmdrun_path().ok_or_else(|| "Microsoft Defender not found".to_owned())?;
    let out = Command::new(mp)
        .args(["-Scan", "-ScanType", "1"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Could not launch Defender: {e}"))?;
    match out.status.code() {
        Some(0) => Ok("Defender quick scan finished: no threats found.".into()),
        Some(2) => Err(
            "Defender quick scan finished: THREAT FOUND. Check Windows Security > Protection history."
                .into(),
        ),
        _ => Err("Defender quick scan could not complete.".into()),
    }
}

/// Disables associated startup/service/task origins, terminates running PIDs,
/// and quarantines (or permanently deletes) the target file.
pub fn remediate_finding(
    finding: &RiskFinding,
    delete_permanently: bool,
) -> Result<String, String> {
    let mut actions = Vec::new();

    for origin in &finding.origins {
        match origin {
            RiskOrigin::Startup(entry) => {
                if startup::set_startup_enabled(entry, false).is_ok() {
                    actions.push("startup entry disabled".to_owned());
                }
            }
            RiskOrigin::Service { name } => {
                let _ = crate::stop_service(name);
                if crate::set_start_type(name, StartType::Disabled).is_ok() {
                    actions.push(format!("service '{name}' disabled"));
                }
            }
            RiskOrigin::ScheduledTask { path } => {
                let ok = Command::new("schtasks")
                    .args(["/Change", "/TN", path, "/Disable"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status()
                    .is_ok_and(|s| s.success());
                if ok {
                    actions.push(format!("task '{path}' disabled"));
                }
            }
            RiskOrigin::Process { .. } | RiskOrigin::File | RiskOrigin::SystemSetting { .. } => {}
        }
    }

    let pids = finding.pids();
    let mut killed = 0usize;
    for pref in &pids {
        if crate::control::kill(pref).is_ok() {
            killed += 1;
        }
    }
    if killed > 0 {
        actions.push(format!("terminated {killed} process(es)"));
        std::thread::sleep(std::time::Duration::from_millis(600));
    }

    if is_removable_target(&finding.path) {
        if delete_permanently {
            fs::remove_file(&finding.path).map_err(|e| format!("Could not delete file: {e}"))?;
            actions.push("file permanently deleted".to_owned());
        } else {
            let dest = move_to_quarantine(&finding.path)?;
            actions.push(format!("quarantined to {}", dest.display()));
        }
    }

    if actions.is_empty() {
        Err("No automated remediation could be performed (elevation may be required)".into())
    } else {
        Ok(actions.join(", "))
    }
}

fn move_to_quarantine(path: &str) -> Result<PathBuf, String> {
    let local = std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?;
    let qdir = PathBuf::from(local).join("RustWTM").join("quarantine");
    fs::create_dir_all(&qdir).map_err(|e| e.to_string())?;

    let src = Path::new(path);
    let fname = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".into());
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let dest = qdir.join(format!("{ts}_{fname}.quarantine"));

    if fs::rename(src, &dest).is_err() {
        fs::copy(src, &dest).map_err(|e| format!("Quarantine copy failed: {e}"))?;
        fs::remove_file(src).map_err(|e| {
            let _ = fs::remove_file(&dest);
            format!("Quarantine remove failed: {e}")
        })?;
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_system_process_masquerading_outside_windir() {
        let sig = Signature::Signed {
            signer: Some("Acme".into()),
            catalog: false,
        };
        let (level, _) = assess_process_risk(
            "svchost.exe",
            r"C:\Users\alice\AppData\Local\Temp\svchost.exe",
            Some(&sig),
        );
        assert_eq!(level, RiskLevel::Suspicious);
    }

    #[test]
    fn flags_unsigned_in_risky_location_as_suspicious() {
        let (level, _) = assess_process_risk(
            "updater.exe",
            r"C:\Users\alice\Downloads\updater.exe",
            Some(&Signature::Unsigned),
        );
        assert_eq!(level, RiskLevel::Suspicious);
    }

    #[test]
    fn detects_double_extensions() {
        assert!(has_double_extension(Path::new("invoice.pdf.exe")));
        assert!(!has_double_extension(Path::new("setup.exe")));
    }
}
