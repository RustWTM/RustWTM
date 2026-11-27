//! Reversible Windows optimization and privacy tweaks.
//!
//! Security-critical protections (Defender, Windows Update, UAC, CPU
//! mitigations) are intentionally excluded. Every change records its previous
//! value in `%LOCALAPPDATA%\RustWTM\tweak-backup.json` so it can be undone.

use std::collections::BTreeMap;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TweakGroup {
    Privacy,
    AdsAndAi,
    Performance,
    Appearance,
    Edge,
}

impl TweakGroup {
    pub const ALL: [TweakGroup; 5] = [
        Self::Privacy,
        Self::AdsAndAi,
        Self::Performance,
        Self::Appearance,
        Self::Edge,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Privacy => "Privacy & Telemetry",
            Self::AdsAndAi => "Ads, Suggestions & AI",
            Self::Performance => "Performance",
            Self::Appearance => "Appearance & Usability",
            Self::Edge => "Microsoft Edge",
        }
    }
}

#[derive(Debug, Clone)]
pub enum RegValue {
    Dword(u32),
    String(&'static str),
}

#[derive(Debug, Clone)]
pub enum TweakOp {
    /// Registry value under HKLM (`hklm = true`) or HKCU (`hklm = false`).
    Reg {
        hklm: bool,
        path: &'static str,
        name: &'static str,
        value: RegValue,
    },
    /// Creates an empty key with an empty default value under HKCU (e.g. classic context menu).
    HkcuEmptyKey(&'static str),
    /// Disables a scheduled task via `schtasks`.
    DisableTask(&'static str),
}

#[derive(Debug, Clone)]
pub struct TweakDef {
    pub id: &'static str,
    pub group: TweakGroup,
    pub recommended: bool,
    pub win11_only: bool,
    pub name: &'static str,
    pub description: &'static str,
    pub ops: Vec<TweakOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TweakState {
    pub id: String,
    pub group: TweakGroup,
    pub recommended: bool,
    pub name: String,
    pub description: String,
    pub applied: bool,
    pub has_backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum BackupEntry {
    Missing,
    Dword(u32),
    String(String),
    KeyExisted(bool),
    TaskEnabled(bool),
}

type BackupStore = BTreeMap<String, BTreeMap<String, BackupEntry>>;

/// Returns `true` on Windows 11 (build >= 22000).
pub fn is_windows_11() -> bool {
    let Ok(hklm) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
    else {
        return false;
    };
    let build: String = hklm.get_value("CurrentBuildNumber").unwrap_or_default();
    build.trim().parse::<u32>().is_ok_and(|n| n >= 22000)
}

fn backup_path() -> Option<PathBuf> {
    let local = std::env::var("LOCALAPPDATA").ok()?;
    Some(
        PathBuf::from(local)
            .join("RustWTM")
            .join("tweak-backup.json"),
    )
}

fn load_backups() -> BackupStore {
    let Some(path) = backup_path() else {
        return BackupStore::new();
    };
    let Ok(bytes) = fs::read(path) else {
        return BackupStore::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_backups(store: &BackupStore) -> Result<(), String> {
    let Some(path) = backup_path() else {
        return Err("LOCALAPPDATA is not set".into());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(store).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

fn root_key(hklm: bool) -> RegKey {
    RegKey::predef(if hklm {
        HKEY_LOCAL_MACHINE
    } else {
        HKEY_CURRENT_USER
    })
}

fn op_key(op: &TweakOp, idx: usize) -> String {
    match op {
        TweakOp::Reg {
            hklm, path, name, ..
        } => {
            let hive = if *hklm { "HKLM" } else { "HKCU" };
            format!("{idx}:{hive}\\{path}::{name}")
        }
        TweakOp::HkcuEmptyKey(path) => format!("{idx}:HKCU\\{path}::(key)"),
        TweakOp::DisableTask(task) => format!("{idx}:TASK::{task}"),
    }
}

fn read_op_applied(op: &TweakOp) -> bool {
    match op {
        TweakOp::Reg {
            hklm,
            path,
            name,
            value,
        } => {
            let Ok(key) = root_key(*hklm).open_subkey_with_flags(path, KEY_READ) else {
                return false;
            };
            match value {
                RegValue::Dword(expected) => key.get_value::<u32, _>(name).ok() == Some(*expected),
                RegValue::String(expected) => {
                    key.get_value::<String, _>(name).ok().as_deref() == Some(*expected)
                }
            }
        }
        TweakOp::HkcuEmptyKey(path) => root_key(false)
            .open_subkey_with_flags(path, KEY_READ)
            .is_ok(),
        TweakOp::DisableTask(task) => {
            let Ok(out) = Command::new("schtasks")
                .args(["/Query", "/TN", task, "/FO", "LIST"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
            else {
                return false;
            };
            if !out.status.success() {
                return true;
            }
            let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            text.contains("disabled")
        }
    }
}

/// Checks whether all operations of `tweak` are currently in their applied state.
pub fn is_applied(tweak: &TweakDef) -> bool {
    !tweak.ops.is_empty() && tweak.ops.iter().all(read_op_applied)
}

/// Applies a tweak after saving previous values for rollback.
pub fn apply_tweak(id: &str) -> Result<(), String> {
    let tweak = catalog()
        .into_iter()
        .find(|t| t.id == id)
        .ok_or_else(|| format!("Unknown tweak: {id}"))?;

    let mut backups = load_backups();
    let entry_map = backups.entry(tweak.id.to_owned()).or_default();

    for (idx, op) in tweak.ops.iter().enumerate() {
        let key_id = op_key(op, idx);
        match op {
            TweakOp::Reg {
                hklm,
                path,
                name,
                value,
            } => {
                entry_map.entry(key_id).or_insert_with(|| {
                    match root_key(*hklm).open_subkey_with_flags(path, KEY_READ) {
                        Ok(k) => match value {
                            RegValue::Dword(_) => k
                                .get_value::<u32, _>(name)
                                .map(BackupEntry::Dword)
                                .unwrap_or(BackupEntry::Missing),
                            RegValue::String(_) => k
                                .get_value::<String, _>(name)
                                .map(BackupEntry::String)
                                .unwrap_or(BackupEntry::Missing),
                        },
                        Err(_) => BackupEntry::Missing,
                    }
                });
                let (k, _) = root_key(*hklm)
                    .create_subkey(path)
                    .map_err(|e| format!("{path}: {e}"))?;
                match value {
                    RegValue::Dword(v) => k.set_value(name, v).map_err(|e| e.to_string())?,
                    RegValue::String(v) => k.set_value(name, v).map_err(|e| e.to_string())?,
                }
            }
            TweakOp::HkcuEmptyKey(path) => {
                entry_map.entry(key_id).or_insert_with(|| {
                    let existed = root_key(false)
                        .open_subkey_with_flags(path, KEY_READ)
                        .is_ok();
                    BackupEntry::KeyExisted(existed)
                });
                let (k, _) = root_key(false)
                    .create_subkey(path)
                    .map_err(|e| format!("{path}: {e}"))?;
                let _ = k.set_value("", &"");
            }
            TweakOp::DisableTask(task) => {
                entry_map.entry(key_id).or_insert_with(|| {
                    let enabled = !read_op_applied(op);
                    BackupEntry::TaskEnabled(enabled)
                });
                let _ = Command::new("schtasks")
                    .args(["/Change", "/TN", task, "/Disable"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .output();
            }
        }
    }

    save_backups(&backups)?;
    Ok(())
}

/// Reverts a tweak using its saved backup.
pub fn undo_tweak(id: &str) -> Result<(), String> {
    let tweak = catalog()
        .into_iter()
        .find(|t| t.id == id)
        .ok_or_else(|| format!("Unknown tweak: {id}"))?;

    let mut backups = load_backups();
    let Some(entry_map) = backups.remove(tweak.id) else {
        return Err("No saved backup exists for this tweak".into());
    };

    for (idx, op) in tweak.ops.iter().enumerate() {
        let key_id = op_key(op, idx);
        let Some(prev) = entry_map.get(&key_id) else {
            continue;
        };
        match op {
            TweakOp::Reg {
                hklm, path, name, ..
            } => match prev {
                BackupEntry::Missing => {
                    if let Ok(k) = root_key(*hklm).open_subkey_with_flags(path, KEY_WRITE) {
                        let _ = k.delete_value(name);
                    }
                }
                BackupEntry::Dword(v) => {
                    if let Ok((k, _)) = root_key(*hklm).create_subkey(path) {
                        k.set_value(name, v).map_err(|e| e.to_string())?;
                    }
                }
                BackupEntry::String(v) => {
                    if let Ok((k, _)) = root_key(*hklm).create_subkey(path) {
                        k.set_value(name, v).map_err(|e| e.to_string())?;
                    }
                }
                _ => {}
            },
            TweakOp::HkcuEmptyKey(path) => {
                if matches!(prev, BackupEntry::KeyExisted(false)) {
                    let _ = root_key(false).delete_subkey_all(path);
                }
            }
            TweakOp::DisableTask(task) => {
                if matches!(prev, BackupEntry::TaskEnabled(true)) {
                    let _ = Command::new("schtasks")
                        .args(["/Change", "/TN", task, "/Enable"])
                        .creation_flags(CREATE_NO_WINDOW)
                        .output();
                }
            }
        }
    }

    save_backups(&backups)?;
    Ok(())
}

/// Returns all tweaks applicable to the current Windows version along with their live status.
pub fn list_states() -> Vec<TweakState> {
    let win11 = is_windows_11();
    let backups = load_backups();
    catalog()
        .into_iter()
        .filter(|t| win11 || !t.win11_only)
        .map(|t| TweakState {
            id: t.id.to_owned(),
            group: t.group,
            recommended: t.recommended,
            name: t.name.to_owned(),
            description: t.description.to_owned(),
            applied: is_applied(&t),
            has_backup: backups.contains_key(t.id),
        })
        .collect()
}

fn hkcu_dword(path: &'static str, name: &'static str, v: u32) -> TweakOp {
    TweakOp::Reg {
        hklm: false,
        path,
        name,
        value: RegValue::Dword(v),
    }
}

fn hklm_dword(path: &'static str, name: &'static str, v: u32) -> TweakOp {
    TweakOp::Reg {
        hklm: true,
        path,
        name,
        value: RegValue::Dword(v),
    }
}

fn hklm_str(path: &'static str, name: &'static str, v: &'static str) -> TweakOp {
    TweakOp::Reg {
        hklm: true,
        path,
        name,
        value: RegValue::String(v),
    }
}

const CDM: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
const ADV: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const EDGE_POL: &str = r"SOFTWARE\Policies\Microsoft\Edge";
const WIN_AI: &str = r"Software\Policies\Microsoft\Windows\WindowsAI";

pub fn catalog() -> Vec<TweakDef> {
    vec![
        // Privacy & Telemetry
        TweakDef {
            id: "telemetry_min",
            group: TweakGroup::Privacy,
            recommended: true,
            win11_only: false,
            name: "Minimize Windows diagnostic telemetry",
            description: "Sets Windows diagnostic data collection to the lowest level supported by your edition.",
            ops: vec![
                hklm_dword(
                    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                    "AllowTelemetry",
                    0,
                ),
                hklm_dword(
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                    "AllowTelemetry",
                    0,
                ),
            ],
        },
        TweakDef {
            id: "advertising_id",
            group: TweakGroup::Privacy,
            recommended: true,
            win11_only: false,
            name: "Disable Windows advertising ID",
            description: "Prevents apps from using your advertising ID for cross-app tracking.",
            ops: vec![hkcu_dword(
                r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                "Enabled",
                0,
            )],
        },
        TweakDef {
            id: "tailored_experiences",
            group: TweakGroup::Privacy,
            recommended: true,
            win11_only: false,
            name: "Disable tailored diagnostic experiences",
            description: "Stops Windows from using diagnostic data for personalized tips and ads.",
            ops: vec![hkcu_dword(
                r"Software\Microsoft\Windows\CurrentVersion\Privacy",
                "TailoredExperiencesWithDiagnosticDataEnabled",
                0,
            )],
        },
        TweakDef {
            id: "activity_history",
            group: TweakGroup::Privacy,
            recommended: true,
            win11_only: false,
            name: "Disable Activity History & Timeline upload",
            description: "Stops Windows from collecting and syncing local activity history.",
            ops: vec![
                hklm_dword(
                    r"SOFTWARE\Policies\Microsoft\Windows\System",
                    "EnableActivityFeed",
                    0,
                ),
                hklm_dword(
                    r"SOFTWARE\Policies\Microsoft\Windows\System",
                    "PublishUserActivities",
                    0,
                ),
                hklm_dword(
                    r"SOFTWARE\Policies\Microsoft\Windows\System",
                    "UploadUserActivities",
                    0,
                ),
            ],
        },
        TweakDef {
            id: "ceip_tasks",
            group: TweakGroup::Privacy,
            recommended: true,
            win11_only: false,
            name: "Disable Customer Experience Improvement tasks",
            description: "Disables Microsoft Compatibility Appraiser and CEIP background scheduled tasks.",
            ops: vec![
                TweakOp::DisableTask(
                    r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                ),
                TweakOp::DisableTask(
                    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                ),
                TweakOp::DisableTask(
                    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                ),
            ],
        },
        // Ads, Suggestions & AI
        TweakDef {
            id: "start_suggestions",
            group: TweakGroup::AdsAndAi,
            recommended: true,
            win11_only: false,
            name: "Disable Start menu & Settings suggestions",
            description: "Turns off suggested apps, silent Store installs, and tips in Start and Settings.",
            ops: vec![
                hkcu_dword(CDM, "SubscribedContent-338388Enabled", 0),
                hkcu_dword(CDM, "SubscribedContent-338389Enabled", 0),
                hkcu_dword(CDM, "SubscribedContent-338393Enabled", 0),
                hkcu_dword(CDM, "SubscribedContent-353694Enabled", 0),
                hkcu_dword(CDM, "SubscribedContent-353696Enabled", 0),
                hkcu_dword(CDM, "SilentInstalledAppsEnabled", 0),
                hkcu_dword(CDM, "SystemPaneSuggestionsEnabled", 0),
            ],
        },
        TweakDef {
            id: "lockscreen_ads",
            group: TweakGroup::AdsAndAi,
            recommended: true,
            win11_only: false,
            name: "Disable lock screen tips & Spotlight overlays",
            description: "Removes fun facts, tips, and promotional overlays on the lock screen.",
            ops: vec![
                hkcu_dword(CDM, "RotatingLockScreenOverlayEnabled", 0),
                hkcu_dword(CDM, "SubscribedContent-338387Enabled", 0),
            ],
        },
        TweakDef {
            id: "bing_search",
            group: TweakGroup::AdsAndAi,
            recommended: true,
            win11_only: false,
            name: "Disable Bing web results in Start Search",
            description: "Keeps Start menu search local without sending queries to Bing.",
            ops: vec![
                hkcu_dword(
                    r"Software\Policies\Microsoft\Windows\Explorer",
                    "DisableSearchBoxSuggestions",
                    1,
                ),
                hkcu_dword(
                    r"Software\Microsoft\Windows\CurrentVersion\Search",
                    "BingSearchEnabled",
                    0,
                ),
            ],
        },
        TweakDef {
            id: "copilot",
            group: TweakGroup::AdsAndAi,
            recommended: true,
            win11_only: false,
            name: "Disable Windows Copilot",
            description: "Turns off the Windows Copilot policy and hides the Copilot button.",
            ops: vec![
                hklm_dword(
                    r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
                    "TurnOffWindowsCopilot",
                    1,
                ),
                hkcu_dword(
                    r"Software\Policies\Microsoft\Windows\WindowsCopilot",
                    "TurnOffWindowsCopilot",
                    1,
                ),
            ],
        },
        TweakDef {
            id: "recall",
            group: TweakGroup::AdsAndAi,
            recommended: true,
            win11_only: true,
            name: "Disable Windows Recall snapshots",
            description: "Prevents Windows 11 Recall from capturing screen snapshots.",
            ops: vec![
                hklm_dword(WIN_AI, "DisableAIDataAnalysis", 1),
                hkcu_dword(WIN_AI, "DisableAIDataAnalysis", 1),
            ],
        },
        TweakDef {
            id: "widgets",
            group: TweakGroup::AdsAndAi,
            recommended: true,
            win11_only: true,
            name: "Hide Taskbar Widgets & News",
            description: "Hides the Windows 11 Widgets button and disables News and Interests feed.",
            ops: vec![
                hkcu_dword(ADV, "TaskbarDa", 0),
                hklm_dword(
                    r"SOFTWARE\Policies\Microsoft\Dsh",
                    "AllowNewsAndInterests",
                    0,
                ),
            ],
        },
        // Performance
        TweakDef {
            id: "startup_delay",
            group: TweakGroup::Performance,
            recommended: true,
            win11_only: false,
            name: "Remove startup app launch delay",
            description: "Sets StartupDelayInMSec to 0 so desktop startup items launch immediately.",
            ops: vec![hkcu_dword(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize",
                "StartupDelayInMSec",
                0,
            )],
        },
        TweakDef {
            id: "menu_delay",
            group: TweakGroup::Performance,
            recommended: true,
            win11_only: false,
            name: "Speed up menu open animation",
            description: "Reduces MenuShowDelay from 400 ms to 20 ms for snappier classic menus.",
            ops: vec![TweakOp::Reg {
                hklm: false,
                path: r"Control Panel\Desktop",
                name: "MenuShowDelay",
                value: RegValue::String("20"),
            }],
        },
        TweakDef {
            id: "background_apps",
            group: TweakGroup::Performance,
            recommended: false,
            win11_only: false,
            name: "Disable UWP background app execution",
            description: "Stops Microsoft Store apps from running background tasks when closed.",
            ops: vec![hkcu_dword(
                r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
                "GlobalUserDisabled",
                1,
            )],
        },
        TweakDef {
            id: "game_dvr",
            group: TweakGroup::Performance,
            recommended: false,
            win11_only: false,
            name: "Disable background Game DVR recording",
            description: "Turns off background screen recording by Xbox Game Bar.",
            ops: vec![
                hkcu_dword(
                    r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
                    "AppCaptureEnabled",
                    0,
                ),
                hkcu_dword(r"System\GameConfigStore", "GameDVR_Enabled", 0),
            ],
        },
        // Appearance & Usability
        TweakDef {
            id: "classic_context_menu",
            group: TweakGroup::Appearance,
            recommended: false,
            win11_only: true,
            name: "Use classic Windows 10 right-click menu",
            description: "Restores the full Explorer context menu without needing 'Show more options'.",
            ops: vec![TweakOp::HkcuEmptyKey(
                r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
            )],
        },
        TweakDef {
            id: "show_extensions",
            group: TweakGroup::Appearance,
            recommended: true,
            win11_only: false,
            name: "Show file name extensions in Explorer",
            description: "Displays full file extensions (helps spot double-extension executables).",
            ops: vec![hkcu_dword(ADV, "HideFileExt", 0)],
        },
        TweakDef {
            id: "taskbar_align_left",
            group: TweakGroup::Appearance,
            recommended: false,
            win11_only: true,
            name: "Align Windows 11 taskbar to the left",
            description: "Moves the Start button and taskbar icons to the left side.",
            ops: vec![hkcu_dword(ADV, "TaskbarAl", 0)],
        },
        TweakDef {
            id: "taskbar_end_task",
            group: TweakGroup::Appearance,
            recommended: true,
            win11_only: true,
            name: "Enable 'End task' on taskbar right-click",
            description: "Adds an End task option directly to the taskbar app context menu.",
            ops: vec![hkcu_dword(
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings",
                "TaskbarEndTask",
                1,
            )],
        },
        // Microsoft Edge
        TweakDef {
            id: "edge_background",
            group: TweakGroup::Edge,
            recommended: true,
            win11_only: false,
            name: "Stop Edge from running in the background",
            description: "Disables Edge Startup Boost and background mode when all windows are closed.",
            ops: vec![
                hklm_dword(EDGE_POL, "StartupBoostEnabled", 0),
                hklm_dword(EDGE_POL, "BackgroundModeEnabled", 0),
            ],
        },
        TweakDef {
            id: "edge_bloat",
            group: TweakGroup::Edge,
            recommended: true,
            win11_only: false,
            name: "Disable Edge shopping, sidebar & telemetry",
            description: "Turns off Edge shopping assistant, sidebar hubs, and diagnostic reporting.",
            ops: vec![
                hklm_dword(EDGE_POL, "EdgeShoppingAssistantEnabled", 0),
                hklm_dword(EDGE_POL, "HubsSidebarEnabled", 0),
                hklm_str(EDGE_POL, "DiagnosticData", "0"),
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique() {
        let cat = catalog();
        let mut ids = std::collections::HashSet::new();
        for t in &cat {
            assert!(ids.insert(t.id), "duplicate tweak id: {}", t.id);
            assert!(!t.ops.is_empty(), "empty ops for {}", t.id);
        }
    }
}
