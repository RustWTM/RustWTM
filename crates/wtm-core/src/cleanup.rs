//! Safe, categorized disk cleanup with dry-run scanning, reparse-point
//! protection, and optional minimum file-age guards.

use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const MAX_WALK_DEPTH: u32 = 48;

#[derive(Debug, Clone)]
pub enum CleanupTarget {
    /// Everything inside the directory (the directory itself is preserved).
    Dir(PathBuf),
    /// Files in the directory matching a lowercase prefix and suffix.
    PrefixSuffix {
        dir: PathBuf,
        prefix: &'static str,
        suffix: &'static str,
    },
    /// A single file.
    File(PathBuf),
    /// Windows Recycle Bin.
    RecycleBin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_enabled: bool,
    pub bytes: u64,
    pub files: u64,
    pub skipped: u64,
    pub scanned: bool,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct CleanupCategory {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub default_enabled: bool,
    pub min_age: Option<Duration>,
    pub targets: Vec<CleanupTarget>,
    pub bytes: u64,
    pub files: u64,
    pub skipped: u64,
    pub scanned: bool,
    pub freed_bytes: u64,
}

impl CleanupCategory {
    pub fn summary(&self) -> CleanupSummary {
        CleanupSummary {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            description: self.description.to_owned(),
            default_enabled: self.default_enabled,
            bytes: self.bytes,
            files: self.files,
            skipped: self.skipped,
            scanned: self.scanned,
            freed_bytes: self.freed_bytes,
        }
    }
}

#[derive(Default)]
struct WalkStats {
    bytes: u64,
    files: u64,
    skipped: u64,
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|v| v.len() > 3)
        .map(PathBuf::from)
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            if md.is_dir() && (md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0) {
                Some(e.path())
            } else {
                None
            }
        })
        .collect()
}

/// Root directories and very short paths are never cleaned.
pub fn is_safe_cleanup_path(path: &Path) -> bool {
    path.is_absolute() && path.components().count() >= 4
}

fn walk_dir(
    dir: &Path,
    min_age: Option<Duration>,
    delete: bool,
    stats: &mut WalkStats,
    depth: u32,
) {
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
            if depth < MAX_WALK_DEPTH {
                walk_dir(&path, min_age, delete, stats, depth + 1);
            }
            if delete {
                let _ = fs::remove_dir(&path);
            }
        } else {
            process_file(&path, &md, min_age, delete, stats);
        }
    }
}

fn process_file(
    path: &Path,
    md: &fs::Metadata,
    min_age: Option<Duration>,
    delete: bool,
    stats: &mut WalkStats,
) {
    if let Some(age) = min_age {
        let old_enough = md
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|el| el >= age);
        if !old_enough {
            return;
        }
    }
    let size = md.len();
    if !delete {
        stats.bytes = stats.bytes.saturating_add(size);
        stats.files = stats.files.saturating_add(1);
        return;
    }
    if md.file_attributes() & FILE_ATTRIBUTE_READONLY != 0 {
        let mut perm = md.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = fs::set_permissions(path, perm);
    }
    match fs::remove_file(path) {
        Ok(()) => {
            stats.bytes = stats.bytes.saturating_add(size);
            stats.files = stats.files.saturating_add(1);
        }
        Err(_) => {
            stats.skipped = stats.skipped.saturating_add(1);
        }
    }
}

fn run_category(cat: &CleanupCategory, delete: bool) -> WalkStats {
    let mut stats = WalkStats::default();
    for target in &cat.targets {
        match target {
            CleanupTarget::Dir(dir) => {
                if is_safe_cleanup_path(dir) {
                    walk_dir(dir, cat.min_age, delete, &mut stats, 0);
                }
            }
            CleanupTarget::PrefixSuffix {
                dir,
                prefix,
                suffix,
            } => {
                if !is_safe_cleanup_path(dir) {
                    continue;
                }
                let Ok(rd) = fs::read_dir(dir) else {
                    continue;
                };
                for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().to_lowercase();
                    if name.starts_with(prefix)
                        && name.ends_with(suffix)
                        && let Ok(md) = entry.metadata()
                        && md.is_file()
                    {
                        process_file(&entry.path(), &md, cat.min_age, delete, &mut stats);
                    }
                }
            }
            CleanupTarget::File(file) => {
                if let Ok(md) = fs::symlink_metadata(file)
                    && md.is_file()
                    && is_safe_cleanup_path(file)
                {
                    process_file(file, &md, cat.min_age, delete, &mut stats);
                }
            }
            CleanupTarget::RecycleBin => {
                if let Ok(rb) = wtm_sys::recycle_bin::query_recycle_bin() {
                    if delete && rb.items > 0 {
                        if wtm_sys::recycle_bin::empty_recycle_bin().is_ok() {
                            stats.bytes = stats.bytes.saturating_add(rb.bytes);
                            stats.files = stats.files.saturating_add(rb.items);
                        } else {
                            stats.skipped = stats.skipped.saturating_add(rb.items);
                        }
                    } else if !delete {
                        stats.bytes = stats.bytes.saturating_add(rb.bytes);
                        stats.files = stats.files.saturating_add(rb.items);
                    }
                }
            }
        }
    }
    stats
}

/// Builds the default list of Windows cleanup categories.
pub fn default_categories() -> Vec<CleanupCategory> {
    let local = env_dir("LOCALAPPDATA");
    let pdata = env_dir("ProgramData");
    let windir = env_dir("WINDIR").unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let day = Some(Duration::from_secs(24 * 60 * 60));

    let mut cats = Vec::new();
    let mut push = |id: &'static str,
                    name: &'static str,
                    description: &'static str,
                    default_enabled: bool,
                    min_age: Option<Duration>,
                    targets: Vec<CleanupTarget>| {
        cats.push(CleanupCategory {
            id,
            name,
            description,
            default_enabled,
            min_age,
            targets,
            bytes: 0,
            files: 0,
            skipped: 0,
            scanned: false,
            freed_bytes: 0,
        });
    };

    let mut temp_targets = Vec::new();
    if let Some(t) = env_dir("TEMP") {
        temp_targets.push(CleanupTarget::Dir(t));
    }
    temp_targets.push(CleanupTarget::Dir(windir.join("Temp")));
    if let Some(l) = &local {
        temp_targets.push(CleanupTarget::Dir(l.join("CrashDumps")));
    }
    push(
        "temp",
        "Temporary files & crash dumps",
        "User and Windows Temp folders plus local crash dumps older than 24 hours.",
        true,
        day,
        temp_targets,
    );

    push(
        "logs",
        "Windows maintenance logs",
        "CBS, DISM and Windows Update servicing logs older than 24 hours.",
        true,
        day,
        vec![
            CleanupTarget::Dir(windir.join(r"Logs\CBS")),
            CleanupTarget::Dir(windir.join(r"Logs\DISM")),
            CleanupTarget::Dir(windir.join(r"Logs\WindowsUpdate")),
        ],
    );

    let mut shader_targets = Vec::new();
    if let Some(l) = &local {
        shader_targets.push(CleanupTarget::Dir(l.join("D3DSCache")));
        shader_targets.push(CleanupTarget::Dir(l.join(r"NVIDIA\DXCache")));
        shader_targets.push(CleanupTarget::Dir(l.join(r"NVIDIA\GLCache")));
    }
    if let Some(p) = &pdata {
        shader_targets.push(CleanupTarget::Dir(p.join(r"NVIDIA Corporation\NV_Cache")));
    }
    push(
        "shader",
        "Graphics shader caches",
        "DirectX and NVIDIA compiled shader caches (rebuilt automatically when needed).",
        true,
        None,
        shader_targets,
    );

    let mut thumb_targets = Vec::new();
    if let Some(l) = &local {
        let ex = l.join(r"Microsoft\Windows\Explorer");
        thumb_targets.push(CleanupTarget::PrefixSuffix {
            dir: ex.clone(),
            prefix: "thumbcache_",
            suffix: ".db",
        });
        thumb_targets.push(CleanupTarget::PrefixSuffix {
            dir: ex,
            prefix: "iconcache_",
            suffix: ".db",
        });
    }
    push(
        "thumbs",
        "Thumbnail & icon cache",
        "Explorer thumbnail and icon database files. Files currently in use are skipped.",
        true,
        None,
        thumb_targets,
    );

    let mut browser_targets = Vec::new();
    if let Some(l) = &local {
        for base in [
            r"Google\Chrome\User Data",
            r"Microsoft\Edge\User Data",
            r"BraveSoftware\Brave-Browser\User Data",
            r"Vivaldi\User Data",
        ] {
            let b = l.join(base);
            for prof in subdirs(&b) {
                if prof.join("Cache").is_dir() || prof.join("Code Cache").is_dir() {
                    browser_targets.push(CleanupTarget::Dir(prof.join("Cache")));
                    browser_targets.push(CleanupTarget::Dir(prof.join("Code Cache")));
                    browser_targets.push(CleanupTarget::Dir(prof.join("GPUCache")));
                }
            }
            browser_targets.push(CleanupTarget::Dir(b.join("ShaderCache")));
            browser_targets.push(CleanupTarget::Dir(b.join("GrShaderCache")));
        }
        for prof in subdirs(&l.join(r"Mozilla\Firefox\Profiles")) {
            browser_targets.push(CleanupTarget::Dir(prof.join("cache2")));
        }
    }
    push(
        "browser",
        "Browser caches",
        "Chrome, Edge, Brave, Vivaldi and Firefox caches. History, passwords and sessions are kept.",
        true,
        None,
        browser_targets,
    );

    let mut dev_targets = Vec::new();
    if let Some(l) = &local {
        dev_targets.push(CleanupTarget::Dir(l.join(r"npm-cache\_cacache")));
        dev_targets.push(CleanupTarget::Dir(l.join(r"pip\cache")));
        dev_targets.push(CleanupTarget::Dir(l.join(r"NuGet\v3-cache")));
        dev_targets.push(CleanupTarget::Dir(l.join("go-build")));
        dev_targets.push(CleanupTarget::Dir(l.join(r"Yarn\Cache")));
    }
    push(
        "dev",
        "Developer package caches",
        "npm, pip, NuGet, Yarn and Go build caches. Next build will re-download needed packages.",
        false,
        None,
        dev_targets,
    );

    push(
        "recycle",
        "Recycle Bin",
        "Permanently removes items currently in the Windows Recycle Bin.",
        false,
        None,
        vec![CleanupTarget::RecycleBin],
    );

    cats
}

/// Scans all categories without deleting anything and updates their estimates.
pub fn scan_categories(cats: &mut [CleanupCategory]) {
    for cat in cats {
        let stats = run_category(cat, false);
        cat.bytes = stats.bytes;
        cat.files = stats.files;
        cat.skipped = 0;
        cat.scanned = true;
    }
}

/// Cleans the selected categories (by `id`) and returns total `(freed_bytes, freed_files, skipped)`.
pub fn clean_categories(cats: &mut [CleanupCategory], selected_ids: &[String]) -> (u64, u64, u64) {
    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    let mut total_skipped = 0u64;

    for cat in cats {
        if !selected_ids.iter().any(|id| id == cat.id) {
            continue;
        }
        let stats = run_category(cat, true);
        cat.freed_bytes = stats.bytes;
        cat.skipped = stats.skipped;
        total_bytes = total_bytes.saturating_add(stats.bytes);
        total_files = total_files.saturating_add(stats.files);
        total_skipped = total_skipped.saturating_add(stats.skipped);

        // Re-scan remaining size after deletion.
        let after = run_category(cat, false);
        cat.bytes = after.bytes;
        cat.files = after.files;
        cat.scanned = true;
    }

    (total_bytes, total_files, total_skipped)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTrimmed {
    pub pid: u32,
    pub name: String,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub freed_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTrimReport {
    pub total_bytes: u64,
    pub before_used_bytes: u64,
    pub after_used_bytes: u64,
    pub freed_bytes: u64,
    pub trimmed_processes: usize,
    pub skipped_processes: usize,
    pub details: Vec<ProcessTrimmed>,
}

/// Trims working sets of non-protected running processes and compares system
/// and per-process memory usage before and after.
pub fn trim_system_memory(processes: &[crate::ProcessInfo]) -> MemoryTrimReport {
    let before = wtm_sys::system::memory_status().unwrap_or_default();
    let before_used = before.total_phys.saturating_sub(before.avail_phys);

    let mut trimmed_list: Vec<(u32, i64, String, u64)> = Vec::new();
    let mut skipped = 0usize;
    for p in processes {
        let pref = crate::control::ProcessRef::from(p);
        if crate::control::trim_memory(&pref).is_ok() {
            trimmed_list.push((p.pid, p.create_time, p.name.clone(), p.working_set));
        } else {
            skipped += 1;
        }
    }

    // Brief pause so Windows updates the working sets and global memory counters.
    std::thread::sleep(Duration::from_millis(180));

    let after = wtm_sys::system::memory_status().unwrap_or_default();
    let after_used = after.total_phys.saturating_sub(after.avail_phys);
    let freed = before_used.saturating_sub(after_used);

    let after_map: std::collections::HashMap<(u32, i64), u64> = crate::Sampler::new()
        .sample()
        .map(|s| {
            s.processes
                .into_iter()
                .map(|p| ((p.pid, p.create_time), p.working_set))
                .collect()
        })
        .unwrap_or_default();

    let mut details: Vec<ProcessTrimmed> = trimmed_list
        .iter()
        .filter_map(|(pid, create_time, name, before_ws)| {
            let after_ws = after_map.get(&(*pid, *create_time)).copied()?;
            let freed_ws = before_ws.saturating_sub(after_ws);
            (freed_ws > 0).then(|| ProcessTrimmed {
                pid: *pid,
                name: name.clone(),
                before_bytes: *before_ws,
                after_bytes: after_ws,
                freed_bytes: freed_ws,
            })
        })
        .collect();
    details.sort_by_key(|a| std::cmp::Reverse(a.freed_bytes));

    MemoryTrimReport {
        total_bytes: after.total_phys.max(before.total_phys),
        before_used_bytes: before_used,
        after_used_bytes: after_used,
        freed_bytes: freed,
        trimmed_processes: trimmed_list.len(),
        skipped_processes: skipped,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_or_root_paths() {
        assert!(!is_safe_cleanup_path(Path::new(r"C:\")));
        assert!(!is_safe_cleanup_path(Path::new(r"C:\Windows")));
        assert!(is_safe_cleanup_path(Path::new(
            r"C:\Users\test\AppData\Temp"
        )));
    }

    #[test]
    fn scan_and_clean_respects_temp_directory_and_min_age() {
        let base = std::env::temp_dir().join(format!("wtm_cleanup_test_{}", std::process::id()));
        let sub = base.join("nested").join("cache");
        fs::create_dir_all(&sub).unwrap();
        let file = sub.join("old.tmp");
        fs::write(&file, b"1234567890").unwrap();

        let mut cats = vec![CleanupCategory {
            id: "test",
            name: "Test",
            description: "Test",
            default_enabled: true,
            min_age: Some(Duration::from_secs(3600)),
            targets: vec![CleanupTarget::Dir(sub.clone())],
            bytes: 0,
            files: 0,
            skipped: 0,
            scanned: false,
            freed_bytes: 0,
        }];

        // Freshly written file is younger than 1 hour, so min_age skips it.
        scan_categories(&mut cats);
        assert_eq!(cats[0].files, 0);

        // Without min_age, scan finds it and clean removes it.
        cats[0].min_age = None;
        scan_categories(&mut cats);
        assert_eq!(cats[0].files, 1);
        assert_eq!(cats[0].bytes, 10);

        let (freed, count, skipped) = clean_categories(&mut cats, &["test".to_owned()]);
        assert_eq!((freed, count, skipped), (10, 1, 0));
        assert!(!file.exists());

        let _ = fs::remove_dir_all(&base);
    }
}
