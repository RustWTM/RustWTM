//! Structured package identities and explicitly reviewed update plans.
use serde::{Deserialize, Serialize};
use std::time::Duration;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub id: String,
    pub source: String,
    pub name: String,
    pub installed: String,
    pub target: Option<String>,
}
/// Returns `true` when a Store package ID prefix matches common preinstalled
/// bloatware/promotional apps.
pub fn is_recommended_bloatware(id: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "microsoft.bingnews",
        "microsoft.bingweather",
        "microsoft.gethelp",
        "microsoft.getstarted",
        "microsoft.microsoft3dviewer",
        "microsoft.microsoftofficehub",
        "microsoft.microsoftsolitairecollection",
        "microsoft.mixedreality.portal",
        "microsoft.oneconnect",
        "microsoft.powerautomatedesktop",
        "microsoft.skypeapp",
        "microsoft.todos",
        "microsoft.windows.devhome",
        "microsoft.windowsfeedbackhub",
        "microsoft.windowsmaps",
        "microsoft.zunevideo",
        "microsoftcorporationii.microsoftfamily",
        "king.com.",
        "spotifyab.spotifymusic",
        "facebook.",
        "bytedancepte.ltd.tiktok",
        "4df9e0f8.netflix",
        "amazonvideo.primevideo",
        "disney.",
        "linkedinforwindows",
    ];
    let lower = id.to_ascii_lowercase();
    PREFIXES.iter().any(|p| lower.starts_with(p))
}

/// Removes a current-user Microsoft Store package by ID or family name.
pub fn remove_store_app(id_or_family: &str) -> Result<String, String> {
    if !identity(id_or_family) {
        return Err("Invalid Store package identifier".into());
    }
    let script = format!(
        "$pkgs = Get-AppxPackage | Where-Object {{ $_.Name -eq '{id_or_family}' -or $_.PackageFamilyName -eq '{id_or_family}' }}; \
         if (-not $pkgs) {{ throw 'Package not found for current user.' }}; \
         $pkgs | Remove-AppxPackage -ErrorAction Stop"
    );
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("powershell: {e}"))?;

    if out.status.success() {
        Ok(format!("Removed Store package '{id_or_family}'."))
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        Err(if err.is_empty() {
            format!("Could not remove '{id_or_family}'")
        } else {
            err
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreApp {
    pub id: String,
    pub family: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub location: String,
    pub removable: bool,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub packages: Vec<Package>,
    pub store: Vec<StoreApp>,
    pub warnings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePlan {
    pub packages: Vec<Package>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    pub id: String,
    pub source: String,
    pub status: String,
    pub message: String,
}
fn text(s: &str) -> bool {
    s.len() <= 512 && !s.chars().any(char::is_control)
}
fn identity(s: &str) -> bool {
    !s.is_empty()
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
impl UpdatePlan {
    pub fn new(selected: &[Package]) -> Result<Self, String> {
        if selected.is_empty() || selected.len() > 16 {
            return Err("Select between one and sixteen packages".into());
        }
        let mut ids = std::collections::HashSet::new();
        for p in selected {
            if !identity(&p.id)
                || !matches!(p.source.as_str(), "winget" | "msstore")
                || p.installed.is_empty()
                || !text(&p.installed)
                || !text(&p.name)
                || p.target
                    .as_ref()
                    .is_none_or(|t| !text(t) || t.is_empty() || t == &p.installed)
                || !ids.insert((&p.source, &p.id))
            {
                return Err(
                    "Package update requires an unambiguous source, identifier and version change"
                        .into(),
                );
            }
        }
        Ok(Self {
            packages: selected.to_vec(),
        })
    }
}
pub fn inventory() -> Result<Inventory, String> {
    let value = crate::probe::json(
        include_str!("packages.ps1"),
        &serde_json::json!({"operation":"inventory"}),
        Duration::from_secs(60),
    )?;
    let report: Inventory = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if report.packages.len() > 1024
        || report.store.len() > 1024
        || report.warnings.len() > 32
        || report.packages.iter().any(|p| {
            !text(&p.id)
                || !text(&p.source)
                || !text(&p.name)
                || !text(&p.installed)
                || p.target.as_ref().is_some_and(|s| !text(s))
        })
        || report.store.iter().any(|p| {
            [
                &p.id,
                &p.family,
                &p.name,
                &p.publisher,
                &p.version,
                &p.location,
            ]
            .iter()
            .any(|s| s.len() > 2048 || s.chars().any(char::is_control))
        })
    {
        return Err("Package inventory exceeds its limit".into());
    }
    Ok(report)
}
pub fn update(plan: &UpdatePlan) -> Result<Vec<UpdateResult>, String> {
    // Revalidate even when a caller constructed/deserialized the public plan directly.
    let plan = UpdatePlan::new(&plan.packages)?;
    let input = serde_json::json!({"operation":"update","packages":plan.packages});
    let value = crate::probe::json(
        include_str!("packages.ps1"),
        &input,
        Duration::from_secs(15 * 60),
    )?;
    let results: Vec<UpdateResult> = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if results.len() != plan.packages.len()
        || results
            .iter()
            .zip(&plan.packages)
            .any(|(r, p)| r.id != p.id || r.source != p.source || r.message.len() > 4096)
    {
        return Err("Invalid package update result".into());
    }
    Ok(results)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p() -> Package {
        Package {
            id: "Example.Editor".into(),
            source: "winget".into(),
            name: "Editor".into(),
            installed: "1.0".into(),
            target: Some("2.0".into()),
        }
    }
    #[test]
    fn update_plans_require_source_identity_and_a_version_change() {
        assert!(UpdatePlan::new(&[p()]).is_ok());
        assert!(UpdatePlan::new(&[]).is_err());
        assert!(UpdatePlan::new(&[p(), p()]).is_err());
        for bad in [
            Package {
                source: "unknown".into(),
                ..p()
            },
            Package {
                id: "--all".into(),
                ..p()
            },
            Package {
                target: None,
                ..p()
            },
            Package {
                target: Some("1.0".into()),
                ..p()
            },
        ] {
            assert!(UpdatePlan::new(&[bad]).is_err());
        }
    }
}
#[cfg(test)]
mod native_review {
    #[test]
    #[ignore = "Read-only installed-package discovery; never installs or updates"]
    fn native_package_inventory() {
        let report = super::inventory().expect("bounded package inventory");
        println!(
            "Packages: {}; Store registrations: {}; provider warnings: {:?}",
            report.packages.len(),
            report.store.len(),
            report.warnings
        );
        assert!(report.packages.len() <= 1024 && report.store.len() <= 1024);
    }
}
