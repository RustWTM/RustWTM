//! Scheduled tasks inspection and enable/disable management via `schtasks`.

use std::os::windows::process::CommandExt;
use std::process::Command;

use serde::{Deserialize, Serialize};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledTask {
    pub name: String,
    pub path: String,
    pub state: String,
    pub command: String,
    pub author: String,
    pub enabled: bool,
    pub is_microsoft: bool,
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

/// Lists scheduled tasks from Windows Task Scheduler.
pub fn list_tasks() -> Result<Vec<ScheduledTask>, String> {
    let out = Command::new("schtasks")
        .args(["/Query", "/FO", "CSV", "/NH", "/V"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("schtasks: {e}"))?;

    if !out.status.success() {
        return Err("Could not query scheduled tasks".into());
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut tasks = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let cols = parse_csv_row(line);
        let Some(task_path) = cols.get(1).map(|s| s.trim().to_owned()) else {
            continue;
        };
        if task_path.is_empty() || task_path == "TaskName" || !seen.insert(task_path.clone()) {
            continue;
        }
        let state = cols.get(3).map(|s| s.trim().to_owned()).unwrap_or_default();
        let author = cols.get(7).map(|s| s.trim().to_owned()).unwrap_or_default();
        let command = cols.get(8).map(|s| s.trim().to_owned()).unwrap_or_default();
        let name = task_path
            .rsplit('\\')
            .next()
            .unwrap_or(&task_path)
            .to_owned();
        let is_microsoft = task_path.to_ascii_lowercase().starts_with(r"\microsoft\");
        let enabled = !state.to_ascii_lowercase().contains("disabled");

        tasks.push(ScheduledTask {
            name,
            path: task_path,
            state,
            command,
            author,
            enabled,
            is_microsoft,
        });
    }

    tasks.sort_by(|a, b| {
        a.is_microsoft
            .cmp(&b.is_microsoft)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(tasks)
}

/// Enables or disables a scheduled task by its full task path.
pub fn set_task_enabled(path: &str, enabled: bool) -> Result<(), String> {
    if path.is_empty() || path.chars().any(char::is_control) {
        return Err("Invalid scheduled task path".into());
    }
    let flag = if enabled { "/Enable" } else { "/Disable" };
    let out = Command::new("schtasks")
        .args(["/Change", "/TN", path, flag])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("schtasks: {e}"))?;

    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        Err(if err.is_empty() {
            format!("Failed to update task '{path}' (administrator rights may be required)")
        } else {
            err
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_csv_row() {
        let row = r#""HOST","\MyTask","N/A","Ready","","0","0","Alice","""C:\Program Files\App\app.exe"" --bg""#;
        let cols = parse_csv_row(row);
        assert_eq!(cols[1], r"\MyTask");
        assert_eq!(cols[3], "Ready");
        assert_eq!(cols[8], r#""C:\Program Files\App\app.exe" --bg"#);
    }
}
