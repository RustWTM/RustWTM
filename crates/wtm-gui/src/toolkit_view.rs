//! Unified Toolkit workspace: Risk Scan & Quarantine, Safe Disk Cleanup,
//! RAM Cleaner, Scheduled Tasks, Reversible Windows Tweaks, and Repair & Network.

use std::collections::{BTreeSet, VecDeque};
use std::time::Instant;

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, Margin, RichText, Stroke, Ui};
use egui_extras::Column;
use wtm_core::ProcessInfo;
use wtm_core::cleanup::{self, CleanupCategory, MemoryTrimReport};
use wtm_core::repair::{self, DnsProvider, NetAdapterInfo, RepairAction};
use wtm_core::risk::{self, RiskFinding, RiskLevel};
use wtm_core::tasks::{self, ScheduledTask};
use wtm_core::tweaks::{self, TweakGroup, TweakState};

use crate::background::Task;
use crate::context_actions::{copy, menu};
use crate::i18n::bytes as format_bytes;
use crate::sort::{Sort, header, text};
use crate::theme::{ACCENT, BAD, CPU, GOOD, GPU, MEMORY, WARN, right};

fn big_stat(ui: &mut Ui, value: &str, label: &str, color: Color32) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(
            RichText::new(value)
                .size(20.0)
                .strong()
                .color(crate::theme::text_color(ui, color)),
        );
        ui.label(RichText::new(label).size(11.0).weak());
    });
}

fn pill(ui: &mut Ui, color: Color32, text: &str) {
    let fg = crate::theme::text_color(ui, color);
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.5).strong().color(fg));
        });
}

fn color_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), 4.0, crate::theme::text_color(ui, color));
}

fn mini_bar(ui: &mut Ui, frac: f32, color: Color32, text: &str) {
    ui.horizontal(|ui| {
        let bar_w = (ui.available_width() - 78.0).max(40.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(bar_w, 6.0), egui::Sense::hover());
        let track = if ui.visuals().dark_mode {
            Color32::from_rgb(42, 46, 54)
        } else {
            Color32::from_rgb(226, 230, 236)
        };
        ui.painter().rect_filled(rect, CornerRadius::same(3), track);
        let fill_w = (rect.width() * frac.clamp(0.0, 1.0)).max(if frac > 0.0 { 3.0 } else { 0.0 });
        if fill_w > 0.0 {
            let fill_rect = egui::Rect::from_min_size(rect.min, egui::vec2(fill_w, rect.height()));
            ui.painter().rect_filled(
                fill_rect,
                CornerRadius::same(3),
                crate::theme::text_color(ui, color),
            );
        }
        right(ui, text);
    });
}

fn paint_stack_bar(ui: &mut Ui, height: f32, parts: &[(u64, Color32, &str)]) {
    let total: u64 = parts.iter().map(|(v, _, _)| *v).sum();
    let width = ui.available_width().max(60.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let track = if ui.visuals().dark_mode {
        Color32::from_rgb(42, 46, 54)
    } else {
        Color32::from_rgb(226, 230, 236)
    };
    let radius = CornerRadius::same((height / 2.0) as u8);
    ui.painter().rect_filled(rect, radius, track);
    if total == 0 {
        return;
    }
    let mut x = rect.left();
    for (val, color, label) in parts {
        if *val == 0 {
            continue;
        }
        let w = ((*val as f32 / total as f32) * rect.width()).max(3.0);
        let seg = egui::Rect::from_min_max(
            egui::pos2(x, rect.top()),
            egui::pos2((x + w).min(rect.right()), rect.bottom()),
        );
        ui.painter().rect_filled(
            seg,
            CornerRadius::same(2),
            crate::theme::text_color(ui, *color),
        );
        ui.interact(seg, ui.scope_id().with(*label), egui::Sense::hover())
            .on_hover_text(format!("{label}: {}", format_bytes(*val as f64)));
        x += w + 1.5;
        if x >= rect.right() {
            break;
        }
    }
}

fn category_color(id: &str) -> Color32 {
    match id {
        "temp" => ACCENT,
        "logs" => CPU,
        "shader" => GPU,
        "thumbs" => GOOD,
        "browser" => MEMORY,
        "dev" => WARN,
        "recycle" => BAD,
        _ => ACCENT,
    }
}

pub struct View {
    subtab: usize,

    // Risk Scan
    risk_scan: Task<Vec<RiskFinding>>,
    findings: Vec<RiskFinding>,
    risk_scanned: bool,
    risk_query: String,
    risk_filter: usize,
    defender_quick: Task<String>,
    defender_file: Task<(String, (Option<bool>, String))>,
    remediate: Task<(String, String)>,
    risk_status: Option<Result<String, String>>,

    // Disk Cleanup
    categories: Vec<CleanupCategory>,
    selected_cleanup: BTreeSet<String>,
    cleanup_scan: Task<Vec<CleanupCategory>>,
    cleanup_run: Task<(Vec<CleanupCategory>, (u64, u64, u64))>,
    cleanup_status: Option<String>,

    // RAM Cleaner
    ram_trim: Task<MemoryTrimReport>,
    ram_report: Option<MemoryTrimReport>,
    ram_history: VecDeque<f32>,
    ram_last_sample: Option<Instant>,

    // Scheduled Tasks
    tasks: Vec<ScheduledTask>,
    tasks_loaded: bool,
    task_query: String,
    show_ms_tasks: bool,
    tasks_refresh: Task<Vec<ScheduledTask>>,
    task_toggle: Task<(String, Vec<ScheduledTask>)>,
    task_status: Option<Result<String, String>>,

    // Windows Tweaks
    tweaks: Vec<TweakState>,
    tweaks_loaded: bool,
    tweak_query: String,
    tweak_refresh: Task<Vec<TweakState>>,
    tweak_op: Task<(String, Vec<TweakState>)>,
    tweak_status: Option<Result<String, String>>,
    restore_point_task: Task<String>,

    // Repair & Network
    dns_choice: DnsProvider,
    repair_task: Task<String>,
    repair_output: Option<Result<String, String>>,
    net_adapters: Vec<NetAdapterInfo>,
    net_loaded: bool,
    net_show_disconnected: bool,
    net_error: Option<String>,
    net_refresh: Task<Vec<NetAdapterInfo>>,
}

impl Default for View {
    fn default() -> Self {
        let categories = cleanup::default_categories();
        let selected_cleanup = categories
            .iter()
            .filter(|c| c.default_enabled)
            .map(|c| c.id.to_owned())
            .collect();
        Self {
            subtab: 0,
            risk_scan: Task::default(),
            findings: Vec::new(),
            risk_scanned: false,
            risk_query: String::new(),
            risk_filter: 0,
            defender_quick: Task::default(),
            defender_file: Task::default(),
            remediate: Task::default(),
            risk_status: None,
            categories,
            selected_cleanup,
            cleanup_scan: Task::default(),
            cleanup_run: Task::default(),
            cleanup_status: None,
            ram_trim: Task::default(),
            ram_report: None,
            ram_history: VecDeque::with_capacity(60),
            ram_last_sample: None,
            tasks: Vec::new(),
            tasks_loaded: false,
            task_query: String::new(),
            show_ms_tasks: false,
            tasks_refresh: Task::default(),
            task_toggle: Task::default(),
            task_status: None,
            tweaks: Vec::new(),
            tweaks_loaded: false,
            tweak_query: String::new(),
            tweak_refresh: Task::default(),
            tweak_op: Task::default(),
            tweak_status: None,
            restore_point_task: Task::default(),
            dns_choice: DnsProvider::Cloudflare,
            repair_task: Task::default(),
            repair_output: None,
            net_adapters: Vec::new(),
            net_loaded: false,
            net_show_disconnected: false,
            net_error: None,
            net_refresh: Task::default(),
        }
    }
}

impl View {
    /// Selects a specific Toolkit subtab (0..=5).
    pub fn open_subtab(&mut self, subtab: usize) {
        self.subtab = subtab.min(5);
    }

    /// Switches to Risk Scan and scans `target`'s executable with Microsoft Defender.
    pub fn scan_process(&mut self, ctx: &egui::Context, target: &wtm_core::control::ProcessRef) {
        self.subtab = 0;
        let target = target.clone();
        self.defender_quick.start(ctx, move || {
            let path = wtm_core::control::image_path(&target).map_err(|e| e.to_string())?;
            let (threat, msg) = risk::defender_scan_file(&path);
            if threat == Some(true) {
                Err(format!("{} ({}): {msg}", target.name, path))
            } else {
                Ok(format!("{} ({}): {msg}", target.name, path))
            }
        });
    }

    pub fn show(&mut self, ui: &mut Ui, processes: &[ProcessInfo]) {
        self.poll_tasks();
        self.show_hero_banner(ui);
        ui.add_space(6.0);

        ui.horizontal_wrapped(|ui| {
            crate::theme::choice(ui, &mut self.subtab, 0, crate::i18n::tr("Risk Scan"));
            crate::theme::choice(ui, &mut self.subtab, 1, crate::i18n::tr("Disk Cleanup"));
            crate::theme::choice(ui, &mut self.subtab, 2, crate::i18n::tr("RAM Cleaner"));
            crate::theme::choice(ui, &mut self.subtab, 3, crate::i18n::tr("Scheduled Tasks"));
            crate::theme::choice(ui, &mut self.subtab, 4, crate::i18n::tr("Windows Tweaks"));
            crate::theme::choice(ui, &mut self.subtab, 5, crate::i18n::tr("Repair & Network"));
        });
        ui.add_space(6.0);

        match self.subtab {
            0 => self.show_risk(ui, processes),
            1 => self.show_cleanup(ui),
            2 => self.show_ram_cleaner(ui, processes),
            3 => self.show_tasks(ui),
            4 => self.show_tweaks(ui),
            _ => self.show_repair(ui),
        }
    }

    fn show_hero_banner(&self, ui: &mut Ui) {
        let dark = ui.visuals().dark_mode;
        let bg_idx = ui.painter().add(egui::Shape::Noop);
        let live_mem = wtm_sys::system::memory_status().ok();
        let avail_str = live_mem
            .map(|m| format_bytes(m.avail_phys as f64))
            .unwrap_or_else(|| "—".into());
        let any_scanned = self.categories.iter().any(|c| c.scanned);
        let reclaim_bytes: u64 = self
            .categories
            .iter()
            .filter(|c| self.selected_cleanup.contains(c.id))
            .map(|c| c.bytes)
            .sum();
        let reclaim_str = if any_scanned {
            format_bytes(reclaim_bytes as f64)
        } else {
            "—".into()
        };
        let applied_tweaks = self.tweaks.iter().filter(|t| t.applied).count();
        let tweaks_str = if self.tweaks_loaded {
            format!("{applied_tweaks}/{}", self.tweaks.len())
        } else {
            "—".into()
        };
        let (risk_str, risk_col) = if !self.risk_scanned {
            ("—".into(), CPU)
        } else {
            let susp = self
                .findings
                .iter()
                .filter(|f| f.level == RiskLevel::Suspicious)
                .count();
            if susp > 0 {
                (format!("{susp} alerts"), BAD)
            } else if !self.findings.is_empty() {
                (format!("{} notes", self.findings.len()), WARN)
            } else {
                ("Clean".into(), GOOD)
            }
        };

        let inner = egui::Frame::new()
            .inner_margin(Margin::symmetric(18, 14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("SYSTEM TOOLKIT")
                                .size(10.5)
                                .strong()
                                .color(crate::theme::text_color(ui, ACCENT)),
                        );
                        ui.label(
                            RichText::new(crate::i18n::tr(
                                "Security, Cleanup, Memory & Windows Maintenance",
                            ))
                            .size(18.0)
                            .strong(),
                        );
                    });
                    ui.add_space(24.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 26.0;
                        big_stat(ui, &avail_str, crate::i18n::tr("Available RAM"), MEMORY);
                        big_stat(ui, &reclaim_str, crate::i18n::tr("Reclaimable"), GPU);
                        big_stat(ui, &tweaks_str, crate::i18n::tr("Active tweaks"), ACCENT);
                        big_stat(ui, &risk_str, crate::i18n::tr("Risk status"), risk_col);
                    });
                });
            });

        let rect = inner.response.rect;
        let base = crate::theme::tile_fill(ui);
        let mut shapes = vec![egui::Shape::rect_filled(
            rect,
            crate::theme::SURFACE_RADIUS,
            base,
        )];
        let radius = (rect.height() * 0.65).clamp(24.0, 68.0);
        if rect.width() >= 680.0 {
            let center = egui::pos2(rect.right() - radius - 18.0, rect.center().y);
            let alpha = if dark { 4 } else { 3 };
            for (c_off, col, r_scale) in [(-radius * 0.5, MEMORY, 0.85), (0.0, ACCENT, 1.0)] {
                for k in 0..20 {
                    let r = radius * r_scale * (1.0 - k as f32 / 20.0);
                    shapes.push(egui::Shape::circle_filled(
                        center + egui::vec2(c_off, 0.0),
                        r,
                        Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), alpha),
                    ));
                }
            }
        }
        shapes.push(egui::Shape::rect_filled(
            egui::Rect::from_min_size(
                rect.min + egui::vec2(14.0, 0.0),
                egui::vec2((rect.width() - 28.0).max(0.0), 3.0),
            ),
            1.5,
            ACCENT,
        ));
        shapes.push(egui::Shape::rect_stroke(
            rect,
            crate::theme::SURFACE_RADIUS,
            Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
            egui::StrokeKind::Inside,
        ));
        ui.painter().set(bg_idx, egui::Shape::Vec(shapes));
    }

    fn poll_tasks(&mut self) {
        if let Some(res) = self.risk_scan.poll() {
            self.risk_scanned = true;
            match res {
                Ok(list) => {
                    self.findings = list;
                    self.risk_status = None;
                }
                Err(e) => self.risk_status = Some(Err(e)),
            }
        }
        if let Some(res) = self.defender_quick.poll() {
            self.risk_status = Some(res);
        }
        if let Some(res) = self.defender_file.poll() {
            match res {
                Ok((key, verdict)) => {
                    if let Some(f) = self.findings.iter_mut().find(|f| f.key == key) {
                        f.defender_verdict = Some(verdict);
                    }
                }
                Err(e) => self.risk_status = Some(Err(e)),
            }
        }
        if let Some(res) = self.remediate.poll() {
            match res {
                Ok((key, msg)) => {
                    self.findings.retain(|f| f.key != key);
                    self.risk_status = Some(Ok(msg));
                }
                Err(e) => self.risk_status = Some(Err(e)),
            }
        }
        if let Some(Ok(cats)) = self.cleanup_scan.poll() {
            self.categories = cats;
        }
        if let Some(res) = self.cleanup_run.poll() {
            match res {
                Ok((cats, (bytes, files, skipped))) => {
                    self.categories = cats;
                    self.cleanup_status = Some(format!(
                        "Freed {} · {files} files ({skipped} skipped)",
                        format_bytes(bytes as f64)
                    ));
                }
                Err(e) => self.cleanup_status = Some(e),
            }
        }
        if let Some(Ok(r)) = self.ram_trim.poll() {
            self.ram_report = Some(r);
        }
        if let Some(res) = self.tasks_refresh.poll() {
            self.tasks_loaded = true;
            match res {
                Ok(list) => self.tasks = list,
                Err(e) => self.task_status = Some(Err(e)),
            }
        }
        if let Some(res) = self.task_toggle.poll() {
            match res {
                Ok((msg, list)) => {
                    self.tasks = list;
                    self.tasks_loaded = true;
                    self.task_status = Some(Ok(msg));
                }
                Err(e) => self.task_status = Some(Err(e)),
            }
        }
        if let Some(res) = self.restore_point_task.poll() {
            self.tweak_status = Some(res);
        }
        if let Some(Ok(list)) = self.tweak_refresh.poll() {
            self.tweaks = list;
            self.tweaks_loaded = true;
        }
        if let Some(res) = self.tweak_op.poll() {
            match res {
                Ok((msg, list)) => {
                    self.tweaks = list;
                    self.tweaks_loaded = true;
                    self.tweak_status = Some(Ok(msg));
                }
                Err(e) => self.tweak_status = Some(Err(e)),
            }
        }
        if let Some(res) = self.repair_task.poll() {
            self.repair_output = Some(res);
            self.net_loaded = false;
        }
        if let Some(res) = self.net_refresh.poll() {
            self.net_loaded = true;
            match res {
                Ok(list) => {
                    self.net_adapters = list;
                    self.net_error = None;
                }
                Err(e) => self.net_error = Some(e),
            }
        }
    }

    fn show_risk(&mut self, ui: &mut Ui, processes: &[ProcessInfo]) {
        let busy = self.risk_scan.busy()
            || self.defender_quick.busy()
            || self.defender_file.busy()
            || self.remediate.busy();

        let susp_count = self
            .findings
            .iter()
            .filter(|f| f.level == RiskLevel::Suspicious)
            .count();
        let unsig_count = self
            .findings
            .iter()
            .filter(|f| f.level == RiskLevel::Unsigned)
            .count();
        let health_pct = if !self.risk_scanned {
            0.0
        } else {
            (100.0 - (susp_count as f32 * 25.0 + unsig_count as f32 * 5.0)).clamp(10.0, 100.0)
        };
        let health_color = if !self.risk_scanned {
            ACCENT
        } else if susp_count > 0 {
            BAD
        } else if unsig_count > 0 {
            WARN
        } else {
            GOOD
        };
        let center = if self.risk_scanned {
            format!("{health_pct:.0}%")
        } else {
            "—".into()
        };

        crate::theme::card(ui, crate::i18n::tr("Security & Risk Triage"), |ui| {
            ui.horizontal(|ui| {
                crate::theme::ring_gauge(ui, 70.0, health_pct, health_color, &center);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    if self.risk_scanned {
                        ui.horizontal_wrapped(|ui| {
                            pill(ui, BAD, &format!("{susp_count} suspicious"));
                            pill(ui, WARN, &format!("{unsig_count} unsigned"));
                        });
                    } else {
                        ui.weak(crate::i18n::tr(
                            "Ready to scan processes, startup, services, tasks and policies.",
                        ));
                    }
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        if crate::theme::primary_action(
                            ui,
                            !busy,
                            crate::i18n::tr("Scan system risks"),
                        )
                        .clicked()
                        {
                            let procs = processes.to_vec();
                            self.risk_scan
                                .start(ui.ctx(), move || Ok(risk::scan_risks(&procs)));
                        }
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Button::new(crate::i18n::tr("Defender quick scan")),
                            )
                            .clicked()
                        {
                            self.defender_quick
                                .start(ui.ctx(), risk::defender_quick_scan);
                        }
                        if let Ok(local) = std::env::var("LOCALAPPDATA") {
                            let qdir = std::path::PathBuf::from(local)
                                .join("RustWTM")
                                .join("quarantine");
                            if qdir.is_dir()
                                && ui
                                    .button(crate::i18n::tr("Open quarantine folder"))
                                    .clicked()
                            {
                                let _ = std::process::Command::new("explorer").arg(&qdir).spawn();
                            }
                        }
                        if busy {
                            ui.spinner();
                        }
                    });
                });
            });
            if let Some(status) = &self.risk_status {
                ui.add_space(4.0);
                match status {
                    Ok(msg) => crate::theme::colored(ui, GOOD, msg),
                    Err(err) => crate::theme::colored(ui, BAD, err),
                };
            }
        });

        ui.add_space(6.0);
        if !self.risk_scanned && !busy {
            crate::theme::empty_state(
                ui,
                crate::i18n::tr("No scan run yet"),
                crate::i18n::tr(
                    "Click 'Scan system risks' to inspect processes, startup entries, services, tasks and policies.",
                ),
            );
            return;
        }
        if self.risk_scanned && self.findings.is_empty() && !busy {
            pill(ui, GOOD, crate::i18n::tr("No suspicious items found."));
            return;
        }

        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.risk_query)
                    .char_limit(128)
                    .hint_text(crate::i18n::tr("Filter findings"))
                    .desired_width(220.0),
            );
            crate::theme::choice(ui, &mut self.risk_filter, 0, crate::i18n::tr("All"));
            crate::theme::choice(ui, &mut self.risk_filter, 1, crate::i18n::tr("Suspicious"));
            crate::theme::choice(ui, &mut self.risk_filter, 2, crate::i18n::tr("Unsigned"));
        });
        ui.add_space(4.0);

        let rq = self.risk_query.to_lowercase();
        let mut visible_findings: Vec<RiskFinding> = self
            .findings
            .iter()
            .filter(|f| {
                let level_ok = match self.risk_filter {
                    1 => f.level == RiskLevel::Suspicious,
                    2 => f.level == RiskLevel::Unsigned,
                    _ => true,
                };
                level_ok
                    && (rq.is_empty()
                        || f.name.to_lowercase().contains(&rq)
                        || f.reason.to_lowercase().contains(&rq)
                        || f.path.to_lowercase().contains(&rq))
            })
            .cloned()
            .collect();
        let mut risk_sort = Sort::load(ui, "toolkit_risk", Sort::new(0, true));
        risk_sort.apply(&mut visible_findings, |a, b, col| match col {
            0 => a.level.cmp(&b.level).then_with(|| text(&a.name, &b.name)),
            1 => text(&a.name, &b.name),
            _ => text(&a.reason, &b.reason),
        });

        let mut scan_target: Option<(String, String)> = None;
        let mut remediate_target: Option<(RiskFinding, bool)> = None;
        let row_height = ui.spacing().interact_size.y.max(28.0);

        let table_w = ui.available_width();
        ui.style_mut().interaction.selectable_labels = false;
        crate::theme::table_panel(ui, "toolkit_risk_table_panel", table_w, |ui| {
            crate::theme::table(ui)
                .id_salt("toolkit_risk_table")
                .sense(egui::Sense::click())
                .striped(true)
                .resizable(true)
                .auto_shrink([false, true])
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(96.0))
                .column(Column::initial(210.0).clip(true))
                .column(Column::remainder().at_least(220.0).clip(true))
                .column(Column::initial(220.0))
                .header(row_height, |mut row| {
                    for (col, label) in ["Risk", "Item", "Reason / Path"].into_iter().enumerate() {
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                header(ui, crate::i18n::tr(label), col, false, &mut risk_sort);
                            });
                        });
                    }
                    row.col(|ui| {
                        crate::theme::table_cell(ui, |ui| {
                            ui.strong(crate::i18n::tr("Actions"));
                        });
                    });
                })
                .body(|body| {
                    body.rows(row_height, visible_findings.len(), |mut row| {
                        let f = &visible_findings[row.index()];
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                let c = match f.level {
                                    RiskLevel::Suspicious => BAD,
                                    RiskLevel::Unsigned => WARN,
                                    _ => GOOD,
                                };
                                pill(ui, c, f.level.label());
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.strong(&f.name).on_hover_text(f.kinds_summary());
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                let info = if let Some((_, msg)) = &f.defender_verdict {
                                    format!("{} · {msg}", f.reason)
                                } else {
                                    f.reason.clone()
                                };
                                ui.add(egui::Label::new(info).truncate())
                                    .on_hover_text(&f.path);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if !f.path.is_empty()
                                        && ui
                                            .add_enabled(
                                                !busy,
                                                egui::Button::new(crate::i18n::tr("Defender"))
                                                    .small(),
                                            )
                                            .clicked()
                                    {
                                        scan_target = Some((f.key.clone(), f.path.clone()));
                                    }
                                    if f.can_quarantine()
                                        && ui
                                            .add_enabled(
                                                !busy,
                                                egui::Button::new(crate::i18n::tr("Quarantine"))
                                                    .small(),
                                            )
                                            .clicked()
                                    {
                                        remediate_target = Some((f.clone(), false));
                                    }
                                    if f.can_quarantine()
                                        && ui
                                            .add_enabled(
                                                !busy,
                                                egui::Button::new(crate::i18n::tr("Delete"))
                                                    .small(),
                                            )
                                            .clicked()
                                    {
                                        remediate_target = Some((f.clone(), true));
                                    }
                                });
                            });
                        });
                        menu(&row.response(), ("risk-row", &f.key), |ui| {
                            copy(ui, crate::i18n::tr("Name"), || f.name.clone());
                            if !f.path.is_empty() {
                                copy(ui, crate::i18n::tr("Path"), || f.path.clone());
                            }
                            copy(ui, crate::i18n::tr("Reason"), || f.reason.clone());
                        });
                    });
                });
        });
        risk_sort.store(ui, "toolkit_risk");

        if let Some((key, path)) = scan_target {
            self.defender_file.start(ui.ctx(), move || {
                let verdict = risk::defender_scan_file(&path);
                Ok((key, verdict))
            });
        }
        if let Some((finding, permanent)) = remediate_target {
            let key = finding.key.clone();
            self.remediate.start(ui.ctx(), move || {
                let msg = risk::remediate_finding(&finding, permanent)?;
                Ok((key, msg))
            });
        }
    }

    fn show_cleanup(&mut self, ui: &mut Ui) {
        let busy = self.cleanup_scan.busy() || self.cleanup_run.busy();
        let total_scanned: u64 = self.categories.iter().map(|c| c.bytes).sum();
        let total_selected: u64 = self
            .categories
            .iter()
            .filter(|c| self.selected_cleanup.contains(c.id))
            .map(|c| c.bytes)
            .sum();
        let max_bytes = self
            .categories
            .iter()
            .map(|c| c.bytes)
            .max()
            .unwrap_or(1)
            .max(1) as f32;
        let any_scanned = self.categories.iter().any(|c| c.scanned);
        let selected_pct = if any_scanned && total_scanned > 0 {
            (total_selected as f32 / total_scanned as f32) * 100.0
        } else {
            0.0
        };
        let center = if any_scanned {
            format_bytes(total_selected as f64)
        } else {
            "—".into()
        };

        crate::theme::card(ui, crate::i18n::tr("Safe Disk Cleanup"), |ui| {
            ui.horizontal(|ui| {
                crate::theme::ring_gauge(ui, 72.0, selected_pct, ACCENT, &center);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(!busy, egui::Button::new(crate::i18n::tr("Scan sizes")))
                            .clicked()
                        {
                            let mut cats = self.categories.clone();
                            self.cleanup_scan.start(ui.ctx(), move || {
                                cleanup::scan_categories(&mut cats);
                                Ok(cats)
                            });
                        }
                        if crate::theme::primary_action(
                            ui,
                            !busy && !self.selected_cleanup.is_empty(),
                            crate::i18n::tr("Clean selected"),
                        )
                        .clicked()
                        {
                            let mut cats = self.categories.clone();
                            let selected: Vec<String> =
                                self.selected_cleanup.iter().cloned().collect();
                            self.cleanup_run.start(ui.ctx(), move || {
                                let res = cleanup::clean_categories(&mut cats, &selected);
                                Ok((cats, res))
                            });
                        }
                        if ui.button(crate::i18n::tr("Recommended")).clicked() {
                            self.selected_cleanup = self
                                .categories
                                .iter()
                                .filter(|c| c.default_enabled)
                                .map(|c| c.id.to_owned())
                                .collect();
                        }
                        if ui.button(crate::i18n::tr("All")).clicked() {
                            self.selected_cleanup =
                                self.categories.iter().map(|c| c.id.to_owned()).collect();
                        }
                        if ui.button(crate::i18n::tr("Clear")).clicked() {
                            self.selected_cleanup.clear();
                        }
                        if busy {
                            ui.spinner();
                        }
                    });
                    if let Some(msg) = &self.cleanup_status {
                        ui.add_space(4.0);
                        pill(ui, GOOD, msg);
                    }
                });
            });
            if any_scanned {
                ui.add_space(8.0);
                let stack_parts: Vec<(u64, Color32, &str)> = self
                    .categories
                    .iter()
                    .filter(|c| self.selected_cleanup.contains(c.id))
                    .map(|c| (c.bytes, category_color(c.id), c.name))
                    .collect();
                paint_stack_bar(ui, 10.0, &stack_parts);
            }
        });

        ui.add_space(6.0);
        let row_height = ui.spacing().interact_size.y.max(26.0);
        let mut cat_indices: Vec<usize> = (0..self.categories.len()).collect();
        let mut clean_sort = Sort::load(ui, "toolkit_cleanup", Sort::new(2, true));
        clean_sort.apply(&mut cat_indices, |&a, &b, col| {
            let ca = &self.categories[a];
            let cb = &self.categories[b];
            match col {
                0 => text(ca.name, cb.name),
                1 => ca.files.cmp(&cb.files),
                _ => ca.bytes.cmp(&cb.bytes),
            }
        });

        let table_w = ui.available_width();
        crate::theme::table_panel(ui, "toolkit_cleanup_table_panel", table_w, |ui| {
            crate::theme::table(ui)
                .id_salt("toolkit_cleanup_table")
                .striped(true)
                .resizable(true)
                .auto_shrink([false, true])
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(56.0))
                .column(Column::remainder().at_least(240.0).clip(true))
                .column(Column::initial(84.0))
                .column(Column::initial(190.0))
                .header(row_height, |mut row| {
                    row.col(|ui| {
                        crate::theme::table_cell(ui, |ui| {
                            ui.strong(crate::i18n::tr("On"));
                        });
                    });
                    for (col, (label, numeric)) in
                        [("Category", false), ("Files", true), ("Reclaimable", true)]
                            .into_iter()
                            .enumerate()
                    {
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                header(ui, crate::i18n::tr(label), col, numeric, &mut clean_sort);
                            });
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_height, cat_indices.len(), |mut row| {
                        let cat = &self.categories[cat_indices[row.index()]];
                        let cat_color = category_color(cat.id);
                        let mut enabled = self.selected_cleanup.contains(cat.id);
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if crate::theme::switch(ui, &mut enabled, cat.name).changed() {
                                    if enabled {
                                        self.selected_cleanup.insert(cat.id.to_owned());
                                    } else {
                                        self.selected_cleanup.remove(cat.id);
                                    }
                                }
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                color_dot(ui, cat_color);
                                ui.label(cat.name).on_hover_text(cat.description);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if cat.scanned {
                                    right(ui, cat.files.to_string());
                                } else {
                                    right(ui, "—");
                                }
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if cat.scanned {
                                    let frac = (cat.bytes as f32 / max_bytes).clamp(0.0, 1.0);
                                    mini_bar(ui, frac, cat_color, &format_bytes(cat.bytes as f64));
                                } else {
                                    right(ui, "—");
                                }
                            });
                        });
                    });
                });
        });
        clean_sort.store(ui, "toolkit_cleanup");
    }

    fn show_ram_cleaner(&mut self, ui: &mut Ui, processes: &[ProcessInfo]) {
        let busy = self.ram_trim.busy();
        let live_mem = wtm_sys::system::memory_status().ok();
        if let Some(m) = live_mem {
            let now = Instant::now();
            if self
                .ram_last_sample
                .is_none_or(|t| now.duration_since(t).as_millis() >= 500)
            {
                let total = m.total_phys.max(1) as f32;
                let used = m.total_phys.saturating_sub(m.avail_phys) as f32;
                let pct = (used / total * 100.0).clamp(0.0, 100.0);
                if self.ram_history.len() >= 60 {
                    self.ram_history.pop_front();
                }
                self.ram_history.push_back(pct);
                self.ram_last_sample = Some(now);
            }
        }

        crate::theme::card(ui, crate::i18n::tr("System Memory"), |ui| {
            ui.horizontal(|ui| {
                if let Some(m) = live_mem {
                    let total = m.total_phys.max(1) as f32;
                    let used = m.total_phys.saturating_sub(m.avail_phys);
                    let pct = (used as f32 / total * 100.0).clamp(0.0, 100.0);
                    crate::theme::ring_gauge(ui, 82.0, pct, MEMORY, &format!("{pct:.0}%"));
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} / {}",
                                format_bytes(used as f64),
                                format_bytes(m.total_phys as f64)
                            ))
                            .size(16.0)
                            .strong(),
                        );
                        ui.weak(format!(
                            "{} {}",
                            format_bytes(m.avail_phys as f64),
                            crate::i18n::tr("available")
                        ));
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if crate::theme::primary_action(
                                ui,
                                !busy,
                                crate::i18n::tr("Free memory now"),
                            )
                            .clicked()
                            {
                                let procs = processes.to_vec();
                                self.ram_trim.start(ui.ctx(), move || {
                                    Ok(cleanup::trim_system_memory(&procs))
                                });
                            }
                            if busy {
                                ui.spinner();
                            }
                        });
                    });
                    if self.ram_history.len() >= 2 {
                        ui.add_space(12.0);
                        let avail_w = ui.available_width().clamp(120.0, 320.0);
                        let (spark_rect, _) =
                            ui.allocate_exact_size(egui::vec2(avail_w, 64.0), egui::Sense::hover());
                        crate::theme::sparkline(
                            ui.painter(),
                            spark_rect,
                            &self.ram_history,
                            100.0,
                            60,
                            crate::theme::text_color(ui, MEMORY),
                        );
                    }
                } else if ui
                    .add_enabled(!busy, egui::Button::new(crate::i18n::tr("Free memory now")))
                    .clicked()
                {
                    let procs = processes.to_vec();
                    self.ram_trim
                        .start(ui.ctx(), move || Ok(cleanup::trim_system_memory(&procs)));
                }
            });
        });

        if let Some(r) = &self.ram_report {
            ui.add_space(8.0);
            let total = r.total_bytes.max(1) as f32;
            let before_pct = (r.before_used_bytes as f32 / total * 100.0).clamp(0.0, 100.0);
            let after_pct = (r.after_used_bytes as f32 / total * 100.0).clamp(0.0, 100.0);
            let freed_pct = if r.before_used_bytes > 0 {
                (r.freed_bytes as f32 / r.before_used_bytes as f32 * 100.0).clamp(0.0, 100.0)
            } else {
                0.0
            };

            ui.columns(3, |cols| {
                crate::theme::card(&mut cols[0], crate::i18n::tr("Before"), |ui| {
                    ui.horizontal(|ui| {
                        crate::theme::ring_gauge(
                            ui,
                            68.0,
                            before_pct,
                            WARN,
                            &format!("{before_pct:.0}%"),
                        );
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format_bytes(r.before_used_bytes as f64))
                                    .size(16.0)
                                    .strong(),
                            );
                            ui.weak(format_bytes(r.total_bytes as f64));
                        });
                    });
                });
                crate::theme::card(&mut cols[1], crate::i18n::tr("After"), |ui| {
                    ui.horizontal(|ui| {
                        crate::theme::ring_gauge(
                            ui,
                            68.0,
                            after_pct,
                            GOOD,
                            &format!("{after_pct:.0}%"),
                        );
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format_bytes(r.after_used_bytes as f64))
                                    .size(16.0)
                                    .strong(),
                            );
                            ui.weak(format_bytes(r.total_bytes as f64));
                        });
                    });
                });
                crate::theme::card(&mut cols[2], crate::i18n::tr("Freed"), |ui| {
                    ui.horizontal(|ui| {
                        crate::theme::ring_gauge(
                            ui,
                            68.0,
                            freed_pct,
                            ACCENT,
                            &format!("-{freed_pct:.0}%"),
                        );
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format_bytes(r.freed_bytes as f64))
                                    .size(16.0)
                                    .strong()
                                    .color(crate::theme::text_color(ui, GOOD)),
                            );
                            ui.weak(format!(
                                "{} trimmed · {} skipped",
                                r.trimmed_processes, r.skipped_processes
                            ));
                        });
                    });
                });
            });

            if !r.details.is_empty() {
                ui.add_space(8.0);
                let max_freed = r.details[0].freed_bytes.max(1) as f32;
                let row_height = ui.spacing().interact_size.y.max(26.0);
                let table_w = ui.available_width();
                ui.style_mut().interaction.selectable_labels = false;
                crate::theme::table_panel(ui, "toolkit_ram_details_panel", table_w, |ui| {
                    crate::theme::table(ui)
                        .id_salt("toolkit_ram_details_table")
                        .sense(egui::Sense::click())
                        .striped(true)
                        .resizable(true)
                        .auto_shrink([false, true])
                        .cell_layout(Layout::left_to_right(Align::Center))
                        .column(Column::remainder().at_least(200.0).clip(true))
                        .column(Column::initial(110.0))
                        .column(Column::initial(110.0))
                        .column(Column::initial(190.0))
                        .header(row_height, |mut row| {
                            for label in ["Process", "Before", "After", "Reduced"] {
                                row.col(|ui| {
                                    crate::theme::table_cell(ui, |ui| {
                                        ui.strong(crate::i18n::tr(label));
                                    });
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(row_height, r.details.len(), |mut row| {
                                let d = &r.details[row.index()];
                                row.col(|ui| {
                                    crate::theme::table_cell(ui, |ui| {
                                        ui.strong(&d.name);
                                        ui.weak(format!("({})", d.pid));
                                    });
                                });
                                row.col(|ui| {
                                    crate::theme::table_cell(ui, |ui| {
                                        right(ui, format_bytes(d.before_bytes as f64));
                                    });
                                });
                                row.col(|ui| {
                                    crate::theme::table_cell(ui, |ui| {
                                        right(ui, format_bytes(d.after_bytes as f64));
                                    });
                                });
                                row.col(|ui| {
                                    crate::theme::table_cell(ui, |ui| {
                                        let frac =
                                            (d.freed_bytes as f32 / max_freed).clamp(0.0, 1.0);
                                        mini_bar(
                                            ui,
                                            frac,
                                            GOOD,
                                            &format!("-{}", format_bytes(d.freed_bytes as f64)),
                                        );
                                    });
                                });
                                menu(&row.response(), ("ram-row", d.pid, &d.name), |ui| {
                                    copy(ui, crate::i18n::tr("Process"), || d.name.clone());
                                    copy(ui, "PID", || d.pid.to_string());
                                });
                            });
                        });
                });
            }
        }
    }

    fn show_tasks(&mut self, ui: &mut Ui) {
        let busy = self.tasks_refresh.busy() || self.task_toggle.busy();
        if !self.tasks_loaded && !busy {
            self.tasks_refresh.start(ui.ctx(), tasks::list_tasks);
        }

        let q = self.task_query.to_lowercase();
        let mut visible: Vec<&ScheduledTask> = self
            .tasks
            .iter()
            .filter(|t| {
                (self.show_ms_tasks || !t.is_microsoft)
                    && (q.is_empty()
                        || t.name.to_lowercase().contains(&q)
                        || t.path.to_lowercase().contains(&q)
                        || t.command.to_lowercase().contains(&q))
            })
            .collect();
        let mut sort = Sort::load(ui, "toolkit_tasks", Sort::new(0, false));
        sort.apply(&mut visible, |a, b, col| match col {
            0 => text(&a.name, &b.name),
            1 => text(&a.author, &b.author),
            2 => text(&a.command, &b.command),
            _ => b
                .enabled
                .cmp(&a.enabled)
                .then_with(|| text(&a.name, &b.name)),
        });
        let enabled_count = visible.iter().filter(|t| t.enabled).count();
        let disabled_count = visible.len().saturating_sub(enabled_count);

        crate::theme::card(ui, crate::i18n::tr("Scheduled Tasks"), |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.task_query)
                        .char_limit(128)
                        .hint_text(crate::i18n::tr("Filter scheduled tasks"))
                        .desired_width(220.0),
                );
                if ui
                    .add_enabled(!busy, egui::Button::new(crate::i18n::tr("Refresh")))
                    .clicked()
                {
                    self.tasks_refresh.start(ui.ctx(), tasks::list_tasks);
                }
                crate::theme::switch(
                    ui,
                    &mut self.show_ms_tasks,
                    crate::i18n::tr("Show Microsoft tasks"),
                );
                ui.label(crate::i18n::tr("Microsoft tasks"));
                pill(ui, GOOD, &format!("{enabled_count} enabled"));
                pill(ui, WARN, &format!("{disabled_count} disabled"));
                if busy {
                    ui.spinner();
                }
            });
            if let Some(status) = &self.task_status {
                ui.add_space(4.0);
                match status {
                    Ok(msg) => crate::theme::colored(ui, GOOD, msg),
                    Err(err) => crate::theme::colored(ui, BAD, err),
                };
            }
        });

        ui.add_space(6.0);
        let mut toggle: Option<(String, bool)> = None;
        let row_height = ui.spacing().interact_size.y.max(28.0);

        let table_w = ui.available_width();
        ui.style_mut().interaction.selectable_labels = false;
        crate::theme::table_panel(ui, "toolkit_tasks_table_panel", table_w, |ui| {
            crate::theme::table(ui)
                .id_salt("toolkit_tasks_table")
                .sense(egui::Sense::click())
                .striped(true)
                .resizable(true)
                .auto_shrink([false, true])
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(220.0).clip(true))
                .column(Column::initial(140.0).clip(true))
                .column(Column::remainder().at_least(220.0).clip(true))
                .column(Column::initial(92.0))
                .column(Column::initial(64.0))
                .header(row_height, |mut row| {
                    for (col, label) in ["Task", "Author", "Action", "State"]
                        .into_iter()
                        .enumerate()
                    {
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                header(ui, crate::i18n::tr(label), col, false, &mut sort);
                            });
                        });
                    }
                    row.col(|ui| {
                        crate::theme::table_cell(ui, |ui| {
                            ui.strong(crate::i18n::tr("Active"));
                        });
                    });
                })
                .body(|body| {
                    body.rows(row_height, visible.len(), |mut row| {
                        let task = visible[row.index()];
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.strong(&task.name).on_hover_text(&task.path);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.add(egui::Label::new(&task.author).truncate());
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.add(egui::Label::new(&task.command).truncate())
                                    .on_hover_text(&task.command);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if task.enabled {
                                    pill(ui, GOOD, crate::i18n::tr("Enabled"));
                                } else {
                                    pill(ui, WARN, crate::i18n::tr("Disabled"));
                                }
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                let mut on = task.enabled;
                                if ui
                                    .add_enabled_ui(!busy, |ui| {
                                        crate::theme::switch(ui, &mut on, &task.name)
                                    })
                                    .inner
                                    .changed()
                                {
                                    toggle = Some((task.path.clone(), on));
                                }
                            });
                        });
                        menu(&row.response(), ("task-row", &task.path), |ui| {
                            copy(ui, crate::i18n::tr("Name"), || task.name.clone());
                            copy(ui, crate::i18n::tr("Path"), || task.path.clone());
                            if !task.command.is_empty() {
                                copy(ui, crate::i18n::tr("Action"), || task.command.clone());
                            }
                        });
                    });
                });
        });
        sort.store(ui, "toolkit_tasks");

        if let Some((path, enable)) = toggle {
            self.task_toggle.start(ui.ctx(), move || {
                tasks::set_task_enabled(&path, enable)?;
                let list = tasks::list_tasks()?;
                let msg = if enable {
                    format!("Enabled '{path}'.")
                } else {
                    format!("Disabled '{path}'.")
                };
                Ok((msg, list))
            });
        }
    }

    fn show_tweaks(&mut self, ui: &mut Ui) {
        let busy =
            self.tweak_refresh.busy() || self.tweak_op.busy() || self.restore_point_task.busy();
        if !self.tweaks_loaded && !busy {
            self.tweak_refresh
                .start(ui.ctx(), || Ok(tweaks::list_states()));
        }

        let total = self.tweaks.len();
        let applied = self.tweaks.iter().filter(|t| t.applied).count();
        let pct = if total > 0 {
            applied as f32 / total as f32 * 100.0
        } else {
            0.0
        };

        let mut batch_apply_rec = false;
        let mut batch_undo_all = false;
        let has_any_backup = self.tweaks.iter().any(|t| t.has_backup);

        crate::theme::card(ui, crate::i18n::tr("Windows Tweaks"), |ui| {
            ui.horizontal(|ui| {
                crate::theme::ring_gauge(ui, 64.0, pct, ACCENT, &format!("{applied}/{total}"));
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.tweak_query)
                                .char_limit(128)
                                .hint_text(crate::i18n::tr("Filter tweaks"))
                                .desired_width(200.0),
                        );
                        if ui
                            .add_enabled(!busy, egui::Button::new(crate::i18n::tr("Refresh")))
                            .clicked()
                        {
                            self.tweak_refresh
                                .start(ui.ctx(), || Ok(tweaks::list_states()));
                        }
                        if crate::theme::primary_action(
                            ui,
                            !busy && total > 0,
                            crate::i18n::tr("Apply recommended"),
                        )
                        .clicked()
                        {
                            batch_apply_rec = true;
                        }
                        if ui
                            .add_enabled(
                                !busy && has_any_backup,
                                egui::Button::new(crate::i18n::tr("Revert all")),
                            )
                            .clicked()
                        {
                            batch_undo_all = true;
                        }
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Button::new(crate::i18n::tr("Create System Restore Point")),
                            )
                            .clicked()
                        {
                            self.restore_point_task.start(ui.ctx(), || {
                                repair::run_repair(RepairAction::CreateRestorePoint)
                            });
                        }
                        if busy {
                            ui.spinner();
                        }
                    });
                    if let Some(status) = &self.tweak_status {
                        ui.add_space(4.0);
                        match status {
                            Ok(msg) => pill(ui, GOOD, msg),
                            Err(err) => pill(ui, BAD, err),
                        }
                    }
                });
            });
        });

        ui.add_space(6.0);
        let tq = self.tweak_query.to_lowercase();
        let mut action: Option<(String, bool)> = None;

        egui::ScrollArea::vertical()
            .id_salt("toolkit_tweaks_scroll")
            .show(ui, |ui| {
                for group in TweakGroup::ALL {
                    let items: Vec<&TweakState> = self
                        .tweaks
                        .iter()
                        .filter(|t| {
                            t.group == group
                                && (tq.is_empty()
                                    || t.name.to_lowercase().contains(&tq)
                                    || t.description.to_lowercase().contains(&tq))
                        })
                        .collect();
                    if items.is_empty() {
                        continue;
                    }
                    let applied_count = items.iter().filter(|t| t.applied).count();
                    let count_str = format!("{applied_count}/{}", items.len());
                    crate::theme::card_with(ui, group.label(), &[(&count_str, ACCENT)], |ui| {
                        let half = items.len().div_ceil(2);
                        let (left, right) = items.split_at(half);
                        ui.columns(2, |cols| {
                            for (col_idx, chunk) in [left, right].into_iter().enumerate() {
                                for t in chunk {
                                    let bg = if t.applied {
                                        ACCENT.gamma_multiply(0.10)
                                    } else {
                                        Color32::TRANSPARENT
                                    };
                                    egui::Frame::new()
                                        .fill(bg)
                                        .corner_radius(CornerRadius::same(6))
                                        .inner_margin(Margin::symmetric(8, 4))
                                        .show(&mut cols[col_idx], |ui| {
                                            ui.horizontal(|ui| {
                                                let mut on = t.applied;
                                                let can_toggle = !t.applied || t.has_backup;
                                                if ui
                                                    .add_enabled_ui(!busy && can_toggle, |ui| {
                                                        crate::theme::switch(ui, &mut on, &t.name)
                                                    })
                                                    .inner
                                                    .changed()
                                                {
                                                    action = Some((t.id.clone(), on));
                                                }
                                                ui.add(egui::Label::new(&t.name).truncate())
                                                    .on_hover_text(&t.description);
                                                if t.recommended {
                                                    crate::theme::colored(ui, GOOD, "★");
                                                }
                                            });
                                        });
                                }
                            }
                        });
                    });
                    ui.add_space(6.0);
                }
            });

        if let Some((id, apply)) = action {
            self.tweak_op.start(ui.ctx(), move || {
                if apply {
                    tweaks::apply_tweak(&id)?;
                    Ok((format!("Applied '{id}'."), tweaks::list_states()))
                } else {
                    tweaks::undo_tweak(&id)?;
                    Ok((format!("Reverted '{id}'."), tweaks::list_states()))
                }
            });
        } else if batch_apply_rec {
            let ids: Vec<String> = self
                .tweaks
                .iter()
                .filter(|t| t.recommended && !t.applied)
                .map(|t| t.id.clone())
                .collect();
            self.tweak_op.start(ui.ctx(), move || {
                let mut count = 0usize;
                for id in &ids {
                    if tweaks::apply_tweak(id).is_ok() {
                        count += 1;
                    }
                }
                Ok((
                    format!("Applied {count} recommended tweak(s)."),
                    tweaks::list_states(),
                ))
            });
        } else if batch_undo_all {
            let ids: Vec<String> = self
                .tweaks
                .iter()
                .filter(|t| t.has_backup)
                .map(|t| t.id.clone())
                .collect();
            self.tweak_op.start(ui.ctx(), move || {
                let mut count = 0usize;
                for id in &ids {
                    if tweaks::undo_tweak(id).is_ok() {
                        count += 1;
                    }
                }
                Ok((
                    format!("Reverted {count} backed-up tweak(s)."),
                    tweaks::list_states(),
                ))
            });
        }
    }

    fn show_repair(&mut self, ui: &mut Ui) {
        let busy = self.repair_task.busy() || self.net_refresh.busy();
        if !self.net_loaded && !self.net_refresh.busy() {
            self.net_refresh
                .start(ui.ctx(), repair::list_network_adapters);
        }

        egui::ScrollArea::vertical()
            .id_salt("toolkit_repair_scroll")
            .show(ui, |ui| {
                self.show_repair_inner(ui, busy);
            });
    }

    fn show_repair_inner(&mut self, ui: &mut Ui, busy: bool) {
        ui.columns(2, |cols| {
            crate::theme::card(
                &mut cols[0],
                crate::i18n::tr("System & Network Repair"),
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (label, action) in [
                            (crate::i18n::tr("Flush DNS"), RepairAction::FlushDns),
                            (crate::i18n::tr("Renew DHCP IP"), RepairAction::RenewIp),
                            (
                                crate::i18n::tr("Reset network stack"),
                                RepairAction::NetworkReset,
                            ),
                            (crate::i18n::tr("Sync system clock"), RepairAction::TimeSync),
                            (crate::i18n::tr("Run SFC (/scannow)"), RepairAction::SfcScan),
                            (
                                crate::i18n::tr("Run DISM (/RestoreHealth)"),
                                RepairAction::DismRestoreHealth,
                            ),
                            (
                                crate::i18n::tr("Create restore point"),
                                RepairAction::CreateRestorePoint,
                            ),
                        ] {
                            if ui
                                .add_enabled(
                                    !busy,
                                    egui::Button::new(label).min_size(egui::vec2(165.0, 26.0)),
                                )
                                .clicked()
                            {
                                self.repair_task
                                    .start(ui.ctx(), move || repair::run_repair(action));
                            }
                        }
                    });
                    if busy {
                        ui.spinner();
                    }
                },
            );

            crate::theme::card(&mut cols[1], crate::i18n::tr("DNS Profile"), |ui| {
                let half = DnsProvider::ALL.len().div_ceil(2);
                let (left, right) = DnsProvider::ALL.split_at(half);
                ui.columns(2, |dns_cols| {
                    for (ci, chunk) in [left, right].into_iter().enumerate() {
                        for &p in chunk {
                            let selected = self.dns_choice == p;
                            let stroke = if selected {
                                Stroke::new(1.5, ACCENT)
                            } else {
                                dns_cols[ci].visuals().widgets.noninteractive.bg_stroke
                            };
                            let frame = egui::Frame::new()
                                .fill(if selected {
                                    ACCENT.gamma_multiply(0.14)
                                } else {
                                    Color32::TRANSPARENT
                                })
                                .stroke(stroke)
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(8, 5))
                                .show(&mut dns_cols[ci], |ui| {
                                    ui.set_width(ui.available_width());
                                    let (name, ips) = match p.servers() {
                                        Some((a, b)) => (
                                            p.label().split(" (").next().unwrap_or(p.label()),
                                            format!("{a} · {b}"),
                                        ),
                                        None => ("Automatic", "DHCP".to_owned()),
                                    };
                                    let r =
                                        ui.selectable_label(selected, RichText::new(name).strong());
                                    ui.label(RichText::new(ips).size(11.0).monospace().weak());
                                    r
                                });
                            let card_click = dns_cols[ci]
                                .interact(
                                    frame.response.rect,
                                    dns_cols[ci].scope_id().with(("dns-tile", p.label())),
                                    egui::Sense::click(),
                                )
                                .on_hover_cursor(egui::CursorIcon::PointingHand);
                            if frame.inner.clicked() || card_click.clicked() {
                                self.dns_choice = p;
                            }
                            dns_cols[ci].add_space(3.0);
                        }
                    }
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if crate::theme::primary_action(ui, !busy, crate::i18n::tr("Apply DNS"))
                        .clicked()
                    {
                        let provider = self.dns_choice;
                        self.repair_task.start(ui.ctx(), move || {
                            repair::run_repair(RepairAction::SetDns(provider))
                        });
                    }
                    if ui
                        .add_enabled(
                            !busy,
                            egui::Button::new(crate::i18n::tr("Refresh IP & DNS")),
                        )
                        .clicked()
                    {
                        self.net_refresh
                            .start(ui.ctx(), repair::list_network_adapters);
                    }
                });
            });
        });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            crate::theme::section(ui, crate::i18n::tr("Network Adapters & IP Configuration"));
            ui.add_space(12.0);
            crate::theme::switch(
                ui,
                &mut self.net_show_disconnected,
                crate::i18n::tr("Show disconnected adapters"),
            );
            ui.label(crate::i18n::tr("Show disconnected"));
        });
        ui.add_space(6.0);

        if let Some(err) = &self.net_error {
            crate::theme::colored(ui, BAD, err);
        } else {
            let mut visible_adapters: Vec<&NetAdapterInfo> = self
                .net_adapters
                .iter()
                .filter(|a| self.net_show_disconnected || a.status.eq_ignore_ascii_case("Up"))
                .collect();
            visible_adapters.sort_by_key(|a| {
                (
                    !a.status.eq_ignore_ascii_case("Up"),
                    a.gateway.is_empty(),
                    a.name.to_lowercase(),
                )
            });

            if visible_adapters.is_empty() {
                ui.weak(if self.net_refresh.busy() {
                    crate::i18n::tr("Reading network configuration…")
                } else {
                    crate::i18n::tr("No active network adapters reported.")
                });
            } else {
                ui.columns(2, |cols| {
                    for adapter in visible_adapters {
                        let ci =
                            usize::from(cols[1].min_rect().height() < cols[0].min_rect().height());
                        let up = adapter.status.eq_ignore_ascii_case("Up");
                        let accent = if up { GOOD } else { WARN };
                        let card_resp = egui::Frame::new()
                            .fill(crate::theme::card_fill(&cols[ci]))
                            .stroke(Stroke::new(
                                1.0,
                                cols[ci].visuals().widgets.noninteractive.bg_stroke.color,
                            ))
                            .corner_radius(crate::theme::SURFACE_RADIUS)
                            .inner_margin(Margin {
                                left: 14,
                                right: 12,
                                top: 10,
                                bottom: 10,
                            })
                            .show(&mut cols[ci], |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal_wrapped(|ui| {
                                    color_dot(ui, accent);
                                    ui.strong(&adapter.name);
                                    if !adapter.link_speed.is_empty() && up {
                                        ui.weak(&adapter.link_speed);
                                    }
                                    pill(
                                        ui,
                                        if adapter.dhcp_enabled { GOOD } else { ACCENT },
                                        if adapter.dhcp_enabled {
                                            "IP: DHCP"
                                        } else {
                                            "IP: Manual"
                                        },
                                    );
                                    pill(
                                        ui,
                                        if adapter.dns_dhcp { GOOD } else { ACCENT },
                                        if adapter.dns_dhcp {
                                            "DNS: Auto"
                                        } else {
                                            "DNS: Manual"
                                        },
                                    );
                                });
                                if !adapter.description.is_empty() {
                                    ui.weak(RichText::new(&adapter.description).size(11.0));
                                }
                                ui.add_space(4.0);
                                egui::Grid::new(("net_adapter_grid", &adapter.name))
                                    .num_columns(2)
                                    .spacing([12.0, 2.0])
                                    .show(ui, |ui| {
                                        let copy_val = |ui: &mut Ui, label: &str, val: &str| {
                                            ui.weak(label);
                                            if ui
                                                .add(
                                                    egui::Label::new(
                                                        RichText::new(val).monospace().size(11.5),
                                                    )
                                                    .truncate()
                                                    .sense(egui::Sense::click()),
                                                )
                                                .on_hover_text(crate::i18n::tr("Click to copy"))
                                                .clicked()
                                            {
                                                ui.ctx().copy_text(val.to_owned());
                                            }
                                            ui.end_row();
                                        };
                                        if !adapter.ipv4.is_empty() {
                                            copy_val(ui, "IPv4", &adapter.ipv4.join(", "));
                                        }
                                        if !adapter.gateway.is_empty() {
                                            copy_val(ui, "GW", &adapter.gateway);
                                        }
                                        if !adapter.dns_servers.is_empty() {
                                            copy_val(ui, "DNS", &adapter.dns_servers.join(", "));
                                        }
                                        if !adapter.ipv6.is_empty() {
                                            copy_val(ui, "IPv6", &adapter.ipv6.join(", "));
                                        }
                                        if !adapter.mac.is_empty() {
                                            copy_val(ui, "MAC", &adapter.mac);
                                        }
                                    });
                            });
                        let r = card_resp.response.rect;
                        cols[ci].painter().rect_filled(
                            egui::Rect::from_min_max(
                                r.left_top() + egui::vec2(1.0, 6.0),
                                egui::pos2(r.left() + 4.0, r.bottom() - 6.0),
                            ),
                            CornerRadius::same(2),
                            crate::theme::text_color(&cols[ci], accent),
                        );
                        cols[ci].add_space(6.0);
                    }
                });
            }
        }

        if let Some(res) = &self.repair_output {
            ui.add_space(6.0);
            crate::theme::card(ui, crate::i18n::tr("Command Output"), |ui| {
                match res {
                    Ok(out) => {
                        ui.monospace(out);
                    }
                    Err(err) => {
                        crate::theme::colored(ui, BAD, err);
                    }
                };
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::Harness;

    #[test]
    fn toolkit_subtabs_render_without_panic() {
        for tab in 0..6 {
            let mut view = View {
                subtab: tab,
                tweaks_loaded: true,
                tasks_loaded: true,
                net_loaded: true,
                ..Default::default()
            };
            let mut harness = Harness::builder()
                .allow_missing_glyphs()
                .with_size([900.0, 600.0])
                .build_ui(|ui| {
                    view.show(ui, &[]);
                });
            harness.run();
        }
    }
}
