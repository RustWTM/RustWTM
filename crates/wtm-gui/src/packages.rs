//! Exact package identities and reviewable installer requests.

use std::collections::BTreeSet;

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, Margin, RichText, Ui};
use egui_extras::Column;
use wtm_core::packages::{Inventory, Package, StoreApp, UpdatePlan, UpdateResult};

use crate::sort::{Sort, header, text};
use crate::theme::{ACCENT, BAD, CPU, GOOD, MEMORY, WARN};

fn pill(ui: &mut Ui, color: Color32, label: &str) {
    let fg = crate::theme::text_color(ui, color);
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(11.5).strong().color(fg));
        });
}

#[derive(Default)]
pub struct View {
    scan: crate::background::Task<Inventory>,
    update: crate::background::Task<Vec<UpdateResult>>,
    remove: crate::background::Task<String>,
    report: Option<Result<Inventory, String>>,
    query: String,
    selected: BTreeSet<(String, String)>,
    confirm: Option<UpdatePlan>,
    results: Option<Result<Vec<UpdateResult>, String>>,
    remove_status: Option<Result<String, String>>,
    error: Option<String>,
    bloat_only: bool,
}

impl View {
    pub fn show(&mut self, ui: &mut Ui, store: bool) -> bool {
        if let Some(r) = self.scan.poll() {
            self.report = Some(r);
            self.selected.clear();
        }
        if let Some(r) = self.update.poll() {
            self.results = Some(r);
            self.selected.clear();
        }
        if let Some(r) = self.remove.poll() {
            let ok = r.is_ok();
            self.remove_status = Some(r);
            if ok {
                self.scan.start(ui.ctx(), wtm_core::packages::inventory);
            }
        }
        let busy = self.scan.busy() || self.update.busy() || self.remove.busy();
        let mut windows = false;

        if self.report.is_none() && !busy {
            self.scan.start(ui.ctx(), wtm_core::packages::inventory);
        }

        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .char_limit(256)
                    .hint_text(crate::i18n::tr("Name, publisher or package ID"))
                    .desired_width(260.0),
            );
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new(crate::i18n::tr("Check applications and updates")),
                )
                .clicked()
            {
                self.scan.start(ui.ctx(), wtm_core::packages::inventory);
            }
            windows = ui
                .button(crate::i18n::tr("Windows Apps settings"))
                .clicked();
            if store {
                crate::theme::switch(
                    ui,
                    &mut self.bloat_only,
                    crate::i18n::tr("Recommended bloatware only"),
                );
                ui.label(crate::i18n::tr("Bloatware only"));
            }
            if busy {
                ui.spinner();
            }
        });

        if self.update.busy() {
            ui.add_space(4.0);
            pill(
                ui,
                ACCENT,
                crate::i18n::tr("Updating selected packages. Installer prompts remain visible."),
            );
        }

        ui.add_space(6.0);

        if let Some(result) = self.report.clone() {
            match result {
                Err(e) => {
                    crate::theme::colored(ui, WARN, e);
                }
                Ok(report) => {
                    for warning in &report.warnings {
                        ui.weak(warning);
                    }
                    let query = self.query.to_lowercase();
                    if store {
                        self.show_store(ui, &report.store, &query, busy);
                    } else {
                        self.show_updates(ui, &report.packages, &query, busy);
                    }
                }
            }
        } else {
            crate::theme::loading(ui, crate::i18n::tr("Loading applications…"));
        }

        if let Some(result) = &self.results {
            ui.add_space(6.0);
            crate::theme::card(ui, crate::i18n::tr("Update results"), |ui| match result {
                Err(e) => {
                    crate::theme::colored(ui, WARN, e);
                    ui.weak(crate::i18n::tr(
                            "An interrupted update may still have an installer running. Refresh before retrying.",
                        ));
                }
                Ok(results) => {
                    for r in results {
                        ui.horizontal_wrapped(|ui| {
                            pill(ui, GOOD, &r.status);
                            ui.strong(&r.id);
                            ui.weak(&r.message);
                        });
                    }
                    ui.weak(crate::i18n::tr(
                            "Refresh to confirm installed versions; an installer result alone is not inventory verification.",
                        ));
                }
            });
        }

        if let Some(plan) = self.confirm.clone() {
            let mut run = false;
            let mut cancel = false;
            let modal = egui::Modal::new(egui::Id::unique("package-update-review"))
                .frame(crate::theme::dialog_frame(ui.ctx()))
                .show(ui.ctx(), |ui| {
                    ui.set_max_width(620.0);
                    ui.heading(crate::i18n::tr("Review package updates"));
                    ui.label(crate::i18n::tr(
                        "Only these package IDs and target versions will be requested. Each package is checked again before its installer starts.",
                    ));
                    egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                        for p in &plan.packages {
                            ui.horizontal_wrapped(|ui| {
                                ui.strong(&p.name);
                                pill(ui, CPU, &p.source);
                                ui.weak(&p.installed);
                                ui.label("→");
                                crate::theme::colored(
                                    ui,
                                    GOOD,
                                    p.target.as_deref().unwrap_or("—"),
                                );
                            });
                            ui.monospace(&p.id);
                            crate::theme::divider(ui);
                        }
                    });
                    ui.horizontal(|ui| {
                        run = crate::theme::primary_action(
                            ui,
                            !busy,
                            crate::i18n::tr("Start selected updates"),
                        )
                        .clicked();
                        cancel = ui.button(crate::i18n::tr("Cancel")).clicked();
                    });
                });
            if run {
                self.confirm = None;
                self.results = None;
                self.update
                    .start(ui.ctx(), move || wtm_core::packages::update(&plan));
            } else if cancel || modal.should_close() {
                self.confirm = None;
            }
        }
        windows
    }

    fn show_store(&mut self, ui: &mut Ui, apps: &[StoreApp], query: &str, busy: bool) {
        let total = apps.len();
        let removable_count = apps.iter().filter(|a| a.removable).count();
        let bloat_count = apps
            .iter()
            .filter(|a| wtm_core::packages::is_recommended_bloatware(&a.id))
            .count();

        let total_txt = format!("{total} apps");
        let rem_txt = format!("{removable_count} removable");
        let bloat_txt = format!("{bloat_count} bloatware");
        crate::theme::card_with(
            ui,
            crate::i18n::tr("Store apps"),
            &[(&total_txt, CPU), (&rem_txt, GOOD), (&bloat_txt, WARN)],
            |ui| {
                if let Some(status) = &self.remove_status {
                    match status {
                        Ok(msg) => pill(ui, GOOD, msg),
                        Err(err) => pill(ui, BAD, err),
                    }
                } else {
                    ui.weak(crate::i18n::tr(
                        "Current-user Microsoft Store packages. Right-click any row to copy ID, version or install path.",
                    ));
                }
            },
        );

        ui.add_space(6.0);
        let mut visible: Vec<&StoreApp> = apps
            .iter()
            .filter(|p| {
                (!self.bloat_only || wtm_core::packages::is_recommended_bloatware(&p.id))
                    && (query.is_empty()
                        || format!("{} {} {}", p.name, p.publisher, p.id)
                            .to_lowercase()
                            .contains(query))
            })
            .collect();

        if visible.is_empty() {
            crate::theme::empty_state(
                ui,
                crate::i18n::tr("No matching Store apps"),
                crate::i18n::tr("Clear the search filter or turn off 'Bloatware only'."),
            );
            return;
        }

        let mut sort = Sort::load(ui, "store_apps", Sort::new(0, false));
        sort.apply(&mut visible, |a, b, col| match col {
            0 => text(&a.name, &b.name),
            1 => text(&a.publisher, &b.publisher),
            2 => text(&a.version, &b.version),
            _ => wtm_core::packages::is_recommended_bloatware(&b.id)
                .cmp(&wtm_core::packages::is_recommended_bloatware(&a.id))
                .then_with(|| text(&a.name, &b.name)),
        });

        let mut remove_id: Option<String> = None;
        let row_height = ui.spacing().interact_size.y.max(28.0);
        let table_w = ui.available_width();
        ui.style_mut().interaction.selectable_labels = false;

        crate::theme::table_panel(ui, "store_apps_table_panel", table_w, |ui| {
            crate::theme::table(ui)
                .id_salt("store_apps_table")
                .sense(egui::Sense::click())
                .striped(true)
                .resizable(true)
                .auto_shrink([false, true])
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::remainder().at_least(210.0).clip(true))
                .column(Column::initial(200.0).clip(true))
                .column(Column::initial(120.0).clip(true))
                .column(Column::initial(104.0))
                .column(Column::initial(100.0))
                .header(row_height, |mut row| {
                    for (col, label) in ["Application", "Publisher", "Version", "Type"]
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
                            ui.strong(crate::i18n::tr("Action"));
                        });
                    });
                })
                .body(|body| {
                    body.rows(row_height, visible.len(), |mut row| {
                        let app = visible[row.index()];
                        let bloat = wtm_core::packages::is_recommended_bloatware(&app.id);
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.strong(&app.name).on_hover_text(&app.id);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.add(egui::Label::new(&app.publisher).truncate());
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&app.version).monospace().size(11.5),
                                    )
                                    .truncate(),
                                );
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if bloat {
                                    pill(ui, WARN, crate::i18n::tr("Bloatware"));
                                } else if !app.removable {
                                    pill(ui, CPU, crate::i18n::tr("System"));
                                } else {
                                    pill(ui, GOOD, crate::i18n::tr("App"));
                                }
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if app.removable {
                                    if ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(crate::i18n::tr("Remove")).small(),
                                        )
                                        .clicked()
                                    {
                                        remove_id = Some(app.id.clone());
                                    }
                                } else {
                                    ui.weak(crate::i18n::tr("Protected"));
                                }
                            });
                        });
                        crate::context_actions::menu(
                            &row.response(),
                            ("store-package", &app.id),
                            |ui| {
                                crate::context_actions::copy(ui, crate::i18n::tr("Name"), || {
                                    app.name.clone()
                                });
                                crate::context_actions::copy(ui, "ID", || app.id.clone());
                                crate::context_actions::copy(
                                    ui,
                                    crate::i18n::tr("Version"),
                                    || app.version.clone(),
                                );
                                if !app.location.is_empty() {
                                    crate::context_actions::copy(
                                        ui,
                                        crate::i18n::tr("Path"),
                                        || app.location.clone(),
                                    );
                                }
                            },
                        );
                    });
                });
        });
        sort.store(ui, "store_apps");

        if let Some(id) = remove_id {
            self.remove
                .start(ui.ctx(), move || wtm_core::packages::remove_store_app(&id));
        }
    }

    fn show_updates(&mut self, ui: &mut Ui, packages: &[Package], query: &str, busy: bool) {
        let updates: Vec<&Package> = packages.iter().filter(|p| p.target.is_some()).collect();
        let upd_txt = crate::i18n::format("{0} updates available", &[updates.len().to_string()]);
        let sel_txt = format!("{} selected", self.selected.len());

        crate::theme::card_with(
            ui,
            crate::i18n::tr("Package updates"),
            &[(&upd_txt, ACCENT), (&sel_txt, GOOD)],
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    if crate::theme::primary_action(
                        ui,
                        !busy && !self.selected.is_empty(),
                        crate::i18n::tr("Review selected updates"),
                    )
                    .clicked()
                    {
                        let selected: Vec<_> = updates
                            .iter()
                            .filter(|p| self.selected.contains(&(p.source.clone(), p.id.clone())))
                            .map(|p| (*p).clone())
                            .collect();
                        match UpdatePlan::new(&selected) {
                            Ok(plan) => {
                                self.confirm = Some(plan);
                                self.error = None;
                            }
                            Err(e) => self.error = Some(e),
                        }
                    }
                    if ui
                        .add_enabled(
                            !busy && !updates.is_empty(),
                            egui::Button::new("Select all"),
                        )
                        .clicked()
                    {
                        for p in &updates {
                            if matches!(p.source.as_str(), "winget" | "msstore") {
                                self.selected.insert((p.source.clone(), p.id.clone()));
                            }
                        }
                    }
                    if ui
                        .add_enabled(
                            !busy && !self.selected.is_empty(),
                            egui::Button::new("Clear"),
                        )
                        .clicked()
                    {
                        self.selected.clear();
                    }
                });
                if let Some(e) = &self.error {
                    ui.add_space(4.0);
                    crate::theme::colored(ui, WARN, e);
                }
            },
        );

        ui.add_space(6.0);
        let mut visible: Vec<&Package> = updates
            .into_iter()
            .filter(|p| {
                query.is_empty()
                    || format!("{} {} {}", p.name, p.id, p.source)
                        .to_lowercase()
                        .contains(query)
            })
            .collect();

        if visible.is_empty() {
            crate::theme::empty_state(
                ui,
                crate::i18n::tr("All packages are up to date"),
                crate::i18n::tr("No package updates were reported by WinGet or Microsoft Store."),
            );
            return;
        }

        let mut sort = Sort::load(ui, "package_updates", Sort::new(0, false));
        sort.apply(&mut visible, |a, b, col| match col {
            0 => text(&a.name, &b.name),
            1 => text(&a.source, &b.source),
            2 => text(&a.installed, &b.installed),
            _ => text(
                a.target.as_deref().unwrap_or(""),
                b.target.as_deref().unwrap_or(""),
            ),
        });

        let row_height = ui.spacing().interact_size.y.max(28.0);
        let table_w = ui.available_width();
        ui.style_mut().interaction.selectable_labels = false;

        crate::theme::table_panel(ui, "package_updates_table_panel", table_w, |ui| {
            crate::theme::table(ui)
                .id_salt("package_updates_table")
                .sense(egui::Sense::click())
                .striped(true)
                .resizable(true)
                .auto_shrink([false, true])
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(56.0))
                .column(Column::remainder().at_least(220.0).clip(true))
                .column(Column::initial(92.0))
                .column(Column::initial(120.0).clip(true))
                .column(Column::initial(130.0).clip(true))
                .header(row_height, |mut row| {
                    row.col(|ui| {
                        crate::theme::table_cell(ui, |ui| {
                            ui.strong(crate::i18n::tr("Pick"));
                        });
                    });
                    for (col, label) in ["Package", "Source", "Installed", "Available"]
                        .into_iter()
                        .enumerate()
                    {
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                header(ui, crate::i18n::tr(label), col, false, &mut sort);
                            });
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_height, visible.len(), |mut row| {
                        let p = visible[row.index()];
                        let key = (p.source.clone(), p.id.clone());
                        let supported = matches!(p.source.as_str(), "winget" | "msstore");
                        let mut on = self.selected.contains(&key);

                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                if ui
                                    .add_enabled_ui(!busy && supported, |ui| {
                                        crate::theme::switch(ui, &mut on, &p.name)
                                    })
                                    .inner
                                    .changed()
                                {
                                    if on {
                                        self.selected.insert(key.clone());
                                    } else {
                                        self.selected.remove(&key);
                                    }
                                }
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.strong(&p.name).on_hover_text(&p.id);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                let col = if p.source == "winget" { CPU } else { MEMORY };
                                pill(ui, col, &p.source);
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.weak(RichText::new(&p.installed).monospace().size(11.5));
                            });
                        });
                        row.col(|ui| {
                            crate::theme::table_cell(ui, |ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "→ {}",
                                        p.target.as_deref().unwrap_or("—")
                                    ))
                                    .monospace()
                                    .size(11.5)
                                    .strong()
                                    .color(crate::theme::text_color(ui, GOOD)),
                                );
                            });
                        });

                        crate::context_actions::menu(
                            &row.response(),
                            ("package-update", &key),
                            |ui| {
                                crate::context_actions::copy(ui, "ID", || p.id.clone());
                                if !busy
                                    && supported
                                    && crate::context_actions::action(
                                        ui,
                                        crate::i18n::tr("Review package updates"),
                                    )
                                {
                                    match UpdatePlan::new(std::slice::from_ref(p)) {
                                        Ok(plan) => {
                                            self.confirm = Some(plan);
                                            self.error = None;
                                        }
                                        Err(e) => self.error = Some(e),
                                    }
                                }
                            },
                        );
                    });
                });
        });
        sort.store(ui, "package_updates");
    }
}

#[cfg(test)]
impl View {
    pub fn fixture(review: bool) -> Self {
        let package = wtm_core::packages::Package {
            id: "Example.Editor".into(),
            source: "winget".into(),
            name: "Example Editor".into(),
            installed: "2.4.0".into(),
            target: Some("2.5.0".into()),
        };
        let report = Inventory {
            packages: vec![package.clone()],
            store: vec![wtm_core::packages::StoreApp {
                id: "Example.Notes_3.0_x64__fixture".into(),
                family: "Example.Notes_fixture".into(),
                name: "Example Notes".into(),
                publisher: "Example Publisher".into(),
                version: "3.0".into(),
                location: "C:\\Program Files\\WindowsApps\\Example.Notes".into(),
                removable: true,
            }],
            warnings: vec![],
        };
        Self {
            report: Some(Ok(report)),
            selected: BTreeSet::from([("winget".into(), "Example.Editor".into())]),
            confirm: review.then(|| UpdatePlan::new(&[package]).unwrap()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::kittest::Queryable;

    #[test]
    fn cancelling_package_review_never_starts_an_update() {
        let mut v = View {
            report: Some(Ok(Inventory::default())),
            ..Default::default()
        };
        v.confirm = Some(
            UpdatePlan::new(&[wtm_core::packages::Package {
                id: "Example.Editor".into(),
                source: "winget".into(),
                name: "Editor".into(),
                installed: "1".into(),
                target: Some("2".into()),
            }])
            .unwrap(),
        );
        let mut h = egui_kittest::Harness::builder()
            .allow_missing_glyphs()
            .with_size([1000.0, 800.0])
            .build_ui_state(
                |ui, v: &mut View| {
                    v.show(ui, false);
                },
                v,
            );
        h.run();
        h.get_by_label("Cancel").click();
        h.run();
        assert!(h.state().confirm.is_none());
        assert!(!h.state().update.busy());
    }
}
