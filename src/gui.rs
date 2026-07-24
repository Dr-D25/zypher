use crate::{pack, unpack, CompressionMethod};
use eframe::egui;
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Serialize, Deserialize)]
struct App {
    tab: Tab,
    // Pack
    files_to_pack: Vec<PathBuf>,
    output_path: PathBuf,
    pack_password: String,
    compression_level: u32,
    compression_method: String,
    // Append
    append_archive: PathBuf,
    append_files: Vec<PathBuf>,
    append_password: String,
    append_compression_level: u32,
    append_compression_method: String,
    // Unpack
    archive_path: PathBuf,
    extract_dir: PathBuf,
    extract_password: String,
    // Verify
    verify_path: PathBuf,
    verify_password: String,
    // SFX
    sfx_archive: PathBuf,
    sfx_output: PathBuf,
    // Theme
    dark_mode: bool,
    // Log
    log: String,
    // transient state (not serialized)
    #[serde(skip)]
    busy: bool,
    #[serde(skip)]
    progress: Option<f32>,
    #[serde(skip)]
    progress_shared: Option<Arc<Mutex<f32>>>,
    #[serde(skip)]
    result_shared: Option<Arc<Mutex<Option<Result<(), String>>>>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            tab: Tab::default(),
            files_to_pack: vec![],
            output_path: PathBuf::new(),
            pack_password: String::new(),
            compression_level: 3,
            compression_method: "zstd".into(),
            append_archive: PathBuf::new(),
            append_files: vec![],
            append_password: String::new(),
            append_compression_level: 3,
            append_compression_method: "zstd".into(),
            archive_path: PathBuf::new(),
            extract_dir: PathBuf::new(),
            extract_password: String::new(),
            verify_path: PathBuf::new(),
            verify_password: String::new(),
            sfx_archive: PathBuf::new(),
            sfx_output: PathBuf::new(),
            dark_mode: false,
            log: String::new(),
            busy: false,
            progress: None,
            progress_shared: None,
            result_shared: None,
        }
    }
}

#[derive(PartialEq, Default, Serialize, Deserialize)]
enum Tab {
    #[default]
    Pack,
    Append,
    Unpack,
    Verify,
    Sfx,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if self.compression_level == 0 && self.compression_method.is_empty() {
            if let Some(storage) = frame.storage() {
                if let Some(saved) = storage.get_string("app_state") {
                    if let Ok(state) = serde_json::from_str::<App>(&saved) {
                        *self = state;
                    }
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            if let Ok(json) = serde_json::to_string(&self) {
                if let Some(storage) = frame.storage_mut() {
                    storage.set_string("app_state", json);
                }
            }
        }

        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        let dropped_files = ctx.input_mut(|i| std::mem::take(&mut i.raw.dropped_files));
        if !dropped_files.is_empty() {
            let paths: Vec<PathBuf> = dropped_files.iter().filter_map(|f| f.path.clone()).collect();
            let num = paths.len();
            match self.tab {
                Tab::Pack if !self.busy => {
                    self.files_to_pack.extend(paths);
                    self.add_log(&format!("Added {} file(s)", num));
                }
                Tab::Append if !self.busy => {
                    self.append_files.extend(paths);
                    self.add_log(&format!("Added {} file(s) to append", num));
                }
                Tab::Unpack if !self.busy && !paths.is_empty() => {
                    self.archive_path = paths[0].clone();
                    self.add_log(&format!("Set archive: {}", self.archive_path.display()));
                }
                Tab::Verify if !self.busy && !paths.is_empty() => {
                    self.verify_path = paths[0].clone();
                    self.add_log(&format!("Set archive: {}", self.verify_path.display()));
                }
                Tab::Sfx if !self.busy && !paths.is_empty() => {
                    self.sfx_archive = paths[0].clone();
                    self.add_log(&format!("Set SFX archive: {}", self.sfx_archive.display()));
                }
                _ => {}
            }
        }

        let result_arc = self.result_shared.take();
        if let Some(arc) = result_arc {
            let mut should_return = false;
            match arc.try_lock() {
                Ok(mut guard) => {
                    if let Some(res) = guard.take() {
                        self.progress_shared = None;
                        self.busy = false;
                        self.progress = None;
                        match res {
                            Ok(()) => self.add_log("Operation completed successfully."),
                            Err(e) => self.add_log(&format!("Error: {}", e)),
                        }
                    } else {
                        should_return = true;
                    }
                }
                Err(_) => {
                    should_return = true;
                }
            }
            if should_return {
                self.result_shared = Some(arc.clone());
            }
        }

        if let Some(ref shared) = self.progress_shared {
            let val = *shared.lock().unwrap();
            self.progress = Some(if val < 0.0 { 1.0 } else { val });
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Zypher - Secure Archive Tool by Dr.D25");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(if self.dark_mode { "☀ Light" } else { "🌙 Dark" })
                        .clicked()
                    {
                        self.dark_mode = !self.dark_mode;
                    }
                });
            });
            ui.separator();

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Pack, "📦 Pack");
                ui.selectable_value(&mut self.tab, Tab::Append, "➕ Append");
                ui.selectable_value(&mut self.tab, Tab::Unpack, "📂 Unpack");
                ui.selectable_value(&mut self.tab, Tab::Verify, "🔍 Verify");
                ui.selectable_value(&mut self.tab, Tab::Sfx, "🚀 SFX");
            });
            ui.separator();

            if self.busy {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new());
                    if let Some(p) = self.progress {
                        ui.add(egui::ProgressBar::new(p).show_percentage());
                    } else {
                        ui.label("Working...");
                    }
                });
            } else if let Some(p) = self.progress {
                ui.add(egui::ProgressBar::new(p).show_percentage());
            }

            match self.tab {
                Tab::Pack => self.pack_tab(ui, ctx),
                Tab::Append => self.append_tab(ui, ctx),
                Tab::Unpack => self.unpack_tab(ui, ctx),
                Tab::Verify => self.verify_tab(ui, ctx),
                Tab::Sfx => self.sfx_tab(ui, ctx),
            }

            ui.separator();
            ui.label("Log:");
            ui.add(
                egui::TextEdit::multiline(&mut self.log)
                    .desired_width(f32::INFINITY)
                    .desired_rows(8)
                    .interactive(false),
            );
        });
    }
}

impl App {
    fn add_log(&mut self, msg: &str) {
        self.log.push_str(msg);
        self.log.push('\n');
    }

    fn parse_method(&self, s: &str) -> CompressionMethod {
        match s {
            "zstd" => CompressionMethod::Zstd,
            "lz4" => CompressionMethod::Lz4,
            "brotli" => CompressionMethod::Brotli,
            _ => CompressionMethod::Zstd,
        }
    }

    fn start_operation<F>(&mut self, ctx: &egui::Context, f: F)
    where
        F: FnOnce(Box<dyn Fn(f32) + Send>) -> Result<(), crate::error::ZypherError> + Send + 'static,
    {
        let progress_shared = Arc::new(Mutex::new(0.0f32));
        let result_shared = Arc::new(Mutex::new(None));
        self.progress_shared = Some(progress_shared.clone());
        self.result_shared = Some(result_shared.clone());
        self.busy = true;
        self.progress = Some(0.0);

        let ctx_clone = ctx.clone();
        let ctx_clone2 = ctx.clone();
        let progress_for_cb = progress_shared.clone();
        let progress_for_final = progress_shared;
        let result_for_final = result_shared;

        thread::spawn(move || {
            let cb = Box::new(move |p: f32| {
                if let Ok(mut val) = progress_for_cb.lock() {
                    *val = p;
                }
                ctx_clone.request_repaint();
            }) as Box<dyn Fn(f32) + Send>;

            let result = f(cb);
            let res_str = match result {
                Ok(()) => Ok(()),
                Err(e) => Err(format!("{}", e)),
            };
            *result_for_final.lock().unwrap() = Some(res_str);
            if let Ok(mut val) = progress_for_final.lock() {
                *val = -1.0;
            }
            ctx_clone2.request_repaint();
        });
    }

    fn pack_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("Add files...").clicked() {
                if let Some(files) = FileDialog::new().pick_files() {
                    self.files_to_pack = files;
                }
            }
            if ui.button("Set output...").clicked() {
                if let Some(path) = FileDialog::new().save_file() {
                    self.output_path = path;
                }
            }
        });
        ui.label(format!(
            "Files: {}",
            self.files_to_pack
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        ui.label(format!(
            "Output: {}",
            if self.output_path.as_os_str().is_empty() {
                "not selected"
            } else {
                self.output_path.to_str().unwrap_or("invalid")
            }
        ));
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.pack_password).password(true));
        });
        ui.horizontal(|ui| {
            ui.label("Compression level:");
            ui.add(egui::Slider::new(&mut self.compression_level, 1..=22).text("level"));
        });

        ui.label("Method:");
        egui::ComboBox::from_id_salt("comp_method")
            .selected_text(self.compression_method.as_str())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.compression_method, "zstd".into(), "zstd");
                ui.selectable_value(&mut self.compression_method, "lz4".into(), "lz4");
                ui.selectable_value(&mut self.compression_method, "brotli".into(), "brotli");
            });

        if ui.button("Pack").clicked() && !self.busy {
            if self.files_to_pack.is_empty() || self.output_path.as_os_str().is_empty() {
                self.add_log("Error: select files and output path");
                return;
            }
            let password = if self.pack_password.is_empty() {
                None
            } else {
                Some(self.pack_password.clone())
            };
            let files = self.files_to_pack.clone();
            let output = self.output_path.clone();
            let level = self.compression_level;
            let method = self.parse_method(&self.compression_method);
            self.start_operation(ctx, move |cb| {
                pack::pack_files(&output, &files, password.as_deref(), level, method, cb)
            });
            self.add_log("Packing started...");
        }
    }

    fn append_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("Select archive...").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.append_archive = path;
                }
            }
            if ui.button("Add files to append...").clicked() {
                if let Some(files) = FileDialog::new().pick_files() {
                    self.append_files = files;
                }
            }
        });
        ui.label(format!(
            "Archive: {}",
            if self.append_archive.as_os_str().is_empty() {
                "not selected"
            } else {
                self.append_archive.to_str().unwrap_or("invalid")
            }
        ));
        ui.label(format!(
            "Files to add: {}",
            self.append_files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.append_password).password(true));
        });
        ui.horizontal(|ui| {
            ui.label("Compression level:");
            ui.add(egui::Slider::new(&mut self.append_compression_level, 1..=22).text("level"));
        });

        ui.label("Method:");
        egui::ComboBox::from_id_salt("append_comp_method")
            .selected_text(self.append_compression_method.as_str())
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.append_compression_method, "zstd".into(), "zstd");
                ui.selectable_value(&mut self.append_compression_method, "lz4".into(), "lz4");
                ui.selectable_value(&mut self.append_compression_method, "brotli".into(), "brotli");
            });

        if ui.button("Append").clicked() && !self.busy {
            if self.append_archive.as_os_str().is_empty() || self.append_files.is_empty() {
                self.add_log("Error: select archive and files to append");
                return;
            }
            let password = if self.append_password.is_empty() {
                None
            } else {
                Some(self.append_password.clone())
            };
            let archive = self.append_archive.clone();
            let files = self.append_files.clone();
            let level = self.append_compression_level;
            let method = self.parse_method(&self.append_compression_method);
            self.start_operation(ctx, move |cb| {
                pack::append_files(&archive, &files, password.as_deref(), level, method, cb)
            });
            self.add_log("Append started...");
        }
    }

    fn unpack_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("Select archive...").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.archive_path = path;
                }
            }
            if ui.button("Select output dir...").clicked() {
                if let Some(path) = FileDialog::new().pick_folder() {
                    self.extract_dir = path;
                }
            }
        });
        ui.label(format!(
            "Archive: {}",
            if self.archive_path.as_os_str().is_empty() {
                "not selected"
            } else {
                self.archive_path.to_str().unwrap_or("invalid")
            }
        ));
        ui.label(format!(
            "Output dir: {}",
            if self.extract_dir.as_os_str().is_empty() {
                "not selected"
            } else {
                self.extract_dir.to_str().unwrap_or("invalid")
            }
        ));
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.extract_password).password(true));
        });

        if ui.button("Unpack all").clicked() && !self.busy {
            if self.archive_path.as_os_str().is_empty() || self.extract_dir.as_os_str().is_empty() {
                self.add_log("Error: select archive and output dir");
                return;
            }
            let password = if self.extract_password.is_empty() {
                None
            } else {
                Some(self.extract_password.clone())
            };
            let archive = self.archive_path.clone();
            let dir = self.extract_dir.clone();
            self.start_operation(ctx, move |cb| {
                unpack::extract_all(&archive, &dir, password.as_deref(), cb)
            });
            self.add_log("Unpacking started...");
        }
    }

    fn verify_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("Select archive...").clicked() {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.verify_path = path;
                }
            }
        });
        ui.label(format!(
            "Archive: {}",
            if self.verify_path.as_os_str().is_empty() {
                "not selected"
            } else {
                self.verify_path.to_str().unwrap_or("invalid")
            }
        ));
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.verify_password).password(true));
        });

        if ui.button("Verify").clicked() && !self.busy {
            if self.verify_path.as_os_str().is_empty() {
                self.add_log("Error: select archive");
                return;
            }
            let password = if self.verify_password.is_empty() {
                None
            } else {
                Some(self.verify_password.clone())
            };
            let archive = self.verify_path.clone();
            self.start_operation(ctx, move |cb| {
                unpack::verify_archive(&archive, password.as_deref(), cb)
            });
            self.add_log("Verification started...");
        }
    }

    fn sfx_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if ui.button("Select archive...").clicked() {
                if let Some(p) = FileDialog::new().pick_file() {
                    self.sfx_archive = p;
                }
            }
            if ui.button("Save SFX as...").clicked() {
                if let Some(p) = FileDialog::new().save_file() {
                    self.sfx_output = p;
                }
            }
        });
        ui.label(format!(
            "Archive: {}",
            if self.sfx_archive.as_os_str().is_empty() {
                "not selected"
            } else {
                self.sfx_archive.to_str().unwrap_or("invalid")
            }
        ));
        ui.label(format!(
            "Output SFX: {}",
            if self.sfx_output.as_os_str().is_empty() {
                "not selected"
            } else {
                self.sfx_output.to_str().unwrap_or("invalid")
            }
        ));
        if ui.button("Create SFX").clicked() && !self.busy {
            if self.sfx_archive.as_os_str().is_empty() || self.sfx_output.as_os_str().is_empty() {
                self.add_log("Error: select archive and SFX output path");
                return;
            }
            let archive = self.sfx_archive.clone();
            let output = self.sfx_output.clone();
            self.start_operation(ctx, move |_cb| pack::create_sfx(&archive, &output));
            self.add_log("SFX creation started...");
        }
    }
}

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 380.0])
            .with_min_inner_size([300.0, 350.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Zypher - Secure Archive Tool by Dr.D25",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}