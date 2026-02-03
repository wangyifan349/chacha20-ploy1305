// ============================================================
//  Batch Encrypt GUI  (ChaCha20-Poly1305, overwrite in-place)
//  ----------------------------------------------------------
//  • Modern GUI based on eframe / egui 0.24
//  • Multithread (1 × background thread  +  rayon inside)
//  • Each file is encrypted/decrypted in-place, 12-byte nonce
//  • Password → 32-byte key via 100 000× SHA-256 iterations
//  • All heavy work off the UI thread → UI stays responsive
//
//  NOTE: Files are overwritten. Make backups first!
// ============================================================

// Hide the console window on Windows when running the *release*
// build (kept in debug for easier tracing).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// ───── Std / Crates Imports ─────────────────────────────────
use anyhow::{anyhow, Result};                // ergonomic error handling
use chacha20poly1305::{                      // AEAD cipher
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use crossbeam_channel::{unbounded, Receiver, Sender}; // zero-cost async channel
use eframe::{
    egui::{
        self,                                        // root `egui` module
        Color32, ProgressBar, RichText, Visuals,     // frequently used widgets/types
        ViewportBuilder, TextStyle, FontId,
    },
    CreationContext,
};
use rand::random;                        // generate random nonce
use rayon::prelude::*;                   // file-level parallelism
use sha2::{Digest, Sha256};              // SHA-256 implementation
use std::{
    fs::{self, OpenOptions},             // file I/O
    io::Write,                           // trait for `write_all`
    path::{Path, PathBuf},               // path helpers
    sync::atomic::{AtomicUsize, Ordering}, // thread-safe counters
    thread,                              // spawn background thread
};
use walkdir::WalkDir;                    // recursive directory walker

// ───── Global Constants ────────────────────────────────────
const NONCE_LEN: usize = 12;             // 96-bit nonce required by ChaCha20-Poly1305
const HASH_ROUNDS: usize = 100_000;      // PBKDF: #iterations of SHA-256
const APP_NAME: &str = "Batch Encrypt GUI";

// ────────────────────────────────────────────────────────────
// 1.  Crypto Helper Functions
// ────────────────────────────────────────────────────────────

/// Derive a 256-bit key from an arbitrary-length password
/// by iterating SHA-256 `HASH_ROUNDS` times.
/// Very small & portable PBKDF (not as strong as Argon2,
/// but zero extra dependency and good enough for offline use).
fn derive_key(password: &str) -> Key {
    // First hash of raw password
    let mut digest = Sha256::digest(password.as_bytes()).to_vec();

    // Repeat hashing `HASH_ROUNDS-1` more times
    for _ in 1..HASH_ROUNDS {
        digest = Sha256::digest(&digest).to_vec();
    }

    // Convert the resulting 32-byte slice into a ChaCha key
    Key::from_slice(&digest).to_owned()
}

/// Encrypt *one* file, overwrite it in-place.
/// Format: [12-byte nonce][ciphertext (incl. tag)]
fn encrypt_file(path: &Path, key: &Key) -> Result<()> {
    let plaintext = fs::read(path)?;                    // load whole file
    let cipher = ChaCha20Poly1305::new(key);            // AEAD instance
    let nonce_bytes: [u8; NONCE_LEN] = random();        // random 96-bit nonce
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AEAD encrypt → ciphertext + 16-byte tag
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| anyhow!("encrypt error"))?;

    // Truncate & overwrite file (atomic on most FS)
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;
    Ok(())
}

/// Decrypt one file in-place. Reverse operation of `encrypt_file`.
fn decrypt_file(path: &Path, key: &Key) -> Result<()> {
    let data = fs::read(path)?;                         // read whole file
    if data.len() < NONCE_LEN {
        return Err(anyhow!("file too small"));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decrypt error"))?;

    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(&plaintext)?;
    Ok(())
}

// ────────────────────────────────────────────────────────────
// 2.  Background Thread / Progress Messaging
// ────────────────────────────────────────────────────────────

/// Progress messages sent from worker thread → GUI thread.
enum BgMsg {
    Total(usize),                 // announce #files to process
    Step,                         // processed 1 file
    Finished { ok: usize, ng: usize }, // everything done
}

/// Heavy worker: enumerate files, then encrypt/decrypt each of them
/// in parallel (`rayon`) while reporting progress through `tx`.
fn background_worker(
    encrypt_mode: bool,
    directory: PathBuf,
    password: String,
    tx: Sender<BgMsg>,
) {
    // Derive key once
    let key = derive_key(&password);

    // Recursively gather all regular files
    let file_list: Vec<PathBuf> = WalkDir::new(&directory)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    // send total
    let _ = tx.send(BgMsg::Total(file_list.len()));

    // Atomic counters for success / failure
    let ok_counter = AtomicUsize::new(0);
    let ng_counter = AtomicUsize::new(0);

    // Parallel for each file
    file_list.par_iter().for_each(|path| {
        let result = if encrypt_mode {
            encrypt_file(path, &key)
        } else {
            decrypt_file(path, &key)
        };

        match result {
            Ok(_) => ok_counter.fetch_add(1, Ordering::Relaxed),
            Err(e) => {
                eprintln!("FAIL {} => {}", path.display(), e);
                ng_counter.fetch_add(1, Ordering::Relaxed)
            }
        };

        // notify GUI: one more finished
        tx.send(BgMsg::Step).ok();
    });

    // Final stats
    let _ = tx.send(BgMsg::Finished {
        ok: ok_counter.load(Ordering::Relaxed),
        ng: ng_counter.load(Ordering::Relaxed),
    });
}

// ────────────────────────────────────────────────────────────
// 3.  Gui State struct (holds all UI data & progress)
// ────────────────────────────────────────────────────────────
struct GuiState {
    /* input fields */
    encrypt_mode: bool,           // true = encrypt, false = decrypt
    target_dir:   Option<PathBuf>,
    password:     String,

    /* progress counters */
    running: bool,
    total:   usize,
    done:    usize,
    ok:      usize,
    ng:      usize,

    /* channel receiver (None when idle) */
    rx: Option<Receiver<BgMsg>>,
}

impl GuiState {
    /// construct + configure dark theme + bigger fonts
    fn new(cc: &CreationContext<'_>) -> Self {
        // dark theme
        cc.egui_ctx.set_visuals(Visuals::dark());

        // bump default font sizes
        let mut style = (*cc.egui_ctx.style()).clone();
        style.text_styles.insert(TextStyle::Body,   FontId::proportional(20.0));
        style.text_styles.insert(TextStyle::Button, FontId::proportional(22.0));
        style.text_styles.insert(TextStyle::Heading,FontId::proportional(36.0));
        cc.egui_ctx.set_style(style);

        Self {
            encrypt_mode: true,
            target_dir: None,
            password: String::new(),
            running: false,
            total: 0,
            done: 0,
            ok: 0,
            ng: 0,
            rx: None,
        }
    }

    /// Launch background worker in a dedicated thread.
    fn start_worker(&mut self) {
        // basic validation
        if self.target_dir.is_none() || self.password.is_empty() {
            return;
        }

        // reset counters
        self.running = true;
        self.total   = 0;
        self.done    = 0;
        self.ok      = 0;
        self.ng      = 0;

        // channel for progress
        let (tx, rx) = unbounded();
        self.rx = Some(rx);

        // capture parameters
        let dir = self.target_dir.clone().unwrap();
        let pwd = self.password.clone();
        let enc = self.encrypt_mode;

        // spawn!
        thread::spawn(move || background_worker(enc, dir, pwd, tx));
    }
}

// ────────────────────────────────────────────────────────────
// 4.  Implement eframe::App for GUI event loop
// ────────────────────────────────────────────────────────────
impl eframe::App for GuiState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ----------------------------------------------------
        // 4.1 Handle incoming progress messages
        // ----------------------------------------------------
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    BgMsg::Total(t)               => self.total = t,
                    BgMsg::Step                   => self.done += 1,
                    BgMsg::Finished { ok, ng } => {
                        self.ok = ok;
                        self.ng = ng;
                        self.running = false;
                    }
                }
            }
        }

        // ----------------------------------------------------
        // 4.2 Build the UI every frame
        // ----------------------------------------------------
        egui::CentralPanel::default().show(ctx, |ui| {
            // Nice centered vertical layout
            ui.vertical_centered_justified(|ui| {
                // ----- Header -----
                ui.add_space(12.0);
                ui.heading(
                    RichText::new(APP_NAME)
                        .color(Color32::from_rgb(230, 200, 60)),
                );
                ui.label("ChaCha20-Poly1305   •   Multithread");
                ui.add_space(20.0);

                ui.separator();
                ui.add_space(8.0);

                // ----- Mode selection -----
                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    ui.selectable_value(&mut self.encrypt_mode, true,  "Encrypt");
                    ui.selectable_value(&mut self.encrypt_mode, false, "Decrypt");
                });
                ui.add_space(6.0);

                // ----- Directory picker -----
                ui.horizontal(|ui| {
                    ui.label("Directory:");
                    let dir_text = self.target_dir
                        .as_ref()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|| "<not selected>".into());
                    ui.label(dir_text);
                    if ui.button("Browse…").clicked() && !self.running {
                        self.target_dir = rfd::FileDialog::new().pick_folder();
                    }
                });
                ui.add_space(6.0);

                // ----- Password -----
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .desired_width(340.0),
                    );
                });

                ui.add_space(18.0);

                // ----- Start / progress -----
                if !self.running {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Start").size(24.0))
                                .min_size(egui::vec2(150.0, 40.0)),
                        )
                        .clicked()
                    {
                        self.start_worker();
                    }
                } else if self.total > 0 {
                    // show progress bar
                    let frac = self.done as f32 / self.total as f32;
                    ui.add(
                        ProgressBar::new(frac)
                            .show_percentage()
                            .text(format!("{}/{}", self.done, self.total)),
                    );
                } else {
                    // still enumerating files
                    ui.spinner();
                    ui.label("Collecting files…");
                }

                ui.add_space(10.0);

                // ----- Summary after completion -----
                if !self.running && self.total > 0 && self.done == self.total {
                    let summary = format!("Done  |  OK {}  •  Fail {}", self.ok, self.ng);
                    ui.label(
                        RichText::new(summary).color(if self.ng == 0 {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::RED
                        }),
                    );
                }
            });
        });

        // force continuous repaint while worker is running
        if self.running {
            ctx.request_repaint();
        }
    }
}

// ────────────────────────────────────────────────────────────
// 5.  Program entry point
// ────────────────────────────────────────────────────────────
fn main() -> Result<()> {
    println!("{APP_NAME}  -  ChaCha20-Poly1305 (overwrite mode)");

    // Configure initial window size (800×520)
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default().with_inner_size([800.0, 520.0]),
        ..Default::default()
    };

    // Launch app; errors (e.g. GL init failure) are printed to stderr
    if let Err(e) = eframe::run_native(
        APP_NAME,
        options,
        Box::new(|cc| Box::new(GuiState::new(cc))),
    ) {
        eprintln!("eframe error: {e}");
    }
    Ok(())
}
