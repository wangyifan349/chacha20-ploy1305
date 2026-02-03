#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use crossbeam_channel::{unbounded, Receiver, Sender};
use eframe::{
    egui::{
        self, Color32, ProgressBar, RichText, Visuals, ViewportBuilder, TextStyle,
        FontId,
    },
    CreationContext,
};
use rand::random;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};
use walkdir::WalkDir;

const NONCE_LEN: usize = 12;
const HASH_ROUNDS: usize = 100_000;
const APP_NAME: &str = "Batch Encrypt GUI";

fn derive_key(password: &str) -> Key {
    let mut d = Sha256::digest(password.as_bytes()).to_vec();
    for _ in 1..HASH_ROUNDS {
        d = Sha256::digest(&d).to_vec();
    }
    Key::from_slice(&d).to_owned()
}

fn encrypt_file(p: &Path, k: &Key) -> Result<()> {
    let plain = fs::read(p)?;
    let cipher = ChaCha20Poly1305::new(k);
    let nonce_bytes: [u8; NONCE_LEN] = random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let crypt = cipher.encrypt(nonce, plain.as_ref()).map_err(|_| anyhow!("encrypt"))?;
    let mut f = OpenOptions::new().write(true).truncate(true).open(p)?;
    f.write_all(&nonce_bytes)?;
    f.write_all(&crypt)?;
    Ok(())
}
fn decrypt_file(p: &Path, k: &Key) -> Result<()> {
    let buf = fs::read(p)?;
    if buf.len() < NONCE_LEN {
        return Err(anyhow!("file too small"));
    }
    let (n, crypt) = buf.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(k);
    let plain = cipher.decrypt(Nonce::from_slice(n), crypt).map_err(|_| anyhow!("decrypt"))?;
    let mut f = OpenOptions::new().write(true).truncate(true).open(p)?;
    f.write_all(&plain)?;
    Ok(())
}

enum BgMsg {
    Total(usize),
    Step,
    Finished { ok: usize, ng: usize },
}

fn worker(encrypt: bool, dir: PathBuf, pwd: String, tx: Sender<BgMsg>) {
    let key = derive_key(&pwd);
    let files: Vec<PathBuf> = WalkDir::new(&dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_owned())
        .collect();

    let _ = tx.send(BgMsg::Total(files.len()));

    let ok_cnt = AtomicUsize::new(0);
    let ng_cnt = AtomicUsize::new(0);

    files.par_iter().for_each(|p| {
        let res = if encrypt { encrypt_file(p, &key) } else { decrypt_file(p, &key) };
        if let Err(e) = res {
            eprintln!("FAIL {} => {}", p.display(), e);
            ng_cnt.fetch_add(1, Ordering::Relaxed);
        } else {
            ok_cnt.fetch_add(1, Ordering::Relaxed);
        }
        tx.send(BgMsg::Step).ok();
    });

    let _ = tx.send(BgMsg::Finished {
        ok: ok_cnt.load(Ordering::Relaxed),
        ng: ng_cnt.load(Ordering::Relaxed),
    });
}

struct Gui {
    encrypt: bool,
    dir: Option<PathBuf>,
    pwd: String,
    running: bool,
    total: usize,
    done: usize,
    ok: usize,
    ng: usize,
    rx: Option<Receiver<BgMsg>>,
}

impl Gui {
    fn new(cc: &CreationContext<'_>) -> Self {
        // theme & big fonts
        cc.egui_ctx.set_visuals(Visuals::dark());
        let mut style = (*cc.egui_ctx.style()).clone();
        style
            .text_styles
            .insert(TextStyle::Body, FontId::proportional(20.0));
        style
            .text_styles
            .insert(TextStyle::Button, FontId::proportional(22.0));
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::proportional(36.0));
        cc.egui_ctx.set_style(style);

        Self {
            encrypt: true,
            dir: None,
            pwd: String::new(),
            running: false,
            total: 0,
            done: 0,
            ok: 0,
            ng: 0,
            rx: None,
        }
    }

    fn start(&mut self) {
        if self.dir.is_none() || self.pwd.is_empty() {
            return;
        }
        self.running = true;
        self.total = 0;
        self.done = 0;
        self.ok = 0;
        self.ng = 0;

        let (tx, rx) = unbounded();
        self.rx = Some(rx);
        let d = self.dir.clone().unwrap();
        let p = self.pwd.clone();
        let enc = self.encrypt;
        thread::spawn(move || worker(enc, d, p, tx));
    }
}

impl eframe::App for Gui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                match m {
                    BgMsg::Total(t) => self.total = t,
                    BgMsg::Step => self.done += 1,
                    BgMsg::Finished { ok, ng } => {
                        self.ok = ok;
                        self.ng = ng;
                        self.running = false;
                    }
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered_justified(|ui| {
                ui.add_space(12.0);
                ui.heading(
                    RichText::new(APP_NAME).color(Color32::from_rgb(230, 200, 60)),
                );
                ui.label("ChaCha20-Poly1305   •   Multithread");
                ui.add_space(20.0);

                ui.separator();
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    ui.selectable_value(&mut self.encrypt, true, "Encrypt");
                    ui.selectable_value(&mut self.encrypt, false, "Decrypt");
                });
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.label("Directory:");
                    let txt = self
                        .dir
                        .as_ref()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|| "<not selected>".into());
                    ui.label(txt);
                    if ui.button("Browse…").clicked() && !self.running {
                        self.dir = rfd::FileDialog::new().pick_folder();
                    }
                });
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pwd)
                            .password(true)
                            .desired_width(340.0),
                    );
                });

                ui.add_space(18.0);

                if !self.running {
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Start").size(24.0))
                                .min_size(egui::vec2(150.0, 40.0)),
                        )
                        .clicked()
                    {
                        self.start();
                    }
                } else if self.total > 0 {
                    let frac = self.done as f32 / self.total as f32;
                    ui.add(
                        ProgressBar::new(frac)
                            .show_percentage()
                            .text(format!("{}/{}", self.done, self.total)),
                    );
                } else {
                    ui.spinner();
                    ui.label("Collecting files…");
                }

                ui.add_space(10.0);

                if !self.running && self.total > 0 && self.done == self.total {
                    let msg = format!("Done  |  OK {}  •  Fail {}", self.ok, self.ng);
                    ui.label(
                        RichText::new(msg).color(if self.ng == 0 {
                            Color32::LIGHT_GREEN
                        } else {
                            Color32::RED
                        }),
                    );
                }
            });
        });

        if self.running {
            ctx.request_repaint();
        }
    }
}

fn main() -> Result<()> {
    println!("{APP_NAME}  -  ChaCha20-Poly1305 (overwrite mode)");

    let opts = eframe::NativeOptions {
        viewport: ViewportBuilder::default().with_inner_size([800.0, 520.0]),
        ..Default::default()
    };

    if let Err(e) = eframe::run_native(
        APP_NAME,
        opts,
        Box::new(|cc| Box::new(Gui::new(cc))),
    ) {
        eprintln!("eframe error: {e}");
    }
    Ok(())
}
