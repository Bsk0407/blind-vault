// Blind Vault — tray vault for secrets an AI agent can use but never see.
// The desktop app shares the pointer manifest and OS credential namespace with
// the platform CLI. No Tauri command ever returns a secret to the WebView.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod platform;

use chrono::Local;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
const SHORTCUT: &str = "alt+cmd+v";
#[cfg(target_os = "macos")]
const SHORTCUT_LABEL: &str = "⌥⌘V";
#[cfg(target_os = "windows")]
const SHORTCUT: &str = "ctrl+alt+v";
#[cfg(target_os = "windows")]
const SHORTCUT_LABEL: &str = "Ctrl+Alt+V";

static VAULT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn vault_guard() -> Result<MutexGuard<'static, ()>, String> {
    VAULT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "vault lock was poisoned".to_string())
}

fn vault_dir() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("BLINDVAULT_DIR") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home_variable = if cfg!(target_os = "windows") {
        "USERPROFILE"
    } else {
        "HOME"
    };
    std::env::var_os(home_variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|path| path.join(".blindvault"))
        .ok_or_else(|| format!("{home_variable} is not set"))
}

fn manifest_path() -> Result<PathBuf, String> {
    Ok(vault_dir()?.join("manifest.json"))
}

fn load_manifest_unlocked() -> Result<Value, String> {
    let path = manifest_path()?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({ "secrets": [] }))
        }
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    let manifest: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid manifest JSON at {}: {error}", path.display()))?;
    if !manifest.get("secrets").is_some_and(Value::is_array) {
        return Err("invalid manifest: missing secrets array".into());
    }
    Ok(manifest)
}

fn save_manifest_unlocked(manifest: &Value) -> Result<(), String> {
    let directory = vault_dir()?;
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let path = directory.join("manifest.json");
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".manifest.{}.{}.tmp",
        std::process::id(),
        counter
    ));
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|error| error.to_string())?;
    bytes.push(b'\n');

    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        platform::replace_file(&temporary, &path)
    })();
    bytes.zeroize();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

fn valid_env_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn today() -> String {
    Local::now().date_naive().to_string()
}

fn pointer_index(manifest: &Value, name: &str) -> Option<usize> {
    manifest["secrets"].as_array().and_then(|secrets| {
        secrets.iter().position(|secret| {
            secret["name"]
                .as_str()
                .is_some_and(|candidate| platform::names_equal(candidate, name))
        })
    })
}

#[tauri::command]
fn list_secrets() -> Result<Value, String> {
    let _guard = vault_guard()?;
    load_manifest_unlocked()
}

#[tauri::command]
fn app_info() -> Value {
    json!({
        "backend": platform::backend_label(),
        "shortcut": SHORTCUT_LABEL,
        "platform": if cfg!(target_os = "windows") { "Windows" } else { "macOS" },
    })
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
fn add_secret(
    name: String,
    value: String,
    service: String,
    env: String,
    allow: String,
    note: String,
    account: String,
) -> Result<String, String> {
    let value = Zeroizing::new(value);
    if !valid_name(&name) {
        return Err("name must be letters, digits, dot, dash, or underscore".into());
    }
    if value.is_empty() {
        return Err("empty value — nothing stored".into());
    }
    let account = if account.trim().is_empty() {
        platform::default_account()
    } else {
        account.trim().to_string()
    };
    let envvar = if env.trim().is_empty() {
        name.to_uppercase().replace(['-', '.'], "_")
    } else {
        env.trim().to_string()
    };
    if !valid_env_name(&envvar) {
        return Err("invalid environment variable name".into());
    }

    let _guard = vault_guard()?;
    let mut manifest = load_manifest_unlocked()?;
    if let Some(index) = pointer_index(&manifest, &name) {
        let existing_name = manifest["secrets"][index]["name"].as_str().unwrap_or("");
        if existing_name != name && platform::names_equal(existing_name, &name) {
            return Err(format!(
                "'{name}' conflicts with existing pointer '{existing_name}' on this platform"
            ));
        }
    }

    platform::store_secret(&name, value.as_str(), &account)?;
    let secrets = manifest["secrets"]
        .as_array_mut()
        .ok_or_else(|| "invalid manifest: secrets is not an array".to_string())?;
    secrets.retain(|secret| {
        !secret["name"]
            .as_str()
            .is_some_and(|candidate| platform::names_equal(candidate, &name))
    });
    secrets.push(json!({
        "name": name.clone(),
        "service": service.trim(),
        "account": account,
        "env": envvar,
        "allowed_for": allow
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>(),
        "note": note.trim(),
        "created": today(),
        "last_used": Value::Null,
        "backend": platform::backend_id(),
    }));
    secrets.sort_by(|left, right| {
        left["name"]
            .as_str()
            .unwrap_or("")
            .cmp(right["name"].as_str().unwrap_or(""))
    });
    save_manifest_unlocked(&manifest)?;
    Ok(format!("Stored '{name}' in {}.", platform::backend_label()))
}

#[tauri::command]
fn remove_secret(name: String) -> Result<String, String> {
    if !valid_name(&name) {
        return Err("bad name".into());
    }
    let _guard = vault_guard()?;
    let mut manifest = load_manifest_unlocked()?;
    if pointer_index(&manifest, &name).is_none() {
        return Err(format!("no secret named '{name}'"));
    }
    platform::delete_secret(&name)?;
    let secrets = manifest["secrets"]
        .as_array_mut()
        .ok_or_else(|| "invalid manifest: secrets is not an array".to_string())?;
    secrets.retain(|secret| {
        !secret["name"]
            .as_str()
            .is_some_and(|candidate| platform::names_equal(candidate, &name))
    });
    save_manifest_unlocked(&manifest)?;
    Ok(format!(
        "removed '{name}' ({} + manifest)",
        platform::backend_label()
    ))
}

#[tauri::command]
fn copy_secret(app: tauri::AppHandle, name: String) -> Result<String, String> {
    if !valid_name(&name) {
        return Err("bad name".into());
    }
    {
        let _guard = vault_guard()?;
        let manifest = load_manifest_unlocked()?;
        if pointer_index(&manifest, &name).is_none() {
            return Err(format!("no secret named '{name}'"));
        }
    }

    let value = platform::read_secret(&name)?;
    app.clipboard()
        .write_text(value.as_str())
        .map_err(|error| format!("clipboard write failed: {error}"))?;
    let mut expected_hash: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    drop(value);

    let clear_app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        if let Ok(current) = clear_app.clipboard().read_text() {
            let current = Zeroizing::new(current);
            let current_hash: [u8; 32] = Sha256::digest(current.as_bytes()).into();
            if current_hash == expected_hash {
                let _ = clear_app.clipboard().clear();
            }
        }
        expected_hash.zeroize();
    });
    Ok(format!("'{name}' on clipboard — clears in 30 s if unchanged"))
}

#[tauri::command]
fn copy_account(app: tauri::AppHandle, name: String) -> Result<String, String> {
    let _guard = vault_guard()?;
    let manifest = load_manifest_unlocked()?;
    let account = pointer_index(&manifest, &name)
        .and_then(|index| manifest["secrets"][index]["account"].as_str())
        .unwrap_or("")
        .to_string();
    if account.is_empty() {
        return Err("no account stored".into());
    }
    app.clipboard()
        .write_text(account.as_str())
        .map_err(|error| format!("clipboard write failed: {error}"))?;
    Ok(format!("ID '{account}' copied"))
}

fn toggle(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
        } else {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let window = app.get_webview_window("main").expect("main window");
            let _ = window.set_theme(Some(tauri::Theme::Dark));
            #[cfg(target_os = "macos")]
            {
                use window_vibrancy::{
                    apply_vibrancy, NSVisualEffectMaterial, NSVisualEffectState,
                };
                let _ = apply_vibrancy(
                    &window,
                    NSVisualEffectMaterial::HudWindow,
                    Some(NSVisualEffectState::Active),
                    Some(16.0),
                );
            }

            {
                use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
                app.global_shortcut()
                    .on_shortcut(SHORTCUT, |app, _shortcut, event| {
                        if event.state() == ShortcutState::Pressed {
                            toggle(app);
                        }
                    })?;
            }

            let open_label = format!("Open Blind Vault  {SHORTCUT_LABEL}");
            let open = MenuItem::with_id(app, "open", open_label, true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let tray_icon = app.default_window_icon().cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "application icon is missing")
            })?;
            let tray = TrayIconBuilder::with_id("blind-vault-tray")
                .icon(tray_icon)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => toggle(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle(tray.app_handle());
                    }
                });
            #[cfg(target_os = "macos")]
            let tray = tray.icon_as_template(true);
            tray.build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            list_secrets,
            add_secret,
            remove_secret,
            copy_secret,
            copy_account
        ])
        .build(tauri::generate_context!())
        .expect("error while building blind-vault")
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            let _ = (app, &event);
        });
}

