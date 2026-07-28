use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use zeroize::Zeroizing;

fn target(name: &str) -> String {
    format!("blindvault.{name}")
}

pub fn store_secret(name: &str, value: &str, account: &str) -> Result<(), String> {
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            &target(name),
            "-j",
            "managed by blind-vault",
            "-w",
            value,
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("Keychain write failed".into())
    }
}

pub fn read_secret(name: &str) -> Result<Zeroizing<String>, String> {
    let output = Command::new("security")
        .args(["find-generic-password", "-w", "-s", &target(name)])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("Keychain lookup failed".into());
    }
    let mut value = String::from_utf8(output.stdout)
        .map_err(|_| "Keychain returned a non-UTF-8 value".to_string())?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(Zeroizing::new(value))
}

pub fn delete_secret(name: &str) -> Result<(), String> {
    let output = Command::new("security")
        .args(["delete-generic-password", "-s", &target(name)])
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() || output.status.code() == Some(44) {
        Ok(())
    } else {
        Err("Keychain delete failed".into())
    }
}

pub fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    match std::fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            std::fs::remove_file(destination).map_err(|e| e.to_string())?;
            std::fs::rename(source, destination).map_err(|e| e.to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

pub fn default_account() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

pub fn backend_id() -> &'static str {
    "macos-keychain"
}

pub fn backend_label() -> &'static str {
    "macOS Keychain"
}

pub fn names_equal(left: &str, right: &str) -> bool {
    left == right
}

