#!/usr/bin/env python3
"""Static security/integration checks that do not require a Rust toolchain."""

from __future__ import annotations

import json
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
assertions = 0


def check(condition: bool, message: str) -> None:
    global assertions
    if not condition:
        raise AssertionError(message)
    assertions += 1


cargo = (ROOT / "app/src-tauri/Cargo.toml").read_text(encoding="utf-8")
main = (ROOT / "app/src-tauri/src/main.rs").read_text(encoding="utf-8")
windows = (ROOT / "app/src-tauri/src/platform/windows.rs").read_text(encoding="utf-8")
macos = (ROOT / "app/src-tauri/src/platform/macos.rs").read_text(encoding="utf-8")
html = (ROOT / "app/ui/index.html").read_text(encoding="utf-8")
javascript = (ROOT / "app/ui/app.js").read_text(encoding="utf-8")
config = json.loads((ROOT / "app/src-tauri/tauri.conf.json").read_text(encoding="utf-8"))
windows_config = json.loads(
    (ROOT / "app/src-tauri/tauri.windows.conf.json").read_text(encoding="utf-8")
)

check('windows-sys = { version = "0.61"' in cargo, "Windows API dependency is pinned")
check("Win32_Security_Credentials" in cargo, "Credential API feature is enabled")
check("tauri-plugin-clipboard-manager" in cargo, "cross-platform clipboard plugin is used")
check('zeroize = "1"' in cargo, "secret buffers use best-effort zeroization")
check('const PREFIX: &str = "BlindVault:v1:"' in windows, "GUI and CLI share the Windows target prefix")
check("CRED_TYPE_GENERIC" in windows and "CRED_PERSIST_LOCAL_MACHINE" in windows, "generic local-machine credentials are used")
check("MAX_CREDENTIAL_BYTES: usize = 5 * 512" in windows, "WinCred byte limit is enforced")
check("CredFree" in windows and "impl Drop for OwnedCredential" in windows, "credential buffers have RAII cleanup")
check("MoveFileExW" in windows and "MOVEFILE_WRITE_THROUGH" in windows, "Windows manifest replacement is atomic")
check('Command::new("security")' not in main, "platform commands are isolated from common backend")
check('Command::new("security")' in macos, "macOS backend remains available")
check("fn read_secret" not in re.sub(r"fn copy_secret.*", "", main, flags=re.S), "no standalone secret-returning Tauri command exists")
check("No Tauri command ever returns a secret" in main, "backend states its IPC invariant")
check("expected_hash" in main and "read_text" in main, "clipboard clear preserves newer clipboard content")
check(config["app"]["security"]["csp"] is not None, "Tauri CSP is enabled")
csp = json.dumps(config["app"]["security"]["csp"])
check("unsafe-eval" not in csp and "https:" not in csp, "CSP permits no eval or remote HTTPS assets")
check("<style" not in html and "<script>" not in html, "UI code is externalized for CSP")
check(not re.search(r"\son[a-z]+\s*=", html, re.I), "HTML has no inline event handlers")
check("innerHTML" in javascript and "escapeHtml" in javascript, "rendered pointer metadata is escaped")
check("args.value = \"\"" in javascript, "frontend drops its direct secret reference after IPC")
check(windows_config["bundle"]["targets"] == ["nsis"], "Windows bundle targets NSIS")
check("icons/icon.ico" in config["bundle"]["icon"], "Windows icon is configured")

print(f"PASS: {assertions} Tauri static assertions")

