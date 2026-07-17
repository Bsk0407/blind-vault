# Windows support

The first Windows backend mirrors the macOS CLI's pointer/value split:

- values: Windows Credential Manager, `CRED_TYPE_GENERIC`
- pointer metadata: `%USERPROFILE%\.blindvault\manifest.json`
- CLI: Windows PowerShell 5.1+ (`bin\vault.cmd`)

Install and run in native Windows PowerShell 5.1 or newer:

```powershell
.\install.ps1 -AddToPath
.\bin\vault.cmd add openai-api-key --service OpenAI --env OPENAI_API_KEY --allow api.openai.com
.\bin\vault.cmd use openai-api-key -- curl.exe https://api.openai.com/v1/models
.\bin\vault.cmd ui
```

The installer creates a directory junction at
`%USERPROFILE%\.claude\skills\vault`, initializes the pointer manifest, and
optionally adds `bin` to the user `PATH`. Use `-SkipSkill` if another agent or
manual installation owns that directory.

Implemented commands: `init`, `add`, `use`, `copy`, `type`, `ls`, `ui`, `rm`.

Interactive `add` opens a masked Windows dialog. Automation must opt into
`--from-stdin`; there is no command-line value flag.

`vault ui` starts a local dashboard on a random `127.0.0.1` port. It validates
the exact Host and POST Origin, requires a per-launch API token, sends no CORS
headers, and applies a restrictive Content Security Policy. It is intentionally
local and is not designed for deployment.

`vault type <name> --account --enter --delay 5` supports hands-free browser
login without using the clipboard. When the delay ends it requires an exact
allowlisted browser process, a stable foreground window, released modifier and
mouse buttons, and a UI Automation password edit field before reading the
credential. With `--account`, the account is typed first and the secret is read
only if Tab reaches a password field. Unicode text is injected with Win32
`SendInput`; partial injection is never retried. The process-name list can be
customized with `BLINDVAULT_TYPE_APPS`, but agents must never use that variable
to bypass a guard.

These checks prevent accidental typing into a terminal, editor, chat, or
browser address bar. They do not authenticate the current page or bind it to an
`allowed_for` domain. A malicious page in a real browser can still expose a
password field; the human's deliberate click is the authorization boundary.

## Native desktop app

`app/` now contains a cross-platform Tauri 2 tray app. On Windows it shares the
same `BlindVault:v1:` WinCred targets and pointer manifest as the CLI, toggles
with `Ctrl+Alt+V`, uses a restrictive CSP, and builds an NSIS installer. Its
Rust IPC surface can add, list, copy, and remove credentials but has no command
that returns a value to JavaScript. Clipboard clearing after 30 seconds first
checks a SHA-256 fingerprint so newer clipboard content is preserved.

Building requires the normal Tauri Windows prerequisites: Rust's MSVC target,
Microsoft C++ Build Tools, WebView2, Node.js, and the Tauri CLI. Then run:

```powershell
cd app
npx @tauri-apps/cli build
```

The installer is emitted under `app\src-tauri\target\release\bundle\nsis`.

## Security boundary

Credential Manager protects values at rest and separates them from the pointer
manifest, chat transcript, shell history, and ordinary command output. It does
**not** make a generic credential unreadable to arbitrary code already running
as the same Windows user. Exact-value output redaction and scope binding are
defense-in-depth controls, not a sandbox or HSM.

Generic credentials are also limited to 2,560 bytes. The CLI rejects larger
UTF-8 values before calling `CredWriteW`.

`vault use` scope matching inspects the composed command string; it is not a
network sandbox or cryptographic destination check. Output redaction replaces
exact secret values only, so transformed/encoded leaks remain possible. Avoid
verbose/debug modes in credential-consuming tools.

## Verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\windows.ps1
python .\tests\windows_ui.py
python .\tests\tauri_static.py
```

The first two suites exercise real temporary Credential Manager entries and
clean them in `finally`. The Tauri suite checks source/config integration when
a Rust toolchain is unavailable; run `cargo check` and a real Tauri build once
the MSVC Rust toolchain is installed.
