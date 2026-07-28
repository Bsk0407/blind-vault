#!/usr/bin/env python3
"""Local-only Blind Vault dashboard.

Values travel browser -> loopback POST body -> vault CLI stdin -> OS credential
store. No endpoint reads a value back or includes one in a response.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
WINDOWS_CLI = ROOT / "bin" / "vault.ps1"
POSIX_CLI = ROOT / "bin" / "vault"
VAULT_DIR = Path(os.environ.get("BLINDVAULT_DIR", Path.home() / ".blindvault"))
MANIFEST = VAULT_DIR / "manifest.json"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_BODY_BYTES = 16 * 1024
MAX_SECRET_BYTES = 5 * 512 if os.name == "nt" else 12 * 1024
BACKEND_LABEL = "Windows Credential Manager" if os.name == "nt" else "macOS Keychain"
PLATFORM_LABEL = "Windows" if os.name == "nt" else "macOS"
RUN_LOCK = threading.RLock()


def vault_command() -> list[str]:
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        return [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(WINDOWS_CLI),
        ]
    return [str(POSIX_CLI)]


def run_vault(args: list[str], stdin: str | None = None) -> tuple[int, str]:
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        with RUN_LOCK:
            result = subprocess.run(
                vault_command() + args,
                input=None if stdin is None else (stdin + "\n").encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                shell=False,
                creationflags=creationflags,
                check=False,
            )
    except subprocess.TimeoutExpired:
        return 124, "vault command timed out"
    except OSError as exc:
        return 1, f"vault command failed: {type(exc).__name__}"
    return result.returncode, result.stdout.decode("utf-8", errors="replace").strip()[:4096]


def load_manifest() -> dict:
    if not MANIFEST.exists():
        code, message = run_vault(["init"])
        if code:
            raise RuntimeError(message or "vault init failed")
    with MANIFEST.open("r", encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or not isinstance(data.get("secrets"), list):
        raise ValueError("invalid manifest structure")
    return data


def valid_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if len(value) <= 128 and NAME_RE.fullmatch(value) else None


def bounded_text(body: dict, key: str, limit: int = 2048) -> str:
    value = body.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    value = value.strip()
    if len(value) > limit or any(ord(char) < 32 for char in value):
        raise ValueError(f"{key} is too long")
    if key == "env" and value and not ENV_RE.fullmatch(value):
        raise ValueError("env is invalid")
    return value


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


class VaultServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler_class: type[Handler]):
        self.token = secrets.token_hex(32)
        self.nonce = secrets.token_urlsafe(24)
        super().__init__(server_address, handler_class)

    def server_bind(self) -> None:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(10)
        return request, client_address


class Handler(BaseHTTPRequestHandler):
    server_version = "blindvault"

    def log_message(self, _format: str, *args: object) -> None:
        # Request paths and bodies never enter console logs.
        return

    @property
    def expected_origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def _local_host(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            return False
        host = hosts[0].strip().lower()
        port = self.server.server_port
        return host == f"127.0.0.1:{port}"

    def _local_origin(self, required: bool = False) -> bool:
        origins = self.headers.get_all("Origin", [])
        if not origins:
            return not required
        if len(origins) != 1:
            return False
        origin = origins[0]
        try:
            parsed = urlsplit(origin)
            return (
                parsed.scheme == "http"
                and parsed.hostname == "127.0.0.1"
                and parsed.port == self.server.server_port
            )
        except ValueError:
            return False

    def _authed(self, require_origin: bool = False) -> bool:
        supplied_tokens = self.headers.get_all("X-Vault-Token", [])
        if len(supplied_tokens) != 1:
            return False
        supplied = supplied_tokens[0]
        return (
            self._local_host()
            and self._local_origin(required=require_origin)
            and hmac.compare_digest(supplied, self.server.token)
        )

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            f"style-src 'nonce-{self.server.nonce}'; script-src 'nonce-{self.server.nonce}'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(code, data, "application/json; charset=utf-8")

    def _read_json(self) -> dict | None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._json(415, {"error": "application/json required"})
            return None
        if self.headers.get("Transfer-Encoding"):
            self._json(400, {"error": "transfer encoding is not supported"})
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            self._json(400, {"error": "one Content-Length header is required"})
            return None
        try:
            length = int(lengths[0])
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": "request body is too large"})
            return None
        try:
            body = json.loads(
                self.rfile.read(length).decode("utf-8"), object_pairs_hook=strict_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._json(400, {"error": "invalid JSON"})
            return None
        if not isinstance(body, dict):
            self._json(400, {"error": "JSON object required"})
            return None
        return body

    def do_GET(self) -> None:
        if not self._local_host():
            self._json(403, {"error": "forbidden"})
            return
        if self.path == "/":
            page = (
                PAGE.replace("__TOKEN__", self.server.token)
                .replace("__NONCE__", self.server.nonce)
                .replace("__BACKEND__", BACKEND_LABEL)
                .replace("__PLATFORM__", PLATFORM_LABEL)
            )
            self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return

        if self.path == "/api/list":
            if not self._authed():
                self._json(403, {"error": "forbidden"})
                return
            try:
                self._json(200, load_manifest())
            except (OSError, ValueError, RuntimeError):
                self._json(500, {"error": "manifest unavailable"})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authed(require_origin=True):
            self._json(403, {"error": "forbidden"})
            return
        body = self._read_json()
        if body is None:
            return

        if self.path == "/api/add":
            allowed_fields = {"name", "value", "service", "account", "env", "allow", "note"}
            if set(body) - allowed_fields:
                self._json(400, {"error": "unknown field"})
                return
            name = valid_name(body.get("name"))
            value = body.pop("value", None)
            if name is None or not isinstance(value, str) or not value:
                self._json(400, {"error": "valid name and non-empty value are required"})
                return
            if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
                value = None
                self._json(
                    400,
                    {"error": f"value exceeds the {MAX_SECRET_BYTES}-byte {PLATFORM_LABEL} UI limit"},
                )
                return
            if any(char in value for char in ("\x00", "\r", "\n")):
                value = None
                self._json(400, {"error": "value must be a single text line"})
                return
            try:
                args = ["add", name, "--from-stdin"]
                for field in ("service", "account", "env", "allow", "note"):
                    option = bounded_text(body, field)
                    if option:
                        args.extend([f"--{field}", option])
                code, message = run_vault(args, stdin=value)
                message = message.replace(value, f"[REDACTED:{name}]")
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            finally:
                value = None
            response_code = 200 if code == 0 else (504 if code == 124 else 422)
            self._json(response_code, {"ok": code == 0, "message": message})
            return

        if self.path in {"/api/rm", "/api/copy"}:
            if set(body) != {"name"}:
                self._json(400, {"error": "only name is accepted"})
                return
            name = valid_name(body.get("name"))
            if name is None:
                self._json(400, {"error": "valid name is required"})
                return
            command = "rm" if self.path == "/api/rm" else "copy"
            code, message = run_vault([command, name])
            response_code = 200 if code == 0 else (504 if code == 124 else 422)
            self._json(response_code, {"ok": code == 0, "message": message})
            return

        self._json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:
        # No CORS support. Cross-origin preflight requests fail closed.
        if not self._local_host():
            self._json(403, {"error": "forbidden"})
        else:
            self._json(405, {"error": "method not allowed"})


PAGE = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Blind Vault</title>
  <style nonce="__NONCE__">
    :root {
      color-scheme: dark;
      --bg: #090b0f;
      --panel: rgba(20, 23, 29, .82);
      --panel-2: rgba(28, 32, 40, .72);
      --line: rgba(255, 255, 255, .09);
      --line-strong: rgba(255, 255, 255, .15);
      --text: #f4f6f8;
      --muted: #99a1ad;
      --faint: #68707c;
      --green: #2adba5;
      --green-soft: rgba(42, 219, 165, .12);
      --red: #ff7979;
      --mono: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
    }
    * { box-sizing: border-box; }
    html, body { min-height: 100%; }
    body {
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(1000px 680px at 0% 0%, rgba(57, 74, 104, .28), transparent 60%),
        radial-gradient(780px 520px at 100% 100%, rgba(42, 219, 165, .08), transparent 58%),
        var(--bg);
      font: 14px/1.5 "Segoe UI Variable", "Segoe UI", sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    button, input { font: inherit; }
    button:focus-visible, input:focus-visible { outline: 2px solid var(--green); outline-offset: 2px; }
    .shell { width: min(1180px, calc(100% - 32px)); margin: 32px auto; }
    header {
      display: flex; align-items: center; gap: 14px; padding: 4px 2px 22px;
    }
    .mark {
      width: 42px; height: 42px; display: grid; place-items: center; border-radius: 13px;
      background: linear-gradient(145deg, rgba(255,255,255,.11), rgba(255,255,255,.035));
      border: 1px solid var(--line-strong); font-size: 20px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.08), 0 14px 40px rgba(0,0,0,.28);
    }
    .brand h1 { margin: 0; font-size: 17px; letter-spacing: -.02em; }
    .brand p { margin: 2px 0 0; color: var(--muted); font-size: 12.5px; }
    .status {
      margin-left: auto; display: flex; align-items: center; gap: 8px; padding: 7px 12px;
      border: 1px solid var(--line); border-radius: 999px; color: var(--muted);
      background: rgba(255,255,255,.035); font: 11px var(--mono);
    }
    .status-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 14px var(--green); }
    .workspace {
      display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(320px, .8fr);
      min-height: 620px; overflow: hidden; border: 1px solid var(--line);
      border-radius: 20px; background: var(--panel); backdrop-filter: blur(28px);
      box-shadow: 0 34px 100px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.06);
    }
    .vault-panel { padding: 26px; }
    .add-panel { padding: 26px; border-left: 1px solid var(--line); background: var(--panel-2); }
    .panel-heading { display: flex; align-items: end; gap: 10px; margin-bottom: 20px; }
    .panel-heading h2 { margin: 0; font-size: 13px; letter-spacing: .08em; text-transform: uppercase; }
    .panel-heading span { color: var(--faint); font-size: 12px; }
    #count { margin-left: auto; font: 11px var(--mono); color: var(--muted); }
    .empty {
      display: grid; place-items: center; min-height: 420px; text-align: center; color: var(--muted);
      border: 1px dashed var(--line-strong); border-radius: 15px; background: rgba(255,255,255,.018);
    }
    .empty strong { display: block; color: var(--text); font-size: 15px; margin-bottom: 4px; }
    .secret-list { display: grid; gap: 10px; }
    .secret-row {
      display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 14px; padding: 15px 16px;
      border: 1px solid var(--line); border-radius: 13px; background: rgba(255,255,255,.025);
      transition: border-color .14s, background .14s, transform .14s;
    }
    .secret-row:hover { border-color: var(--line-strong); background: rgba(255,255,255,.045); transform: translateY(-1px); }
    .secret-name { font: 600 13px var(--mono); overflow-wrap: anywhere; }
    .metadata { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin-top: 7px; color: var(--muted); font-size: 11.5px; }
    .env { font-family: var(--mono); }
    .chip { padding: 2px 8px; border: 1px solid var(--line); border-radius: 999px; font: 10px var(--mono); background: rgba(255,255,255,.03); }
    .last-used { margin-top: 7px; color: var(--faint); font-size: 11px; }
    .actions { display: flex; align-items: center; gap: 7px; }
    .button {
      min-height: 34px; padding: 0 12px; border-radius: 9px; cursor: pointer;
      border: 1px solid var(--line); color: var(--muted); background: rgba(255,255,255,.04);
    }
    .button:hover { color: var(--text); border-color: var(--line-strong); background: rgba(255,255,255,.075); }
    .button.danger:hover { color: var(--red); border-color: rgba(255,121,121,.35); background: rgba(255,121,121,.08); }
    form { display: grid; gap: 13px; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: .045em; text-transform: uppercase; }
    label span { text-transform: none; letter-spacing: 0; font-weight: 400; color: var(--faint); }
    input {
      width: 100%; min-height: 40px; padding: 9px 11px; color: var(--text); border-radius: 10px;
      border: 1px solid var(--line); background: rgba(5,7,10,.48); outline: none;
    }
    input::placeholder { color: #555e6b; }
    input:focus { border-color: rgba(42,219,165,.58); box-shadow: 0 0 0 3px var(--green-soft); }
    input[type=password] { font-family: var(--mono); letter-spacing: .08em; }
    .primary {
      min-height: 43px; margin-top: 4px; border: 0; border-radius: 10px; cursor: pointer;
      color: #06100d; background: linear-gradient(180deg, #42edba, #25cf9d); font-weight: 700;
      box-shadow: 0 8px 24px rgba(42,219,165,.17), inset 0 1px 0 rgba(255,255,255,.35);
    }
    .primary:hover { filter: brightness(1.06); }
    .primary:disabled { opacity: .55; cursor: wait; }
    .security-note { margin: 18px 1px 0; padding-top: 16px; border-top: 1px solid var(--line); color: var(--faint); font-size: 11.5px; }
    .security-note strong { color: var(--muted); }
    #toast {
      position: fixed; left: 50%; bottom: 26px; z-index: 10; max-width: min(560px, calc(100% - 32px));
      transform: translate(-50%, 18px); opacity: 0; pointer-events: none; padding: 11px 16px;
      border: 1px solid var(--line-strong); border-radius: 11px; color: var(--text);
      background: rgba(20,23,29,.96); box-shadow: 0 20px 60px rgba(0,0,0,.45); transition: .2s;
    }
    #toast.show { transform: translate(-50%, 0); opacity: 1; }
    @media (max-width: 860px) {
      .workspace { grid-template-columns: 1fr; }
      .add-panel { border-left: 0; border-top: 1px solid var(--line); }
      .secret-row { grid-template-columns: 1fr; }
      .actions { justify-content: flex-start; }
    }
    @media (max-width: 560px) {
      .shell { width: min(100% - 20px, 1180px); margin: 14px auto; }
      header { padding-inline: 4px; }
      .brand p { display: none; }
      .status { font-size: 0; padding: 9px; }
      .vault-panel, .add-panel { padding: 19px; }
      .workspace { border-radius: 16px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div class="mark" aria-hidden="true">🕶️</div>
      <div class="brand"><h1>Blind Vault</h1><p>Values stay in __BACKEND__. This page only gets pointers back.</p></div>
      <div class="status"><span class="status-dot"></span><span>local · 127.0.0.1</span></div>
    </header>
    <main class="workspace">
      <section class="vault-panel" aria-labelledby="pointers-title">
        <div class="panel-heading"><h2 id="pointers-title">Pointers</h2><span>safe metadata</span><strong id="count">0 items</strong></div>
        <div id="list" aria-live="polite"></div>
      </section>
      <aside class="add-panel" aria-labelledby="add-title">
        <div class="panel-heading"><h2 id="add-title">Add a secret</h2><span>__PLATFORM__</span></div>
        <form id="add-form" autocomplete="off">
          <label>Name <input name="name" required pattern="[A-Za-z0-9._-]+" placeholder="openai-api-key"></label>
          <label>Account / ID <span>pointer metadata</span><input name="account" placeholder="you@example.com"></label>
          <label>Secret value <input name="value" type="password" required autocomplete="new-password" placeholder="stored, never returned"></label>
          <label>Service <input name="service" placeholder="OpenAI"></label>
          <label>Allowed for <input name="allow" placeholder="api.openai.com, curl"></label>
          <label>Environment variable <input name="env" pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="OPENAI_API_KEY (auto)"></label>
          <label>Note <input name="note" placeholder="personal, pay-as-you-go"></label>
          <button class="primary" type="submit">Save to __BACKEND__</button>
        </form>
        <p class="security-note"><strong>No reveal path.</strong> The password field is sent over loopback to the CLI's standard input. API responses and the pointer list never contain the value.</p>
      </aside>
    </main>
  </div>
  <div id="toast" role="status" aria-live="polite"></div>
  <script nonce="__NONCE__">
    const TOKEN = "__TOKEN__";
    const list = document.getElementById("list");
    const count = document.getElementById("count");
    const form = document.getElementById("add-form");
    const submit = form.querySelector("button[type=submit]");
    const toastElement = document.getElementById("toast");
    let toastTimer;

    function toast(message) {
      toastElement.textContent = String(message || "Done");
      toastElement.classList.add("show");
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toastElement.classList.remove("show"), 3200);
    }

    async function api(path, body) {
      const response = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        credentials: "omit",
        cache: "no-store",
        headers: {
          "X-Vault-Token": TOKEN,
          ...(body === undefined ? {} : {"Content-Type": "application/json"})
        },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      const data = await response.json();
      if (!response.ok || data.ok === false) throw new Error(data.error || data.message || "Request failed");
      return data;
    }

    function text(tag, className, value) {
      const node = document.createElement(tag);
      if (className) node.className = className;
      node.textContent = value;
      return node;
    }

    function renderSecret(secret) {
      const row = document.createElement("article");
      row.className = "secret-row";
      const content = document.createElement("div");
      content.append(text("div", "secret-name", secret.name || "unnamed"));
      const metadata = document.createElement("div");
      metadata.className = "metadata";
      metadata.append(text("span", "env", "$" + (secret.env || "-")));
      if (secret.service) metadata.append(text("span", "", secret.service));
      if (secret.account) metadata.append(text("span", "chip", "ID · " + secret.account));
      for (const allowed of secret.allowed_for || []) metadata.append(text("span", "chip", allowed));
      content.append(metadata);
      content.append(text("div", "last-used", secret.last_used ? "Last used " + secret.last_used : "Never used"));

      const actions = document.createElement("div");
      actions.className = "actions";
      for (const [action, label, extra] of [["copy", "Copy 30s", ""], ["delete", "Delete", "danger"]]) {
        const button = text("button", "button " + extra, label);
        button.type = "button";
        button.dataset.action = action;
        button.dataset.name = secret.name;
        actions.append(button);
      }
      row.append(content, actions);
      return row;
    }

    async function refresh() {
      const data = await api("/api/list");
      const secrets = Array.isArray(data.secrets) ? data.secrets : [];
      count.textContent = secrets.length + (secrets.length === 1 ? " item" : " items");
      if (!secrets.length) {
        const empty = document.createElement("div");
        empty.className = "empty";
        const wrap = document.createElement("div");
        wrap.append(text("strong", "", "No secrets yet"), document.createTextNode("Add one on the right. Only its pointer returns here."));
        empty.append(wrap);
        list.replaceChildren(empty);
        return;
      }
      const fragment = document.createDocumentFragment();
      for (const secret of secrets) fragment.append(renderSecret(secret));
      const container = document.createElement("div");
      container.className = "secret-list";
      container.append(fragment);
      list.replaceChildren(container);
    }

    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const payload = Object.fromEntries(new FormData(form));
      form.elements.value.value = "";
      submit.disabled = true;
      try {
        const result = await api("/api/add", payload);
        form.reset();
        toast(result.message || "Stored");
        await refresh();
      } catch (error) {
        toast(error.message);
      } finally {
        payload.value = "";
        submit.disabled = false;
      }
    });

    list.addEventListener("click", async event => {
      const button = event.target.closest("button[data-action]");
      if (!button) return;
      const name = button.dataset.name;
      try {
        if (button.dataset.action === "copy") {
          const result = await api("/api/copy", {name});
          toast(result.message);
        } else if (confirm(`Delete '${name}' from __BACKEND__ and the manifest?`)) {
          const result = await api("/api/rm", {name});
          toast(result.message);
          await refresh();
        }
      } catch (error) {
        toast(error.message);
      }
    });

    refresh().catch(error => toast(error.message));
  </script>
</body>
</html>'''


def main() -> None:
    port = int(os.environ.get("BLINDVAULT_UI_PORT", "0"))
    server = VaultServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"blind-vault ui -> {url} (local only; Ctrl+C to stop)", flush=True)
    if os.environ.get("BLINDVAULT_UI_NO_OPEN") != "1":
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
