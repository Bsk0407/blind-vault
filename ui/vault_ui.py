#!/usr/bin/env python3
"""blind-vault UI — a local-only dashboard for the pointer manifest.

Security invariants:
  * binds 127.0.0.1 only; Host and Origin are checked (DNS-rebinding guard)
  * every /api/* call requires the per-session token embedded in the page
  * NO endpoint ever returns, logs, or echoes a secret value. Writes go
    browser -> loopback -> `vault add --from-stdin` -> macOS Keychain.
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "vault")
VAULT_DIR = os.environ.get("BLINDVAULT_DIR", os.path.expanduser("~/.blindvault"))
MANIFEST = os.path.join(VAULT_DIR, "manifest.json")
TOKEN = secrets.token_hex(16)


def run_vault(args, stdin=None):
    r = subprocess.run([BIN] + args, input=stdin, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def load_manifest():
    if not os.path.exists(MANIFEST):
        run_vault(["init"])
    with open(MANIFEST) as f:
        return json.load(f)


class Handler(BaseHTTPRequestHandler):
    server_version = "blindvault"

    def log_message(self, fmt, *args):  # no per-request path logging
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        host = self.headers.get("Host", "")
        if not (host.startswith("127.0.0.1") or host.startswith("localhost")):
            return False
        origin = self.headers.get("Origin")
        if origin and not origin.startswith(("http://127.0.0.1", "http://localhost")):
            return False
        return self.headers.get("X-Vault-Token") == TOKEN

    def do_GET(self):
        if self.path == "/":
            self._send(200, PAGE.replace("__TOKEN__", TOKEN).encode(), "text/html; charset=utf-8")
        elif self.path == "/api/list":
            if not self._authed():
                return self._send(403, {"error": "forbidden"})
            self._send(200, load_manifest())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._send(403, {"error": "forbidden"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except (ValueError, TypeError):
            return self._send(400, {"error": "bad json"})

        if self.path == "/api/add":
            name = (body.get("name") or "").strip()
            value = body.pop("value", "")
            if not name or not value:
                return self._send(400, {"error": "name and value are required"})
            args = ["add", name, "--from-stdin"]
            for flag in ("service", "account", "env", "allow", "note"):
                if body.get(flag):
                    args += ["--" + flag, str(body[flag]).strip()]
            code, out = run_vault(args, stdin=value)
            del value
            return self._send(200 if code == 0 else 500, {"ok": code == 0, "msg": out})

        if self.path == "/api/rm":
            code, out = run_vault(["rm", (body.get("name") or "").strip()])
            return self._send(200 if code == 0 else 500, {"ok": code == 0, "msg": out})

        if self.path == "/api/copy":
            code, out = run_vault(["copy", (body.get("name") or "").strip()])
            return self._send(200 if code == 0 else 500, {"ok": code == 0, "msg": out})

        self._send(404, {"error": "not found"})


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>blind-vault</title>
<style>
  :root{
    --bg:#0B0E12; --panel:#11151B; --panel2:#151A21; --line:#1E242C;
    --txt:#E6EDF3; --dim:#8B949E; --faint:#586069; --green:#27DBA2;
    --green-dim:rgba(39,219,162,.12); --red:#F47067; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--txt);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       -webkit-font-smoothing:antialiased;min-height:100vh}
  .wrap{max-width:1060px;margin:0 auto;padding:44px 28px 80px}
  header{display:flex;align-items:baseline;gap:14px;margin-bottom:6px}
  h1{font-size:22px;font-weight:700;letter-spacing:-.02em}
  h1 .glyph{margin-right:8px}
  .sub{color:var(--dim);font-size:14px}
  .local{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--faint);font-size:12.5px;font-family:var(--mono)}
  .local .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green)}
  main{display:grid;grid-template-columns:1fr 320px;gap:20px;margin-top:28px;align-items:start}
  @media (max-width:860px){main{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .panel h2{font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);
            padding:14px 18px;border-bottom:1px solid var(--line)}
  .row{display:flex;align-items:center;gap:14px;padding:14px 18px;border-bottom:1px solid var(--line)}
  .row:last-child{border-bottom:none}
  .row:hover{background:var(--panel2)}
  .id{flex:1;min-width:0}
  .name{font-family:var(--mono);font-size:14px;font-weight:600}
  .meta{color:var(--dim);font-size:12.5px;margin-top:3px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .env{font-family:var(--mono);color:var(--green);font-size:12px}
  .chip{font-family:var(--mono);font-size:11px;color:var(--green);background:var(--green-dim);
        border:1px solid rgba(39,219,162,.25);border-radius:99px;padding:1px 8px}
  .used{color:var(--faint);font-size:12px;white-space:nowrap}
  .btn{border:1px solid var(--line);background:transparent;color:var(--dim);border-radius:7px;
       padding:5px 11px;font-size:12.5px;cursor:pointer;transition:.12s}
  .btn:hover{color:var(--txt);border-color:#2C333C}
  .btn.danger:hover{color:var(--red);border-color:rgba(244,112,103,.4)}
  .empty{padding:44px 24px;text-align:center;color:var(--dim);font-size:14px}
  .empty b{color:var(--txt)}
  form{padding:16px 18px;display:flex;flex-direction:column;gap:11px}
  label{font-size:11.5px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--faint)}
  input{background:var(--bg);border:1px solid var(--line);border-radius:8px;color:var(--txt);
        padding:9px 11px;font-size:14px;width:100%;outline:none;transition:.12s}
  input:focus{border-color:var(--green)}
  input[type=password]{font-family:var(--mono);letter-spacing:.18em}
  input::placeholder{color:var(--faint);letter-spacing:normal;font-family:-apple-system,sans-serif}
  .save{background:var(--green);border:none;color:#06251B;font-weight:700;font-size:14px;
        border-radius:8px;padding:10px;cursor:pointer;margin-top:4px}
  .save:hover{filter:brightness(1.08)}
  .note{color:var(--faint);font-size:12px;line-height:1.55;padding:0 18px 16px}
  .note b{color:var(--dim)}
  footer{margin-top:34px;color:var(--faint);font-size:12.5px;text-align:center;font-family:var(--mono)}
  #toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%) translateY(70px);
         background:var(--panel2);border:1px solid var(--line);border-left:3px solid var(--green);
         color:var(--txt);padding:11px 18px;border-radius:9px;font-size:13.5px;transition:.25s;opacity:0}
  #toast.show{transform:translateX(-50%) translateY(0);opacity:1}
</style></head><body>
<div class="wrap">
  <header>
    <h1><span class="glyph">🕶️</span>blind-vault</h1>
    <span class="sub">secrets your agent can use — but never see</span>
    <span class="local"><span class="dot"></span>local only · 127.0.0.1</span>
  </header>
  <main>
    <section class="panel">
      <h2>Pointers <span style="text-transform:none;letter-spacing:0">— the only thing Claude ever reads</span></h2>
      <div id="list"><div class="empty">loading…</div></div>
    </section>
    <aside class="panel">
      <h2>Add a secret</h2>
      <form id="add" autocomplete="off">
        <div><label>Name</label><input name="name" placeholder="openai-api-key" required></div>
        <div><label>Value</label><input name="value" type="password" placeholder="pasted here → straight to Keychain" required></div>
        <div><label>Service</label><input name="service" placeholder="OpenAI"></div>
        <div><label>Allowed for</label><input name="allow" placeholder="api.openai.com, curl"></div>
        <div><label>Env var</label><input name="env" placeholder="OPENAI_API_KEY (auto)"></div>
        <div><label>Note</label><input name="note" placeholder="personal, pay-as-you-go"></div>
        <button class="save" type="submit">Save to Keychain</button>
      </form>
      <p class="note"><b>Where the value goes:</b> this form → 127.0.0.1 → macOS Keychain.
      It is never written to this page again, never returned by any API, and never enters
      Claude's context. This dashboard has no “reveal” button — by design.</p>
    </aside>
  </main>
  <footer>Claude reads this table without a value column — because there isn't one.</footer>
</div>
<div id="toast"></div>
<script>
const T="__TOKEN__";
const api=(p,body)=>fetch(p,{method:body?"POST":"GET",
  headers:{"X-Vault-Token":T,...(body?{"Content-Type":"application/json"}:{})},
  body:body?JSON.stringify(body):undefined}).then(r=>r.json());
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let toastT;const toast=m=>{const t=document.getElementById("toast");t.textContent=m;
  t.classList.add("show");clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove("show"),3200);};
async function refresh(){
  const d=await api("/api/list"),el=document.getElementById("list");
  if(!d.secrets||!d.secrets.length){el.innerHTML=
    '<div class="empty"><b>No secrets yet.</b><br>Add your first on the right — Claude will find it by name, never by value.</div>';return;}
  el.innerHTML=d.secrets.map(s=>`
    <div class="row">
      <div class="id">
        <div class="name">${esc(s.name)}</div>
        <div class="meta">
          <span class="env">$${esc(s.env)}</span>
          ${s.service?`<span>${esc(s.service)}</span>`:""}
          ${(s.allowed_for||[]).map(a=>`<span class="chip">${esc(a)}</span>`).join("")}
        </div>
      </div>
      <span class="used">${s.last_used?("used "+esc(s.last_used)):"never used"}</span>
      <button class="btn" onclick="copyIt('${esc(s.name)}')">Copy 30s</button>
      <button class="btn danger" onclick="rmIt('${esc(s.name)}')">Delete</button>
    </div>`).join("");
}
async function copyIt(n){const r=await api("/api/copy",{name:n});
  toast(r.ok?`'${n}' on clipboard — clears in 30 s`:r.msg);}
async function rmIt(n){if(!confirm(`Delete '${n}' from Keychain + manifest?`))return;
  const r=await api("/api/rm",{name:n});toast(r.msg);refresh();}
document.getElementById("add").addEventListener("submit",async e=>{
  e.preventDefault();
  const f=Object.fromEntries(new FormData(e.target));
  const r=await api("/api/add",f);
  if(r.ok){e.target.reset();toast("Stored. The value never left this machine.");refresh();}
  else toast(r.msg||"failed");
});
refresh();
</script>
</body></html>"""


def main():
    port = int(os.environ.get("BLINDVAULT_UI_PORT", 0))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"blind-vault ui → {url}  (local only · ctrl-c to stop)")
    if os.environ.get("BLINDVAULT_UI_NO_OPEN") != "1":
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
