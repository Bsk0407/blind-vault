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
    --txt:#F2F3F5; --dim:#9CA1A8; --faint:#61666E; --green:#27DBA2;
    --line:rgba(255,255,255,.09); --line-soft:rgba(255,255,255,.06);
    --glass:rgba(255,255,255,.035); --hover:rgba(255,255,255,.05);
    --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{min-height:100vh}
  body{background:#08090B;color:var(--txt);-webkit-font-smoothing:antialiased;
       font:14.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       display:flex;align-items:center;justify-content:center;padding:52px 24px}
  body::before{content:"";position:fixed;inset:0;pointer-events:none;
       background:radial-gradient(700px 500px at 18% 8%,rgba(255,255,255,.075),transparent 62%),
                  radial-gradient(900px 600px at 88% 100%,rgba(255,255,255,.05),transparent 62%),
                  radial-gradient(520px 380px at 78% -6%,rgba(39,219,162,.055),transparent 65%)}
  body::after{content:"";position:fixed;inset:0;pointer-events:none;opacity:.5;
       background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2'/%3E%3CfeColorMatrix values='0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 0 0 .05 0'/%3E%3C/filter%3E%3Crect width='140' height='140' filter='url(%23n)'/%3E%3C/svg%3E")}
  .window{position:relative;z-index:1;width:100%;max-width:1000px;border-radius:20px;
       background:rgba(22,24,28,.58);backdrop-filter:blur(42px) saturate(150%);
       -webkit-backdrop-filter:blur(42px) saturate(150%);
       border:1px solid var(--line);
       box-shadow:0 40px 100px rgba(0,0,0,.65),0 2px 8px rgba(0,0,0,.4),
                  inset 0 1px 0 rgba(255,255,255,.07);overflow:hidden}
  header{display:flex;align-items:center;gap:12px;padding:18px 22px;
       border-bottom:1px solid var(--line-soft)}
  h1{font-size:16px;font-weight:650;letter-spacing:-.01em}
  h1 .glyph{margin-right:9px;filter:grayscale(1) brightness(1.3)}
  .sub{color:var(--faint);font-size:13px}
  .local{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--faint);
       font-size:11.5px;font-family:var(--mono);background:var(--glass);
       border:1px solid var(--line-soft);border-radius:99px;padding:4px 12px}
  .local .dot{width:6px;height:6px;border-radius:50%;background:var(--green);
       box-shadow:0 0 10px rgba(39,219,162,.8)}
  main{display:grid;grid-template-columns:1.55fr 1fr;min-height:430px}
  @media (max-width:860px){main{grid-template-columns:1fr}}
  section.panel{padding:10px 10px 16px}
  aside.panel{border-left:1px solid var(--line-soft);padding:10px 10px 16px;
       background:rgba(255,255,255,.015)}
  .panel h2{font-size:10.5px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
       color:var(--faint);padding:12px 14px 8px}
  .panel h2 span{text-transform:none;letter-spacing:0;font-weight:500}
  .row{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:11px;
       transition:background .12s}
  .row:hover{background:var(--hover)}
  .id{flex:1;min-width:0}
  .name{font-family:var(--mono);font-size:13.5px;font-weight:600}
  .meta{color:var(--dim);font-size:12px;margin-top:3px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  .env{font-family:var(--mono);color:var(--dim);font-size:11.5px}
  .chip{font-family:var(--mono);font-size:10.5px;color:var(--dim);background:var(--glass);
       border:1px solid var(--line-soft);border-radius:99px;padding:1.5px 9px}
  .used{color:var(--faint);font-size:11.5px;white-space:nowrap}
  .btn{border:1px solid var(--line-soft);background:var(--glass);color:var(--dim);
       border-radius:8px;padding:5px 11px;font-size:12px;cursor:pointer;transition:.12s;
       backdrop-filter:blur(8px)}
  .btn:hover{color:var(--txt);background:rgba(255,255,255,.09);border-color:var(--line)}
  .btn.danger:hover{color:#F2F3F5;background:rgba(244,112,103,.18);border-color:rgba(244,112,103,.3)}
  .empty{padding:52px 24px;text-align:center;color:var(--faint);font-size:13.5px;line-height:1.7}
  .empty b{color:var(--dim)}
  form{padding:6px 14px;display:flex;flex-direction:column;gap:10px}
  label{font-size:10.5px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
       color:var(--faint);display:block;margin-bottom:5px}
  input{background:rgba(0,0,0,.28);border:1px solid var(--line-soft);border-radius:9px;
       color:var(--txt);padding:8.5px 11px;font-size:13.5px;width:100%;outline:none;transition:.15s}
  input:focus{border-color:rgba(39,219,162,.55);box-shadow:0 0 0 3px rgba(39,219,162,.12)}
  input[type=password]{font-family:var(--mono);letter-spacing:.18em}
  input::placeholder{color:#4A4F56;letter-spacing:normal;font-family:-apple-system,sans-serif}
  .save{background:linear-gradient(180deg,#FFFFFF,#DFE2E6);border:none;color:#0A0B0D;
       font-weight:650;font-size:13.5px;border-radius:9px;padding:10px;cursor:pointer;margin-top:5px;
       box-shadow:0 1px 3px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.9);transition:.12s}
  .save:hover{filter:brightness(.96)}
  .save:active{transform:translateY(1px)}
  .note{color:var(--faint);font-size:11.5px;line-height:1.6;padding:12px 14px 6px}
  .note b{color:var(--dim)}
  .bar{display:flex;align-items:center;gap:10px;padding:12px 20px;
       border-top:1px solid var(--line-soft);color:var(--faint);
       font-size:11.5px;font-family:var(--mono);background:rgba(0,0,0,.18)}
  .bar .hints{margin-left:auto;display:flex;gap:14px;align-items:center;font-family:-apple-system,sans-serif;font-size:11.5px}
  kbd{font-family:var(--mono);font-size:10.5px;color:var(--dim);background:var(--glass);
       border:1px solid var(--line-soft);border-bottom-width:2px;border-radius:5px;padding:1px 6px;margin-right:4px}
  #toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(70px);
       background:rgba(28,30,34,.75);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
       border:1px solid var(--line);color:var(--txt);padding:11px 20px;border-radius:12px;
       font-size:13px;transition:.25s;opacity:0;box-shadow:0 16px 48px rgba(0,0,0,.5);z-index:9}
  #toast.show{transform:translateX(-50%) translateY(0);opacity:1}
</style></head><body>
<div class="window">
  <header>
    <h1><span class="glyph">🕶️</span>blind-vault</h1>
    <span class="sub">secrets your agent can use — but never see</span>
    <span class="local"><span class="dot"></span>local only · 127.0.0.1</span>
  </header>
  <main>
    <section class="panel">
      <h2>Pointers <span>— the only thing Claude ever reads</span></h2>
      <div id="list"><div class="empty">loading…</div></div>
    </section>
    <aside class="panel">
      <h2>Add a secret</h2>
      <form id="add" autocomplete="off">
        <div><label>Name</label><input name="name" placeholder="openai-api-key · github-login" required></div>
        <div><label>Account / ID (optional — for logins)</label><input name="account" placeholder="you@example.com"></div>
        <div><label>Value — API key or password</label><input name="value" type="password" placeholder="pasted here → straight to Keychain" required></div>
        <div><label>Service</label><input name="service" placeholder="OpenAI"></div>
        <div><label>Allowed for</label><input name="allow" placeholder="api.openai.com, curl"></div>
        <div><label>Env var</label><input name="env" placeholder="OPENAI_API_KEY (auto)"></div>
        <div><label>Note</label><input name="note" placeholder="personal, pay-as-you-go"></div>
        <button class="save" type="submit">Save to Keychain</button>
      </form>
      <p class="note"><b>Where the value goes:</b> this form → 127.0.0.1 → macOS Keychain.
      Never written back to this page, never returned by any API, never in Claude's context.
      No “reveal” button — by design.</p>
    </aside>
  </main>
  <div class="bar">
    Claude reads this table without a value column — because there isn't one.
    <span class="hints"><span><kbd>↵</kbd>Save</span><span><kbd>ctrl·c</kbd>Stop server</span></span>
  </div>
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
          ${s.account?`<span class="chip">👤 ${esc(s.account)}</span>`:""}
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
