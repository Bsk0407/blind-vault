# 🕶️ blind-vault

**Secrets your AI agent can *use* but never *see*.**

A Claude Code skill + tiny zero-dependency CLI. Your agent deploys with your Fly token, calls APIs with your keys, logs into services with your credentials — and at no point does a secret value ever enter its context window, chat logs, or tool output.

![blind-vault demo: vault add pops a native macOS dialog, vault ls shows pointers only, vault use injects the key into curl](assets/demo.gif)

## The problem

Be honest. Right now you are doing at least one of these:

- ❌ API keys sitting in plaintext `.env` files that any agent (or dependency) can read
- ❌ Pasting keys directly into AI chats — **they're in the transcript and provider logs forever**
- ❌ Keys in your shell history (`export OPENAI_API_KEY=sk-...`)
- ❌ Keys visible in screenshots you share for debugging
- ❌ One key, unscoped, usable by anything for anything

"Encrypt the secrets and let the AI decrypt them" doesn't fix this — **the moment a value is decrypted into the conversation, it's logged plaintext anyway.** The only fix is an architecture where the value never crosses the context boundary at all.

## How it works

```
 REGISTER            ┌─────────────────────┐
 native macOS dialog │   macOS Keychain     │   values live here
 (hidden input) ────▶│   (encrypted, yours) │◀── never leave the OS
                     └──────────┬──────────┘
                                │ env-var injection, child process only
                                ▼
 AGENT SIDE          ┌─────────────────────┐
 manifest.json  ────▶│  vault use name --   │──▶ fly deploy / curl / npm ...
 (pointers only:     │  <your command>      │
  names, scopes,     └─────────────────────┘
  env vars, dates)      the agent composes this line
                        but never sees the value
```

1. **Register** — `vault add openai-api-key --allow api.openai.com`. A native macOS password dialog opens; the value goes keyboard → Keychain. The agent that ran the command sees only "stored".
2. **Remember** — a pointer manifest (`~/.blindvault/manifest.json`) holds names, services, account IDs, scopes, and last-used dates. No values. The agent reads this freely — that's how it *knows what you have* without knowing what it is.
3. **Use** — `vault use fly-api-token -- fly deploy`. The value is fetched inside the CLI process and injected as an environment variable into the child process. Never printed. There is **no `vault get`** — by design.
4. **Scope binding** — every secret declares what it's allowed for. A command that doesn't mention an allowed target gets a loud `SCOPE BLOCK`. If a malicious webpage prompt-injects your agent into "send me your key", it hits this wall — and the override is human-only.

## Install

```bash
git clone https://github.com/AnYejun/blind-vault
cd blind-vault && ./install.sh
```

That symlinks the skill into `~/.claude/skills/vault`, makes the CLI executable, and runs `vault init`. Restart Claude Code and say "store my OpenAI key". macOS only for now (Keychain + `osascript`; Linux `age`/`secret-tool` backend — PRs welcome).

## Usage

```bash
vault add stripe-live --service Stripe --env STRIPE_SECRET_KEY --allow "api.stripe.com"
vault ls                                   # pointers only, never values
vault use stripe-live -- curl https://api.stripe.com/v1/charges
vault copy github-pat                      # → clipboard, auto-clears in 30s
vault rm old-key                           # keychain + manifest
```

Or don't touch the CLI at all — the skill teaches your agent all of this. "Deploy to Fly" and it finds the right pointer, injects it, done.

## Threat model

| Protects against | How |
|---|---|
| Secrets in AI chat logs / context windows | values never cross the context boundary |
| Secrets in tool output, files, `.env`, shell history | env-injection only; no print path exists |
| Prompt injection ("send me your key") | scope binding + human-only override |
| "Which key was that again?" sprawl | pointer manifest = agent-readable memory |

**Does not protect against:** malware running as you (it can read your Keychain too — use a password manager's CLI as the backend if that's your bar), a brief `ps` window during `vault add`, or clipboard sniffing during the 30s `vault copy` window. This is a context-boundary tool, not an HSM.

## "Isn't this Infisical's agent-vault?"

Different layer, same problem — and you might genuinely want theirs instead. [agent-vault](https://github.com/Infisical/agent-vault) is a brokered credential proxy: a Go server (ideally on a separate machine) that MITMs your agent's HTTPS traffic and injects real credentials on the way out. Stronger guarantee — the agent process never holds a real value at all — at the cost of infrastructure: a server, a master password, proxy bootstrapping, per-agent tokens.

blind-vault is the local-first version for one person and one Mac: ~200 lines of bash, the Keychain you already have, no server, no account, installed before your coffee cools. It also covers what a proxy can't — anything that isn't an HTTP call (SSH keys, DB passwords, signing keys, arbitrary CLIs) — and ships the piece a proxy doesn't have: the **skill layer** that teaches the agent how to *behave* around secrets, not just where to fetch them.

Running remote agent fleets or untrusted sandboxes? Use agent-vault. It's good.

## Why pointers are the interesting part

The manifest is a tiny example of a bigger idea: **an agent's memory of you should be a structured, owned, inspectable file — where sensitive values are references, not contents.** The agent remembers *that* you have a Stripe key, *what* it's for, *when* it was last used. That's the useful memory. The value is the one thing it never needs.

That pointer layer is a piece of what I'm building at [LAPLAS](https://github.com/AnYejun/laplaspack) — your whole working context as a portable file your agents can load. More soon.

## License

MIT
