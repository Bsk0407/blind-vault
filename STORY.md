# The story — built and battle-tested in one conversation

This repo went from "what should I post on LinkedIn?" to a native macOS app
managing its author's real credentials — in a single working session, one
human and one AI agent (Claude) pair-building. This is the build log, kept
because the *process* proves the product: every design decision below exists
because something real happened.

## 1. The inversion

It started as content brainstorming. Someone's LinkedIn post about a
motion-design skill was making rounds; we wanted an open-source skill with
that kind of pull. First idea: "an AI that remembers everything about you —
and can store your passwords, encrypted."

Then the obvious problem: **encrypt-and-let-the-AI-decrypt is security
theater.** The moment a value is decrypted into a conversation, it's in the
transcript and the provider's logs — plaintext, forever. Encryption at rest
fixes nothing if the read path runs through a context window.

So the design inverted: the agent gets **pointers**, the OS keeps **values**.
The agent knows *that* you have a Stripe key, *what* it's for, *when* it was
last used — and composes every command that uses it — while the value rides
an env var from Keychain straight into the child process. There is no
`vault get`. That's not a missing feature; it's the feature.

## 2. The CLI, and the bug that designed the scope matcher

v0.1 was ~200 lines of bash. The first test run caught a real bug: scope
binding used substring matching, and a secret scoped to `sh` happily matched
the word "should" in an unrelated command. Substring matching was quietly
useless — `example.com` would also have matched `example.com.evil.io`.

The fix became one of the repo's better ideas: **asymmetric boundary
matching**. A leading dot is a boundary (`api.openai.com` matches a secret
scoped to `openai.com` — subdomains are the same owner), a trailing dot is
not (`openai.com.evil.io` is blocked — suffix attacks are not). Six-case
test matrix in the first commit.

## 3. Prior art, found the same day

Hours after v0.1: [Infisical's agent-vault](https://github.com/Infisical/agent-vault)
already existed — 1.8k stars, a Go MITM credential proxy, same problem.
Brief despair, then the honest read: it's a *server* you deploy on a separate
machine for agent fleets. This is ~200 lines of bash and the Keychain you
already have, for one person and one Mac — plus the piece a proxy doesn't
ship: the skill layer that teaches the agent how to *behave* around secrets.
Their stars validate the problem. The comparison went straight into the
README instead of being buried.

## 4. "웹 말고 프로그램으로 만들어줘" — the app

The human didn't want a localhost page; they wanted a *program*. So the web
dashboard became a Tauri menu-bar app: no dock icon, a sunglasses icon in the
menu bar, **⌥⌘V** summons a frameless glass window with real
NSVisualEffectView vibrancy. The Rust side calls `security`/`pbcopy`
in-process — the web server, its port, and its CSRF token all *ceased to
exist* as attack surface. Same manifest, same Keychain namespace: keys added
in the app are instantly usable by the agent's CLI.

First launch on a light-mode Mac rendered ghost-on-glass — vibrancy follows
system appearance, and white text on light glass vanishes. One screenshot
from the human ("정말 하나도 안 보인다"), one fix: pin the window to dark.
Design bugs get found by real eyes, not by the builder's dark-mode setup.

## 5. Real credentials, same day

The human registered their actual Gemini API key, GitHub login, and Google
login through the app. Then the first blind API call:

```
vault use gemini-api-key -- curl https://generativelanguage.googleapis.com/...
```

Gemini's actual reply, quoted verbatim:

> *"Yejun, Claude just called me, blindly using my API key. Congrats on that
> slick new `blind-vault` setup!"*

The agent composed that command, ran it, and read the response — and at no
point could it have printed the key, because it never had it.

## 6. The guards fire — twice, for real

**Scope block.** During testing, a command that didn't mention the secret's
allowed target got refused with `SCOPE BLOCK` and a note that the override is
human-only. The prompt-injection tripwire, observed working.

**Frontmost-app guard.** The first hands-free login attempt aborted with:

```
vault: frontmost app is 'Claude', not a browser — aborted, nothing typed.
```

The chat window had focus at typing time. Without the guard, a password
would have been keystroked into a chat box — which is exactly the disaster
`vault type` was designed never to allow. The tool refused its own demo,
correctly, on day one.

**And one confession.** Mid-session, a commit accidentally included local
session files containing an internal daemon token — pushed to this public
repo. Rule zero applied to its own authors: the token was rotated
immediately, history was rewritten, and the lesson is the same one the skill
teaches: *once a secret touches a public surface, rotation is the only fix.*
We kept this paragraph because a secrets tool that hides its own incident
would be worthless.

## 7. Hands-free login, end to end

Final act: `osascript` opened a fresh Chrome incognito window at
github.com/login, and `vault type GitHub-account --account --enter` typed
ID → Tab → password → Return as raw OS keystrokes. Value path:
Keychain → env → System Events. The human touched nothing. The agent saw
nothing. The login form got everything.

## What one day proved

The two-surface principle held under real use: **the human-facing surface
has a password field; the agent-facing surface has a table with no value
column.** Every capability added that day — API calls, deploys, clipboard,
keystrokes — was a new *path for the value that routes around the agent*,
never through it.

The pointer manifest is the part that generalizes: an agent's knowledge of
you should be structured, owned, and inspectable — with sensitive values as
references, not contents. That idea is bigger than secrets; it's what
[LAPLAS](https://github.com/AnYejun/laplaspack) is about.

## Timeline (one session)

| Commit | What happened |
|---|---|
| `0328ce9` | v0.1 — skill + CLI + demo GIF, boundary-matched scope binding |
| `b90da97` | README: the "password secretary" narrative |
| `f06a5ad` | Web dashboard (`vault ui`), DNS-rebinding guards |
| `b8ca1c0` | Raycast-grade glassmorphism, monochrome |
| `e8ea319` | Native menu-bar app (Tauri 2, real vibrancy, ⌥⌘V) |
| `6975174` | Quiet start — login-item ready |
| `21a4938` | Light-mode ghost fix (pin window theme to dark) |
| `c86375c` | Logins: ID = pointer, password = value |
| `737d0ef` | `vault type` — hands-free login + frontmost-app guard |
| `a6fc5cb` | Day-one field notes |

Built with [Claude Code](https://claude.com/claude-code). The agent that
wrote this file cannot read the passwords it helped store — and that's the
whole point. 🕶️
