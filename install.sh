#!/usr/bin/env bash
# blind-vault installer: skill symlink + CLI + vault init
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$HOME/.claude/skills/vault"

[ "$(uname)" = "Darwin" ] || { echo "blind-vault v1 is macOS-only (Keychain + osascript)."; exit 1; }

chmod +x "$REPO_DIR/bin/vault"

mkdir -p "$HOME/.claude/skills"
if [ -e "$SKILL_DIR" ] && [ ! -L "$SKILL_DIR" ]; then
  echo "~/.claude/skills/vault already exists and is not a symlink — remove it first."; exit 1
fi
ln -sfn "$REPO_DIR" "$SKILL_DIR"

"$REPO_DIR/bin/vault" init

echo
echo "installed:"
echo "  skill  ~/.claude/skills/vault -> $REPO_DIR"
echo "  cli    $REPO_DIR/bin/vault"
echo
echo "optional — put 'vault' on your PATH:"
echo "  ln -s $REPO_DIR/bin/vault \$HOME/.local/bin/vault"
echo
echo "restart Claude Code, then try: \"store my OpenAI API key\""
