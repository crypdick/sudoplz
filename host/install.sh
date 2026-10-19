#!/usr/bin/env bash
# Portable host install for sudoplz (no machine-specific paths in templates).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${ROOT}/host"

WITH_CURSOR_RULE=0
SKIP_UV=0
SKIP_SUDOERS=0
FORCE_CONFIG=0

usage() {
  cat <<'EOF'
Usage: ./host/install.sh [options]

  --with-cursor-rule   Copy host/cursor/sudoplz.mdc → ~/.cursor/rules/
  --skip-uv            Do not run `uv tool install`
  --skip-sudoers       Do not install /etc/sudoers.d/sudoplz-env
  --force-config       Overwrite ~/.config/sudoplz/config.json from template
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-cursor-rule) WITH_CURSOR_RULE=1 ;;
    --skip-uv) SKIP_UV=1 ;;
    --skip-sudoers) SKIP_SUDOERS=1 ;;
    --force-config) FORCE_CONFIG=1 ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z "${HOME:-}" ]]; then
  echo "HOME is unset" >&2
  exit 1
fi

if [[ ! -x /usr/bin/sudo ]]; then
  echo "Need traditional /usr/bin/sudo (sudo-rs is not supported)." >&2
  exit 1
fi

log() { printf '+ %s\n' "$*"; }

ensure_shell_source() {
  local rc="$1"
  local marker='.config/sudoplz/env.sh'
  local block

  block=$(cat <<'EOF'

# sudoplz
[ -f "${HOME}/.config/sudoplz/env.sh" ] && . "${HOME}/.config/sudoplz/env.sh"
EOF
)

  if [[ ! -f "$rc" ]]; then
    log "create $rc"
    printf '%s\n' "$block" >"$rc"
    return
  fi

  if grep -Fq "$marker" "$rc"; then
    log "shell source already present in $rc"
    return
  fi

  log "append sudoplz source to $rc"
  printf '%s\n' "$block" >>"$rc"
}

seed_config() {
  local dest="${HOME}/.config/sudoplz/config.json"

  if [[ -f "$dest" && "$FORCE_CONFIG" -eq 0 ]]; then
    log "keep existing $dest"
    return
  fi

  python3 - "$ROOT/askpass-config.json" "$dest" "$HOME" <<'PY'
import json, pathlib, sys

src, dest, home = sys.argv[1:4]
data = json.loads(pathlib.Path(src).read_text())
paths = []
for p in data.get("allowed_paths") or []:
    if p.endswith("REPLACE_ME") or p == "/home/REPLACE_ME":
        paths.append(home)
    else:
        paths.append(p)
if home not in paths:
    paths.insert(0, home)
if "/tmp/" not in paths and "/tmp" not in paths:
    paths.append("/tmp/")
data["allowed_paths"] = paths
data["expiration_hours"] = int(data.get("expiration_hours") or 0)
path = pathlib.Path(dest)
path.write_text(json.dumps(data, indent=2) + "\n")
path.chmod(0o600)
PY
  log "wrote $dest (allowed_paths includes $HOME)"
}

# --- uv tool ---
if [[ "$SKIP_UV" -eq 0 ]]; then
  if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found. Install uv, then re-run (Arch: pacman -S uv)." >&2
    exit 1
  fi
  if ! command -v age >/dev/null 2>&1; then
    echo "warning: age not found (needed for Ed25519 password store). Arch: pacman -S age" >&2
  fi
  log "uv tool install --force $ROOT"
  uv tool install --force "$ROOT"
else
  log "skip uv tool install"
fi

# --- user files ---
mkdir -p "${HOME}/bin" \
  "${HOME}/.config/sudoplz" \
  "${HOME}/.config/environment.d"

install -m 0755 "${HOST}/bin/sudo" "${HOME}/bin/sudo"
log "installed ${HOME}/bin/sudo"

install -m 0644 "${HOST}/env.sh" "${HOME}/.config/sudoplz/env.sh"
log "installed ${HOME}/.config/sudoplz/env.sh"

install -m 0644 "${HOST}/environment.d/sudoplz.conf" \
  "${HOME}/.config/environment.d/sudoplz.conf"
log "installed ${HOME}/.config/environment.d/sudoplz.conf (%h portable)"

seed_config

ensure_shell_source "${HOME}/.bashrc"
if [[ -f "${HOME}/.zshrc" ]] || [[ -n "${ZSH_VERSION:-}" ]]; then
  ensure_shell_source "${HOME}/.zshrc"
fi

if [[ "$WITH_CURSOR_RULE" -eq 1 ]]; then
  mkdir -p "${HOME}/.cursor/rules"
  install -m 0644 "${HOST}/cursor/sudoplz.mdc" "${HOME}/.cursor/rules/sudoplz.mdc"
  log "installed ${HOME}/.cursor/rules/sudoplz.mdc"
fi

# --- sudoers ---
if [[ "$SKIP_SUDOERS" -eq 0 ]]; then
  SUDOERS_SRC="${ROOT}/sudoers.d/sudoplz-env"
  SUDOERS_DST="/etc/sudoers.d/sudoplz-env"
  if [[ -f "$SUDOERS_DST" ]] && cmp -s "$SUDOERS_SRC" "$SUDOERS_DST"; then
    log "sudoers drop-in already up to date"
  else
    log "install sudoers drop-in (may prompt for password on a TTY)"
    if [[ -t 0 ]]; then
      /usr/bin/sudo install -m 0440 "$SUDOERS_SRC" "$SUDOERS_DST"
      /usr/bin/sudo visudo -cf "$SUDOERS_DST"
    else
      echo "No TTY: skip sudoers install. On a terminal run:" >&2
      echo "  sudo install -m 0440 $SUDOERS_SRC $SUDOERS_DST && sudo visudo -cf $SUDOERS_DST" >&2
    fi
  fi
else
  log "skip sudoers"
fi

cat <<EOF

Done. Next:
  1. Re-login (or restart your IDE) so environment.d applies.
  2. Open a new shell so bashrc/zshrc sources env.sh.
  3. Ensure ssh-agent holds your key, then either:
       sudoplz set
     or click Allow on the first sudo -A and enter the password in the GUI.
  4. Smoke:  sudoplz test

Password ciphertext stays local (~/.config/sudoplz/askpass.age) — never in git.
EOF
