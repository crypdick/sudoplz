# sudoplz

Give Claude Code, Cursor, and other AI coding agents the ability to run `sudo` — with case-by-case GUI approval, no passwordless sudo, no `/etc/sudoers` allowlists.

Your sudo password is encrypted with your SSH private key and only decrypted after you approve a dialog showing **why** elevation is needed and the **full command** about to run (not just a truncated argv). Deny the dialog and nothing happens.

![Sudo approval dialog showing explanation and command body, with Deny and Allow buttons](assets/screenshot.png)

## Why

Coding agents can't handle interactive terminal prompts. Ask Claude Code to run `sudo apt install foo` and you get `sudo: Authentication failed`. The common workarounds all have problems:

- **Passwordless sudo** gives the agent — and anything else running as your user — unrestricted root.
- **`/etc/sudoers` allowlists** require predicting every command the agent will ever need. No case-by-case review.
- **Manual copy-paste** is tedious and breaks the agent's flow.

`sudoplz` plugs into `sudo -A`, so the agent runs `sudo -A <command>`, you see a dialog with the exact command, and you click Allow or Deny. Works for any command without pre-declaring what's permitted.

This threat model assumes a personal workstation with an encrypted disk and a passphrase-protected SSH key. Not appropriate for shared or production systems.

## Installation

Everything needed to rebuild the **non-secret** stack lives in the repo (tool + portable host wiring). Secrets do **not** — `~/.config/sudoplz/askpass.age` is created on the machine after install.

### One-shot (recommended)

```bash
git clone https://github.com/mwsmws22/sudoplz.git   # or your fork / path
cd sudoplz

# deps (example Arch): sudo pacman -S --needed age uv
# need traditional sudo (not sudo-rs) and an SSH key (ed25519 preferred)

./host/install.sh --with-cursor-rule
```

`host/install.sh` is **portable** (`$HOME` / systemd `%h` only — no hardcoded username):

| Step | Result |
|------|--------|
| `uv tool install --force .` | `~/.local/bin/askpass`, `sudoplz` |
| `~/bin/sudo` | Refuse non-TTY plain sudo; force sudoplz askpass |
| `~/.config/sudoplz/env.sh` | `PATH` + `SUDO_ASKPASS`; sourced from bashrc/zshrc |
| `~/.config/environment.d/sudoplz.conf` | Same for Plasma/IDE sessions (`%h`) |
| `~/.config/sudoplz/config.json` | Seeded with **this** user’s home in `allowed_paths` (won’t overwrite unless `--force-config`) |
| `/etc/sudoers.d/sudoplz-env` | Keep `SUDOPLZ_*` through `env_reset` (needs a TTY once) |
| optional Cursor rule | `--with-cursor-rule` → `~/.cursor/rules/sudoplz.mdc` |

Then re-login (or restart the IDE), ensure ssh-agent has your key, and either `sudoplz set` or enter the password on the first Allow dialog. Smoke: `sudoplz test`.

Shipped in-repo:

| Path | Role |
|------|------|
| `src/sudoplz/` | askpass + CLI |
| `host/` | portable wrapper, env, installer, Cursor rule |
| `sudoers.d/sudoplz-env` | `env_keep` for `SUDOPLZ_*` |
| `askpass-config.json` | template for `~/.config/sudoplz/config.json` |
| `pyproject.toml` / `uv.lock` | `uv tool install .` |

Not in the repo (machine-local): `askpass.age`, `audit.log`, live `config.json`.

### Upstream / PyPI style (tool only)

```bash
uv tool install sudoplz   # crypdick/PyPI — may lag this fork; no host/ wiring
```

1. **Use traditional `sudo`, not `sudo-rs`.** `sudo-rs` doesn't support askpass.
2. SSH key + [`age`](https://github.com/FiloSottile/age) for Ed25519.
3. On Linux, all GUI prompts use **PySide6** (pulled in by the tool). Missing `SUDOPLZ_EXPLAIN` or command body → deny (no dialog).

## Usage

Your agent (or you) runs `sudo -A <command>`. Before that, set what the dialog should show:

| Variable | Meaning |
|----------|---------|
| `SUDOPLZ_EXPLAIN` | One or two sentences — why root is needed |
| `SUDOPLZ_SCRIPT_BODY` | Full command text (include heredoc/script bodies; not just `python3 -`) |
| `SUDOPLZ_SCRIPT` | Optional path to a file containing that text (prefer for large bodies) |

```bash
export SUDOPLZ_EXPLAIN='Reload keyd after editing input-shortcuts.conf.'
export SUDOPLZ_SCRIPT_BODY='keyd reload'
sudo -A keyd reload
```

The dialog shows user/host, the explanation, and a scrollable **Command** panel with the body above. Missing explain or body → deny (no dialog).

After **Allow**, askpass may show further PySide6 dialogs in order:

1. **SSH key passphrase** — if the key is not already in ssh-agent (`Unlock` / Cancel)
2. **Sudo password** — if the encrypted store is missing or still cannot decrypt (enter + confirm)

No zenity / system `SSH_ASKPASS` dialogs.

As a fallback when env is stripped, askpass also reads `$XDG_RUNTIME_DIR/sudoplz/pending.json` (`{explain, body, created_at}`, mode `0600`) and clears it after the dialog.

Gotchas:

- `sudo -n` explicitly disallows prompting and will never trigger askpass. Always use `-A`.
- Each `sudo -A` opens its own dialog — batch root work in one `sudo -A bash -c '…'` when you can.

Test the integration with:

```bash
sudoplz test
```

## Security

### Encryption at rest

Passwords are encrypted with your SSH key:

- **Ed25519**: `age` encryption, stored at `~/.config/sudoplz/askpass.age`
- **RSA/ECDSA/DSA**: OpenSSL asymmetric encryption, stored at `~/.config/sudoplz/askpass.ssh`

Older `~/.sudo_askpass.age` / `~/.sudo_askpass.ssh` files are moved into that directory on first `askpass` or `sudoplz` run.

Encrypted files have 600 permissions. Key preference: ed25519 > ecdsa > rsa > dsa. Falls back to the system keyring if available. Refuses plain text storage.

### Defense in depth

Encryption alone doesn't cover every abuse path — anything running as your user can in principle request decryption. The askpass script runs these checks on every invocation; any failure means no decryption:

- **Caller path whitelist.** Only decrypts when the caller's working directory is on an allowlist (home, `/tmp`, etc.). Blocks invocations from unexpected locations like `/var/tmp/malicious`.
- **Caller process whitelist.** Parent process must be on an allowlist (sudo, your shell, your IDE, your deploy tool). Keeps arbitrary binaries from invoking askpass directly.
- **User confirmation.** A GUI dialog asks for approval on each decryption (explanation + full command body when provided), so any sudo elevation you didn't initiate is visible and can be denied. On Linux the dialog is PySide6; stdout/stderr are redirected while it runs so Qt cannot corrupt the password sudo reads from askpass.
- **Rate limiting.** Configurable max-attempts-per-hour and lockout window. Contains runaway scripts and brute-force attempts.
- **pam_faillock pre-check.** If locked, one wait/Dismiss dialog (Polkit cannot unlock — same lock). One askpass cycle per sudo process; further retries get no UI.


- **Password expiration (optional).** Default is **off** (`expiration_hours: 0`). If you enable it, expired ciphertext is deleted; after you click Allow, askpass opens a password dialog so you can re-enter and continue without a separate `sudoplz set`.

Configure these in `~/.config/sudoplz/config.json` — an example is shipped as `askpass-config.json` in the repo; copy it and edit. Or: `sudoplz config --no-expire` / `sudoplz config --expire-hours N`.

### Why age for Ed25519?

Ed25519 is a signing algorithm (EdDSA), not encryption. OpenSSL handles RSA encryption directly, but Ed25519 keys can't do asymmetric encryption at all. `age` was designed to work with SSH keys including Ed25519.

Passphrase-protected SSH keys are unlocked via the PySide6 passphrase dialog (then `ssh-add`) when not already in ssh-agent. Askpass reconnects to `$XDG_RUNTIME_DIR/ssh-agent.socket` when sudo strips `SSH_AUTH_SOCK`, and strips `SSH_ASKPASS` so OpenSSH/`age` cannot spawn a second system prompt.

## Commands

```bash
sudoplz set        # Store password (terminal prompt; or re-enter via askpass GUI after Allow)
sudoplz set-totp   # Store password with TOTP verification (headless)
sudoplz totp-setup # Set up TOTP for headless sessions
sudoplz get        # Check if password exists
sudoplz clear      # Remove password
sudoplz test       # Test sudo integration
sudoplz audit      # Show recent askpass usage
```

## Headless/SSH usage with TOTP

For servers or SSH sessions without a display, authenticate with TOTP.

### Initial setup (run once from a GUI session)

```bash
sudoplz totp-setup
```

Prints a TOTP secret and an `otpauth://` URL to add to your authenticator app.

### Setting a password from a headless session

```bash
sudoplz set-totp
```

Enter your 6-digit TOTP code, then your password.

### Using sudo with TOTP

When `DISPLAY` isn't set, askpass prompts for a TOTP code:

```bash
# Interactive — prompts for TOTP code
sudo -A command

# Non-interactive — pass TOTP via environment
TOTP="123456" sudo -A command
```

## Credits

The idea — an SSH-key-encrypted sudo password served via `SUDO_ASKPASS`, gated by a confirmation dialog — is from [GlassOnTin/secure-askpass](https://github.com/GlassOnTin/secure-askpass). That project is dormant; `sudoplz` is a substantially rewritten and cleaned up fork. Thanks to [@GlassOnTin](https://github.com/GlassOnTin) for the original idea.

## License

MIT — see LICENSE.
