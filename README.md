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

Everything needed to rebuild this tool lives in the repo. Secrets do **not** — `~/.config/sudoplz/askpass.age` is created on the machine after install.

### From this repo (recommended for the mws fork)

```bash
git clone https://github.com/mwsmws22/sudoplz.git
cd sudoplz

# system deps
# Arch: sudo pacman -S --needed age uv
# also need a traditional sudo (not sudo-rs) and an SSH key (ed25519 preferred)

uv tool install --force .
# → ~/.local/bin/askpass and ~/.local/bin/sudoplz

# shell (e.g. ~/.bashrc)
export PATH="$HOME/.local/bin:$PATH"
export SUDO_ASKPASS="$HOME/.local/bin/askpass"

# keep SUDOPLZ_* through sudo env_reset (one-time; needs a working sudo once)
sudo install -m 0440 sudoers.d/sudoplz-env /etc/sudoers.d/sudoplz-env
sudo visudo -cf /etc/sudoers.d/sudoplz-env

# optional: copy example config and put your home in allowed_paths
mkdir -p ~/.config/sudoplz
cp askpass-config.json ~/.config/sudoplz/config.json
# edit allowed_paths → ["/home/YOU", "/tmp/"]
# expiration_hours: 0 is recommended (no auto-delete)

# store password (terminal) — or skip and enter it in the GUI after the first Allow
sudoplz set
# sudoplz config --no-expire   # if you copied an old config with expiration

# ssh-agent must be running (Plasma usually starts one). Ed25519 path uses age + the key file;
# passphrase-protected keys need the key loaded in the agent for decrypt.
sudoplz test
```

Shipped in-repo for setup:

| Path | Role |
|------|------|
| `src/sudoplz/` | askpass + CLI |
| `sudoers.d/sudoplz-env` | `env_keep` for `SUDOPLZ_*` |
| `askpass-config.json` | example `~/.config/sudoplz/config.json` |
| `pyproject.toml` / `uv.lock` | install via `uv tool install .` |

Not in the repo (machine-local): `~/.config/sudoplz/askpass.age`, `audit.log`, live `config.json`.

### Upstream / PyPI style

```bash
uv tool install sudoplz   # crypdick/PyPI — may lag this fork
```

1. **Use traditional `sudo`, not `sudo-rs`.** `sudo-rs` doesn't support askpass.
2. SSH key + [`age`](https://github.com/FiloSottile/age) for Ed25519.
3. On Linux, approval UI is **PySide6** (pulled in by the tool). `zenity` is a fallback.

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

The dialog shows user/host, the explanation, and a scrollable **Command** panel with the body above. If those env vars are missing, the panel falls back to what `ps` reports for the sudo parent (often incomplete for heredocs).

If you click **Allow** but no encrypted password is stored (never set, expired, or deleted), a second dialog asks for the sudo password (enter + confirm). On success it is encrypted with your SSH key and used for that `sudo -A` call.

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
- **Password expiration (optional).** Default is **off** (`expiration_hours: 0`). If you enable it, expired ciphertext is deleted; after you click Allow, askpass opens a password dialog so you can re-enter and continue without a separate `sudoplz set`.

Configure these in `~/.config/sudoplz/config.json` — an example is shipped as `askpass-config.json` in the repo; copy it and edit. Or: `sudoplz config --no-expire` / `sudoplz config --expire-hours N`.

### Why age for Ed25519?

Ed25519 is a signing algorithm (EdDSA), not encryption. OpenSSL handles RSA encryption directly, but Ed25519 keys can't do asymmetric encryption at all. `age` was designed to work with SSH keys including Ed25519.

### SSH key unlocking

If your SSH key has a passphrase (recommended), the askpass tool will:

1. Check whether the key is loaded in ssh-agent
2. Prompt for the passphrase via GUI if it isn't
3. Load the key into ssh-agent for the session

You enter the passphrase once per session. After that, sudo commands only need the confirmation dialog. You need a running ssh-agent — most desktop environments start one on login; if not, `eval "$(ssh-agent -s)"` in your shell startup.

This works under `sudo -A` even though sudo strips `SSH_AUTH_SOCK`: the script reconnects to your running ssh-agent (including common sockets such as `$XDG_RUNTIME_DIR/ssh-agent.socket`).

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
