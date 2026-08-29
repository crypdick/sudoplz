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

1. **Use traditional `sudo`, not `sudo-rs`.** `sudo-rs` doesn't support askpass. Check with `sudo --version` — it should say "Sudo version 1.x.x". If you're on `sudo-rs`, switch:
   ```bash
   sudo update-alternatives --install /usr/bin/sudo sudo /usr/bin/sudo.ws 100
   sudo update-alternatives --config sudo   # pick sudo.ws
   ```
2. Make sure you have an SSH key (ed25519, ecdsa, rsa, or dsa).
3. Install system dependencies:
   - [`age`](https://github.com/FiloSottile/age) — required if your SSH key is Ed25519 (the most common case today). `sudo pacman -S age` / `sudo apt install age` / `brew install age`.
   - On Linux, the approval UI uses **PySide6** (installed with the tool). `zenity` remains a fallback if Qt is unavailable. Not needed on macOS (uses AppleScript).
4. Install with [`uv`](https://docs.astral.sh/uv/):
   ```bash
   uv tool install sudoplz
   ```
   This puts `askpass` and `sudoplz` on your PATH. (For development: clone the repo and run `uv tool install .` instead.)
5. Point `SUDO_ASKPASS` at the installed binary (add to `~/.bashrc`, `~/.zshrc`, etc.):
   ```bash
   export SUDO_ASKPASS="$(which askpass)"
   ```
6. So agent context survives sudo's `env_reset`, install the bundled sudoers drop-in once:
   ```bash
   sudo install -m 0440 sudoers.d/sudoplz-env /etc/sudoers.d/sudoplz-env
   sudo visudo -cf /etc/sudoers.d/sudoplz-env
   ```
   (Keeps `SUDOPLZ_EXPLAIN`, `SUDOPLZ_SCRIPT_BODY`, and `SUDOPLZ_SCRIPT`.)
7. Store your sudo password:
   ```bash
   sudoplz set
   ```

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

- **Ed25519**: `age` encryption, stored at `~/.sudo_askpass.age`
- **RSA/ECDSA/DSA**: OpenSSL asymmetric encryption, stored at `~/.sudo_askpass.ssh`

Encrypted files have 600 permissions. Key preference: ed25519 > ecdsa > rsa > dsa. Falls back to the system keyring if available. Refuses plain text storage.

### Defense in depth

Encryption alone doesn't cover every abuse path — anything running as your user can in principle request decryption. The askpass script runs these checks on every invocation; any failure means no decryption:

- **Caller path whitelist.** Only decrypts when the caller's working directory is on an allowlist (home, `/tmp`, etc.). Blocks invocations from unexpected locations like `/var/tmp/malicious`.
- **Caller process whitelist.** Parent process must be on an allowlist (sudo, your shell, your IDE, your deploy tool). Keeps arbitrary binaries from invoking askpass directly.
- **User confirmation.** A GUI dialog asks for approval on each decryption (explanation + full command body when provided), so any sudo elevation you didn't initiate is visible and can be denied. On Linux the dialog is PySide6; stdout/stderr are redirected while it runs so Qt cannot corrupt the password sudo reads from askpass.
- **Rate limiting.** Configurable max-attempts-per-hour and lockout window. Contains runaway scripts and brute-force attempts.
- **Password expiration.** Stored passwords age out automatically (default: 1 week). A stolen blob becomes useless once it expires, even with your SSH key.

Configure these in `~/.config/sudoplz/config.json` — an example is shipped as `askpass-config.json` in the repo; copy it and edit.

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
sudoplz set        # Store password (terminal prompt; expires per config, 1 week default)
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
