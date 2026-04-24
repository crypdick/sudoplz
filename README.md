# SSH Askpass Helper

A secure askpass implementation using SSH key encryption for non-interactive sudo operations.

## About this fork

Long-lived fork of [GlassOnTin/secure-askpass](https://github.com/GlassOnTin/secure-askpass). Upstream is dormant and hasn't pulled these patches, so this fork is the canonical source if you need:

- **Working macOS dialogs.** Upstream's cross-platform Python GUI is unreliable on recent macOS. This fork uses native AppleScript dialogs on macOS.
- **No SSH passphrase re-prompt on every sudo.** `sudo` strips `SSH_AUTH_SOCK`, which would otherwise force age-encrypted passwords to re-prompt on each call. This fork reconnects to your running ssh-agent instead.
- **Less shell-config glue.** Sudo sanitizes `PATH`, which breaks shebang resolution in upstream's wrapper. This fork handles PATH and `SUDO_ASKPASS` identity inside `askpass` itself — install with `uv tool install .` and point `SUDO_ASKPASS` at the resulting binary.

## Installation

1. Clone the repo.
2. Make sure you have an SSH key (ed25519, ecdsa, rsa, or dsa).
3. For Ed25519 keys, install [`age`](https://github.com/FiloSottile/age):
   - Arch Linux: `sudo pacman -S age`
   - Ubuntu/Debian: `sudo apt install age`
   - macOS: `brew install age`
4. Install the tools with [`uv`](https://docs.astral.sh/uv/):
   ```bash
   uv tool install .
   ```
   This puts `askpass` and `askpass-manager` on your PATH.
5. Point `SUDO_ASKPASS` at the installed binary (add to `~/.bashrc`, `~/.zshrc`, etc.):
   ```bash
   export SUDO_ASKPASS="$(which askpass)"
   ```
6. Store your sudo password:
   ```bash
   askpass-manager set
   ```

## sudo-rs note

`sudo-rs` doesn't support askpass. If you're running `sudo-rs`, configure `sudo.ws` as an alternative:

```bash
sudo update-alternatives --install /usr/bin/sudo sudo /usr/bin/sudo.ws 100
# Adjust the priority if you have other sudo alternatives.
# Switch back with: sudo update-alternatives --config sudo
```

## Usage

```bash
export SUDO_ASKPASS="$(which askpass)"
sudo -A command
```

Or test the integration:

```bash
askpass-manager test
```

## Security

### Encryption at rest

Passwords are encrypted with your SSH key:

- **Ed25519**: `age` encryption, stored at `~/.sudo_askpass.age`
- **RSA/ECDSA/DSA**: OpenSSL asymmetric encryption, stored at `~/.sudo_askpass.ssh`

Encrypted files have 600 permissions. Key preference: ed25519 > ecdsa > rsa > dsa. Falls back to the system keyring if available. Refuses plain text storage.

### Defense in depth

Encryption alone doesn't cover every abuse path — anything running as your user can in principle request decryption. The askpass script checks several conditions on each invocation and refuses to decrypt if any fail:

- **Caller path whitelist.** Only decrypts when the caller's working directory is on an allowlist (home, `/tmp`, etc.). Blocks invocations from unexpected locations like `/var/tmp/malicious`.
- **Caller process whitelist.** Parent process must be on an allowlist (sudo, your shell, your IDE, your deploy tool). Keeps arbitrary binaries from invoking askpass directly.
- **User confirmation.** A GUI dialog asks for approval on each decryption, so any sudo elevation you didn't initiate is visible and can be denied.
- **Rate limiting.** Configurable max-attempts-per-hour and lockout window. Caps the blast radius of runaway scripts and brute-force attempts.
- **Password expiration.** Stored passwords age out automatically (default: 1 week). A stolen blob becomes useless once it expires, even with your SSH key.

Configure these in `~/.config/secure-askpass/config.json` (an example is shipped as `askpass-config.json` in the repo — copy it and edit). The built-in defaults are reasonable for a personal workstation.

### Why age for Ed25519?

Ed25519 is a signing algorithm (EdDSA), not encryption. OpenSSL handles RSA encryption directly, but Ed25519 keys can't do asymmetric encryption at all. `age` was designed to work with SSH keys including Ed25519.

### SSH key unlocking

If your SSH key has a passphrase (recommended), the askpass tool will:

1. Check whether the key is loaded in ssh-agent
2. Prompt for the passphrase via GUI if it isn't
3. Load the key into ssh-agent for the session

You enter the passphrase once per session. After that, sudo commands only need the confirmation dialog. You need a running ssh-agent — most desktop environments start one on login; if not, `eval "$(ssh-agent -s)"` in your shell startup.

This works under `sudo -A` despite the `SSH_AUTH_SOCK` stripping: the script finds your running ssh-agent and reconnects.

## Commands

```bash
askpass-manager set        # Store password (terminal prompt; expires per config, 1 week default)
askpass-manager set-totp   # Store password with TOTP verification (headless)
askpass-manager totp-setup # Set up TOTP for headless sessions
askpass-manager get        # Check if password exists
askpass-manager clear      # Remove password
askpass-manager test       # Test sudo integration
askpass-manager audit      # Show recent askpass usage
```

## Headless/SSH usage with TOTP

For servers or SSH sessions without a display, authenticate with TOTP.

### Initial setup (run once from a GUI session)

```bash
askpass-manager totp-setup
```

Prints a TOTP secret and an `otpauth://` URL to add to your authenticator app.

### Setting a password from a headless session

```bash
askpass-manager set-totp
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

## License

MIT — see LICENSE.
