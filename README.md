# SSH Askpass Helper

A secure askpass implementation using SSH key encryption for non-interactive sudo operations.

## About this fork

This is a long-lived fork of [GlassOnTin/secure-askpass](https://github.com/GlassOnTin/secure-askpass). Upstream is currently dormant and hasn't absorbed the fork's patches, so this fork is the canonical source if any of the following matters to you:

- **Works on macOS without crashing.** Upstream renders the confirmation dialog with a cross-platform Python GUI that's unreliable on recent macOS. This fork uses native AppleScript dialogs on macOS and keeps the Python dialog for Linux only, so the prompt just works regardless of platform.
- **You don't re-type your SSH key passphrase on every sudo.** `sudo` strips `SSH_AUTH_SOCK` from the environment before calling askpass, which would otherwise force age-encrypted passwords to re-prompt for your SSH key passphrase on every invocation. This fork reconnects to your running ssh-agent automatically, so you unlock your key once per session and forget about it.
- **Fewer shell-config rituals.** Sudo sanitizes `PATH` in ways that break shebang resolution for upstream's wrapper script. This fork handles PATH and `SUDO_ASKPASS` identity inside the `askpass` script directly, so installation is just "point `SUDO_ASKPASS` at `./askpass`" without extra glue.

If you're coming from upstream, no config change needed — point `SUDO_ASKPASS` at this fork's `askpass` and everything behaves the same, plus the above fixes.

## Installation

1. Clone this repository
2. Ensure you have SSH keys (supports ed25519, ecdsa, rsa, or dsa)
3. **For Ed25519 keys**: Install the `age` encryption tool
   - Arch Linux: `sudo pacman -S age`
   - Ubuntu/Debian: `sudo apt install age`
   - macOS: `brew install age`
   - Or build from source: https://github.com/FiloSottile/age#installation
4. Set the `SUDO_ASKPASS` environment variable in your shell configuration:
   ```bash
   export SUDO_ASKPASS="/path/to/secure-askpass/askpass"
   ```
5. Store your sudo password:
   ```bash
   ./askpass-manager set
   ```

## Sudo Alternative for Askpass (sudo.ws)

If you are using `sudo-rs` and need `askpass` functionality, you might need to
configure `sudo.ws` as an alternative for `sudo`, as `sudo-rs` currently
does not support `askpass`.

To do this, you can use `update-alternatives`:

```bash
sudo update-alternatives --install /usr/bin/sudo sudo /usr/bin/sudo.ws 100
# If you have other sudo alternatives, adjust the priority (100) accordingly.
# To switch back to another sudo implementation, you can use:
# sudo update-alternatives --config sudo
```


## Usage

```bash
export SUDO_ASKPASS="/path/to/askpass"
sudo -A command
```

Or use the test command:
```bash
./askpass-manager test
```

## Security

### Encryption at rest

Passwords are encrypted with your SSH keys using one of two methods:
- **Ed25519 keys**: Uses `age` encryption (requires age tool)
- **RSA/ECDSA/DSA keys**: Uses OpenSSL asymmetric encryption

Other details:
- Supports multiple SSH key types (ed25519, ecdsa, rsa, dsa) with automatic detection
- Keys are checked in order of preference: ed25519 > ecdsa > rsa > dsa
- Encrypted files stored with 600 permissions:
  - Ed25519: `~/.sudo_askpass.age`
  - RSA/ECDSA/DSA: `~/.sudo_askpass.ssh`
- Falls back to system keyring if available
- Refuses plain text storage

### Defense in depth

Encryption can't stop every abuse path — anything running as your user could in principle request decryption. To limit how a stored password can be misused, the askpass script checks several conditions on every invocation and refuses to decrypt if any of them fail:

- **Caller path whitelist.** Only decrypts when the caller's working directory matches a whitelisted path (your home dir, `/tmp`, etc.). Prevents a rogue script executing from somewhere unexpected (e.g. `/var/tmp/malicious`) from silently triggering a sudo prompt behind your back.
- **Caller process whitelist.** Only decrypts when the parent process is on an allowlist (sudo, your shell, your IDE, your deploy tool). Blocks arbitrary binaries from impersonating a legitimate caller by simply invoking askpass directly.
- **User confirmation.** A GUI dialog always asks you to approve the decryption. Every sudo elevation is visible — if something triggers askpass that you didn't initiate, you see it and can deny.
- **Rate limiting.** Configurable max-attempts-per-hour plus a lockout window. Defangs runaway scripts and brute-force attempts.
- **Password expiration.** Stored passwords age out automatically (default: 1 week) and must be re-cached. Limits damage if your encrypted blob is ever stolen — even with your SSH key, a week-old stolen blob becomes useless.

Configure any of these in `~/.config/secure-askpass/config.json` or the repo-local `askpass-config.json`. The shipped defaults are sensible for a personal workstation.

### Why age for Ed25519?

Ed25519 is a signing algorithm (EdDSA), not an encryption algorithm. While OpenSSL can handle RSA encryption directly, Ed25519 keys cannot be used for asymmetric encryption. The `age` tool was specifically designed to work with SSH keys including Ed25519, providing a secure and modern encryption solution.

### Automatic SSH Key Management

If your SSH key is password-protected (recommended!), the askpass tool will:
1. Automatically start ssh-agent if not running
2. Check if your SSH key is loaded
3. Prompt for your SSH key passphrase via GUI dialog if needed
4. Load the key into ssh-agent for the session

**Workflow:** You enter your SSH key passphrase once per session. After that, sudo commands need only the confirmation dialog — no terminal interaction.

This works cleanly even under `sudo -A`, which strips `SSH_AUTH_SOCK` from the environment: the askpass script detects your running ssh-agent and reconnects automatically, so you don't re-enter your passphrase on every sudo call.

## Commands

```bash
./askpass-manager set        # Store password (GUI/terminal input; expires per config, 1 week default)
./askpass-manager set-totp   # Store password with TOTP verification (headless)
./askpass-manager totp-setup # Set up TOTP for headless sessions
./askpass-manager get        # Check if password exists
./askpass-manager clear      # Remove password
./askpass-manager test       # Test sudo integration
./askpass-manager audit      # Show recent askpass usage
```

## Headless/SSH Usage with TOTP

For servers or SSH sessions without a display, use TOTP authentication:

### Initial Setup (run once from a GUI session)

```bash
./askpass-manager totp-setup
```

This generates a TOTP secret and displays:
- The secret key to add to your authenticator app
- An `otpauth://` URL you can use with any TOTP app

### Setting Password from Headless Session

```bash
./askpass-manager set-totp
```

Enter your 6-digit TOTP code, then your password.

### Using sudo with TOTP

When `DISPLAY` is not available, the askpass script will prompt for a TOTP code:

```bash
# Interactive - prompts for TOTP code
sudo -A command

# Non-interactive - pass TOTP via environment
TOTP="123456" sudo -A command
```

## License

MIT License - see LICENSE file
