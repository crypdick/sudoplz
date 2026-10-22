# sudoplz

Run privileged commands from Claude Code, Cursor, and other AI coding agents with GUI approval:

```bash
sudoplz apt install foo
```

sudoplz encrypts your sudo password to your SSH public key and decrypts it after you approve a dialog showing the command. If you deny the dialog, sudo authentication fails.

![Sudo approval dialog showing a command about to run, with Deny and Allow buttons](assets/screenshot.png)

## Why

Coding agents can't handle interactive terminal prompts. Ask Claude Code to run `sudo apt install foo` and you get `sudo: Authentication failed`. The common workarounds all have problems:

- **Passwordless sudo** gives the agent and anything else running as your user the privileges allowed by your sudo policy without approval.
- **`/etc/sudoers` allowlists** require predicting which commands the agent needs. They don't provide case-by-case approval.
- **Manual copy-paste** is tedious and breaks the agent's flow.

`sudoplz` sets up the askpass helper and runs `sudo -k -A` for you. The `-k` option ignores cached sudo credentials so each command that requires a password goes through approval. Your sudo policy still controls which commands you can run. Rules that allow execution without a password, such as `NOPASSWD`, bypass askpass and its approval dialog.

This threat model assumes a personal workstation with an encrypted disk and a passphrase-protected SSH key. Not appropriate for shared or production systems.

## Installation

1. **Use traditional `sudo`, not `sudo-rs`.** `sudo-rs` doesn't support askpass. Check with `sudo --version` — it should say "Sudo version 1.x.x". If you're on `sudo-rs`, switch:
   ```bash
   sudo update-alternatives --install /usr/bin/sudo sudo /usr/bin/sudo.ws 100
   sudo update-alternatives --config sudo   # pick sudo.ws
   ```
2. Make sure you have an Ed25519 or RSA SSH key. ECDSA and DSA keys are not supported.
3. Install system dependencies:
   - [`age`](https://github.com/FiloSottile/age) — required for SSH-backed password storage and TOTP. `sudo pacman -S age` / `sudo apt install age` / `brew install age`.
   - `zenity` on Linux — provides the GUI approval dialog. Pre-installed on most GNOME-based distros; `sudo apt install zenity` if missing. Not needed on macOS (uses AppleScript).
4. Install from PyPI with [`uv`](https://docs.astral.sh/uv/):
   ```bash
   uv tool install sudoplz
   ```
   This puts `askpass` and `sudoplz` on your `PATH`. For development, clone the repository and use `uv tool install .` instead.
5. Store your sudo password:
   ```bash
   sudoplz set
   ```

## Usage

Run a command with `sudoplz`, then approve or deny the dialog:

```bash
sudoplz apt install foo
```

Sudo options pass through to sudo. For example, to run as another user:

```bash
sudoplz -u postgres psql
```

Arguments, standard input, output, signals, and exit status pass through to sudo. Shell quoting works as usual. A pipeline or redirection outside the command still runs in your shell.

Management commands such as `set`, `get`, `test`, `config`, and `audit` keep their meaning. Use `--` before an executable whose name matches a management command:

```bash
sudoplz -- test -f /etc/shadow
```

`sudoplz rm-stored-password` removes stored credentials. It replaces the former `sudoplz clear` command. `sudoplz clear` runs the terminal's `clear` executable through sudo.

Avoid `-n` (`--non-interactive`) and `-S` (`--stdin`): they conflict with askpass prompting. Use `sudoplz --help` for management help and `sudo --help` for sudo options.

Test the integration with:

```bash
sudoplz test
```

### Direct sudo integration

For tools that invoke sudo directly, set `SUDO_ASKPASS` in their environment:

```bash
export SUDO_ASKPASS="$(command -v askpass)"
sudo -k -A apt install foo
```

Add the export to your shell startup file if you need it across sessions. The `sudoplz` command sets this variable automatically. Using `sudo -A` without `-k` can reuse cached credentials and skip approval.

### Agent reminder with i-insist

If you use [i-insist](https://github.com/crypdick/i-insist), install its hooks
and [`shfmt`](https://github.com/mvdan/sh), then install the optional global
rule and its checker:

```bash
i-insist ensure
mkdir -p ~/.local/share/sudoplz
cp src/sudoplz/i_insist_guard.py ~/.local/share/sudoplz/i_insist_guard.py
cp hooks/i-insist.toml ~/.i-insist/sudoplz.toml
```

The rule blocks local shell commands that invoke `sudo` without `-A` or
`--askpass` and recommends `sudoplz <command>`. Calls to `sudoplz` pass through.
It also blocks sudo's `-n` and `--non-interactive` options even with askpass enabled.
It ignores quoted command strings, including `ssh host 'sudo apt update'`, since sudo runs on the remote
host. It also ignores `sudo` passed as data to another command, including
heredoc bodies, except heredocs fed to `sh`, `bash`, `zsh`, or `dash`. Without
`shfmt` or on a syntax error, the rule allows the command. This is a
convenience check for ordinary shell calls, not a security boundary. i-insist's configuration protection requires human approval
before copying the rule. After upgrading sudoplz, copy the checker again to update the installed warning.

## Security

### Encryption at rest

New passwords use `age` encryption with an Ed25519 or RSA SSH key. The encrypted
payload, original key path, and creation time are stored together in
`~/.config/sudoplz/credential.json` with 600 permissions. Key preference for new
credentials is Ed25519, then RSA. Adding another key does not change how an
existing credential is decrypted.

Without an SSH key, passwords use the system keyring with creation-time metadata
in the same credential file. A decryption failure never falls back to an older
password. Replacement and clearing retire previous storage; an empty record
prevents legacy credentials from being rediscovered after clearing.

Existing `~/.sudo_askpass.age` and RSA `~/.sudo_askpass.ssh` credentials are imported
on first use, preserving their original modification time. If both exist, the
newest file is selected. Legacy RSA keys can use OpenSSH or PEM format. A legacy
keyring entry has no reliable creation time: run `sudoplz set` again to use it with
expiration enabled. Keep the original SSH key available during migration.

### Defense in depth

Encryption alone doesn't cover every abuse path — anything running as your user can in principle request decryption. The askpass script runs these checks on every invocation; any failure means no decryption:

- **Caller path allowlist.** Only decrypts when the caller's working directory is on an allowlist (home, `/tmp`, etc.). Blocks invocations from unexpected locations like `/var/tmp/malicious`.
- **Caller process allowlist.** Parent process must be on an allowlist (sudo, your shell, your IDE, your deploy tool). Keeps arbitrary binaries from invoking askpass directly.
- **User confirmation.** A GUI dialog asks for approval on each decryption, so any sudo elevation you didn't initiate is visible and can be denied.
- **Rate limiting.** Configurable max-attempts-per-hour and lockout window. Contains runaway scripts and brute-force attempts.
- **Password expiration.** Retrieval is refused after the configured age (default: 1 week), including keyring credentials. Expiration does not destroy stored data or revoke stolen copies; use `sudoplz rm-stored-password` to remove stored credentials.

Configure these in `~/.config/sudoplz/config.json` — an example is shipped as `askpass-config.json` in the repo; copy it and edit. Unknown settings, invalid types, and invalid ranges are rejected; malformed policy never silently falls back to defaults.

### Why age for Ed25519?

Ed25519 is a signing algorithm (EdDSA), not encryption. OpenSSL handles RSA encryption directly, but Ed25519 keys can't do asymmetric encryption at all. `age` was designed to work with SSH keys including Ed25519.

### SSH key unlocking

Passphrase-protected SSH keys are unlocked in memory using `cryptography[ssh]`.
Askpass requests the passphrase through a hidden GUI prompt, or a hidden terminal
prompt in headless sessions. The decrypted identity is piped to age; it is never
written to a temporary key file or placed in command arguments.

Unlocking is per invocation. When TOTP and the password use the same identity,
askpass prompts once during that invocation. There is no session-wide passphrase
cache and no ssh-agent requirement: [age does not support ssh-agent](https://github.com/FiloSottile/age#ssh-keys).
A fully non-interactive session cannot unlock a passphrase-protected key. Supplying
`TOTP` authorizes the request but does not unlock the SSH key.

## Commands

Manage stored credentials and inspect configuration:

```bash
sudoplz set                # Store password; default expiration is 1 week
sudoplz set-totp           # Store password with TOTP verification (headless)
sudoplz totp-setup         # Set up TOTP for headless sessions
sudoplz get                # Check if password exists
sudoplz rm-stored-password # Remove password
sudoplz test               # Test sudo integration
sudoplz config --show      # View validated policy
sudoplz audit              # Show recent askpass usage
```

## Headless/SSH usage with TOTP

For servers or SSH sessions without a display, authenticate with a time-based one-time password (TOTP).

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

On Linux without `DISPLAY`, askpass prompts for a TOTP code:

```bash
# Interactive — prompts for TOTP code
sudoplz command

# Non-interactive — pass TOTP via environment
TOTP="123456" sudoplz command
```

## Development checks

Install `age`, `ssh-keygen`, and `openssl`, then run:

```bash
uv run --group dev ruff check .
uv run --group dev mypy src
uv run python -m unittest discover -s tests -v
```

Tests use temporary SSH keys, dummy credentials, and an in-memory keyring.

## Releases

`.github/workflows/publish.yml` runs the checks on pull requests. Each
successful push to `main` publishes a release to PyPI and creates a tagged
GitHub release with the wheel and source distribution. Manual workflow
dispatch retries a release without another commit.

CI owns patch versions: it keeps an unpublished version from `pyproject.toml`,
otherwise it increments the latest PyPI patch version and commits
`pyproject.toml` and `uv.lock`. Use `uv version --bump minor` or
`uv version --bump major` for an intentional version change. Publishing uses
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) for
workflow `publish.yml`; GitHub stores no PyPI token.

## Credits

The idea — an SSH-key-encrypted sudo password served via `SUDO_ASKPASS`, gated by a confirmation dialog — is from [GlassOnTin/secure-askpass](https://github.com/GlassOnTin/secure-askpass). That project is dormant; `sudoplz` is a substantially rewritten and cleaned up fork. Thanks to [@GlassOnTin](https://github.com/GlassOnTin) for the original idea.

## License

MIT — see LICENSE.
