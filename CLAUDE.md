# sudoplz Project Guidelines

## Project Overview
sudoplz gives AI coding agents (Claude Code, Cursor, etc.) the ability to run `sudo` commands with case-by-case GUI approval. The sudo password is encrypted with the user's SSH key. The project ships two entry points:
- `askpass` - Invoked by `sudo -A` via `SUDO_ASKPASS`; performs security checks and prints the decrypted password on approval
- `sudoplz` - Management CLI (set/get/clear/test/audit, plus TOTP for headless sessions)

## Development Guidelines

1. **Tool Usage**:
   - Use `bash` commands directly for basic operations
   - For complex searches, use the `Task` tool
   - When making multiple bash calls, use `Batch` for parallel execution

2. **Code Style**:
   - Follow existing conventions in the askpass scripts
   - Keep scripts minimal and focused on single responsibilities
   - No unnecessary comments unless explicitly requested

3. **Testing**:
   - Test both `askpass` and `sudoplz` components
   - Verify SSH key encryption/decryption functionality
   - Ensure secure password handling

4. **Security**:
   - Never log or expose passwords in plain text
   - Verify SSH key permissions are properly restricted
   - Follow secure coding practices for password handling

5. **Commits**:
   - Only commit when explicitly requested
   - Follow existing commit style from git history