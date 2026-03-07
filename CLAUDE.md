# AeroVault Development Guidelines

## Language

Always respond in **Italian** (italiano). Code, commit messages, and documentation remain in English.

## Architecture

- **Workspace**: `aerovault/` (library crate) + `aerovault-cli/` (binary crate)
- **Modules**: `constants.rs`, `crypto.rs`, `error.rs`, `format.rs`, `vault.rs`
- **No unsafe code**. No external runtime dependencies beyond crypto crates.

## Commit Message Standards

Follow **Conventional Commits** (same as AeroFTP):

```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
No emojis. Lowercase. Imperative mood.

## Code Style

- `rustfmt` defaults
- `clippy` clean (`-D warnings`)
- Document all public APIs with `///`
- Use `SecretVec`/`SecretString` for key material
- Zeroize all sensitive buffers when done

## Testing

```bash
cargo test           # All tests
cargo clippy         # Lint
cargo doc --no-deps  # Documentation
```

## Security Rules

- Never log or print key material
- Always use constant-time comparison for MAC verification
- Always use OsRng (not thread_rng) for cryptographic randomness
- Validate manifest length before allocation (DoS prevention)
- Validate paths: reject `..`, absolute paths, null bytes
- Atomic writes (temp + rename) for all mutations

## Format Specification

See `docs/AEROVAULT-V2-SPEC.md` for the complete binary format.
