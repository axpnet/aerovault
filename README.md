# AeroVault

[![Crates.io](https://img.shields.io/crates/v/aerovault)](https://crates.io/crates/aerovault)
[![docs.rs](https://docs.rs/aerovault/badge.svg)](https://docs.rs/aerovault)
[![License: GPL-3.0](https://img.shields.io/crates/l/aerovault)](LICENSE)

Military-grade encrypted vault format for single-file encrypted containers.

AeroVault v2 combines **AES-256-GCM-SIV** (nonce misuse-resistant), **Argon2id** (128 MiB), **AES-256-KW** key wrapping, and optional **ChaCha20-Poly1305** cascade encryption into a portable `.aerovault` file format.

## Cryptographic Stack

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| KDF | Argon2id (128 MiB, t=4, p=4) | RFC 9106 |
| Key Wrapping | AES-256-KW | RFC 3394 |
| Content Encryption | AES-256-GCM-SIV | RFC 8452 |
| Cascade Mode | ChaCha20-Poly1305 | RFC 8439 |
| Filename Encryption | AES-256-SIV | RFC 5297 |
| Header Integrity | HMAC-SHA512 | RFC 2104 |
| Key Separation | HKDF-SHA256 | RFC 5869 |

## Installation

### From source

```bash
cargo install --path aerovault-cli
```

### From crates.io

```bash
cargo add aerovault
```

## CLI Usage

```bash
# Create a new vault
aerovault create my-vault.aerovault

# Create with cascade encryption (AES-GCM-SIV + ChaCha20-Poly1305)
aerovault create my-vault.aerovault --cascade

# Add files
aerovault add my-vault.aerovault file1.pdf file2.jpg

# Add files to a directory
aerovault add my-vault.aerovault document.pdf --dir docs/reports

# List contents
aerovault list my-vault.aerovault -H

# Extract a specific file
aerovault extract my-vault.aerovault -e document.pdf -o /tmp/output/

# Extract all
aerovault extract my-vault.aerovault -o /tmp/output/

# Create directories
aerovault mkdir my-vault.aerovault docs/reports

# Delete an entry
aerovault rm my-vault.aerovault document.pdf

# Show security info
aerovault info my-vault.aerovault

# Change password
aerovault passwd my-vault.aerovault

# Check if file is an AeroVault
aerovault check suspicious-file.bin
```

## Library Usage

```rust
use aerovault::{Vault, CreateOptions, EncryptionMode};

// Create a new vault
let opts = CreateOptions::new("secure.aerovault", "strong-password")
    .with_mode(EncryptionMode::Cascade);
let vault = Vault::create(opts)?;

// Add files
vault.add_files(&["secret.pdf", "keys.txt"])?;

// Open and list
let vault = Vault::open("secure.aerovault", "strong-password")?;
for entry in vault.list()? {
    println!("{} ({} bytes)", entry.name, entry.size);
}

// Extract
vault.extract("secret.pdf", "/tmp/")?;
```

## Format Specification

See [docs/AEROVAULT-V2-SPEC.md](docs/AEROVAULT-V2-SPEC.md) for the complete binary format specification.

## vs Cryptomator

| | AeroVault v2 | Cryptomator v8 |
|---|---|---|
| KDF | Argon2id (128 MiB) | scrypt (64 MiB) |
| Content cipher | AES-256-GCM-SIV | AES-256-GCM |
| Nonce misuse resistance | Yes | No |
| Cascade mode | Optional | No |
| Storage | Single file | Directory tree |
| Implementation | Rust | Java |

## Security

- All key material is zeroized after use
- Constant-time MAC comparison prevents timing attacks
- Chunk index AAD prevents reordering attacks
- Atomic writes prevent corruption on crash
- 128 MiB Argon2id makes GPU brute-force impractical

## License

GPL-3.0 -- See [LICENSE](LICENSE) for details.

## Origin

AeroVault v2 was originally developed as the encryption engine for [AeroFTP](https://github.com/axpnet/aeroftp), a professional FTP/SFTP/cloud client. This standalone crate makes the format available for any Rust project.
