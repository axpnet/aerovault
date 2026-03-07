//! # AeroVault v2
//!
//! Military-grade encrypted vault format with defense-in-depth cryptography.
//!
//! AeroVault v2 provides a single-file encrypted container format designed for
//! maximum security while maintaining practical usability. It combines multiple
//! cryptographic primitives in a layered architecture that remains secure even
//! if individual algorithms are compromised.
//!
//! ## Cryptographic Stack
//!
//! | Layer | Algorithm | Purpose |
//! |-------|-----------|---------|
//! | KDF | Argon2id (128 MiB, t=4, p=4) | Password-based key derivation |
//! | Key Wrapping | AES-256-KW (RFC 3394) | Master key protection |
//! | Content Encryption | AES-256-GCM-SIV (RFC 8452) | Nonce misuse-resistant AEAD |
//! | Cascade Mode | ChaCha20-Poly1305 | Optional second encryption layer |
//! | Filename Encryption | AES-256-SIV | Deterministic authenticated encryption |
//! | Header Integrity | HMAC-SHA512 | Header tamper detection |
//! | Key Separation | HKDF-SHA256 | Domain separation for key purposes |
//!
//! ## Quick Start
//!
//! ```no_run
//! use aerovault::{Vault, CreateOptions, EncryptionMode};
//!
//! // Create a new vault
//! let opts = CreateOptions::new("my-vault.aerovault", "strong-password-here")
//!     .with_mode(EncryptionMode::Standard);
//! let vault = Vault::create(opts)?;
//!
//! // Add files
//! vault.add_files(&["document.pdf", "photo.jpg"])?;
//!
//! // Open existing vault
//! let vault = Vault::open("my-vault.aerovault", "strong-password-here")?;
//!
//! // List contents
//! for entry in vault.list()? {
//!     println!("{} ({} bytes)", entry.name, entry.size);
//! }
//!
//! // Extract a file
//! vault.extract("document.pdf", "/tmp/output/")?;
//! # Ok::<(), aerovault::Error>(())
//! ```
//!
//! ## File Format
//!
//! An `.aerovault` file consists of three sections:
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │          Header (512 bytes)      │
//! │  magic, version, flags, salt,    │
//! │  wrapped keys, chunk size, MAC   │
//! ├──────────────────────────────────┤
//! │     Manifest Length (4 bytes)    │
//! ├──────────────────────────────────┤
//! │   AES-SIV Encrypted Manifest    │
//! │  (JSON: entries, timestamps)    │
//! ├──────────────────────────────────┤
//! │       Encrypted Data Chunks     │
//! │  [len:4][encrypted_chunk:len]   │
//! │  [len:4][encrypted_chunk:len]   │
//! │            ...                  │
//! └──────────────────────────────────┘
//! ```
//!
//! See [`AEROVAULT-V2-SPEC.md`](https://github.com/axpnet/aerovault/blob/main/docs/AEROVAULT-V2-SPEC.md)
//! for the complete format specification.

pub(crate) mod constants;
pub(crate) mod crypto;
pub mod error;
pub mod format;
pub mod vault;

// Re-export primary API
pub use error::Error;
pub use format::{EncryptionMode, HeaderFlags, ManifestEntry, VaultHeader, VaultManifest};
pub use vault::{CompactResult, CreateOptions, EntryInfo, PeekInfo, Vault};

/// Result type alias for AeroVault operations.
pub type Result<T> = std::result::Result<T, Error>;
