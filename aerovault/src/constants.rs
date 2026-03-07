//! Vault format constants and cryptographic parameters.
//!
//! All constants are derived from the AeroVault v2 specification.
//! Changing these values will produce incompatible vault files.

/// Magic bytes identifying an AeroVault v2 file.
pub const MAGIC: &[u8; 10] = b"AEROVAULT2";

/// Current format version.
pub const VERSION: u8 = 2;

/// Total header size in bytes.
pub const HEADER_SIZE: usize = 512;

/// Default plaintext chunk size (64 KiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

/// AES-GCM-SIV nonce size in bytes.
pub const NONCE_SIZE: usize = 12;

/// AES-GCM-SIV authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Master key and MAC key size in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Argon2id salt size in bytes (256-bit).
pub const SALT_SIZE: usize = 32;

/// AES-256-KW wrapped key size (32-byte key + 8-byte integrity check).
pub const WRAPPED_KEY_SIZE: usize = 40;

/// HMAC-SHA512 output size in bytes.
pub const MAC_SIZE: usize = 64;

/// Maximum manifest size to prevent denial-of-service (64 MiB).
pub const MAX_MANIFEST_SIZE: usize = 64 * 1024 * 1024;

/// Minimum password length enforced at the API level.
pub const MIN_PASSWORD_LENGTH: usize = 8;

// --- Argon2id Parameters ---
// These exceed OWASP 2024 recommendations (64 MiB / t=3 / p=1).

/// Argon2id memory cost in KiB (128 MiB).
pub const ARGON2_M_COST: u32 = 128 * 1024;

/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 4;

/// Argon2id parallelism degree.
pub const ARGON2_P_COST: u32 = 4;

// --- HKDF Domain Separation Labels ---

/// HKDF info label for the master KEK derivation.
pub const HKDF_LABEL_MASTER: &[u8] = b"AeroVault v2 KEK for master key";

/// HKDF info label for the MAC KEK derivation.
pub const HKDF_LABEL_MAC: &[u8] = b"AeroVault v2 KEK for MAC key";

/// HKDF info label for the ChaCha20-Poly1305 cascade key.
pub const HKDF_LABEL_CHACHA: &[u8] = b"AeroVault v2 ChaCha20-Poly1305 cascade";

/// HKDF info label for the AES-SIV filename encryption key.
pub const HKDF_LABEL_SIV: &[u8] = b"AeroVault v2 AES-SIV filename encryption";
