//! Binary format definitions for the AeroVault v2 container.
//!
//! This module defines the on-disk structures: the 512-byte header, the encrypted
//! manifest, and the manifest entry format. All multi-byte integers are little-endian.

use serde::{Deserialize, Serialize};

use crate::constants::*;
use crate::error::{CryptoError, FormatError};

/// Encryption mode for vault content chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMode {
    /// AES-256-GCM-SIV only (RFC 8452). Nonce misuse-resistant.
    Standard,
    /// AES-256-GCM-SIV + ChaCha20-Poly1305 double encryption.
    /// Defense-in-depth: data remains secure even if one cipher is broken.
    Cascade,
}

/// Flags stored in the vault header (byte offset 11).
#[derive(Debug, Clone, Copy)]
pub struct HeaderFlags {
    /// Whether cascade encryption (GCM-SIV + ChaCha20-Poly1305) is enabled.
    pub cascade_mode: bool,
}

impl HeaderFlags {
    /// Encode flags into a single byte.
    pub fn to_byte(self) -> u8 {
        let mut flags = 0u8;
        if self.cascade_mode {
            flags |= 0x01;
        }
        flags
    }

    /// Decode flags from a single byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            cascade_mode: byte & 0x01 != 0,
        }
    }
}

/// The 512-byte vault header.
///
/// ## Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0 | 10 | Magic (`AEROVAULT2`) |
/// | 10 | 1 | Version (2) |
/// | 11 | 1 | Flags (bit 0 = cascade) |
/// | 12 | 32 | Argon2id salt |
/// | 44 | 40 | AES-KW wrapped master key |
/// | 84 | 40 | AES-KW wrapped MAC key |
/// | 124 | 4 | Chunk size (LE u32) |
/// | 128 | 320 | Reserved (zero-filled) |
/// | 448 | 64 | HMAC-SHA512 over all 512 bytes (MAC field zeroed) |
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// Magic bytes: `AEROVAULT2`.
    pub magic: [u8; 10],
    /// Format version (currently 2).
    pub version: u8,
    /// Header flags.
    pub flags: HeaderFlags,
    /// Argon2id salt for password derivation.
    pub salt: [u8; SALT_SIZE],
    /// Master key wrapped with AES-256-KW.
    pub wrapped_master_key: [u8; WRAPPED_KEY_SIZE],
    /// MAC key wrapped with AES-256-KW.
    pub wrapped_mac_key: [u8; WRAPPED_KEY_SIZE],
    /// Plaintext chunk size in bytes.
    pub chunk_size: u32,
    /// HMAC-SHA512 of header bytes 0..128.
    pub header_mac: [u8; MAC_SIZE],
}

impl VaultHeader {
    /// Serialize the header to a 512-byte array.
    ///
    /// MAC is stored at bytes 448..512 (end of header), matching AeroFTP format.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];

        buf[0..10].copy_from_slice(&self.magic);
        buf[10] = self.version;
        buf[11] = self.flags.to_byte();
        buf[12..44].copy_from_slice(&self.salt);
        buf[44..84].copy_from_slice(&self.wrapped_master_key);
        buf[84..124].copy_from_slice(&self.wrapped_mac_key);
        buf[124..128].copy_from_slice(&self.chunk_size.to_le_bytes());
        // bytes 128..448 remain zero (reserved)
        buf[HEADER_SIZE - MAC_SIZE..].copy_from_slice(&self.header_mac);

        buf
    }

    /// Deserialize a header from a 512-byte slice.
    ///
    /// Validates magic bytes and version number.
    /// MAC is read from bytes 448..512 (end of header).
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(FormatError::TooSmall {
                actual: data.len(),
                expected: HEADER_SIZE,
            }
            .into());
        }

        let mut magic = [0u8; 10];
        magic.copy_from_slice(&data[0..10]);
        if &magic != MAGIC {
            return Err(FormatError::InvalidMagic.into());
        }

        let version = data[10];
        if version != VERSION {
            return Err(FormatError::UnsupportedVersion(version).into());
        }

        let flags = HeaderFlags::from_byte(data[11]);

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[12..44]);

        let mut wrapped_master_key = [0u8; WRAPPED_KEY_SIZE];
        wrapped_master_key.copy_from_slice(&data[44..84]);

        let mut wrapped_mac_key = [0u8; WRAPPED_KEY_SIZE];
        wrapped_mac_key.copy_from_slice(&data[84..124]);

        let chunk_size = u32::from_le_bytes([data[124], data[125], data[126], data[127]]);

        let mut header_mac = [0u8; MAC_SIZE];
        header_mac.copy_from_slice(&data[HEADER_SIZE - MAC_SIZE..]);

        Ok(Self {
            magic,
            version,
            flags,
            salt,
            wrapped_master_key,
            wrapped_mac_key,
            chunk_size,
            header_mac,
        })
    }

    /// Compute HMAC-SHA512 over the entire 512-byte header with MAC field zeroed.
    ///
    /// This matches the original AeroFTP format: HMAC is computed over all 512
    /// bytes with bytes 448..512 (the MAC field itself) set to zero.
    pub fn compute_mac(&self, mac_key: &[u8]) -> [u8; MAC_SIZE] {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let mut header_bytes = self.to_bytes();
        // Zero out the MAC field before computing
        header_bytes[HEADER_SIZE - MAC_SIZE..].fill(0);

        let mut hmac = Hmac::<Sha512>::new_from_slice(mac_key)
            .expect("HMAC key length is always valid for SHA-512");
        hmac.update(&header_bytes);
        let result = hmac.finalize();

        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(&result.into_bytes());
        mac
    }

    /// Verify the header MAC using constant-time comparison.
    pub fn verify_mac(&self, mac_key: &[u8]) -> crate::Result<()> {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let mut header_bytes = self.to_bytes();
        // Zero out the MAC field before computing
        header_bytes[HEADER_SIZE - MAC_SIZE..].fill(0);

        let mut hmac = Hmac::<Sha512>::new_from_slice(mac_key)
            .expect("HMAC key length is always valid for SHA-512");
        hmac.update(&header_bytes);

        // Constant-time comparison via the hmac crate
        hmac.verify_slice(&self.header_mac)
            .map_err(|_| CryptoError::HeaderMacMismatch)?;
        Ok(())
    }
}

/// A single entry in the vault manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// AES-SIV encrypted filename (base64-encoded ciphertext).
    pub encrypted_name: String,

    /// Plaintext name — populated only after decryption, empty on disk.
    #[serde(default, skip_serializing)]
    pub name: String,

    /// Original file size in bytes (0 for directories).
    pub size: u64,

    /// Byte offset of this entry's first chunk in the data section.
    pub offset: u64,

    /// Number of encrypted chunks.
    pub chunk_count: u32,

    /// `true` for directory entries (manifest-only, no data section).
    #[serde(default)]
    pub is_dir: bool,

    /// Last modification timestamp (ISO 8601).
    pub modified: String,
}

/// The vault manifest, stored as AES-SIV encrypted JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    /// Vault creation timestamp (ISO 8601).
    pub created: String,
    /// Last modification timestamp (ISO 8601).
    pub modified: String,
    /// Optional description (backward compatibility with AeroFTP vaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// List of encrypted entries.
    pub entries: Vec<ManifestEntry>,
}
