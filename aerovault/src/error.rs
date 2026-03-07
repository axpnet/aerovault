//! Error types for AeroVault operations.
//!
//! All errors are organized by domain to aid debugging and programmatic handling.

use std::fmt;

/// Primary error type for all AeroVault operations.
#[derive(Debug)]
pub enum Error {
    /// Invalid or corrupted vault file format.
    Format(FormatError),
    /// Cryptographic operation failure (wrong password, tampered data, etc.).
    Crypto(CryptoError),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// Manifest parsing or validation error.
    Manifest(String),
    /// Entry not found in vault.
    EntryNotFound(String),
    /// Password policy violation.
    PasswordPolicy(String),
    /// Path validation failure (traversal, invalid characters, etc.).
    InvalidPath(String),
}

/// Errors related to the binary vault format.
#[derive(Debug)]
pub enum FormatError {
    /// File is too small to contain a valid header.
    TooSmall { actual: usize, expected: usize },
    /// Magic bytes do not match `AEROVAULT2`.
    InvalidMagic,
    /// Unsupported format version.
    UnsupportedVersion(u8),
    /// Manifest length exceeds `MAX_MANIFEST_SIZE`.
    ManifestTooLarge(usize),
    /// Manifest data is truncated.
    ManifestTruncated,
    /// Invalid chunk size in header.
    InvalidChunkSize(u32),
}

/// Errors from cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// Argon2id key derivation failed.
    KeyDerivation(String),
    /// AES-KW key unwrapping failed (wrong password).
    KeyUnwrap,
    /// HMAC-SHA512 header verification failed (tampered header).
    HeaderMacMismatch,
    /// AES-GCM-SIV chunk encryption failed.
    ChunkEncrypt { chunk_index: u32 },
    /// AES-GCM-SIV chunk decryption failed.
    ChunkDecrypt { chunk_index: u32 },
    /// AES-SIV encryption/decryption failed.
    SivOperation(String),
    /// ChaCha20-Poly1305 cascade encryption failed.
    CascadeEncrypt { chunk_index: u32 },
    /// ChaCha20-Poly1305 cascade decryption failed.
    CascadeDecrypt { chunk_index: u32 },
    /// Manifest encoding is not valid UTF-8.
    ManifestEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format(e) => write!(f, "format error: {e}"),
            Error::Crypto(e) => write!(f, "crypto error: {e}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Manifest(msg) => write!(f, "manifest error: {msg}"),
            Error::EntryNotFound(name) => write!(f, "entry not found: {name}"),
            Error::PasswordPolicy(msg) => write!(f, "password policy: {msg}"),
            Error::InvalidPath(msg) => write!(f, "invalid path: {msg}"),
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::TooSmall { actual, expected } => {
                write!(f, "file too small ({actual} bytes, need {expected})")
            }
            FormatError::InvalidMagic => write!(f, "invalid magic bytes (not an AeroVault v2 file)"),
            FormatError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            FormatError::ManifestTooLarge(size) => {
                write!(f, "manifest too large ({size} bytes, max 64 MiB)")
            }
            FormatError::ManifestTruncated => write!(f, "manifest data truncated"),
            FormatError::InvalidChunkSize(size) => {
                write!(f, "invalid chunk size {size} (must be 4 KiB - 16 MiB)")
            }
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyDerivation(msg) => write!(f, "key derivation failed: {msg}"),
            CryptoError::KeyUnwrap => write!(f, "key unwrap failed (wrong password?)"),
            CryptoError::HeaderMacMismatch => write!(f, "header MAC mismatch (tampered or wrong password)"),
            CryptoError::ChunkEncrypt { chunk_index } => {
                write!(f, "chunk {chunk_index} encryption failed")
            }
            CryptoError::ChunkDecrypt { chunk_index } => {
                write!(f, "chunk {chunk_index} decryption failed")
            }
            CryptoError::SivOperation(msg) => write!(f, "AES-SIV operation failed: {msg}"),
            CryptoError::CascadeEncrypt { chunk_index } => {
                write!(f, "cascade encryption failed at chunk {chunk_index}")
            }
            CryptoError::CascadeDecrypt { chunk_index } => {
                write!(f, "cascade decryption failed at chunk {chunk_index}")
            }
            CryptoError::ManifestEncoding => write!(f, "manifest is not valid UTF-8"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Format(e) => Some(e),
            Error::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl std::error::Error for FormatError {}
impl std::error::Error for CryptoError {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        Error::Format(e)
    }
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        Error::Crypto(e)
    }
}
