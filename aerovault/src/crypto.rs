//! Cryptographic operations for AeroVault v2.
//!
//! This module implements the full key derivation chain, chunk encryption/decryption,
//! and filename encryption using AES-SIV.
//!
//! ## Key Derivation Chain
//!
//! ```text
//! password
//!     │
//!     ▼ Argon2id (128 MiB, t=4, p=4)
//! base_kek (32 bytes)
//!     │
//!     ├─► HKDF-SHA256(info="aerovault-kek-master") → kek_master
//!     │       │
//!     │       ▼ AES-256-KW unwrap
//!     │   master_key (32 bytes)
//!     │       │
//!     │       ├─► HKDF-SHA256(info="aerovault-siv") → siv_key (for filenames)
//!     │       └─► HKDF-SHA256(info="aerovault-chacha") → chacha_key (cascade only)
//!     │
//!     └─► HKDF-SHA256(info="aerovault-kek-mac") → kek_mac
//!             │
//!             ▼ AES-256-KW unwrap
//!         mac_key (32 bytes) → HMAC-SHA512 header verification
//! ```

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use aes_kw::Kek;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::constants::*;
use crate::error::CryptoError;

/// Derive a 32-byte base KEK from a password and salt using Argon2id.
///
/// Parameters: 128 MiB memory, 4 iterations, 4 parallelism threads.
/// This exceeds OWASP 2024 recommendations.
pub(crate) fn derive_key(password: &SecretString, salt: &[u8; SALT_SIZE]) -> crate::Result<SecretVec<u8>> {
    use argon2::Argon2;

    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(SecretVec::new(key))
}

/// Derive separate KEK pair from the base KEK using HKDF-SHA256.
///
/// Returns `(kek_master, kek_mac)` — two independent 32-byte keys for
/// wrapping the master key and the MAC key respectively.
/// Both keys are auto-zeroized when dropped.
pub(crate) fn derive_kek_pair(base_kek: &[u8]) -> (Zeroizing<[u8; KEY_SIZE]>, Zeroizing<[u8; KEY_SIZE]>) {
    let hkdf = Hkdf::<Sha256>::new(None, base_kek);

    let mut kek_master = Zeroizing::new([0u8; KEY_SIZE]);
    hkdf.expand(HKDF_LABEL_MASTER, kek_master.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    let mut kek_mac = Zeroizing::new([0u8; KEY_SIZE]);
    hkdf.expand(HKDF_LABEL_MAC, kek_mac.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    (kek_master, kek_mac)
}

/// Wrap a 32-byte key using AES-256-KW (RFC 3394).
///
/// Returns a 40-byte wrapped key (32 bytes + 8-byte integrity check value).
pub(crate) fn wrap_key(
    kek: &[u8; KEY_SIZE],
    key_to_wrap: &[u8],
) -> crate::Result<[u8; WRAPPED_KEY_SIZE]> {
    let kek = Kek::from(*kek);
    let mut output = [0u8; WRAPPED_KEY_SIZE];
    kek.wrap(key_to_wrap, &mut output)
        .map_err(|_| CryptoError::KeyUnwrap)?;
    Ok(output)
}

/// Unwrap a 40-byte wrapped key using AES-256-KW (RFC 3394).
///
/// Returns the original 32-byte key. Fails if the password is wrong
/// (integrity check value mismatch).
pub(crate) fn unwrap_key(
    kek: &[u8; KEY_SIZE],
    wrapped: &[u8; WRAPPED_KEY_SIZE],
) -> crate::Result<SecretVec<u8>> {
    let kek = Kek::from(*kek);
    let mut output = [0u8; KEY_SIZE];
    match kek.unwrap(wrapped, &mut output) {
        Ok(_) => {
            let result = SecretVec::new(output.to_vec());
            output.zeroize();
            Ok(result)
        }
        Err(_) => {
            output.zeroize();
            Err(CryptoError::KeyUnwrap.into())
        }
    }
}

/// Derive the AES-SIV key for filename encryption from the master key.
pub(crate) fn derive_siv_key(master_key: &[u8]) -> Zeroizing<[u8; 64]> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut siv_key = Zeroizing::new([0u8; 64]);
    hkdf.expand(HKDF_LABEL_SIV, siv_key.as_mut())
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    siv_key
}

/// Derive the ChaCha20-Poly1305 key for cascade mode from the master key.
pub(crate) fn derive_chacha_key(master_key: &[u8]) -> Zeroizing<[u8; KEY_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut chacha_key = Zeroizing::new([0u8; KEY_SIZE]);
    hkdf.expand(HKDF_LABEL_CHACHA, chacha_key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    chacha_key
}

/// Encrypt a filename (or manifest JSON) using AES-256-SIV.
///
/// Returns a hex-encoded ciphertext string. AES-SIV is deterministic:
/// the same plaintext always produces the same ciphertext, enabling
/// efficient duplicate detection without decrypting all entries.
pub(crate) fn encrypt_filename(master_key: &[u8], plaintext: &str) -> crate::Result<String> {
    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit as SivKeyInit;

    let siv_key = derive_siv_key(master_key);
    let mut cipher = Aes256Siv::new_from_slice(siv_key.as_ref())
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let ciphertext = cipher
        .encrypt([&[]], plaintext.as_bytes())
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    Ok(hex::encode(&ciphertext))
}

/// Decrypt a filename (or manifest JSON) from hex-encoded AES-256-SIV ciphertext.
pub(crate) fn decrypt_filename(master_key: &[u8], hex_ciphertext: &str) -> crate::Result<String> {
    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit as SivKeyInit;

    let siv_key = derive_siv_key(master_key);
    let mut cipher = Aes256Siv::new_from_slice(siv_key.as_ref())
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let ciphertext =
        hex::decode(hex_ciphertext).map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let plaintext = cipher
        .decrypt([&[]], &ciphertext)
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| CryptoError::SivOperation(e.to_string()).into())
}

/// Encrypt a plaintext chunk using AES-256-GCM-SIV (RFC 8452).
///
/// The chunk index is used as additional authenticated data (AAD) to bind
/// each chunk to its position, preventing reordering attacks.
///
/// A random 12-byte nonce is prepended to the ciphertext.
pub(crate) fn encrypt_chunk(
    master_key: &[u8],
    plaintext: &[u8],
    chunk_index: u32,
) -> crate::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(master_key)
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = chunk_index.to_le_bytes();

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm_siv::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::ChunkEncrypt {
            chunk_index,
        })?;

    // nonce || ciphertext || tag (tag is appended by the AEAD)
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a chunk encrypted with AES-256-GCM-SIV.
///
/// Input format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub(crate) fn decrypt_chunk(
    master_key: &[u8],
    encrypted: &[u8],
    chunk_index: u32,
) -> crate::Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::ChunkDecrypt { chunk_index }.into());
    }

    let cipher = Aes256GcmSiv::new_from_slice(master_key)
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];
    let aad = chunk_index.to_le_bytes();

    cipher
        .decrypt(
            nonce,
            aes_gcm_siv::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::ChunkDecrypt { chunk_index }.into())
}

/// Encrypt a chunk with cascade mode: AES-256-GCM-SIV then ChaCha20-Poly1305.
///
/// This provides defense-in-depth: data remains confidential even if one of the
/// two algorithms is compromised.
pub(crate) fn encrypt_chunk_cascade(
    master_key: &[u8],
    chacha_key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    chunk_index: u32,
) -> crate::Result<Vec<u8>> {
    // First layer: AES-256-GCM-SIV
    let inner = encrypt_chunk(master_key, plaintext, chunk_index)?;

    // Second layer: ChaCha20-Poly1305
    let chacha = ChaCha20Poly1305::new_from_slice(chacha_key)
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let aad = chunk_index.to_le_bytes();
    let outer = chacha
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::CascadeEncrypt { chunk_index })?;

    let mut output = Vec::with_capacity(NONCE_SIZE + outer.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&outer);
    Ok(output)
}

/// Decrypt a cascade-encrypted chunk: ChaCha20-Poly1305 then AES-256-GCM-SIV.
pub(crate) fn decrypt_chunk_cascade(
    master_key: &[u8],
    chacha_key: &[u8; KEY_SIZE],
    encrypted: &[u8],
    chunk_index: u32,
) -> crate::Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::CascadeDecrypt { chunk_index }.into());
    }

    // Peel outer layer: ChaCha20-Poly1305
    let chacha = ChaCha20Poly1305::new_from_slice(chacha_key)
        .map_err(|e| CryptoError::SivOperation(e.to_string()))?;

    let nonce = chacha20poly1305::Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];
    let aad = chunk_index.to_le_bytes();

    let inner = chacha
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::CascadeDecrypt { chunk_index })?;

    // Peel inner layer: AES-256-GCM-SIV
    decrypt_chunk(master_key, &inner, chunk_index)
}

/// Validate that a manifest length is within bounds.
pub(crate) fn validate_manifest_len(len: usize) -> crate::Result<()> {
    if len > MAX_MANIFEST_SIZE {
        return Err(crate::error::FormatError::ManifestTooLarge(len).into());
    }
    Ok(())
}

/// Read the manifest length and encrypted manifest from a reader.
///
/// Returns `(manifest_len, encrypted_bytes)`. Validates the length against
/// `MAX_MANIFEST_SIZE` to prevent denial-of-service via crafted headers.
pub(crate) fn read_manifest_bounded(
    reader: &mut impl std::io::Read,
) -> crate::Result<(usize, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let manifest_len = u32::from_le_bytes(len_buf) as usize;

    validate_manifest_len(manifest_len)?;

    let mut manifest = vec![0u8; manifest_len];
    reader.read_exact(&mut manifest)?;

    Ok((manifest_len, manifest))
}

// Private hex encode/decode to avoid an external dependency
mod hex {
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for byte in data {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_kek_pair_deterministic() {
        let base = [42u8; 32];
        let (kek1_a, kek1_b) = derive_kek_pair(&base);
        let (kek2_a, kek2_b) = derive_kek_pair(&base);
        assert_eq!(*kek1_a, *kek2_a);
        assert_eq!(*kek1_b, *kek2_b);
        assert_ne!(*kek1_a, *kek1_b); // master and mac keys are different
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let kek = [1u8; KEY_SIZE];
        let key = [2u8; KEY_SIZE];
        let wrapped = wrap_key(&kek, &key).unwrap();
        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped.expose_secret().as_slice(), &key);
    }

    #[test]
    fn test_wrap_unwrap_wrong_kek() {
        let kek = [1u8; KEY_SIZE];
        let key = [2u8; KEY_SIZE];
        let wrapped = wrap_key(&kek, &key).unwrap();
        let wrong_kek = [3u8; KEY_SIZE];
        assert!(unwrap_key(&wrong_kek, &wrapped).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_filename() {
        let master_key = [7u8; KEY_SIZE];
        let encrypted = encrypt_filename(&master_key, "test.txt").unwrap();
        let decrypted = decrypt_filename(&master_key, &encrypted).unwrap();
        assert_eq!(decrypted, "test.txt");
    }

    #[test]
    fn test_siv_deterministic() {
        let master_key = [7u8; KEY_SIZE];
        let a = encrypt_filename(&master_key, "same.txt").unwrap();
        let b = encrypt_filename(&master_key, "same.txt").unwrap();
        assert_eq!(a, b); // AES-SIV is deterministic
    }

    #[test]
    fn test_encrypt_decrypt_chunk() {
        let key = [5u8; KEY_SIZE];
        let plaintext = b"Hello, AeroVault!";
        let encrypted = encrypt_chunk(&key, plaintext, 0).unwrap();
        let decrypted = decrypt_chunk(&key, &encrypted, 0).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_chunk_wrong_index_fails() {
        let key = [5u8; KEY_SIZE];
        let plaintext = b"data";
        let encrypted = encrypt_chunk(&key, plaintext, 0).unwrap();
        // Decrypting with wrong chunk index must fail (AAD mismatch)
        assert!(decrypt_chunk(&key, &encrypted, 1).is_err());
    }

    #[test]
    fn test_cascade_roundtrip() {
        let master = [8u8; KEY_SIZE];
        let chacha = derive_chacha_key(&master);
        let plaintext = b"cascade test data";
        let encrypted = encrypt_chunk_cascade(&master, &chacha, plaintext, 3).unwrap();
        let decrypted = decrypt_chunk_cascade(&master, &chacha, &encrypted, 3).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_cascade_wrong_index_fails() {
        let master = [8u8; KEY_SIZE];
        let chacha = derive_chacha_key(&master);
        let plaintext = b"data";
        let encrypted = encrypt_chunk_cascade(&master, &chacha, plaintext, 0).unwrap();
        assert!(decrypt_chunk_cascade(&master, &chacha, &encrypted, 1).is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0x00, 0xff, 0xab, 0x12];
        let encoded = hex::encode(&data);
        assert_eq!(encoded, "00ffab12");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_validate_manifest_len() {
        assert!(validate_manifest_len(1024).is_ok());
        assert!(validate_manifest_len(MAX_MANIFEST_SIZE).is_ok());
        assert!(validate_manifest_len(MAX_MANIFEST_SIZE + 1).is_err());
    }
}
