//! High-level vault operations.
//!
//! This module provides the public API for creating, opening, and manipulating
//! AeroVault v2 containers. All mutations use atomic writes (temp + fsync + rename)
//! to prevent data corruption on crash or power loss.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use zeroize::Zeroize;

use crate::constants::*;
use crate::crypto;
use crate::error::{CryptoError, FormatError};
use crate::format::*;

/// Minimum allowed chunk size (4 KiB).
const MIN_CHUNK_SIZE: u32 = 4 * 1024;

/// Maximum allowed chunk size (16 MiB).
const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Options for creating a new vault.
pub struct CreateOptions {
    path: PathBuf,
    password: SecretString,
    mode: EncryptionMode,
    chunk_size: u32,
}

impl CreateOptions {
    /// Create new vault options with the given path and password.
    pub fn new(path: impl Into<PathBuf>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: SecretString::from(password.into()),
            mode: EncryptionMode::Standard,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Set the encryption mode.
    pub fn with_mode(mut self, mode: EncryptionMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set a custom chunk size.
    ///
    /// Must be between 4 KiB and 16 MiB. Returns an error at vault creation
    /// if the value is out of range.
    pub fn with_chunk_size(mut self, size: u32) -> Self {
        self.chunk_size = size;
        self
    }
}

/// Decrypted entry information returned by listing operations.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// Decrypted filename (may contain `/` for nested paths).
    pub name: String,
    /// Original file size in bytes.
    pub size: u64,
    /// Whether this is a directory entry.
    pub is_dir: bool,
    /// Last modification timestamp (ISO 8601).
    pub modified: String,
}

/// An unlocked AeroVault v2 container.
///
/// Created via [`Vault::create`] or [`Vault::open`]. Holds decrypted keys
/// in memory — drop the vault when done to zeroize secrets.
pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
    master_key: SecretVec<u8>,
    mac_key: SecretVec<u8>,
}

impl Vault {
    /// Create a new empty vault at the specified path.
    ///
    /// # Errors
    ///
    /// Returns an error if the password is too short (< 8 chars), the chunk
    /// size is out of range, or the file cannot be written.
    pub fn create(opts: CreateOptions) -> crate::Result<Self> {
        if opts.password.expose_secret().len() < MIN_PASSWORD_LENGTH {
            return Err(crate::Error::PasswordPolicy(format!(
                "password must be at least {MIN_PASSWORD_LENGTH} characters"
            )));
        }

        if opts.chunk_size < MIN_CHUNK_SIZE || opts.chunk_size > MAX_CHUNK_SIZE {
            return Err(FormatError::InvalidChunkSize(opts.chunk_size).into());
        }

        // Generate random salt
        let mut salt = [0u8; SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // Derive base KEK from password
        let base_kek = crypto::derive_key(&opts.password, &salt)?;
        let (kek_master, kek_mac) = crypto::derive_kek_pair(base_kek.expose_secret());

        // Generate random master and MAC keys
        let mut master_key_raw = [0u8; KEY_SIZE];
        let mut mac_key_raw = [0u8; KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut master_key_raw);
        rand::rngs::OsRng.fill_bytes(&mut mac_key_raw);

        // Wrap keys
        let wrapped_master = crypto::wrap_key(&kek_master, &master_key_raw)?;
        let wrapped_mac = crypto::wrap_key(&kek_mac, &mac_key_raw)?;

        // kek_master and kek_mac are Zeroizing — auto-dropped

        // Build header
        let flags = HeaderFlags {
            cascade_mode: opts.mode == EncryptionMode::Cascade,
        };

        let mut header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            flags,
            salt,
            wrapped_master_key: wrapped_master,
            wrapped_mac_key: wrapped_mac,
            chunk_size: opts.chunk_size,
            header_mac: [0u8; MAC_SIZE],
        };
        header.header_mac = header.compute_mac(&mac_key_raw);

        // Create empty manifest
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let manifest = VaultManifest {
            created: now.clone(),
            modified: now,
            entries: Vec::new(),
        };

        let manifest_json =
            serde_json::to_string(&manifest).map_err(|e| crate::Error::Manifest(e.to_string()))?;
        let encrypted_manifest = crypto::encrypt_filename(&master_key_raw, &manifest_json)?;
        let manifest_bytes = encrypted_manifest.as_bytes();

        // Write vault file atomically via temp + fsync + rename
        let tmp_path = format!("{}.create.tmp", opts.path.display());
        let file = File::create(&tmp_path)?;
        let mut writer = BufWriter::new(file);

        writer.write_all(&header.to_bytes())?;
        writer.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(manifest_bytes)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);

        // If target already exists, use safe rename; otherwise just rename
        if opts.path.exists() {
            atomic_rename(&tmp_path, &opts.path)?;
        } else {
            std::fs::rename(&tmp_path, &opts.path)?;
        }

        let master_key = SecretVec::new(master_key_raw.to_vec());
        let mac_key = SecretVec::new(mac_key_raw.to_vec());

        master_key_raw.zeroize();
        mac_key_raw.zeroize();

        Ok(Self {
            path: opts.path,
            header,
            master_key,
            mac_key,
        })
    }

    /// Open an existing vault with the given password.
    ///
    /// Verifies the header MAC before unwrapping the master key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyUnwrap`] if the password is wrong, or
    /// [`CryptoError::HeaderMacMismatch`] if the header has been tampered with.
    pub fn open(path: impl Into<PathBuf>, password: impl Into<String>) -> crate::Result<Self> {
        let path = path.into();
        let pwd = SecretString::from(password.into());

        let file = File::open(&path)?;
        let mut reader = BufReader::new(file);

        // Read header
        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;
        let header = VaultHeader::from_bytes(&header_buf)?;

        // Derive keys
        let base_kek = crypto::derive_key(&pwd, &header.salt)?;
        let (kek_master, kek_mac) = crypto::derive_kek_pair(base_kek.expose_secret());

        // Unwrap MAC key first, verify header MAC, then unwrap master key
        let mac_key = crypto::unwrap_key(&kek_mac, &header.wrapped_mac_key)?;
        header.verify_mac(mac_key.expose_secret())?;
        let master_key = crypto::unwrap_key(&kek_master, &header.wrapped_master_key)?;

        // kek_master and kek_mac are Zeroizing — auto-dropped

        Ok(Self {
            path,
            header,
            master_key,
            mac_key,
        })
    }

    /// Check if a file is an AeroVault v2 container (reads only the first 11 bytes).
    pub fn is_vault(path: impl AsRef<Path>) -> bool {
        let Ok(file) = File::open(path.as_ref()) else {
            return false;
        };
        let mut buf = [0u8; 11];
        let mut reader = BufReader::new(file);
        if reader.read_exact(&mut buf).is_err() {
            return false;
        }
        &buf[..10] == MAGIC && buf[10] == VERSION
    }

    /// Get the vault file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the encryption mode.
    pub fn mode(&self) -> EncryptionMode {
        if self.header.flags.cascade_mode {
            EncryptionMode::Cascade
        } else {
            EncryptionMode::Standard
        }
    }

    /// Get the chunk size.
    pub fn chunk_size(&self) -> u32 {
        self.header.chunk_size
    }

    /// Return security information about the vault.
    pub fn security_info(&self) -> SecurityInfo {
        SecurityInfo {
            version: self.header.version,
            mode: self.mode(),
            chunk_size: self.header.chunk_size,
            argon2_m_cost_kib: ARGON2_M_COST,
            argon2_t_cost: ARGON2_T_COST,
            argon2_p_cost: ARGON2_P_COST,
        }
    }

    /// List all entries in the vault with decrypted filenames.
    pub fn list(&self) -> crate::Result<Vec<EntryInfo>> {
        let manifest = self.read_manifest()?;
        let mut entries = Vec::with_capacity(manifest.entries.len());

        for entry in &manifest.entries {
            let name = crypto::decrypt_filename(
                self.master_key.expose_secret(),
                &entry.encrypted_name,
            )?;
            entries.push(EntryInfo {
                name,
                size: entry.size,
                is_dir: entry.is_dir,
                modified: entry.modified.clone(),
            });
        }

        Ok(entries)
    }

    /// Add files from disk into the vault.
    ///
    /// Files are encrypted in chunks and appended to the data section.
    /// Duplicate filenames are silently skipped.
    pub fn add_files(&self, file_paths: &[impl AsRef<Path>]) -> crate::Result<u32> {
        self.add_files_to_dir(file_paths, "")
    }

    /// Add files to a specific directory inside the vault.
    ///
    /// The `target_dir` must already exist (or be empty for root).
    pub fn add_files_to_dir(
        &self,
        file_paths: &[impl AsRef<Path>],
        target_dir: &str,
    ) -> crate::Result<u32> {
        let target_dir = target_dir.trim().trim_matches('/');
        if target_dir.contains("..") {
            return Err(crate::Error::InvalidPath(
                "directory path cannot contain '..'".into(),
            ));
        }

        let cascade_mode = self.header.flags.cascade_mode;
        let chunk_size = self.header.chunk_size as usize;

        // Read current vault state
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str = std::str::from_utf8(&manifest_encrypted)
            .map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json = crypto::decrypt_filename(
            self.master_key.expose_secret(),
            manifest_str,
        )?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        // Verify target directory exists (if non-empty)
        if !target_dir.is_empty() {
            let target_encrypted =
                crypto::encrypt_filename(self.master_key.expose_secret(), target_dir)?;
            let dir_exists = manifest
                .entries
                .iter()
                .any(|e| e.encrypted_name == target_encrypted && e.is_dir);
            if !dir_exists {
                return Err(crate::Error::EntryNotFound(format!(
                    "target directory '{target_dir}'"
                )));
            }
        }

        // Read existing data
        let mut existing_data = Vec::new();
        reader.read_to_end(&mut existing_data)?;

        let chacha_key = if cascade_mode {
            crypto::derive_chacha_key(self.master_key.expose_secret())
        } else {
            zeroize::Zeroizing::new([0u8; KEY_SIZE])
        };

        let mut data_offset = existing_data.len() as u64;
        let mut new_data = Vec::new();
        let mut added_count = 0u32;

        for file_path in file_paths {
            let file_path = file_path.as_ref();
            let source = File::open(file_path)?;
            let metadata = source.metadata()?;

            let filename = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| crate::Error::InvalidPath(format!("{}", file_path.display())))?;

            let vault_name = if target_dir.is_empty() {
                filename.to_string()
            } else {
                format!("{target_dir}/{filename}")
            };

            // Check for duplicate
            let encrypted_name =
                crypto::encrypt_filename(self.master_key.expose_secret(), &vault_name)?;
            if manifest
                .entries
                .iter()
                .any(|e| e.encrypted_name == encrypted_name)
            {
                continue;
            }

            let mut source_reader = BufReader::new(source);
            let mut chunk_count = 0u32;
            let entry_offset = data_offset;

            loop {
                let mut chunk = vec![0u8; chunk_size];
                let bytes_read = source_reader.read(&mut chunk)?;
                if bytes_read == 0 {
                    break;
                }
                chunk.truncate(bytes_read);

                let encrypted_chunk = if cascade_mode {
                    crypto::encrypt_chunk_cascade(
                        self.master_key.expose_secret(),
                        &chacha_key,
                        &chunk,
                        chunk_count,
                    )?
                } else {
                    crypto::encrypt_chunk(self.master_key.expose_secret(), &chunk, chunk_count)?
                };

                let chunk_len = encrypted_chunk.len() as u32;
                new_data.extend_from_slice(&chunk_len.to_le_bytes());
                new_data.extend_from_slice(&encrypted_chunk);

                data_offset += 4 + encrypted_chunk.len() as u64;
                chunk_count = chunk_count.checked_add(1).ok_or_else(|| {
                    crate::Error::Manifest("chunk count overflow".into())
                })?;

                chunk.zeroize();
            }

            let modified = metadata
                .modified()
                .map(|t| {
                    let datetime: chrono::DateTime<chrono::Utc> = t.into();
                    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                })
                .unwrap_or_else(|_| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

            manifest.entries.push(ManifestEntry {
                encrypted_name,
                name: String::new(),
                size: metadata.len(),
                offset: entry_offset,
                chunk_count,
                is_dir: false,
                modified,
            });

            added_count += 1;
        }

        if added_count > 0 {
            manifest.modified = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            self.write_vault_atomic(&header_buf, &manifest, &existing_data, &new_data)?;
        }

        // chacha_key is Zeroizing — auto-dropped
        Ok(added_count)
    }

    /// Create a directory inside the vault.
    ///
    /// Intermediate directories are created automatically (like `mkdir -p`).
    pub fn create_directory(&self, dir_name: &str) -> crate::Result<u32> {
        let dir_name = dir_name.trim().trim_matches('/');
        if dir_name.is_empty() {
            return Err(crate::Error::InvalidPath("directory name cannot be empty".into()));
        }
        if dir_name.contains("..") {
            return Err(crate::Error::InvalidPath(
                "directory name cannot contain '..'".into(),
            ));
        }
        if dir_name.len() > 4096 {
            return Err(crate::Error::InvalidPath("directory name too long".into()));
        }

        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str = std::str::from_utf8(&manifest_encrypted)
            .map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json = crypto::decrypt_filename(
            self.master_key.expose_secret(),
            manifest_str,
        )?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut existing_data = Vec::new();
        reader.read_to_end(&mut existing_data)?;

        // Collect directories to create (including intermediates)
        let mut dirs_to_create = Vec::new();
        let parts: Vec<&str> = dir_name.split('/').collect();
        for i in 1..=parts.len() {
            let partial = parts[..i].join("/");
            let encrypted = crypto::encrypt_filename(self.master_key.expose_secret(), &partial)?;
            if !manifest.entries.iter().any(|e| e.encrypted_name == encrypted) {
                dirs_to_create.push((partial, encrypted));
            }
        }

        if dirs_to_create.is_empty() {
            return Ok(0);
        }

        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for (_, encrypted_name) in &dirs_to_create {
            manifest.entries.push(ManifestEntry {
                encrypted_name: encrypted_name.clone(),
                name: String::new(),
                size: 0,
                offset: 0,
                chunk_count: 0,
                is_dir: true,
                modified: now.clone(),
            });
        }

        manifest.modified = now;
        let created = dirs_to_create.len() as u32;
        self.write_vault_atomic(&header_buf, &manifest, &existing_data, &[])?;

        Ok(created)
    }

    /// Extract a single entry to the specified output directory.
    ///
    /// Returns the full path of the extracted file. Validates that the output
    /// path stays within `output_dir` to prevent path traversal attacks.
    pub fn extract(&self, entry_name: &str, output_dir: impl AsRef<Path>) -> crate::Result<PathBuf> {
        let output_dir = output_dir.as_ref();

        // Validate entry name against path traversal
        validate_entry_name(entry_name)?;

        let manifest = self.read_manifest()?;

        // Find matching entry
        let entry = manifest
            .entries
            .iter()
            .find(|e| {
                crypto::decrypt_filename(self.master_key.expose_secret(), &e.encrypted_name)
                    .map(|name| name == entry_name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| crate::Error::EntryNotFound(entry_name.to_string()))?;

        if entry.is_dir {
            let dir_path = output_dir.join(entry_name);
            validate_output_path(&dir_path, output_dir)?;
            std::fs::create_dir_all(&dir_path)?;
            return Ok(dir_path);
        }

        let cascade_mode = self.header.flags.cascade_mode;

        let chacha_key = if cascade_mode {
            crypto::derive_chacha_key(self.master_key.expose_secret())
        } else {
            zeroize::Zeroizing::new([0u8; KEY_SIZE])
        };

        // Open vault and seek to data section
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        // Skip header
        let mut skip_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut skip_buf)?;

        // Skip manifest
        let (manifest_len, _manifest_data) = crypto::read_manifest_bounded(&mut reader)?;
        let _ = manifest_len;

        // Skip to entry offset
        let mut skipped = 0u64;
        while skipped < entry.offset {
            let to_skip = std::cmp::min(entry.offset - skipped, 8192) as usize;
            let mut skip = vec![0u8; to_skip];
            reader.read_exact(&mut skip)?;
            skipped += to_skip as u64;
        }

        // Determine safe output path
        let filename = Path::new(entry_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| crate::Error::InvalidPath(format!("invalid entry name: {entry_name}")))?;
        let dest_path = output_dir.join(filename);
        validate_output_path(&dest_path, output_dir)?;

        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let out_file = File::create(&dest_path)?;
        let mut writer = BufWriter::new(out_file);

        // Read and decrypt chunks
        for chunk_idx in 0..entry.chunk_count {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let chunk_len = u32::from_le_bytes(len_buf) as usize;

            let mut encrypted_chunk = vec![0u8; chunk_len];
            reader.read_exact(&mut encrypted_chunk)?;

            let mut plaintext = if cascade_mode {
                crypto::decrypt_chunk_cascade(
                    self.master_key.expose_secret(),
                    &chacha_key,
                    &encrypted_chunk,
                    chunk_idx,
                )?
            } else {
                crypto::decrypt_chunk(
                    self.master_key.expose_secret(),
                    &encrypted_chunk,
                    chunk_idx,
                )?
            };

            writer.write_all(&plaintext)?;
            plaintext.zeroize();
            encrypted_chunk.zeroize();
        }

        writer.flush()?;
        // chacha_key is Zeroizing — auto-dropped

        Ok(dest_path)
    }

    /// Extract all entries to the specified output directory.
    ///
    /// Returns the number of entries extracted.
    pub fn extract_all(&self, output_dir: impl AsRef<Path>) -> crate::Result<u32> {
        let entries = self.list()?;
        let mut count = 0u32;
        for entry in &entries {
            self.extract(&entry.name, output_dir.as_ref())?;
            count += 1;
        }
        Ok(count)
    }

    /// Delete an entry from the vault manifest.
    ///
    /// The encrypted data remains in the file but becomes orphaned.
    /// Use [`Vault::compact`] (future) to reclaim space.
    pub fn delete_entry(&self, entry_name: &str) -> crate::Result<()> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str = std::str::from_utf8(&manifest_encrypted)
            .map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json = crypto::decrypt_filename(
            self.master_key.expose_secret(),
            manifest_str,
        )?;

        let mut manifest: VaultManifest = serde_json::from_str(&manifest_json)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;

        let mut data_section = Vec::new();
        reader.read_to_end(&mut data_section)?;

        // Find and remove entry
        let mut found = false;
        manifest.entries.retain(|entry| {
            match crypto::decrypt_filename(self.master_key.expose_secret(), &entry.encrypted_name) {
                Ok(name) if name == entry_name => {
                    found = true;
                    false
                }
                _ => true,
            }
        });

        if !found {
            return Err(crate::Error::EntryNotFound(entry_name.to_string()));
        }

        manifest.modified = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        self.write_vault_atomic(&header_buf, &manifest, &data_section, &[])?;
        Ok(())
    }

    /// Change the vault password.
    ///
    /// Re-wraps the master and MAC keys with a new KEK. The encrypted content
    /// remains unchanged — only the 512-byte header is modified.
    pub fn change_password(
        &mut self,
        new_password: impl Into<String>,
    ) -> crate::Result<()> {
        let new_pwd = SecretString::from(new_password.into());
        if new_pwd.expose_secret().len() < MIN_PASSWORD_LENGTH {
            return Err(crate::Error::PasswordPolicy(format!(
                "password must be at least {MIN_PASSWORD_LENGTH} characters"
            )));
        }

        let mut vault_data = std::fs::read(&self.path)?;

        if vault_data.len() < HEADER_SIZE {
            return Err(FormatError::TooSmall {
                actual: vault_data.len(),
                expected: HEADER_SIZE,
            }
            .into());
        }

        // Generate new salt
        let mut new_salt = [0u8; SALT_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);

        // Derive new KEKs
        let new_base_kek = crypto::derive_key(&new_pwd, &new_salt)?;
        let (new_kek_master, new_kek_mac) =
            crypto::derive_kek_pair(new_base_kek.expose_secret());

        // Re-wrap keys
        let new_wrapped_master =
            crypto::wrap_key(&new_kek_master, self.master_key.expose_secret())?;
        let new_wrapped_mac = crypto::wrap_key(&new_kek_mac, self.mac_key.expose_secret())?;

        // new_kek_master and new_kek_mac are Zeroizing — auto-dropped

        // Build new header
        let mut new_header = VaultHeader {
            magic: *MAGIC,
            version: VERSION,
            flags: self.header.flags,
            salt: new_salt,
            wrapped_master_key: new_wrapped_master,
            wrapped_mac_key: new_wrapped_mac,
            chunk_size: self.header.chunk_size,
            header_mac: [0u8; MAC_SIZE],
        };
        new_header.header_mac = new_header.compute_mac(self.mac_key.expose_secret());

        // Write new header into vault data
        let header_bytes = new_header.to_bytes();
        vault_data[..HEADER_SIZE].copy_from_slice(&header_bytes);

        // Atomic write with fsync
        atomic_write(&self.path, &vault_data, "chpw")?;

        self.header = new_header;
        vault_data.zeroize();

        Ok(())
    }

    // --- Internal Helpers ---

    /// Read and decrypt the vault manifest.
    fn read_manifest(&self) -> crate::Result<VaultManifest> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);

        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;

        let (_manifest_len, manifest_encrypted) = crypto::read_manifest_bounded(&mut reader)?;
        let manifest_str = std::str::from_utf8(&manifest_encrypted)
            .map_err(|_| CryptoError::ManifestEncoding)?;
        let manifest_json = crypto::decrypt_filename(
            self.master_key.expose_secret(),
            manifest_str,
        )?;

        serde_json::from_str(&manifest_json).map_err(|e| crate::Error::Manifest(e.to_string()))
    }

    /// Write vault atomically: header + manifest + data_old + data_new.
    fn write_vault_atomic(
        &self,
        header_buf: &[u8; HEADER_SIZE],
        manifest: &VaultManifest,
        existing_data: &[u8],
        new_data: &[u8],
    ) -> crate::Result<()> {
        let manifest_json = serde_json::to_string(manifest)
            .map_err(|e| crate::Error::Manifest(e.to_string()))?;
        let encrypted_manifest =
            crypto::encrypt_filename(self.master_key.expose_secret(), &manifest_json)?;
        let manifest_bytes = encrypted_manifest.as_bytes();

        let tmp_path = format!("{}.tmp", self.path.display());
        let file = File::create(&tmp_path)?;
        let mut writer = BufWriter::new(file);

        writer.write_all(header_buf)?;
        writer.write_all(&(manifest_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(manifest_bytes)?;
        writer.write_all(existing_data)?;
        writer.write_all(new_data)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);

        atomic_rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

/// Security information about a vault.
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    /// Format version.
    pub version: u8,
    /// Encryption mode.
    pub mode: EncryptionMode,
    /// Chunk size in bytes.
    pub chunk_size: u32,
    /// Argon2id memory cost in KiB.
    pub argon2_m_cost_kib: u32,
    /// Argon2id time cost.
    pub argon2_t_cost: u32,
    /// Argon2id parallelism.
    pub argon2_p_cost: u32,
}

impl std::fmt::Display for SecurityInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode_str = match self.mode {
            EncryptionMode::Standard => "AES-256-GCM-SIV",
            EncryptionMode::Cascade => "AES-256-GCM-SIV + ChaCha20-Poly1305",
        };
        write!(
            f,
            "Version: {}\n\
             Encryption: {}\n\
             Chunk size: {} bytes\n\
             KDF: Argon2id ({} MiB, t={}, p={})\n\
             Key wrapping: AES-256-KW (RFC 3394)\n\
             Filename encryption: AES-256-SIV\n\
             Header integrity: HMAC-SHA512",
            self.version,
            mode_str,
            self.chunk_size,
            self.argon2_m_cost_kib / 1024,
            self.argon2_t_cost,
            self.argon2_p_cost,
        )
    }
}

/// Validate that an entry name is safe (no path traversal, no absolute paths).
fn validate_entry_name(name: &str) -> crate::Result<()> {
    if name.contains("..") {
        return Err(crate::Error::InvalidPath(
            "entry name contains '..' (path traversal)".into(),
        ));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(crate::Error::InvalidPath(
            "entry name is an absolute path".into(),
        ));
    }
    if name.contains('\0') {
        return Err(crate::Error::InvalidPath(
            "entry name contains null byte".into(),
        ));
    }
    Ok(())
}

/// Validate that a resolved output path stays within the output directory.
fn validate_output_path(path: &Path, output_dir: &Path) -> crate::Result<()> {
    // Canonicalize the output directory (it must exist)
    let canonical_dir = output_dir.canonicalize().unwrap_or_else(|_| output_dir.to_path_buf());

    // For the file path, canonicalize the parent (which should exist after create_dir_all)
    // and append the filename
    let canonical_path = if let Some(parent) = path.parent() {
        let canon_parent = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
        if let Some(filename) = path.file_name() {
            canon_parent.join(filename)
        } else {
            canon_parent
        }
    } else {
        path.to_path_buf()
    };

    if !canonical_path.starts_with(&canonical_dir) {
        return Err(crate::Error::InvalidPath(format!(
            "output path escapes target directory: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Atomic rename: original → .bak, tmp → original, delete .bak.
fn atomic_rename(tmp_path: &str, final_path: &Path) -> crate::Result<()> {
    let bak_path = format!("{}.bak", final_path.display());
    std::fs::rename(final_path, &bak_path)?;
    if let Err(e) = std::fs::rename(tmp_path, final_path) {
        let _ = std::fs::rename(&bak_path, final_path); // Rollback
        return Err(e.into());
    }
    let _ = std::fs::remove_file(&bak_path);
    Ok(())
}

/// Atomic write: write to temp file with fsync, then rename.
fn atomic_write(path: &Path, data: &[u8], suffix: &str) -> crate::Result<()> {
    let tmp_path = format!("{}.{suffix}.tmp", path.display());
    let file = File::create(&tmp_path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(data)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);

    let bak_path = format!("{}.bak", path.display());
    std::fs::rename(path, &bak_path)?;
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::rename(&bak_path, path); // Rollback
        return Err(e.into());
    }
    let _ = std::fs::remove_file(&bak_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_vault_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("aerovault-test-{}.aerovault", rand::random::<u64>()));
        path
    }

    #[test]
    fn test_create_and_open() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let _vault = Vault::create(opts).unwrap();

        assert!(Vault::is_vault(&path));

        let vault = Vault::open(&path, "test-password-123").unwrap();
        let entries = vault.list().unwrap();
        assert!(entries.is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_wrong_password() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "correct-password");
        let _vault = Vault::create(opts).unwrap();

        let result = Vault::open(&path, "wrong-password");
        assert!(result.is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_password_too_short() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "short");
        let result = Vault::create(opts);
        assert!(result.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_chunk_size_validation() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123")
            .with_chunk_size(1); // too small
        assert!(Vault::create(opts).is_err());

        let opts = CreateOptions::new(&path, "test-password-123")
            .with_chunk_size(32 * 1024 * 1024); // too large
        assert!(Vault::create(opts).is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_add_and_extract() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        // Create a test file
        let test_file = std::env::temp_dir().join("aerovault-test-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"Hello from AeroVault!").unwrap();

        // Add file
        let added = vault.add_files(&[&test_file]).unwrap();
        assert_eq!(added, 1);

        // List
        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "aerovault-test-input.txt");
        assert_eq!(entries[0].size, 21);
        assert!(!entries[0].is_dir);

        // Extract
        let out_dir = std::env::temp_dir().join("aerovault-test-output");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault.extract("aerovault-test-input.txt", &out_dir).unwrap();
        let content = std::fs::read_to_string(&extracted).unwrap();
        assert_eq!(content, "Hello from AeroVault!");

        // Cleanup
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_cascade_mode() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123")
            .with_mode(EncryptionMode::Cascade);
        let vault = Vault::create(opts).unwrap();

        assert_eq!(vault.mode(), EncryptionMode::Cascade);

        let test_file = std::env::temp_dir().join("aerovault-cascade-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"Cascade mode test").unwrap();

        vault.add_files(&[&test_file]).unwrap();

        // Re-open and extract
        let vault2 = Vault::open(&path, "test-password-123").unwrap();
        let out_dir = std::env::temp_dir().join("aerovault-cascade-output");
        std::fs::create_dir_all(&out_dir).ok();
        let extracted = vault2.extract("aerovault-cascade-input.txt", &out_dir).unwrap();
        let content = std::fs::read_to_string(&extracted).unwrap();
        assert_eq!(content, "Cascade mode test");

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&test_file).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn test_create_directory() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        // Create nested directory
        let created = vault.create_directory("docs/notes").unwrap();
        assert_eq!(created, 2); // "docs" + "docs/notes"

        // Creating again should return 0
        let created = vault.create_directory("docs/notes").unwrap();
        assert_eq!(created, 0);

        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.is_dir));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_delete_entry() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();

        let test_file = std::env::temp_dir().join("aerovault-delete-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"to be deleted").unwrap();

        vault.add_files(&[&test_file]).unwrap();
        assert_eq!(vault.list().unwrap().len(), 1);

        vault.delete_entry("aerovault-delete-input.txt").unwrap();
        assert_eq!(vault.list().unwrap().len(), 0);

        // Deleting again should fail
        assert!(vault.delete_entry("aerovault-delete-input.txt").is_err());

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_change_password() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "old-password-123");
        let mut vault = Vault::create(opts).unwrap();

        let test_file = std::env::temp_dir().join("aerovault-chpw-input.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"password change test").unwrap();
        vault.add_files(&[&test_file]).unwrap();

        vault.change_password("new-password-456").unwrap();

        // Old password should fail
        assert!(Vault::open(&path, "old-password-123").is_err());

        // New password should work and data should be intact
        let vault2 = Vault::open(&path, "new-password-456").unwrap();
        let entries = vault2.list().unwrap();
        assert_eq!(entries.len(), 1);

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_is_vault_negative() {
        let path = std::env::temp_dir().join("not-a-vault.txt");
        std::fs::write(&path, b"just text").ok();
        assert!(!Vault::is_vault(&path));
        std::fs::remove_file(&path).ok();

        assert!(!Vault::is_vault("/nonexistent/path"));
    }

    #[test]
    fn test_security_info_display() {
        let path = temp_vault_path();
        let opts = CreateOptions::new(&path, "test-password-123");
        let vault = Vault::create(opts).unwrap();
        let info = vault.security_info();
        let display = format!("{info}");
        assert!(display.contains("AES-256-GCM-SIV"));
        assert!(display.contains("128 MiB"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_path_traversal_rejected() {
        assert!(validate_entry_name("../etc/passwd").is_err());
        assert!(validate_entry_name("/etc/passwd").is_err());
        assert!(validate_entry_name("foo\0bar").is_err());
        assert!(validate_entry_name("normal/file.txt").is_ok());
    }
}
