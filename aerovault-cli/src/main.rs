use std::path::PathBuf;

use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use zeroize::Zeroize;

use aerovault::{CreateOptions, EncryptionMode, Vault};

/// AeroVault — Military-grade encrypted vault manager.
///
/// Create, manage, and extract files from AES-256-GCM-SIV encrypted containers.
#[derive(Parser)]
#[command(name = "aerovault", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new encrypted vault.
    Create {
        /// Path for the new vault file.
        path: PathBuf,

        /// Use cascade encryption (AES-256-GCM-SIV + ChaCha20-Poly1305).
        #[arg(long)]
        cascade: bool,

        /// Chunk size in KiB (default: 64).
        #[arg(long, default_value = "64")]
        chunk_size: u32,
    },

    /// Open a vault and list its contents.
    List {
        /// Path to the vault file.
        path: PathBuf,

        /// Show sizes in human-readable format.
        #[arg(short = 'H', long)]
        human: bool,
    },

    /// Add files to a vault.
    Add {
        /// Path to the vault file.
        vault: PathBuf,

        /// Files to add.
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Target directory inside the vault.
        #[arg(long, default_value = "")]
        dir: String,
    },

    /// Extract entries from a vault.
    Extract {
        /// Path to the vault file.
        vault: PathBuf,

        /// Output directory (default: current directory).
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Specific entry to extract (omit for all).
        #[arg(short, long)]
        entry: Option<String>,
    },

    /// Create a directory inside a vault.
    Mkdir {
        /// Path to the vault file.
        vault: PathBuf,

        /// Directory name (e.g. "docs/notes").
        name: String,
    },

    /// Delete an entry from a vault.
    #[command(name = "rm")]
    Remove {
        /// Path to the vault file.
        vault: PathBuf,

        /// Entry name to delete.
        name: String,
    },

    /// Show vault security information.
    Info {
        /// Path to the vault file.
        path: PathBuf,
    },

    /// Change vault password.
    #[command(name = "passwd")]
    ChangePassword {
        /// Path to the vault file.
        path: PathBuf,
    },

    /// Check if a file is an AeroVault v2 container.
    Check {
        /// Path to check.
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Create {
            path,
            cascade,
            chunk_size,
        } => {
            let mut password = read_password("Password: ")?;
            let mut confirm = read_password("Confirm password: ")?;

            if password != confirm {
                confirm.zeroize();
                password.zeroize();
                return Err("passwords do not match".into());
            }
            confirm.zeroize();

            let mode = if cascade {
                EncryptionMode::Cascade
            } else {
                EncryptionMode::Standard
            };

            let pb = spinner("Creating vault...");
            let opts = CreateOptions::new(&path, password.clone())
                .with_mode(mode)
                .with_chunk_size(chunk_size * 1024);
            password.zeroize();

            Vault::create(opts)?;
            pb.finish_with_message("Vault created");

            let mode_str = match mode {
                EncryptionMode::Standard => "AES-256-GCM-SIV",
                EncryptionMode::Cascade => "AES-256-GCM-SIV + ChaCha20-Poly1305",
            };
            println!("  Path: {}", path.display());
            println!("  Mode: {mode_str}");
            println!("  Chunk: {} KiB", chunk_size);
        }

        Commands::List { path, human } => {
            let mut password = read_password("Password: ")?;
            let pb = spinner("Unlocking vault...");
            let vault = Vault::open(&path, password.clone())?;
            password.zeroize();
            pb.finish_and_clear();

            let entries = vault.list()?;
            if entries.is_empty() {
                println!("(empty vault)");
                return Ok(());
            }

            println!("{:<8} {:<12} {:<20} NAME", "TYPE", "SIZE", "MODIFIED");
            println!("{}", "-".repeat(60));
            for entry in &entries {
                let type_str = if entry.is_dir { "DIR" } else { "FILE" };
                let size_str = if entry.is_dir {
                    "-".to_string()
                } else if human {
                    format_size(entry.size)
                } else {
                    entry.size.to_string()
                };
                println!(
                    "{:<8} {:<12} {:<20} {}",
                    type_str, size_str, entry.modified, entry.name
                );
            }
            println!("\n{} entries", entries.len());
        }

        Commands::Add { vault, files, dir } => {
            let mut password = read_password("Password: ")?;
            let pb = spinner("Unlocking vault...");
            let v = Vault::open(&vault, password.clone())?;
            password.zeroize();
            pb.finish_and_clear();

            let pb = spinner("Adding files...");
            let added = if dir.is_empty() {
                v.add_files(&files)?
            } else {
                v.add_files_to_dir(&files, &dir)?
            };
            pb.finish_with_message(format!("{added} file(s) added"));
        }

        Commands::Extract {
            vault,
            output,
            entry,
        } => {
            let mut password = read_password("Password: ")?;
            let pb = spinner("Unlocking vault...");
            let v = Vault::open(&vault, password.clone())?;
            password.zeroize();
            pb.finish_and_clear();

            if let Some(name) = entry {
                let pb = spinner("Extracting...");
                let dest = v.extract(&name, &output)?;
                pb.finish_with_message(format!("Extracted to {}", dest.display()));
            } else {
                let pb = spinner("Extracting all...");
                let count = v.extract_all(&output)?;
                pb.finish_with_message(format!("{count} entries extracted to {}", output.display()));
            }
        }

        Commands::Mkdir { vault, name } => {
            let mut password = read_password("Password: ")?;
            let pb = spinner("Unlocking vault...");
            let v = Vault::open(&vault, password.clone())?;
            password.zeroize();
            pb.finish_and_clear();

            let created = v.create_directory(&name)?;
            println!("{created} directory(ies) created");
        }

        Commands::Remove { vault, name } => {
            let mut password = read_password("Password: ")?;
            let pb = spinner("Unlocking vault...");
            let v = Vault::open(&vault, password.clone())?;
            password.zeroize();
            pb.finish_and_clear();

            v.delete_entry(&name)?;
            println!("Deleted: {name}");
        }

        Commands::Info { path } => {
            let mut password = read_password("Password: ")?;
            let pb = spinner("Unlocking vault...");
            let vault = Vault::open(&path, password.clone())?;
            password.zeroize();
            pb.finish_and_clear();

            let info = vault.security_info();
            println!("{info}");

            let entries = vault.list()?;
            let total_size: u64 = entries.iter().map(|e| e.size).sum();
            let dir_count = entries.iter().filter(|e| e.is_dir).count();
            let file_count = entries.len() - dir_count;
            println!("Files: {file_count}");
            println!("Directories: {dir_count}");
            println!("Total original size: {}", format_size(total_size));
        }

        Commands::ChangePassword { path } => {
            let mut old_password = read_password("Current password: ")?;
            let pb = spinner("Unlocking vault...");
            let mut vault = Vault::open(&path, old_password.clone())?;
            old_password.zeroize();
            pb.finish_and_clear();

            let mut new_password = read_password("New password: ")?;
            let mut confirm = read_password("Confirm new password: ")?;

            if new_password != confirm {
                confirm.zeroize();
                new_password.zeroize();
                return Err("passwords do not match".into());
            }
            confirm.zeroize();

            let pb = spinner("Changing password...");
            vault.change_password(new_password.clone())?;
            new_password.zeroize();
            pb.finish_with_message("Password changed");
        }

        Commands::Check { path } => {
            if Vault::is_vault(&path) {
                println!("{}: AeroVault v2", path.display());
            } else {
                println!("{}: not an AeroVault v2 file", path.display());
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn read_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{prompt}");
    let password = rpassword::read_password()?;
    Ok(password)
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .expect("valid template"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} PiB")
}
