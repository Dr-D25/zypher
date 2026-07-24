mod crypto;
mod error;
mod format;
mod gui;
mod pack;
mod unpack;

use clap::{Parser, Subcommand};
use pack::CompressionMethod;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zypher", about = "Next-gen archive tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Pack {
        #[arg(short = 'o', long = "output", default_value = "archive.zypher")]
        output: PathBuf,
        files: Vec<PathBuf>,
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
        #[arg(short = 'l', long = "compression-level", default_value = "3", value_parser = clap::value_parser!(u32).range(1..=22))]
        compression_level: u32,
        #[arg(short = 'm', long = "method", default_value = "zstd")]
        method: String,
    },
    Append {
        archive: PathBuf,
        files: Vec<PathBuf>,
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
        #[arg(short = 'l', long = "compression-level", default_value = "3", value_parser = clap::value_parser!(u32).range(1..=22))]
        compression_level: u32,
        #[arg(short = 'm', long = "method", default_value = "zstd")]
        method: String,
    },
    List {
        archive: PathBuf,
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
    },
    Unpack {
        archive: PathBuf,
        #[arg(short = 'o', long = "output-dir", default_value = ".")]
        output_dir: PathBuf,
        files: Vec<String>,
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
    },
    Verify {
        archive: PathBuf,
        #[arg(short = 'p', long = "password")]
        password: Option<String>,
    },
    Sfx {
        archive: PathBuf,
        #[arg(short = 'o', long = "output", default_value = "archive.sfx")]
        output: PathBuf,
    },
    Gui,
}

fn parse_method(s: &str) -> anyhow::Result<CompressionMethod> {
    match s.to_lowercase().as_str() {
        "zstd" => Ok(CompressionMethod::Zstd),
        "lz4" => Ok(CompressionMethod::Lz4),
        "brotli" => Ok(CompressionMethod::Brotli),
        _ => anyhow::bail!("Unknown compression method: {}", s),
    }
}

fn main() -> anyhow::Result<()> {
    if let Ok(true) = pack::try_run_sfx() {
        println!("Self-extracting archive extracted successfully.");
        return Ok(());
    }

    let cli = Cli::parse();
    match cli.command {
        None | Some(Commands::Gui) => {
            gui::run_gui().map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;
            Ok(())
        }
        Some(cmd) => match cmd {
            Commands::Pack {
                output,
                files,
                password,
                compression_level,
                method,
            } => {
                if files.is_empty() {
                    anyhow::bail!("No input files specified");
                }
                let method = parse_method(&method)?;
                pack::pack_files(&output, &files, password.as_deref(), compression_level, method, |_| {})?;
                println!("Archive created: {}", output.display());
                Ok(())
            }
            Commands::Append {
                archive,
                files,
                password,
                compression_level,
                method,
            } => {
                if files.is_empty() {
                    anyhow::bail!("No files to append");
                }
                let method = parse_method(&method)?;
                pack::append_files(&archive, &files, password.as_deref(), compression_level, method, |_| {})?;
                println!("Files appended to {}", archive.display());
                Ok(())
            }
            Commands::List { archive, password } => {
                unpack::list_files(&archive, password.as_deref())?;
                Ok(())
            }
            Commands::Unpack {
                archive,
                output_dir,
                files,
                password,
            } => {
                if files.is_empty() {
                    unpack::extract_all(&archive, &output_dir, password.as_deref(), |_| {})?;
                } else {
                    for fname in files {
                        unpack::extract_file(&archive, &fname, &output_dir, password.as_deref())?;
                    }
                }
                Ok(())
            }
            Commands::Verify { archive, password } => {
                unpack::verify_archive(&archive, password.as_deref(), |_| {})?;
                Ok(())
            }
            Commands::Sfx { archive, output } => {
                pack::create_sfx(&archive, &output)?;
                println!("Self-extracting archive created: {}", output.display());
                Ok(())
            }
            Commands::Gui => unreachable!(),
        },
    }
}