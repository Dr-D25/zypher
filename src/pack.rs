use crate::crypto;
use crate::error::ZypherError;
use crate::format::{
    Footer, TocEntry, ARCHIVE_FLAG_ENCRYPTED, CURRENT_VERSION, FLAG_COMPRESSED, FLAG_ENCRYPTED,
    MAGIC, COMPRESSION_ZSTD, COMPRESSION_LZ4, COMPRESSION_BROTLI,
};
use binrw::{BinReaderExt, BinWriterExt};
use rayon::prelude::*;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub enum CompressionMethod {
    Zstd,
    Lz4,
    Brotli,
}

impl CompressionMethod {
    pub fn code(&self) -> u8 {
        match self {
            CompressionMethod::Zstd => COMPRESSION_ZSTD,
            CompressionMethod::Lz4 => COMPRESSION_LZ4,
            CompressionMethod::Brotli => COMPRESSION_BROTLI,
        }
    }
}

fn compress_data(data: &[u8], level: u32, method: &CompressionMethod) -> Result<Vec<u8>, ZypherError> {
    match method {
        CompressionMethod::Zstd => {
            zstd::encode_all(data, level as i32)
                .map_err(|e| ZypherError::Format(format!("Zstd error: {}", e)))
        }
        CompressionMethod::Lz4 => {
            let mode = if level >= 10 { lz4::block::CompressionMode::HIGHCOMPRESSION(level as i32) }
                       else { lz4::block::CompressionMode::FAST(level as i32) };
            lz4::block::compress(data, Some(mode), true)
                .map_err(|e| ZypherError::Format(format!("LZ4 error: {}", e)))
        }
        CompressionMethod::Brotli => {
            let mut compressed = Vec::new();
            {
                let mut compressor = brotli::CompressorWriter::new(&mut compressed, 4096, level, 22);
                compressor.write_all(data)
                    .map_err(|e| ZypherError::Format(format!("Brotli write error: {}", e)))?;
            }
            Ok(compressed)
        }
    }
}

fn read_archive_header(file: &mut fs::File) -> Result<(u16, u16), ZypherError> {
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(ZypherError::Format("Invalid magic".into()));
    }
    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);
    let mut flags_bytes = [0u8; 2];
    file.read_exact(&mut flags_bytes)?;
    let archive_flags = u16::from_le_bytes(flags_bytes);
    Ok((version, archive_flags))
}

fn read_index(
    file: &mut fs::File,
    password: Option<&str>,
    archive_flags: u16,
) -> Result<(Vec<TocEntry>, Footer), ZypherError> {
    let footer_size: i64 = 56;
    file.seek(SeekFrom::End(-footer_size))?;
    let footer: Footer = file.read_le()?;
    file.seek(SeekFrom::Start(footer.index_offset))?;
    let mut encrypted_index = vec![0u8; footer.index_size as usize];
    file.read_exact(&mut encrypted_index)?;

    let index_bytes = if archive_flags & ARCHIVE_FLAG_ENCRYPTED != 0 {
        let master_key = match password {
            Some(p) => crypto::derive_key_from_password(p),
            None => {
                return Err(ZypherError::Format(
                    "Archive is encrypted, password required".into(),
                ))
            }
        };
        crypto::decrypt_data(&master_key, &footer.index_nonce, &encrypted_index)
            .map_err(|e| ZypherError::Format(format!("Failed to decrypt index: {}", e)))?
    } else {
        encrypted_index
    };

    let mut cursor = std::io::Cursor::new(&index_bytes);
    let num_entries: u32 = cursor.read_le()?;
    let mut entries = Vec::with_capacity(num_entries as usize);
    for _ in 0..num_entries {
        let entry: TocEntry = cursor.read_le()?;
        entries.push(entry);
    }
    Ok((entries, footer))
}

pub fn pack_files(
    output: &PathBuf,
    files: &[PathBuf],
    password: Option<&str>,
    compression_level: u32,
    method: CompressionMethod,
    progress_callback: impl Fn(f32),
) -> Result<(), ZypherError> {
    let mut out = fs::File::create(output)?;
    out.write_all(MAGIC)?;
    out.write_all(&CURRENT_VERSION.to_le_bytes())?;

    let master_key = password.map(|p| crypto::derive_key_from_password(p));
    let encrypted = master_key.is_some();
    let archive_flags: u16 = if encrypted { ARCHIVE_FLAG_ENCRYPTED } else { 0 };
    out.write_all(&archive_flags.to_le_bytes())?;

    let total = files.len();
    let method_code = method.code();

    let prepared: Vec<Result<(TocEntry, Vec<u8>), ZypherError>> = files
        .par_iter()
        .map(|path| {
            let original_data = fs::read(path)?;
            let original_size = original_data.len() as u64;
            let content_hash: [u8; 32] = blake3::hash(&original_data).into();

            let compressed = compress_data(&original_data, compression_level, &method)?;

            let name = path
                .file_name()
                .ok_or_else(|| ZypherError::Format("No file name".into()))?
                .to_str()
                .unwrap_or("unknown")
                .as_bytes()
                .to_vec();

            let (block_data, flags) = if let Some(ref mk) = master_key {
                let (file_key, _) = crypto::generate_file_key();
                let (wrapped_nonce, wrapped_key) = crypto::wrap_file_key(mk, &file_key);
                let (data_nonce, encrypted_compressed) =
                    crypto::encrypt_data(&file_key, &compressed);

                let mut block = Vec::new();
                block.extend_from_slice(&wrapped_nonce);
                block.extend_from_slice(&(wrapped_key.len() as u32).to_le_bytes());
                block.extend_from_slice(&wrapped_key);
                block.extend_from_slice(&data_nonce);
                block.extend_from_slice(&encrypted_compressed);

                (block, FLAG_COMPRESSED | FLAG_ENCRYPTED)
            } else {
                let mut block = Vec::new();
                block.extend_from_slice(&compressed);
                (block, FLAG_COMPRESSED)
            };

            let entry = TocEntry {
                file_name_len: name.len() as u16,
                file_name: name,
                offset: 0,
                compressed_size: block_data.len() as u64,
                original_size,
                content_hash,
                flags,
                compression_method: method_code,
            };

            Ok((entry, block_data))
        })
        .collect();

    let mut entries: Vec<TocEntry> = Vec::with_capacity(total);
    let mut current_offset: u64 = 4 + 2 + 2;
    let mut first_error: Option<ZypherError> = None;

    for (i, prepared_item) in prepared.into_iter().enumerate() {
        match prepared_item {
            Ok((mut entry, block)) => {
                entry.offset = current_offset;
                out.write_all(&block)?;
                current_offset += block.len() as u64;
                entries.push(entry);
                progress_callback(i as f32 / total as f32);
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    let mut index_bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut index_bytes);
    cursor.write_le(&(entries.len() as u32))?;
    for entry in &entries {
        cursor.write_le(entry)?;
    }

    let index_offset = current_offset;
    let (final_index_bytes, index_nonce) = if let Some(ref mk) = master_key {
        let (nonce, encrypted_index) = crypto::encrypt_data(mk, &index_bytes);
        (encrypted_index, nonce)
    } else {
        (index_bytes, [0u8; 12])
    };

    let index_size = final_index_bytes.len() as u32;
    out.write_all(&final_index_bytes)?;

    let footer = Footer {
        index_offset,
        index_size,
        index_hash: [0u8; 32],
        index_nonce,
    };
    let mut footer_bytes = Vec::new();
    let mut fw = std::io::Cursor::new(&mut footer_bytes);
    fw.write_le(&footer)?;
    out.write_all(&footer_bytes)?;

    progress_callback(1.0);
    Ok(())
}

pub fn append_files(
    archive_path: &PathBuf,
    new_files: &[PathBuf],
    password: Option<&str>,
    compression_level: u32,
    method: CompressionMethod,
    progress_callback: impl Fn(f32),
) -> Result<(), ZypherError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive_path)?;

    let (_version, archive_flags) = read_archive_header(&mut file)?;
    let (old_entries, old_footer) = read_index(&mut file, password, archive_flags)?;
    let encrypted = archive_flags & ARCHIVE_FLAG_ENCRYPTED != 0;
    let master_key = if encrypted {
        Some(crypto::derive_key_from_password(password.ok_or_else(|| {
            ZypherError::Format("Password required for encrypted archive".into())
        })?))
    } else {
        None
    };

    let mut current_offset = old_footer.index_offset;
    file.set_len(current_offset)?;
    file.seek(SeekFrom::End(0))?;

    let total = new_files.len();
    let method_code = method.code();

    let prepared: Vec<Result<(TocEntry, Vec<u8>), ZypherError>> = new_files
        .par_iter()
        .map(|path| {
            let original_data = fs::read(path)?;
            let original_size = original_data.len() as u64;
            let content_hash: [u8; 32] = blake3::hash(&original_data).into();

            let compressed = compress_data(&original_data, compression_level, &method)?;

            let name = path
                .file_name()
                .ok_or_else(|| ZypherError::Format("No file name".into()))?
                .to_str()
                .unwrap_or("unknown")
                .as_bytes()
                .to_vec();

            let (block_data, flags) = if let Some(ref mk) = master_key {
                let (file_key, _) = crypto::generate_file_key();
                let (wrapped_nonce, wrapped_key) = crypto::wrap_file_key(mk, &file_key);
                let (data_nonce, encrypted_compressed) =
                    crypto::encrypt_data(&file_key, &compressed);

                let mut block = Vec::new();
                block.extend_from_slice(&wrapped_nonce);
                block.extend_from_slice(&(wrapped_key.len() as u32).to_le_bytes());
                block.extend_from_slice(&wrapped_key);
                block.extend_from_slice(&data_nonce);
                block.extend_from_slice(&encrypted_compressed);

                (block, FLAG_COMPRESSED | FLAG_ENCRYPTED)
            } else {
                let mut block = Vec::new();
                block.extend_from_slice(&compressed);
                (block, FLAG_COMPRESSED)
            };

            let entry = TocEntry {
                file_name_len: name.len() as u16,
                file_name: name,
                offset: 0,
                compressed_size: block_data.len() as u64,
                original_size,
                content_hash,
                flags,
                compression_method: method_code,
            };

            Ok((entry, block_data))
        })
        .collect();

    let mut new_entries: Vec<TocEntry> = Vec::new();
    let mut first_error: Option<ZypherError> = None;

    for (i, prepared_item) in prepared.into_iter().enumerate() {
        match prepared_item {
            Ok((mut entry, block)) => {
                entry.offset = current_offset;
                file.write_all(&block)?;
                current_offset += block.len() as u64;
                new_entries.push(entry);
                progress_callback(i as f32 / total as f32);
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    let mut all_entries = old_entries;
    all_entries.extend(new_entries);

    let mut index_bytes = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut index_bytes);
    cursor.write_le(&(all_entries.len() as u32))?;
    for entry in &all_entries {
        cursor.write_le(entry)?;
    }

    let index_offset = current_offset;
    let (final_index_bytes, index_nonce) = if let Some(ref mk) = master_key {
        let (nonce, encrypted_index) = crypto::encrypt_data(mk, &index_bytes);
        (encrypted_index, nonce)
    } else {
        (index_bytes, [0u8; 12])
    };

    let index_size = final_index_bytes.len() as u32;
    file.write_all(&final_index_bytes)?;

    let footer = Footer {
        index_offset,
        index_size,
        index_hash: [0u8; 32],
        index_nonce,
    };
    let mut footer_bytes = Vec::new();
    let mut fw = std::io::Cursor::new(&mut footer_bytes);
    fw.write_le(&footer)?;
    file.write_all(&footer_bytes)?;

    progress_callback(1.0);
    Ok(())
}

pub fn create_sfx(archive_path: &PathBuf, output_sfx: &PathBuf) -> Result<(), ZypherError> {
    let current_exe = std::env::current_exe()
        .map_err(|e| ZypherError::Format(format!("Cannot get current exe: {}", e)))?;
    let mut archive_data = fs::read(archive_path)?;
    archive_data.extend_from_slice(b"SFX1");
    
    let mut sfx_file = fs::File::create(output_sfx)?;
    let exe_data = fs::read(&current_exe)?;
    sfx_file.write_all(&exe_data)?;
    sfx_file.write_all(&archive_data)?;
    Ok(())
}

pub fn try_run_sfx() -> Result<bool, ZypherError> {
    let exe_path = std::env::current_exe()
        .map_err(|e| ZypherError::Format(format!("Cannot get current exe: {}", e)))?;
    let mut file = fs::File::open(&exe_path)?;
    let file_len = file.metadata()?.len();
    if file_len < 4 {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-4))?;
    let mut marker = [0u8; 4];
    file.read_exact(&mut marker)?;
    if &marker != b"SFX1" {
        return Ok(false);
    }
    let mut buf = [0u8; 4];
    let search_start = file_len.saturating_sub(1024 * 1024);
    let mut offset = file_len - 4;
    while offset >= search_start {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        if &buf == MAGIC {
            let archive_start = offset;
            let archive_data_len = (file_len - 4) - archive_start;
            file.seek(SeekFrom::Start(archive_start))?;
            let mut archive_bytes = vec![0u8; archive_data_len as usize];
            file.read_exact(&mut archive_bytes)?;
            let temp_dir = std::env::temp_dir();
            let temp_archive = temp_dir.join("__sfx_temp.zypher");
            fs::write(&temp_archive, &archive_bytes)?;
            let output_dir = std::env::current_dir()
                .map_err(|e| ZypherError::Format(format!("current dir: {}", e)))?;
            crate::unpack::extract_all(&temp_archive, &output_dir, None, |_| {})?;
            fs::remove_file(&temp_archive)?;
            return Ok(true);
        }
        offset -= 1;
    }
    Ok(false)
}