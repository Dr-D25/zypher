use crate::crypto;
use crate::error::ZypherError;
use crate::format::{
    Footer, TocEntry, ARCHIVE_FLAG_ENCRYPTED, FLAG_COMPRESSED, FLAG_ENCRYPTED, MAGIC,
    COMPRESSION_ZSTD, COMPRESSION_LZ4, COMPRESSION_BROTLI,
};
use binrw::BinReaderExt;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

const FOOTER_SIZE: i64 = 56;

fn open_archive(archive_path: &PathBuf) -> Result<(fs::File, u16), ZypherError> {
    let mut file = fs::File::open(archive_path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(ZypherError::Format("Invalid magic".into()));
    }
    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)?;
    let mut flags_bytes = [0u8; 2];
    file.read_exact(&mut flags_bytes)?;
    let archive_flags = u16::from_le_bytes(flags_bytes);
    Ok((file, archive_flags))
}

fn get_index(
    file: &mut fs::File,
    password: Option<&str>,
    archive_flags: u16,
) -> Result<Vec<TocEntry>, ZypherError> {
    let encrypted = archive_flags & ARCHIVE_FLAG_ENCRYPTED != 0;
    file.seek(SeekFrom::End(-FOOTER_SIZE))?;
    let footer: Footer = file.read_le()?;
    file.seek(SeekFrom::Start(footer.index_offset))?;
    let mut encrypted_index = vec![0u8; footer.index_size as usize];
    file.read_exact(&mut encrypted_index)?;

    let index_bytes = if encrypted {
        let master_key = match password {
            Some(p) => crypto::derive_key_from_password(p),
            None => return Err(ZypherError::Format(
                "Archive is encrypted, password required".into(),
            )),
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
    Ok(entries)
}

fn decompress_data(data: &[u8], method: u8) -> Result<Vec<u8>, ZypherError> {
    match method {
        COMPRESSION_ZSTD => {
            zstd::decode_all(data)
                .map_err(|e| ZypherError::Format(format!("Zstd decode: {}", e)))
        }
        COMPRESSION_LZ4 => {
            let mut decompressed = Vec::new();
            let mut decoder = lz4::Decoder::new(data)
                .map_err(|e| ZypherError::Format(format!("LZ4 decoder: {}", e)))?;
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| ZypherError::Format(format!("LZ4 read: {}", e)))?;
            Ok(decompressed)
        }
        COMPRESSION_BROTLI => {
            let mut decompressed = Vec::new();
            brotli::Decompressor::new(data, 4096)
                .read_to_end(&mut decompressed)
                .map_err(|e| ZypherError::Format(format!("Brotli decompress: {}", e)))?;
            Ok(decompressed)
        }
        _ => Err(ZypherError::Format(format!("Unknown compression method: {}", method))),
    }
}

fn verify_single_file(
    file: &mut fs::File,
    entry: &TocEntry,
    password: Option<&str>,
) -> Result<(), ZypherError> {
    let encrypted = entry.flags & FLAG_ENCRYPTED != 0;
    let compressed = entry.flags & FLAG_COMPRESSED != 0;

    file.seek(SeekFrom::Start(entry.offset))?;
    let mut block = vec![0u8; entry.compressed_size as usize];
    file.read_exact(&mut block)?;

    let compressed_data = if encrypted {
        let master_key = match password {
            Some(p) => crypto::derive_key_from_password(p),
            None => return Err(ZypherError::Format("Password required".into())),
        };
        if block.len() < 12 + 4 {
            return Err(ZypherError::Format("Encrypted block too short".into()));
        }
        let wrapped_nonce: [u8; 12] = block[..12].try_into().unwrap();
        let len_wrapped = u32::from_le_bytes(block[12..16].try_into().unwrap()) as usize;
        let wrapped_key = &block[16..16 + len_wrapped];
        let data_nonce_offset = 16 + len_wrapped;
        if block.len() < data_nonce_offset + 12 {
            return Err(ZypherError::Format("Encrypted block missing data nonce".into()));
        }
        let data_nonce: [u8; 12] = block[data_nonce_offset..data_nonce_offset + 12]
            .try_into()
            .unwrap();
        let encrypted_data = &block[data_nonce_offset + 12..];

        let file_key = crypto::unwrap_file_key(&master_key, &wrapped_nonce, wrapped_key)
            .map_err(|e| ZypherError::Format(e))?;
        crypto::decrypt_data(&file_key, &data_nonce, encrypted_data)
            .map_err(|e| ZypherError::Format(e))?
    } else {
        block
    };

    let original_data = if compressed {
        decompress_data(&compressed_data, entry.compression_method)?
    } else {
        compressed_data
    };

    let actual_hash: [u8; 32] = blake3::hash(&original_data).into();
    if actual_hash != entry.content_hash {
        return Err(ZypherError::Format(format!(
            "Hash mismatch: expected {:?}, got {:?}",
            entry.content_hash, actual_hash
        )));
    }
    Ok(())
}

fn extract_single_file(
    file: &mut fs::File,
    entry: &TocEntry,
    output_dir: &PathBuf,
    password: Option<&str>,
) -> Result<(), ZypherError> {
    let encrypted = entry.flags & FLAG_ENCRYPTED != 0;
    let compressed = entry.flags & FLAG_COMPRESSED != 0;

    file.seek(SeekFrom::Start(entry.offset))?;
    let mut block = vec![0u8; entry.compressed_size as usize];
    file.read_exact(&mut block)?;

    let compressed_data = if encrypted {
        let master_key = match password {
            Some(p) => crypto::derive_key_from_password(p),
            None => return Err(ZypherError::Format("Password required".into())),
        };
        if block.len() < 12 + 4 {
            return Err(ZypherError::Format("Encrypted block too short".into()));
        }
        let wrapped_nonce: [u8; 12] = block[..12].try_into().unwrap();
        let len_wrapped = u32::from_le_bytes(block[12..16].try_into().unwrap()) as usize;
        let wrapped_key = &block[16..16 + len_wrapped];
        let data_nonce_offset = 16 + len_wrapped;
        if block.len() < data_nonce_offset + 12 {
            return Err(ZypherError::Format("Encrypted block missing data nonce".into()));
        }
        let data_nonce: [u8; 12] = block[data_nonce_offset..data_nonce_offset + 12]
            .try_into()
            .unwrap();
        let encrypted_data = &block[data_nonce_offset + 12..];

        let file_key = crypto::unwrap_file_key(&master_key, &wrapped_nonce, wrapped_key)
            .map_err(|e| ZypherError::Format(e))?;
        crypto::decrypt_data(&file_key, &data_nonce, encrypted_data)
            .map_err(|e| ZypherError::Format(e))?
    } else {
        block
    };

    let original_data = if compressed {
        decompress_data(&compressed_data, entry.compression_method)?
    } else {
        compressed_data
    };

    let actual_hash: [u8; 32] = blake3::hash(&original_data).into();
    if actual_hash != entry.content_hash {
        return Err(ZypherError::Format(format!(
            "Hash mismatch for '{}': expected {:?}, got {:?}",
            String::from_utf8_lossy(&entry.file_name),
            entry.content_hash,
            actual_hash
        )));
    }

    let output_path = output_dir.join(String::from_utf8_lossy(&entry.file_name).to_string());
    fs::write(&output_path, &original_data)?;
    Ok(())
}

pub fn verify_archive(
    archive_path: &PathBuf,
    password: Option<&str>,
    progress_callback: impl Fn(f32),
) -> Result<(), ZypherError> {
    let (mut file, archive_flags) = open_archive(archive_path)?;
    let entries = get_index(&mut file, password, archive_flags)?;
    let total = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        progress_callback(i as f32 / total as f32);
        let _ = verify_single_file(&mut file, entry, password);
    }
    progress_callback(1.0);
    Ok(())
}

pub fn extract_all(
    archive_path: &PathBuf,
    output_dir: &PathBuf,
    password: Option<&str>,
    progress_callback: impl Fn(f32),
) -> Result<(), ZypherError> {
    let (mut file, archive_flags) = open_archive(archive_path)?;
    let entries = get_index(&mut file, password, archive_flags)?;
    fs::create_dir_all(output_dir)?;
    let total = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        progress_callback(i as f32 / total as f32);
        let _ = extract_single_file(&mut file, entry, output_dir, password);
    }
    progress_callback(1.0);
    Ok(())
}

pub fn extract_file(
    archive_path: &PathBuf,
    file_name: &str,
    output_dir: &PathBuf,
    password: Option<&str>,
) -> Result<(), ZypherError> {
    let (mut file, archive_flags) = open_archive(archive_path)?;
    let entries = get_index(&mut file, password, archive_flags)?;
    let entry = entries
        .iter()
        .find(|e| String::from_utf8_lossy(&e.file_name) == file_name)
        .ok_or(ZypherError::FileNotFound(file_name.into()))?;
    extract_single_file(&mut file, entry, output_dir, password)
}

pub fn list_files(archive_path: &PathBuf, password: Option<&str>) -> Result<(), ZypherError> {
    let (mut file, archive_flags) = open_archive(archive_path)?;
    let entries = get_index(&mut file, password, archive_flags)?;
    println!("Files in archive:");
    for entry in entries {
        let name = String::from_utf8_lossy(&entry.file_name);
        let comp_str = match entry.compression_method {
            COMPRESSION_ZSTD => "zstd",
            COMPRESSION_LZ4 => "lz4",
            COMPRESSION_BROTLI => "brotli",
            _ => "unknown",
        };
        let flags_str = match (entry.flags & FLAG_COMPRESSED != 0, entry.flags & FLAG_ENCRYPTED != 0) {
            (true, true) => format!("compressed({})+encrypted", comp_str),
            (true, false) => format!("compressed({})", comp_str),
            (false, true) => "encrypted".into(),
            _ => "none".into(),
        };
        println!(
            "  {} (orig: {} bytes, stored: {} bytes, flags: {})",
            name, entry.original_size, entry.compressed_size, flags_str
        );
    }
    Ok(())
}