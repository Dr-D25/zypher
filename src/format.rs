use binrw::{BinRead, BinWrite};

pub const MAGIC: &[u8; 4] = b"ZYPR";
pub const CURRENT_VERSION: u16 = 2;

pub const COMPRESSION_ZSTD: u8 = 0;
pub const COMPRESSION_LZ4: u8  = 1;
pub const COMPRESSION_BROTLI: u8 = 2;

pub const FLAG_COMPRESSED: u16 = 0x01;
pub const FLAG_ENCRYPTED: u16 = 0x02;
pub const ARCHIVE_FLAG_ENCRYPTED: u16 = 0x01;

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(magic = b"ENTR")]
pub struct TocEntry {
    pub file_name_len: u16,
    #[br(count = file_name_len)]
    pub file_name: Vec<u8>,
    pub offset: u64,
    pub compressed_size: u64,
    pub original_size: u64,
    pub content_hash: [u8; 32],
    pub flags: u16,
    pub compression_method: u8,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct Footer {
    pub index_offset: u64,
    pub index_size: u32,
    pub index_hash: [u8; 32],
    pub index_nonce: [u8; 12],
}