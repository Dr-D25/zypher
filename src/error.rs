use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZypherError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("BinRW error: {0}")]
    BinRw(#[from] binrw::Error),
    #[error("Invalid archive format: {0}")]
    Format(String),
    #[error("File not found in archive: {0}")]
    FileNotFound(String),
}