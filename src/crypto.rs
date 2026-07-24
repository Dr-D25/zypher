use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use rand::RngCore;

pub const MASTER_KEY_SIZE: usize = 32;
pub const FILE_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const ARGON2_SALT: &[u8] = b"Zypher-archive-salt-v1";

pub fn derive_key_from_password(password: &str) -> [u8; MASTER_KEY_SIZE] {
    let mut key = [0u8; MASTER_KEY_SIZE];
    Argon2::default()
        .hash_password_into(password.as_bytes(), ARGON2_SALT, &mut key)
        .expect("Argon2 failed");
    key
}

pub fn generate_file_key() -> ([u8; FILE_KEY_SIZE], [u8; NONCE_SIZE]) {
    let mut key = [0u8; FILE_KEY_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);
    (key, nonce)
}

pub fn wrap_file_key(
    master_key: &[u8; MASTER_KEY_SIZE],
    file_key: &[u8; FILE_KEY_SIZE],
) -> ([u8; NONCE_SIZE], Vec<u8>) {
    let cipher = ChaCha20Poly1305::new_from_slice(master_key).unwrap();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let wrapped = cipher.encrypt(&nonce, file_key.as_ref()).unwrap();
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&nonce);
    (nonce_bytes, wrapped)
}

pub fn unwrap_file_key(
    master_key: &[u8; MASTER_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    wrapped: &[u8],
) -> Result<[u8; FILE_KEY_SIZE], String> {
    let cipher = ChaCha20Poly1305::new_from_slice(master_key).unwrap();
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, wrapped)
        .map_err(|e| format!("Failed to unwrap file key: {}", e))?;
    let mut key = [0u8; FILE_KEY_SIZE];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

pub fn encrypt_data(
    file_key: &[u8; FILE_KEY_SIZE],
    plaintext: &[u8],
) -> ([u8; NONCE_SIZE], Vec<u8>) {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).unwrap();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(&nonce);
    (nonce_bytes, ciphertext)
}

pub fn decrypt_data(
    file_key: &[u8; FILE_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(file_key).unwrap();
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}