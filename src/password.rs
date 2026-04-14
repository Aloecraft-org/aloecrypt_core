// src/password.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::core_api::*;
use super::password_api::*;
use super::*;

pub const EMPTY_PASSWORD_ENCRYPTED_CHUNK: PasswordEncryptedChunk =
    [0u8; PASSWORD_CIPHER_CHUNK_SZ as usize + ENCRYPTED_TAG_SZ];
pub const EMPTY_PASSWORD_UNENCRYPTED_CHUNK: PasswordUnencryptedChunk =
    [0u8; PASSWORD_CIPHER_CHUNK_SZ as usize];

impl IPasswordCipher for PasswordCipher {
    fn new(data: &[u8], key: PbkdfKey, nonce: PasswordNonce) -> Self {
        Self {
            key,
            nonce,
            counter: 0u32,
            n_bytes: data.len() as u64,
            chunk_sz: PASSWORD_CIPHER_CHUNK_SZ as u64,
        }
    }
}

pub fn to_encrypted_byte_size(unencrypted_byte_size: u64) -> u64 {
    if unencrypted_byte_size == 0 {
        return 0;
    }
    let chunk_sz = PASSWORD_CIPHER_CHUNK_SZ as u64;
    let tag_sz = ENCRYPTED_TAG_SZ as u64;
    let num_chunks = (unencrypted_byte_size + chunk_sz - 1) / chunk_sz;
    unencrypted_byte_size + (num_chunks * tag_sz)
}

pub fn to_unencrypted_byte_size(encrypted_byte_size: u64) -> u64 {
    if encrypted_byte_size == 0 {
        return 0;
    }
    let chunk_sz = PASSWORD_CIPHER_CHUNK_SZ as u64;
    let tag_sz = ENCRYPTED_TAG_SZ as u64;
    let encrypted_chunk_sz = chunk_sz + tag_sz;
    let full_chunks = encrypted_byte_size / encrypted_chunk_sz;
    let remainder = encrypted_byte_size % encrypted_chunk_sz;
    let remainder_data = remainder.saturating_sub(tag_sz);
    (full_chunks * chunk_sz) + remainder_data
}

pub fn password_encrypt_next_chunk(
    chunk: PasswordUnencryptedChunk,
    mut cipher: PasswordCipher,
) -> EncryptChunkResult {
    let mut current_nonce = EMPTY_PASSWORD_NONCE;
    current_nonce[7..11].copy_from_slice(&cipher.counter.to_le_bytes());
    for (c, n) in current_nonce.iter_mut().zip(cipher.nonce.iter()) {
        *c ^= *n;
    }

    let mut next_chunk = EMPTY_PASSWORD_ENCRYPTED_CHUNK;

    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{AeadInPlace, KeyInit},
    };

    let offset = (cipher.counter as u64 + 1) * cipher.chunk_sz;
    let is_done = (offset >= cipher.n_bytes) as u8;

    let (data_part, tag_part) = next_chunk.split_at_mut(PASSWORD_CIPHER_CHUNK_SZ);
    data_part.copy_from_slice(&chunk);

    let aead = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&cipher.key));
    let nonce = Nonce::from_slice(&current_nonce);

    let tag = aead
        .encrypt_in_place_detached(nonce, b"", data_part)
        .expect("Encryption failed");
    tag_part.copy_from_slice(&tag);

    cipher.counter = match is_done == 1 {
        true => 0,
        false => cipher.counter + 1,
    };
    EncryptChunkResult {
        cipher: cipher,
        next_chunk,
        is_done,
    }
}

pub fn password_decrypt_next_chunk(
    chunk: PasswordEncryptedChunk,
    mut cipher: PasswordCipher,
) -> DecryptChunkResult {
    let mut current_nonce = EMPTY_PASSWORD_NONCE;
    current_nonce[7..11].copy_from_slice(&cipher.counter.to_le_bytes());
    for (c, n) in current_nonce.iter_mut().zip(cipher.nonce.iter()) {
        *c ^= *n;
    }

    let mut next_chunk = EMPTY_PASSWORD_UNENCRYPTED_CHUNK;

    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{AeadInPlace, KeyInit},
    };

    let offset = (cipher.counter as u64 + 1) * cipher.chunk_sz;
    let is_done = (offset >= cipher.n_bytes) as u8;

    let remaining = cipher
        .n_bytes
        .saturating_sub(cipher.counter as u64 * cipher.chunk_sz);
    let n_bytes = if is_done != 0 {
        remaining as u16
    } else {
        cipher.chunk_sz as u16
    };

    let (data_part, tag_part) = chunk.split_at(PASSWORD_CIPHER_CHUNK_SZ);
    next_chunk.copy_from_slice(data_part);

    let aead = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&cipher.key));
    let nonce = Nonce::from_slice(&current_nonce);

    aead.decrypt_in_place_detached(nonce, b"", &mut next_chunk, tag_part.into())
        .expect("Decryption failed");

    cipher.counter = match is_done != 0 {
        true => 0,
        false => cipher.counter + 1,
    };
    DecryptChunkResult {
        cipher: cipher,
        next_chunk,
        n_bytes,
        is_done,
    }
}

pub fn password_encrypt_next(data: &[u8], cipher: &mut PasswordCipher) -> EncryptChunkResult {
    let offset = (cipher.counter as u64 * cipher.chunk_sz) as usize;
    let mut unencrypted_chunk = EMPTY_PASSWORD_UNENCRYPTED_CHUNK;

    let remaining = data.len().saturating_sub(offset);
    let len_to_copy = core::cmp::min(remaining, cipher.chunk_sz as usize);

    if len_to_copy > 0 {
        unencrypted_chunk[..len_to_copy].copy_from_slice(&data[offset..offset + len_to_copy]);
    }

    let cipher_val = PasswordCipher {
        key: cipher.key,
        nonce: cipher.nonce,
        counter: cipher.counter,
        n_bytes: cipher.n_bytes,
        chunk_sz: cipher.chunk_sz,
    };

    let result = password_encrypt_next_chunk(unencrypted_chunk, cipher_val);
    cipher.counter = result.cipher.counter;

    result
}

pub fn password_decrypt_next(data: &[u8], cipher: &mut PasswordCipher) -> DecryptChunkResult {
    let encrypted_chunk_sz = PASSWORD_CIPHER_CHUNK_SZ + ENCRYPTED_TAG_SZ;
    let offset = (cipher.counter as usize) * encrypted_chunk_sz;
    let mut encrypted_chunk = EMPTY_PASSWORD_ENCRYPTED_CHUNK;

    let remaining = data.len().saturating_sub(offset);
    let len_to_copy = core::cmp::min(remaining, encrypted_chunk_sz);

    if len_to_copy > 0 {
        encrypted_chunk[..len_to_copy].copy_from_slice(&data[offset..offset + len_to_copy]);
    }

    let cipher_val = PasswordCipher {
        key: cipher.key,
        nonce: cipher.nonce,
        counter: cipher.counter,
        n_bytes: cipher.n_bytes,
        chunk_sz: cipher.chunk_sz,
    };

    let result = password_decrypt_next_chunk(encrypted_chunk, cipher_val);
    cipher.counter = result.cipher.counter;

    result
}
// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
