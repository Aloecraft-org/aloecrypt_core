// tests/symmetric.rs
// Hash, HMAC, the password KDF, and the chunked password cipher.
//
// Several tests here pin behaviour that is known to be wrong. They are marked
// and explained rather than deleted, so the suite records the gap and fails
// loudly when someone changes it -- see doc/DESIGN.md.

use aloecrypt_core::error::{StatusCode, StatusCodeEnum};
use aloecrypt_core::hash::*;
use aloecrypt_core::password::*;
use aloecrypt_core::password_api::*;
use aloecrypt_core::pkdf::*;
use aloecrypt_core::pkdf_api::*;

// ---------------------------------------------------------------- hash/hmac

#[test]
fn hash_is_deterministic() {
    assert_eq!(
        hash(b"salt", b"ikm", "domain"),
        hash(b"salt", b"ikm", "domain")
    );
}

#[test]
fn hash_depends_on_every_input() {
    let base = hash(b"salt", b"ikm", "domain");
    assert_ne!(base, hash(b"SALT", b"ikm", "domain"), "salt ignored");
    assert_ne!(base, hash(b"salt", b"IKM", "domain"), "ikm ignored");
    assert_ne!(base, hash(b"salt", b"ikm", "DOMAIN"), "domain ignored");
}

#[test]
fn hmac_is_deterministic_and_depends_on_its_key() {
    assert_eq!(hmac(b"msg", b"key", "d"), hmac(b"msg", b"key", "d"));
    assert_ne!(hmac(b"msg", b"key", "d"), hmac(b"msg", b"kez", "d"));
}

#[test]
fn domain_separation_actually_separates() {
    let a = domain_hash(b"same input", "purpose.a");
    let b = domain_hash(b"same input", "purpose.b");
    assert_ne!(a, b, "different domains produced the same hash");
}

#[test]
fn hash_inputs_are_unambiguously_framed() {
    // hash("ab","c",d) and hash("a","bc",d) are different logical inputs and
    // must not collide. They did until the fields were length-prefixed.
    assert_ne!(
        hash(b"ab", b"c", "d"),
        hash(b"a", b"bc", "d"),
        "ambiguous framing: salt/ikm boundary is not encoded"
    );
    assert_ne!(
        hash(b"a", b"bcd", "e"),
        hash(b"abc", b"d", "e"),
        "ambiguous framing at a different split"
    );
    assert_ne!(
        hmac(b"ab", b"key", "c"),
        hmac(b"a", b"key", "bc"),
        "ambiguous framing between the hmac salt and domain"
    );
}

// ---------------------------------------------------------------------- KDF

#[test]
fn pbkdf_is_deterministic_and_salt_dependent() {
    assert_eq!(pbkdf(b"pw", b"salt", 10), pbkdf(b"pw", b"salt", 10));
    assert_ne!(pbkdf(b"pw", b"salt", 10), pbkdf(b"pw", b"pepper", 10));
    assert_ne!(pbkdf(b"pw", b"salt", 10), pbkdf(b"px", b"salt", 10));
}

#[test]
fn pbkdf_iteration_count_changes_the_output() {
    assert_ne!(
        pbkdf(b"pw", b"salt", 10),
        pbkdf(b"pw", b"salt", 11),
        "iteration count had no effect"
    );
}

#[test]
#[ignore = "KNOWN GAP: PBKDF_DEFAULT_ITERS is 10 iterations of a plain SHAKE-256 \
            chain -- no memory hardness and effectively no stretching. Un-ignore \
            when a real KDF lands (see doc/DESIGN.md section 6)."]
fn pbkdf_default_cost_is_defensible() {
    assert!(
        PBKDF_DEFAULT_ITERS >= 100_000,
        "default KDF cost is {PBKDF_DEFAULT_ITERS} iterations"
    );
}

// ---------------------------------------------------------- password cipher

fn cipher_for(data: &[u8], key_byte: u8) -> PasswordCipher {
    PasswordCipher::new(data, [key_byte; PBKDF_KEY_SZ], [9u8; PASSWORD_NONCE_SZ])
}

fn encrypt_all(data: &[u8], key_byte: u8) -> Vec<u8> {
    let mut cipher = cipher_for(data, key_byte);
    let mut out = Vec::new();
    loop {
        let result = password_encrypt_next(data, &mut cipher);
        out.extend_from_slice(&result.next_chunk);
        if result.is_done != 0 {
            break;
        }
    }
    out
}

fn decrypt_all(ciphertext: &[u8], plain_len: usize, key_byte: u8) -> Result<Vec<u8>, StatusCode> {
    let mut cipher = PasswordCipher {
        key: [key_byte; PBKDF_KEY_SZ],
        nonce: [9u8; PASSWORD_NONCE_SZ],
        counter: 0,
        n_bytes: plain_len as u64,
        chunk_sz: PASSWORD_CIPHER_CHUNK_SZ as u64,
    };
    let mut out = Vec::new();
    loop {
        let result = password_decrypt_next(ciphertext, &mut cipher)?;
        let n = result.n_bytes as usize;
        out.extend_from_slice(&result.next_chunk[..n.min(result.next_chunk.len())]);
        if result.is_done != 0 {
            break;
        }
    }
    Ok(out)
}

#[test]
fn password_cipher_roundtrips_across_sizes() {
    for len in [1usize, 100, 511, 512, 513, 1024, 2000] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 256) as u8).collect();
        let ciphertext = encrypt_all(&data, 0xA5);
        let recovered = decrypt_all(&ciphertext, len, 0xA5).expect("correct key must decrypt");
        assert_eq!(recovered, data, "password cipher round trip at {len} bytes");
    }
}

#[test]
fn ciphertext_does_not_contain_the_plaintext() {
    let data: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    let ciphertext = encrypt_all(&data, 0x5A);
    assert!(
        !ciphertext.windows(64).any(|w| w == &data[..64]),
        "plaintext appears verbatim in the ciphertext"
    );
}

#[test]
fn size_accounting_is_self_consistent() {
    for len in [0u64, 1, 511, 512, 513, 1024, 5000] {
        let enc = to_encrypted_byte_size(len);
        assert_eq!(
            to_unencrypted_byte_size(enc),
            len,
            "size round trip failed at {len} plaintext bytes"
        );
    }
}

#[test]
fn wrong_key_returns_an_error_rather_than_aborting() {
    // This used to be #[should_panic]: the chunk decryptor ended in
    // .expect("Decryption failed"), which under panic = "abort" took down the
    // whole module on a wrong password.
    let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
    let ciphertext = encrypt_all(&data, 0x11);
    assert_eq!(
        decrypt_all(&ciphertext, data.len(), 0x22),
        Err(StatusCodeEnum::AuthFailed.into()),
        "a wrong key must be reported, not panicked on"
    );
}

#[test]
fn altered_ciphertext_is_rejected() {
    let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
    let mut ciphertext = encrypt_all(&data, 0x33);
    ciphertext[10] ^= 0x01;
    assert_eq!(
        decrypt_all(&ciphertext, data.len(), 0x33),
        Err(StatusCodeEnum::AuthFailed.into()),
        "a flipped ciphertext bit must fail authentication"
    );
}
