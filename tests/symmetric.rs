// tests/symmetric.rs
// Hash, HMAC, the password KDF, and the chunked password cipher.

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
    assert_eq!(pbkdf(b"pw", b"salt", 1), pbkdf(b"pw", b"salt", 1));
    assert_ne!(pbkdf(b"pw", b"salt", 1), pbkdf(b"pw", b"pepper", 1));
    assert_ne!(pbkdf(b"pw", b"salt", 1), pbkdf(b"px", b"salt", 1));
}

#[test]
fn pbkdf_iteration_count_changes_the_output() {
    assert_ne!(
        pbkdf(b"pw", b"salt", 1),
        pbkdf(b"pw", b"salt", 2),
        "iteration count had no effect"
    );
}

#[test]
fn pbkdf_accepts_any_salt_length() {
    // Argon2 itself rejects salts under 8 bytes; the API contract here has
    // always been "any salt, including none", which the salt normalization
    // preserves. An empty salt must work and still differ from a present one.
    let none = pbkdf(b"pw", b"", 1);
    let long = pbkdf(b"pw", &[7u8; 100], 1);
    assert_ne!(none, long, "salt ignored after normalization");
    assert_eq!(
        none,
        pbkdf_with_iters(b"pw", 1),
        "empty-salt paths disagree"
    );
}

#[test]
fn pbkdf_zero_iterations_clamps_rather_than_panics() {
    // t_cost 0 is outside Argon2's domain; the wire can still send it. It
    // must derive at the minimum pass count, not take the module down.
    assert_eq!(pbkdf(b"pw", b"salt", 0), pbkdf(b"pw", b"salt", 1));
}

// This was #[ignore]d while pbkdf was ten iterations of a plain SHAKE-256
// chain -- no memory hardness, no stretching. It now derives with Argon2id,
// and these are the floors the defaults must not quietly sink below.
#[test]
fn pbkdf_default_cost_is_defensible() {
    #[cfg(feature = "host_kdf")]
    {
        // The OWASP-recommended Argon2id tier: 19 MiB, 2 passes.
        assert!(PBKDF_M_COST_KIB >= 19 * 1024, "hosted memory cost lowered");
        assert!(PBKDF_DEFAULT_ITERS >= 2, "hosted pass count lowered");
    }
    #[cfg(not(feature = "host_kdf"))]
    {
        // Memory is capped by the device; passes partially compensate.
        assert!(PBKDF_M_COST_KIB >= 64, "embedded memory cost lowered");
        assert!(PBKDF_DEFAULT_ITERS >= 4, "embedded pass count lowered");
    }
}

// Pinned against argon2-cffi (the phc-winner-argon2 C reference): Argon2id
// v19, p=1, 32-byte output, salt = keccak256 of the length-framed fields
// ("", "salt", "aloecrypt.pkdf.salt.v1"). Any change here changes every key
// ever derived from a password, so drift must be deliberate, not accidental.
#[test]
fn pbkdf_output_matches_the_reference_implementation() {
    #[cfg(feature = "host_kdf")]
    // m=19456, t=1
    const EXPECTED: [u8; PBKDF_KEY_SZ] = [
        0x3f, 0x0c, 0xc3, 0x6f, 0x09, 0x41, 0xf7, 0xb8, 0xba, 0xa7, 0x98, 0x57, 0x10, 0x12, 0x19,
        0x1c, 0x17, 0x94, 0x66, 0xdb, 0xc7, 0x9a, 0x71, 0x32, 0x56, 0x8a, 0x1d, 0xbd, 0x72, 0xa2,
        0xa7, 0x9c,
    ];
    #[cfg(not(feature = "host_kdf"))]
    // m=64, t=1
    const EXPECTED: [u8; PBKDF_KEY_SZ] = [
        0x97, 0x56, 0x3a, 0x90, 0x8d, 0xe9, 0x27, 0x61, 0x70, 0x8c, 0x81, 0xa1, 0x79, 0xbf, 0xf4,
        0x37, 0x3f, 0xee, 0x62, 0x16, 0xb6, 0x9b, 0x15, 0x68, 0x9d, 0xb9, 0x01, 0x21, 0x18, 0x99,
        0x95, 0x09,
    ];
    assert_eq!(pbkdf(b"password", b"salt", 1), EXPECTED);
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
