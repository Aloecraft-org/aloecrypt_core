// tests/totp.rs
// TOTP against the RFC 6238 Appendix B reference vectors.
//
// These matter because TOTP is the one place the library deliberately
// interoperates with existing implementations. The SHA-1 rows are not an
// endorsement of SHA-1; they are the compatibility contract.

use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::totp_api::*;

/// RFC 6238 seeds, base32-encoded for the otpauth URI.
const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SEED_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

fn credential(secret: &str, algorithm: &str) -> TotpCredential {
    let uri = format!(
        "otpauth://totp/Example:alice@example.com?secret={secret}&algorithm={algorithm}&digits=8&period=30"
    );
    TotpCredential::from_uri(&uri)
}

/// Render the digit array the way a user would read it.
fn code(result: [i8; 8], digits: usize) -> String {
    result[..digits]
        .iter()
        .map(|d| char::from_digit(*d as u32, 10).expect("digit out of range"))
        .collect()
}

#[test]
fn rfc6238_sha1_vectors() {
    let cred = credential(SEED_SHA1, "SHA1");
    for (time, expected) in [
        (59u64, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ] {
        assert_eq!(
            code(cred.generate(time), 8),
            expected,
            "RFC 6238 SHA-1 vector at T={time}"
        );
    }
}

#[test]
fn rfc6238_sha256_vectors() {
    let cred = credential(SEED_SHA256, "SHA256");
    for (time, expected) in [
        (59u64, "46119246"),
        (1111111109, "68084774"),
        (1234567890, "91819424"),
    ] {
        assert_eq!(
            code(cred.generate(time), 8),
            expected,
            "RFC 6238 SHA-256 vector at T={time}"
        );
    }
}

#[test]
fn rfc6238_sha512_vectors() {
    let cred = credential(SEED_SHA512, "SHA512");
    for (time, expected) in [(59u64, "90693936"), (1234567890, "93441116")] {
        assert_eq!(
            code(cred.generate(time), 8),
            expected,
            "RFC 6238 SHA-512 vector at T={time}"
        );
    }
}

#[test]
fn codes_are_stable_within_a_step_and_change_across_it() {
    let cred = credential(SEED_SHA1, "SHA1");
    assert_eq!(cred.generate(0), cred.generate(29), "same 30s step");
    assert_ne!(cred.generate(29), cred.generate(30), "step boundary");
}

#[test]
fn post_quantum_hashes_are_selectable_and_differ_from_sha1() {
    // Not a compatibility claim -- TOTP is a shared-secret HMAC scheme with no
    // asymmetric primitive, so a stronger hash is a hash upgrade and not a
    // post-quantum one. This only asserts the option is wired up.
    let sha1 = credential(SEED_SHA1, "SHA1").generate(59);
    for algorithm in ["SHA3-256", "KECCAK256"] {
        let other = credential(SEED_SHA1, algorithm).generate(59);
        assert_ne!(sha1, other, "{algorithm} produced the SHA-1 code");
    }
}

#[test]
fn uri_parsing_rejects_malformed_input() {
    for bad in [
        "not a uri",
        "https://totp/x?secret=GEZDGNBVGY3TQOJQ",
        "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ",
        "otpauth://totp/x",
    ] {
        let cred = TotpCredential::from_uri(bad);
        assert_eq!(
            cred.secret.to_byte_arr(),
            &[] as &[u8],
            "malformed URI {bad:?} produced a credential with a secret"
        );
    }
}

#[test]
fn digits_and_period_are_honoured() {
    let uri =
        format!("otpauth://totp/Example:a?secret={SEED_SHA1}&algorithm=SHA1&digits=6&period=60");
    let cred = TotpCredential::from_uri(&uri);
    // Generated structs are #[repr(C, packed)], so fields must be copied to a
    // local before they can be referenced -- `assert_eq!(cred.digits, 6)` is a
    // compile error (E0793), not just a lint.
    let (digits, period) = (cred.digits, cred.step_seconds);
    assert_eq!(digits, 6);
    assert_eq!(period, 60);
    let result = cred.generate(59);
    assert_eq!(result[6], -1, "unused digit slots should stay -1");
    assert_eq!(result[7], -1, "unused digit slots should stay -1");
}
