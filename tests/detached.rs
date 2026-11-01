// tests/detached.rs
// Detached signatures over the document envelope, and address derivation.

use aloecrypt_core::aloecrypt_api::{AloecryptAddress, AloecryptAlgorithmEnum};
use aloecrypt_core::document::*;
use aloecrypt_core::document_api::*;
use aloecrypt_core::dsa_api::*;
use aloecrypt_core::error::{StatusCode, StatusCodeEnum};

const MSG: &[u8] = b"aloecrypt detached signature fixture";

// Signed once from seed [7; 32] and pinned. Verifying it locks the whole
// construction at once: the envelope layout, the signature section format,
// the address domain string, the detached signing domain string, and
// ML-DSA's deterministic signing -- a silent change to any of them makes
// this document unverifiable.
const FIXTURE_44: &str = include_str!("fixtures/detached_44.asc");

fn code(c: StatusCodeEnum) -> StatusCode {
    c.into()
}

fn kp44() -> MlDsa44Keypair {
    MlDsa44Keypair::from_seed(&[7u8; MLDSA_SEED_SZ])
}
fn kp65() -> MlDsa65Keypair {
    MlDsa65Keypair::from_seed(&[7u8; MLDSA_SEED_SZ])
}
fn kp87() -> MlDsa87Keypair {
    MlDsa87Keypair::from_seed(&[7u8; MLDSA_SEED_SZ])
}

fn signed_44(msg: &[u8]) -> Vec<u8> {
    let mut doc = vec![0u8; detached_signature_size(MLDSA_44_SIGNATURE_SZ)];
    let n = sign_detached_44(&kp44(), msg, &mut doc).unwrap();
    assert_eq!(n, doc.len(), "detached_signature_size disagrees with sign");
    doc
}

// ----------------------------------------------------------------- fixture

#[test]
fn the_pinned_fixture_still_verifies() {
    let mut doc = vec![0u8; dearmored_size_bound(FIXTURE_44.len())];
    let n = dearmor(FIXTURE_44.as_bytes(), SIGNATURE_LABEL, &mut doc).unwrap();
    assert_eq!(
        verify_detached_44(&kp44().get_verifier(), MSG, &doc[..n]),
        Ok(())
    );
}

#[test]
fn signing_is_deterministic_and_reproduces_the_fixture() {
    let doc = signed_44(MSG);
    assert_eq!(
        doc,
        signed_44(MSG),
        "two signatures over one message differ"
    );

    let mut text = vec![0u8; armored_size(SIGNATURE_LABEL.len(), doc.len())];
    let n = armor(SIGNATURE_LABEL, &doc, &mut text).unwrap();
    assert_eq!(
        core::str::from_utf8(&text[..n]).unwrap(),
        FIXTURE_44,
        "the construction drifted from the pinned document"
    );
}

// ---------------------------------------------------------------- addresses

#[test]
fn the_address_derivation_is_pinned() {
    let expected: AloecryptAddress = [
        0x06, 0x2b, 0x93, 0xdb, 0x37, 0x33, 0x13, 0xde, 0x81, 0x7c, 0xcf, 0x11, 0xcb, 0xe8, 0xe3,
        0xa0, 0x35, 0x9c, 0x5b, 0x20, 0x2a, 0x54, 0x8a, 0xfd, 0x2e, 0x56, 0xf3, 0x98, 0x44, 0x71,
        0xb1, 0xff,
    ];
    assert_eq!(kp44().address(), expected);
}

#[test]
fn keypair_and_verifier_agree_on_the_address() {
    assert_eq!(kp44().address(), kp44().get_verifier().address());
    assert_eq!(kp65().address(), kp65().get_verifier().address());
    assert_eq!(kp87().address(), kp87().get_verifier().address());
}

#[test]
fn addresses_are_distinct_across_algorithms_and_keys() {
    // One seed, three parameter sets: three addresses. And two seeds under
    // one parameter set: two addresses.
    let a44 = kp44().address();
    let a65 = kp65().address();
    let a87 = kp87().address();
    assert_ne!(a44, a65);
    assert_ne!(a44, a87);
    assert_ne!(a65, a87);
    let other = MlDsa44Keypair::from_seed(&[8u8; MLDSA_SEED_SZ]);
    assert_ne!(a44, other.address());
}

// -------------------------------------------------------------- round trips

#[test]
fn detached_signatures_round_trip_at_every_level() {
    let msg = b"a message worth signing";

    let doc = {
        let mut d = vec![0u8; detached_signature_size(MLDSA_44_SIGNATURE_SZ)];
        let n = sign_detached_44(&kp44(), msg, &mut d).unwrap();
        d.truncate(n);
        d
    };
    assert_eq!(
        verify_detached_44(&kp44().get_verifier(), msg, &doc),
        Ok(())
    );

    let doc = {
        let mut d = vec![0u8; detached_signature_size(MLDSA_65_SIGNATURE_SZ)];
        let n = sign_detached_65(&kp65(), msg, &mut d).unwrap();
        d.truncate(n);
        d
    };
    assert_eq!(
        verify_detached_65(&kp65().get_verifier(), msg, &doc),
        Ok(())
    );

    let doc = {
        let mut d = vec![0u8; detached_signature_size(MLDSA_87_SIGNATURE_SZ)];
        let n = sign_detached_87(&kp87(), msg, &mut d).unwrap();
        d.truncate(n);
        d
    };
    assert_eq!(
        verify_detached_87(&kp87().get_verifier(), msg, &doc),
        Ok(())
    );
}

// ------------------------------------------------------------------ tamper

#[test]
fn a_changed_message_fails() {
    let doc = signed_44(MSG);
    assert_eq!(
        verify_detached_44(&kp44().get_verifier(), b"a different message", &doc),
        Err(code(StatusCodeEnum::AuthFailed))
    );
}

#[test]
fn a_flipped_signature_bit_fails_without_panicking() {
    let mut doc = signed_44(MSG);
    // Deep inside the signature bytes. Before Signature::decode's unwrap was
    // removed, byte patterns that do not decode as a signature aborted the
    // process here instead of failing verification.
    let n = doc.len();
    for i in [n - 1, n - 100, DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ + 40] {
        let mut tampered = doc.clone();
        tampered[i] ^= 0x01;
        assert_eq!(
            verify_detached_44(&kp44().get_verifier(), MSG, &tampered),
            Err(code(StatusCodeEnum::AuthFailed)),
            "flip at {i} verified"
        );
    }
    // And the all-invalid pattern, straight at the verifier.
    doc.clear();
    assert!(
        !kp44()
            .get_verifier()
            .verify(MSG, &[0xFF; MLDSA_44_SIGNATURE_SZ]),
        "an undecodable signature must simply fail"
    );
}

#[test]
fn a_wrong_key_fails() {
    let doc = signed_44(MSG);
    let other = MlDsa44Keypair::from_seed(&[8u8; MLDSA_SEED_SZ]);
    assert_eq!(
        verify_detached_44(&other.get_verifier(), MSG, &doc),
        Err(code(StatusCodeEnum::AuthFailed)),
        "someone else's signature satisfied this verifier"
    );
}

#[test]
fn a_wrong_parameter_set_fails() {
    // Same seed, different algorithm: the attestation names MlDsa44, so the
    // 65-level verifier finds nothing addressed to it.
    let doc = signed_44(MSG);
    assert_eq!(
        verify_detached_65(&kp65().get_verifier(), MSG, &doc),
        Err(code(StatusCodeEnum::AuthFailed))
    );
}

#[test]
fn truncated_and_malformed_documents_are_bad_encoding() {
    let doc = signed_44(MSG);
    let v = kp44().get_verifier();
    assert_eq!(
        verify_detached_44(&v, MSG, &doc[..doc.len() - 1]),
        Err(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        verify_detached_44(&v, MSG, b"not an envelope"),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // A Signature section too short to carry even its own header.
    let mut buf = [0u8; 64];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(SectionTagEnum::Signature as u16, b"short").unwrap();
    let n = w.finish();
    assert_eq!(
        verify_detached_44(&v, MSG, &buf[..n]),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // The right algorithm id but the wrong length for it.
    let mut buf = [0u8; 128];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add_parts(
        SectionTagEnum::Signature as u16,
        &[
            &(AloecryptAlgorithmEnum::MlDsa44 as u16).to_le_bytes(),
            &[0u8; 32],
            b"wrong size",
        ],
    )
    .unwrap();
    let n = w.finish();
    assert_eq!(
        verify_detached_44(&v, MSG, &buf[..n]),
        Err(code(StatusCodeEnum::BadEncoding))
    );
}

// ------------------------------------------------------------ extensibility

#[test]
fn unknown_sections_do_not_disturb_verification() {
    let signed = signed_44(MSG);
    let attestation = EnvelopeReader::new(&signed)
        .unwrap()
        .find(SectionTagEnum::Signature as u16)
        .unwrap()
        .to_vec();

    let mut buf = vec![0u8; signed.len() + 64];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(500, b"metadata from a future version").unwrap();
    w.add(SectionTagEnum::Signature as u16, &attestation)
        .unwrap();
    let n = w.finish();
    assert_eq!(
        verify_detached_44(&kp44().get_verifier(), MSG, &buf[..n]),
        Ok(())
    );
}

#[test]
fn unknown_critical_sections_refuse_verification() {
    let signed = signed_44(MSG);
    let attestation = EnvelopeReader::new(&signed)
        .unwrap()
        .find(SectionTagEnum::Signature as u16)
        .unwrap()
        .to_vec();

    let mut buf = vec![0u8; signed.len() + 64];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(SECTION_TAG_CRITICAL | 5, b"you must understand this")
        .unwrap();
    w.add(SectionTagEnum::Signature as u16, &attestation)
        .unwrap();
    let n = w.finish();
    assert_eq!(
        verify_detached_44(&kp44().get_verifier(), MSG, &buf[..n]),
        Err(code(StatusCodeEnum::Unsupported)),
        "a critical section this build cannot judge was skipped"
    );
}

#[test]
fn two_signers_share_one_document() {
    let msg = b"co-signed";
    let d44 = {
        let mut d = vec![0u8; detached_signature_size(MLDSA_44_SIGNATURE_SZ)];
        let n = sign_detached_44(&kp44(), msg, &mut d).unwrap();
        d.truncate(n);
        d
    };
    let d65 = {
        let mut d = vec![0u8; detached_signature_size(MLDSA_65_SIGNATURE_SZ)];
        let n = sign_detached_65(&kp65(), msg, &mut d).unwrap();
        d.truncate(n);
        d
    };
    let a44 = EnvelopeReader::new(&d44)
        .unwrap()
        .find(SectionTagEnum::Signature as u16)
        .unwrap()
        .to_vec();
    let a65 = EnvelopeReader::new(&d65)
        .unwrap()
        .find(SectionTagEnum::Signature as u16)
        .unwrap()
        .to_vec();

    let mut buf = vec![0u8; d44.len() + d65.len()];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(SectionTagEnum::Signature as u16, &a44).unwrap();
    w.add(SectionTagEnum::Signature as u16, &a65).unwrap();
    let n = w.finish();
    let doc = &buf[..n];

    assert_eq!(verify_detached_44(&kp44().get_verifier(), msg, doc), Ok(()));
    assert_eq!(verify_detached_65(&kp65().get_verifier(), msg, doc), Ok(()));
    assert_eq!(
        verify_detached_87(&kp87().get_verifier(), msg, doc),
        Err(code(StatusCodeEnum::AuthFailed)),
        "an uninvolved key found an attestation"
    );
}
