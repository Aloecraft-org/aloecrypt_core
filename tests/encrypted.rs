// tests/encrypted.rs
// Encrypt-to-recipient over the document envelope.

use aloecrypt_core::aloecrypt_api::{AloecryptAddress, AloecryptAlgorithmEnum, ENCRYPTED_TAG_SZ};
use aloecrypt_core::document::*;
use aloecrypt_core::document_api::*;
use aloecrypt_core::error::{StatusCode, StatusCodeEnum};
use aloecrypt_core::kem_api::*;

const PAYLOAD: &[u8] = b"aloecrypt encrypted document fixture";
const PRK: MlKemPrkSeed = [9u8; MLKEM_PRK_SEED_SZ];

// Encrypted once to the [7; 64]-seeded recipient with PRK [9; 32] and
// pinned. Decrypting it locks the construction: envelope layout, recipient
// block format, the encryption and address domain strings, the zero-nonce
// AEAD, and deterministic encapsulation from a fixed PRK seed.
const FIXTURE_768: &str = include_str!("fixtures/encrypted_768.asc");

fn code(c: StatusCodeEnum) -> StatusCode {
    c.into()
}

fn kem512() -> MlKem512Keypair {
    MlKem512Keypair::from_seed(&[7u8; MLKEM_DECAP_KEY_SZ])
}
fn kem768() -> MlKem768Keypair {
    MlKem768Keypair::from_seed(&[7u8; MLKEM_DECAP_KEY_SZ])
}
fn kem1024() -> MlKem1024Keypair {
    MlKem1024Keypair::from_seed(&[7u8; MLKEM_DECAP_KEY_SZ])
}

fn encrypted_768(payload: &[u8]) -> Vec<u8> {
    let mut doc = vec![0u8; encrypted_document_size(MLKEM_768_CIPHER_SZ, payload.len())];
    let n = encrypt_to_recipient_768(&kem768().get_encapsulator(), PRK, payload, &mut doc).unwrap();
    assert_eq!(
        n,
        doc.len(),
        "encrypted_document_size disagrees with encrypt"
    );
    doc
}

// ----------------------------------------------------------------- fixture

#[test]
fn the_pinned_fixture_still_decrypts() {
    let mut doc = vec![0u8; dearmored_size_bound(FIXTURE_768.len())];
    let n = dearmor(FIXTURE_768.as_bytes(), ENCRYPTED_LABEL, &mut doc).unwrap();
    let mut out = vec![0u8; n];
    let m = decrypt_as_recipient_768(&kem768(), &doc[..n], &mut out).unwrap();
    assert_eq!(&out[..m], PAYLOAD);
}

#[test]
fn encryption_is_deterministic_and_reproduces_the_fixture() {
    let doc = encrypted_768(PAYLOAD);
    assert_eq!(doc, encrypted_768(PAYLOAD));

    let mut text = vec![0u8; armored_size(ENCRYPTED_LABEL.len(), doc.len())];
    let n = armor(ENCRYPTED_LABEL, &doc, &mut text).unwrap();
    assert_eq!(
        core::str::from_utf8(&text[..n]).unwrap(),
        FIXTURE_768,
        "the construction drifted from the pinned document"
    );
}

// ---------------------------------------------------------------- addresses

#[test]
fn kem_addresses_are_pinned_and_distinct() {
    let expected: AloecryptAddress = [
        0x16, 0xdc, 0x5a, 0xae, 0x71, 0x1d, 0xd0, 0x67, 0x8e, 0x31, 0x93, 0x83, 0x08, 0xa2, 0x2f,
        0x1d, 0x7e, 0xb8, 0xb8, 0xd4, 0xab, 0x84, 0x66, 0xb3, 0x69, 0x4c, 0x51, 0xb4, 0x08, 0xf2,
        0x35, 0x41,
    ];
    assert_eq!(kem768().get_encapsulator().address(), expected);

    // One seed, three parameter sets: three addresses.
    let a512 = kem512().get_encapsulator().address();
    let a768 = kem768().get_encapsulator().address();
    let a1024 = kem1024().get_encapsulator().address();
    assert_ne!(a512, a768);
    assert_ne!(a512, a1024);
    assert_ne!(a768, a1024);
}

// -------------------------------------------------------------- round trips

#[test]
fn encrypted_documents_round_trip_at_every_level() {
    let payload = b"a payload worth protecting";
    let mut out = vec![0u8; payload.len()];

    let mut doc = vec![0u8; encrypted_document_size(MLKEM_512_CIPHER_SZ, payload.len())];
    let n = encrypt_to_recipient_512(&kem512().get_encapsulator(), PRK, payload, &mut doc).unwrap();
    let m = decrypt_as_recipient_512(&kem512(), &doc[..n], &mut out).unwrap();
    assert_eq!(&out[..m], payload);

    let mut doc = vec![0u8; encrypted_document_size(MLKEM_768_CIPHER_SZ, payload.len())];
    let n = encrypt_to_recipient_768(&kem768().get_encapsulator(), PRK, payload, &mut doc).unwrap();
    let m = decrypt_as_recipient_768(&kem768(), &doc[..n], &mut out).unwrap();
    assert_eq!(&out[..m], payload);

    let mut doc = vec![0u8; encrypted_document_size(MLKEM_1024_CIPHER_SZ, payload.len())];
    let n =
        encrypt_to_recipient_1024(&kem1024().get_encapsulator(), PRK, payload, &mut doc).unwrap();
    let m = decrypt_as_recipient_1024(&kem1024(), &doc[..n], &mut out).unwrap();
    assert_eq!(&out[..m], payload);
}

#[test]
fn an_empty_payload_round_trips() {
    let doc = encrypted_768(b"");
    let mut out = [0u8; 1];
    assert_eq!(decrypt_as_recipient_768(&kem768(), &doc, &mut out), Ok(0));
}

// ------------------------------------------------------------------ tamper

#[test]
fn every_flipped_bit_fails_and_wipes_the_output() {
    let doc = encrypted_768(PAYLOAD);
    let mut out = vec![0u8; PAYLOAD.len()];
    // One flip in the KEM ciphertext (implicit rejection: decapsulation
    // yields a wrong secret, the tag fails), one in the sealed payload, one
    // in the tag itself.
    let kem_at = DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ + 34 + 100;
    let aead_at = doc.len() - ENCRYPTED_TAG_SZ - 5;
    let tag_at = doc.len() - 1;
    for i in [kem_at, aead_at, tag_at] {
        let mut tampered = doc.clone();
        tampered[i] ^= 0x01;
        out.fill(0xAA);
        assert_eq!(
            decrypt_as_recipient_768(&kem768(), &tampered, &mut out),
            Err(code(StatusCodeEnum::AuthFailed)),
            "flip at {i} decrypted"
        );
        assert_eq!(out, vec![0u8; out.len()], "failed decrypt left plaintext");
    }
}

#[test]
fn the_wrong_recipient_fails() {
    let doc = encrypted_768(PAYLOAD);
    let mut out = vec![0u8; PAYLOAD.len()];
    let other = MlKem768Keypair::from_seed(&[8u8; MLKEM_DECAP_KEY_SZ]);
    assert_eq!(
        decrypt_as_recipient_768(&other, &doc, &mut out),
        Err(code(StatusCodeEnum::AuthFailed)),
        "a document for someone else opened"
    );
}

#[test]
fn the_wrong_parameter_set_fails() {
    // Same seed, different algorithm: the recipient block names MlKem768.
    let doc = encrypted_768(PAYLOAD);
    let mut out = vec![0u8; PAYLOAD.len()];
    assert_eq!(
        decrypt_as_recipient_1024(&kem1024(), &doc, &mut out),
        Err(code(StatusCodeEnum::AuthFailed))
    );
}

#[test]
fn spliced_documents_fail() {
    // The sealed payload of one document behind the recipient block of
    // another: both sections are individually well-formed, but the keys
    // disagree.
    let doc_a = encrypted_768(PAYLOAD);
    let doc_b = {
        let payload = b"a different payload entirely";
        let mut d = vec![0u8; encrypted_document_size(MLKEM_768_CIPHER_SZ, payload.len())];
        let prk_b = [10u8; MLKEM_PRK_SEED_SZ];
        let n =
            encrypt_to_recipient_768(&kem768().get_encapsulator(), prk_b, payload, &mut d).unwrap();
        d.truncate(n);
        d
    };
    let reader_a = EnvelopeReader::new(&doc_a).unwrap();
    let reader_b = EnvelopeReader::new(&doc_b).unwrap();
    let kem_a = reader_a.find(SectionTagEnum::KemCipher as u16).unwrap();
    let aead_b = reader_b.find(SectionTagEnum::AeadCipher as u16).unwrap();

    let mut buf = vec![0u8; doc_a.len() + doc_b.len()];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(SectionTagEnum::KemCipher as u16, kem_a).unwrap();
    w.add(SectionTagEnum::AeadCipher as u16, aead_b).unwrap();
    let n = w.finish();

    let mut out = vec![0u8; doc_b.len()];
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), &buf[..n], &mut out),
        Err(code(StatusCodeEnum::AuthFailed)),
        "a spliced document decrypted"
    );
}

#[test]
fn malformed_documents_are_bad_encoding_or_bad_argument() {
    let doc = encrypted_768(PAYLOAD);
    let mut out = vec![0u8; PAYLOAD.len()];
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), b"not an envelope", &mut out),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // A recipient block naming the right algorithm at the wrong length.
    let mut buf = vec![0u8; 256];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add_parts(
        SectionTagEnum::KemCipher as u16,
        &[
            &(AloecryptAlgorithmEnum::MlKem768 as u16).to_le_bytes(),
            &kem768().get_encapsulator().address(),
            b"wrong size",
        ],
    )
    .unwrap();
    let n = w.finish();
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), &buf[..n], &mut out),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // A matching recipient block but no sealed payload at all.
    let reader = EnvelopeReader::new(&doc).unwrap();
    let kem = reader.find(SectionTagEnum::KemCipher as u16).unwrap();
    let mut buf = vec![0u8; doc.len()];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(SectionTagEnum::KemCipher as u16, kem).unwrap();
    let n = w.finish();
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), &buf[..n], &mut out),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // An output buffer too small for the payload.
    let mut small = vec![0u8; PAYLOAD.len() - 1];
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), &doc, &mut small),
        Err(code(StatusCodeEnum::BadArgument))
    );
}

// ------------------------------------------------------------ extensibility

#[test]
fn unknown_sections_do_not_disturb_decryption_but_critical_ones_refuse() {
    let doc = encrypted_768(PAYLOAD);
    let reader = EnvelopeReader::new(&doc).unwrap();
    let kem = reader.find(SectionTagEnum::KemCipher as u16).unwrap();
    let aead = reader.find(SectionTagEnum::AeadCipher as u16).unwrap();

    let mut buf = vec![0u8; doc.len() + 128];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(600, b"harmless future metadata").unwrap();
    w.add(SectionTagEnum::KemCipher as u16, kem).unwrap();
    w.add(SectionTagEnum::AeadCipher as u16, aead).unwrap();
    let n = w.finish();
    let mut out = vec![0u8; PAYLOAD.len()];
    let m = decrypt_as_recipient_768(&kem768(), &buf[..n], &mut out).unwrap();
    assert_eq!(&out[..m], PAYLOAD);

    let mut buf = vec![0u8; doc.len() + 128];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    w.add(SECTION_TAG_CRITICAL | 9, b"you must understand this")
        .unwrap();
    w.add(SectionTagEnum::KemCipher as u16, kem).unwrap();
    w.add(SectionTagEnum::AeadCipher as u16, aead).unwrap();
    let n = w.finish();
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), &buf[..n], &mut out),
        Err(code(StatusCodeEnum::Unsupported))
    );
}
