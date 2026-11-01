// tests/public_key.rs
// Public-key documents: SIGNER (ML-DSA) and RECIPIENT (ML-KEM).

use aloecrypt_core::aloecrypt_api::{AloecryptAddressable, AloecryptAlgorithmEnum};
use aloecrypt_core::document::*;
use aloecrypt_core::document_api::*;
use aloecrypt_core::dsa_api::*;
use aloecrypt_core::error::{StatusCode, StatusCodeEnum};
use aloecrypt_core::kem_api::*;

// Written once from the [7]-seeded keys and pinned. Reading them locks the
// envelope layout, the PublicKey section format, the section tag, the
// labels, and both address domain strings.
const SIGNER_FIXTURE_44: &str = include_str!("fixtures/signer_44.asc");
const RECIPIENT_FIXTURE_768: &str = include_str!("fixtures/recipient_768.asc");

/// Offset of the key bytes inside a single-section public-key document.
const KEY_AT: usize = DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ + 2 + 32;
/// Offset of the carried address.
const ADDRESS_AT: usize = DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ + 2;

fn code(c: StatusCodeEnum) -> StatusCode {
    c.into()
}

fn dsa44() -> MlDsa44Keypair {
    MlDsa44Keypair::from_seed(&[7u8; MLDSA_SEED_SZ])
}
fn dsa65() -> MlDsa65Keypair {
    MlDsa65Keypair::from_seed(&[7u8; MLDSA_SEED_SZ])
}
fn dsa87() -> MlDsa87Keypair {
    MlDsa87Keypair::from_seed(&[7u8; MLDSA_SEED_SZ])
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

fn signer_44() -> Vec<u8> {
    let mut doc = vec![0u8; public_key_document_size(MLDSA_44_PUBKEY_SZ)];
    let n = write_signer_44(&dsa44().get_verifier(), &mut doc).unwrap();
    assert_eq!(
        n,
        doc.len(),
        "public_key_document_size disagrees with write"
    );
    doc
}

fn recipient_768() -> Vec<u8> {
    let mut doc = vec![0u8; public_key_document_size(MLKEM_768_ENCAP_KEY_SZ)];
    let n = write_recipient_768(&kem768().get_encapsulator(), &mut doc).unwrap();
    assert_eq!(
        n,
        doc.len(),
        "public_key_document_size disagrees with write"
    );
    doc
}

fn armored(label: &str, doc: &[u8]) -> Vec<u8> {
    let mut text = vec![0u8; armored_size(label.len(), doc.len())];
    let n = armor(label, doc, &mut text).unwrap();
    assert_eq!(n, text.len());
    text
}

fn dearmored(text: &[u8], label: &str) -> Result<Vec<u8>, StatusCode> {
    let mut doc = vec![0u8; dearmored_size_bound(text.len())];
    let n = dearmor(text, label, &mut doc)?;
    doc.truncate(n);
    Ok(doc)
}

// ----------------------------------------------------------------- fixture

#[test]
fn the_pinned_fixtures_still_read() {
    let doc = dearmored(SIGNER_FIXTURE_44.as_bytes(), SIGNER_LABEL).unwrap();
    let verifier = read_signer_44(&doc).unwrap();
    assert_eq!(verifier.pack_bytes(), dsa44().get_verifier().pack_bytes());

    let doc = dearmored(RECIPIENT_FIXTURE_768.as_bytes(), RECIPIENT_LABEL).unwrap();
    let recipient = read_recipient_768(&doc).unwrap();
    assert_eq!(
        recipient.addressing_material(),
        kem768().get_encapsulator().addressing_material()
    );
}

#[test]
fn writing_reproduces_the_fixtures() {
    assert_eq!(
        armored(SIGNER_LABEL, &signer_44()),
        SIGNER_FIXTURE_44.as_bytes()
    );
    assert_eq!(
        armored(RECIPIENT_LABEL, &recipient_768()),
        RECIPIENT_FIXTURE_768.as_bytes()
    );
}

#[test]
fn the_layout_is_pinned() {
    let verifier = dsa44().get_verifier();
    let doc = signer_44();
    assert_eq!(&doc[..4], b"ALOE");
    assert_eq!(&doc[4..6], &1u16.to_le_bytes());
    assert_eq!(&doc[6..8], &50u16.to_le_bytes(), "PublicKey tag");
    assert_eq!(
        &doc[8..12],
        &((2 + 32 + MLDSA_44_PUBKEY_SZ) as u32).to_le_bytes()
    );
    assert_eq!(&doc[12..14], &10u16.to_le_bytes(), "MlDsa44 id");
    assert_eq!(&doc[ADDRESS_AT..KEY_AT], &verifier.address());
    assert_eq!(&doc[KEY_AT..], verifier.pack_bytes());
}

// -------------------------------------------------------------- round trip

#[test]
fn signers_round_trip_at_every_level_and_still_verify() {
    let msg = b"handed between hosts";

    let mut doc = vec![0u8; public_key_document_size(MLDSA_44_PUBKEY_SZ)];
    write_signer_44(&dsa44().get_verifier(), &mut doc).unwrap();
    let doc = dearmored(&armored(SIGNER_LABEL, &doc), SIGNER_LABEL).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlDsa44)
    );
    let verifier = read_signer_44(&doc).unwrap();
    let mut sig = vec![0u8; detached_signature_size(MLDSA_44_SIGNATURE_SZ)];
    sign_detached_44(&dsa44(), msg, &mut sig).unwrap();
    assert_eq!(verify_detached_44(&verifier, msg, &sig), Ok(()));

    let mut doc = vec![0u8; public_key_document_size(MLDSA_65_PUBKEY_SZ)];
    write_signer_65(&dsa65().get_verifier(), &mut doc).unwrap();
    let doc = dearmored(&armored(SIGNER_LABEL, &doc), SIGNER_LABEL).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlDsa65)
    );
    let verifier = read_signer_65(&doc).unwrap();
    let mut sig = vec![0u8; detached_signature_size(MLDSA_65_SIGNATURE_SZ)];
    sign_detached_65(&dsa65(), msg, &mut sig).unwrap();
    assert_eq!(verify_detached_65(&verifier, msg, &sig), Ok(()));

    let mut doc = vec![0u8; public_key_document_size(MLDSA_87_PUBKEY_SZ)];
    write_signer_87(&dsa87().get_verifier(), &mut doc).unwrap();
    let doc = dearmored(&armored(SIGNER_LABEL, &doc), SIGNER_LABEL).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlDsa87)
    );
    let verifier = read_signer_87(&doc).unwrap();
    let mut sig = vec![0u8; detached_signature_size(MLDSA_87_SIGNATURE_SZ)];
    sign_detached_87(&dsa87(), msg, &mut sig).unwrap();
    assert_eq!(verify_detached_87(&verifier, msg, &sig), Ok(()));
}

#[test]
fn recipients_round_trip_at_every_level_and_still_decrypt() {
    let payload = b"sealed to a key that travelled";
    let prk = [9u8; MLKEM_PRK_SEED_SZ];
    let mut out = vec![0u8; payload.len()];

    let mut doc = vec![0u8; public_key_document_size(MLKEM_512_ENCAP_KEY_SZ)];
    write_recipient_512(&kem512().get_encapsulator(), &mut doc).unwrap();
    let doc = dearmored(&armored(RECIPIENT_LABEL, &doc), RECIPIENT_LABEL).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlKem512)
    );
    let recipient = read_recipient_512(&doc).unwrap();
    let mut sealed = vec![0u8; encrypted_document_size(MLKEM_512_CIPHER_SZ, payload.len())];
    encrypt_to_recipient_512(&recipient, prk, payload, &mut sealed).unwrap();
    assert_eq!(
        decrypt_as_recipient_512(&kem512(), &sealed, &mut out),
        Ok(payload.len())
    );
    assert_eq!(&out, payload);

    let mut doc = vec![0u8; public_key_document_size(MLKEM_768_ENCAP_KEY_SZ)];
    write_recipient_768(&kem768().get_encapsulator(), &mut doc).unwrap();
    let doc = dearmored(&armored(RECIPIENT_LABEL, &doc), RECIPIENT_LABEL).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlKem768)
    );
    let recipient = read_recipient_768(&doc).unwrap();
    let mut sealed = vec![0u8; encrypted_document_size(MLKEM_768_CIPHER_SZ, payload.len())];
    encrypt_to_recipient_768(&recipient, prk, payload, &mut sealed).unwrap();
    assert_eq!(
        decrypt_as_recipient_768(&kem768(), &sealed, &mut out),
        Ok(payload.len())
    );
    assert_eq!(&out, payload);

    let mut doc = vec![0u8; public_key_document_size(MLKEM_1024_ENCAP_KEY_SZ)];
    write_recipient_1024(&kem1024().get_encapsulator(), &mut doc).unwrap();
    let doc = dearmored(&armored(RECIPIENT_LABEL, &doc), RECIPIENT_LABEL).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlKem1024)
    );
    let recipient = read_recipient_1024(&doc).unwrap();
    let mut sealed = vec![0u8; encrypted_document_size(MLKEM_1024_CIPHER_SZ, payload.len())];
    encrypt_to_recipient_1024(&recipient, prk, payload, &mut sealed).unwrap();
    assert_eq!(
        decrypt_as_recipient_1024(&kem1024(), &sealed, &mut out),
        Ok(payload.len())
    );
    assert_eq!(&out, payload);
}

// ---------------------------------------------------------------- refusals

#[test]
fn the_label_is_the_callers_to_state() {
    let text = armored(SIGNER_LABEL, &signer_44());
    assert_eq!(
        dearmored(&text, RECIPIENT_LABEL),
        Err(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn the_wrong_algorithm_is_refused() {
    let doc = signer_44();
    assert_eq!(
        read_signer_65(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        read_signer_87(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        read_recipient_768(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );

    let doc = recipient_768();
    assert_eq!(
        read_recipient_512(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        read_recipient_1024(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        read_signer_44(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn every_flipped_key_or_address_bit_is_caught() {
    // Exhaustive over the address and a stride through the key: a key that
    // no longer hashes to its carried address never comes back.
    let doc = signer_44();
    let positions = (ADDRESS_AT..KEY_AT).chain((KEY_AT..doc.len()).step_by(7));
    for i in positions {
        for bit in 0..8 {
            let mut bad = doc.clone();
            bad[i] ^= 1 << bit;
            assert_eq!(
                read_signer_44(&bad).err(),
                Some(code(StatusCodeEnum::BadEncoding)),
                "byte {i} bit {bit}"
            );
        }
    }
    let doc = recipient_768();
    for i in (ADDRESS_AT..doc.len()).step_by(5) {
        let mut bad = doc.clone();
        bad[i] ^= 0x01;
        assert_eq!(
            read_recipient_768(&bad).err(),
            Some(code(StatusCodeEnum::BadEncoding)),
            "byte {i}"
        );
    }
}

#[test]
fn a_malformed_kem_key_is_refused_even_with_its_own_address() {
    // All-ones bytes decode to coefficients >= q, which FIPS 203's
    // encapsulation-key check rejects. The address is computed honestly, so
    // only the key check stands between this document and a panic in
    // encapsulate.
    let bad_key = [0xFFu8; MLKEM_768_ENCAP_KEY_SZ];
    assert_eq!(
        MlKem768Encapsulator::try_from_public_key(&bad_key).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
    let unchecked = MlKem768Encapsulator::from_public_key(&bad_key);
    let mut doc = vec![0u8; public_key_document_size(MLKEM_768_ENCAP_KEY_SZ)];
    write_recipient_768(&unchecked, &mut doc).unwrap();
    assert_eq!(
        public_key_algorithm(&doc),
        Ok(AloecryptAlgorithmEnum::MlKem768)
    );
    assert_eq!(
        read_recipient_768(&doc).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn two_keys_in_one_document_are_ambiguous() {
    let doc = signer_44();
    let value = &doc[DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ..];
    let mut twice = vec![0u8; envelope_size(&[value.len(), value.len()])];
    let mut writer = EnvelopeWriter::new(&mut twice).unwrap();
    writer.add(SectionTagEnum::PublicKey as u16, value).unwrap();
    writer.add(SectionTagEnum::PublicKey as u16, value).unwrap();
    writer.finish();
    assert_eq!(
        read_signer_44(&twice).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        public_key_algorithm(&twice),
        Err(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn unknown_sections_skip_and_unknown_critical_ones_refuse() {
    let doc = signer_44();
    let value = &doc[DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ..];
    for (tag, expected) in [
        (0x0777u16, None),
        (0x8777u16, Some(code(StatusCodeEnum::Unsupported))),
    ] {
        let mut extended = vec![0u8; envelope_size(&[3, value.len()])];
        let mut writer = EnvelopeWriter::new(&mut extended).unwrap();
        writer.add(tag, b"new").unwrap();
        writer.add(SectionTagEnum::PublicKey as u16, value).unwrap();
        writer.finish();
        assert_eq!(read_signer_44(&extended).err(), expected, "tag {tag:#x}");
    }
}

#[test]
fn an_empty_or_unknown_algorithm_document_is_refused() {
    let mut empty = [0u8; DOC_HEADER_SZ];
    EnvelopeWriter::new(&mut empty).unwrap().finish();
    assert_eq!(
        public_key_algorithm(&empty),
        Err(code(StatusCodeEnum::BadEncoding))
    );
    assert_eq!(
        read_signer_44(&empty).err(),
        Some(code(StatusCodeEnum::BadEncoding))
    );

    let mut doc = signer_44();
    doc[DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ..][..2].copy_from_slice(&999u16.to_le_bytes());
    assert_eq!(
        public_key_algorithm(&doc),
        Err(code(StatusCodeEnum::Unsupported))
    );
}

#[test]
fn a_short_buffer_is_a_bad_argument() {
    let mut out = vec![0u8; public_key_document_size(MLDSA_44_PUBKEY_SZ) - 1];
    assert_eq!(
        write_signer_44(&dsa44().get_verifier(), &mut out),
        Err(code(StatusCodeEnum::BadArgument))
    );
    let mut out = vec![0u8; public_key_document_size(MLKEM_768_ENCAP_KEY_SZ) - 1];
    assert_eq!(
        write_recipient_768(&kem768().get_encapsulator(), &mut out),
        Err(code(StatusCodeEnum::BadArgument))
    );
}
