// tests/document.rs
// The document envelope and the armored text encoding.

use aloecrypt_core::document::*;
use aloecrypt_core::document_api::*;
use aloecrypt_core::error::{StatusCode, StatusCodeEnum};

fn code(c: StatusCodeEnum) -> StatusCode {
    c.into()
}

fn payload_200() -> Vec<u8> {
    (0..200).map(|i| i as u8).collect()
}

// Generated with Python (base64.b64encode + textwrap.wrap(64)) so the armor
// is pinned against an implementation that shares no code with this crate.
const PYTHON_FIXTURE: &str = "-----BEGIN ALOECRYPT SIGNER-----\n\
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n\
MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n\
YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n\
kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/\n\
wMHCw8TFxsc=\n\
-----END ALOECRYPT SIGNER-----\n";

// The same base64, wrapped at the MIME width instead of ours. A decoder that
// only accepts its own line width is not a decoder of the format.
const PYTHON_FIXTURE_76COL: &str = "-----BEGIN ALOECRYPT SIGNER-----\n\
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\n\
OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3Bx\n\
cnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmq\n\
q6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsc=\n\
-----END ALOECRYPT SIGNER-----\n";

fn armor_to_vec(label: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; armored_size(label.len(), payload.len())];
    let n = armor(label, payload, &mut out).expect("armor must fit its own size calculation");
    assert_eq!(n, out.len(), "armored_size disagrees with armor");
    out
}

fn dearmor_to_vec(text: &[u8], label: &str) -> Result<Vec<u8>, StatusCode> {
    let mut out = vec![0u8; dearmored_size_bound(text.len())];
    let n = dearmor(text, label, &mut out)?;
    out.truncate(n);
    Ok(out)
}

// -------------------------------------------------------------------- armor

#[test]
fn armor_matches_the_python_reference() {
    let text = armor_to_vec("SIGNER", &payload_200());
    assert_eq!(
        core::str::from_utf8(&text).unwrap(),
        PYTHON_FIXTURE,
        "armor output diverged from the independently generated form"
    );
}

#[test]
fn dearmor_reads_the_python_reference() {
    assert_eq!(
        dearmor_to_vec(PYTHON_FIXTURE.as_bytes(), "SIGNER").unwrap(),
        payload_200()
    );
}

#[test]
fn dearmor_is_line_width_agnostic() {
    assert_eq!(
        dearmor_to_vec(PYTHON_FIXTURE_76COL.as_bytes(), "SIGNER").unwrap(),
        payload_200()
    );
}

#[test]
fn armor_round_trips_across_sizes() {
    // 0 and 1..=3 exercise the padding cases; 47..=49 straddle a line
    // boundary; 2000 spans many lines.
    for len in [0usize, 1, 2, 3, 46, 47, 48, 49, 96, 2000] {
        let payload: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
        let text = armor_to_vec("ENVELOPE", &payload);
        let back = dearmor_to_vec(&text, "ENVELOPE").expect("round trip failed");
        assert_eq!(back, payload, "payload changed at {len} bytes");
    }
}

#[test]
fn dearmor_tolerates_transport_wrapping() {
    // Email-style preamble and trailer, and CRLF line endings.
    let mut text = String::from("From: someone@example.org\n\nSee attached.\n");
    text.push_str(&PYTHON_FIXTURE.replace('\n', "\r\n"));
    text.push_str("-- \nsig block\n");
    assert_eq!(
        dearmor_to_vec(text.as_bytes(), "SIGNER").unwrap(),
        payload_200()
    );
}

#[test]
fn dearmor_requires_the_expected_label() {
    // The caller names the type they expect; a document of another type is
    // not that document, however well it parses.
    assert_eq!(
        dearmor_to_vec(PYTHON_FIXTURE.as_bytes(), "ENVELOPE"),
        Err(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn dearmor_rejects_a_mismatched_end_label() {
    let text = PYTHON_FIXTURE.replace("END ALOECRYPT SIGNER", "END ALOECRYPT ENVELOPE");
    assert_eq!(
        dearmor_to_vec(text.as_bytes(), "SIGNER"),
        Err(code(StatusCodeEnum::BadEncoding)),
        "an END delimiter for a different label terminated the document"
    );
}

#[test]
fn dearmor_rejects_truncation() {
    // Cut anywhere: mid-body, before END, mid-END. None of it may parse.
    let text = PYTHON_FIXTURE.as_bytes();
    for cut in [40, 100, text.len() - 5] {
        assert_eq!(
            dearmor_to_vec(&text[..cut], "SIGNER"),
            Err(code(StatusCodeEnum::BadEncoding)),
            "truncation at {cut} parsed"
        );
    }
}

#[test]
fn dearmor_rejects_bytes_outside_the_alphabet() {
    for bad in ["*", " ", "\t", "é"] {
        let text = PYTHON_FIXTURE.replacen("MDEy", &format!("MD{bad}Ey"), 1);
        assert_eq!(
            dearmor_to_vec(text.as_bytes(), "SIGNER"),
            Err(code(StatusCodeEnum::BadEncoding)),
            "{bad:?} inside the body was accepted"
        );
    }
}

#[test]
fn dearmor_rejects_data_after_padding() {
    // Padding ends the base64 stream; a second stream glued on after it must
    // not silently extend the payload.
    let text = PYTHON_FIXTURE.replace("wMHCw8TFxsc=\n", "wMHCw8TFxsc=\nAAAA\n");
    assert_eq!(
        dearmor_to_vec(text.as_bytes(), "SIGNER"),
        Err(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn dearmor_rejects_non_canonical_padding() {
    // "xsd=" decodes to the same bytes as "xsc=" only if the decoder ignores
    // the trailing bits; two spellings of one payload is a malleability bug.
    let text = PYTHON_FIXTURE.replace("wMHCw8TFxsc=", "wMHCw8TFxsd=");
    assert_eq!(
        dearmor_to_vec(text.as_bytes(), "SIGNER"),
        Err(code(StatusCodeEnum::BadEncoding)),
        "non-canonical trailing bits were accepted"
    );
}

#[test]
fn dearmor_rejects_a_dangling_partial_group() {
    // A body whose character count is not a multiple of four was cut
    // mid-group, even when the END delimiter is present and every line
    // looks plausible. Built from an unpadded body (48 bytes = one full
    // line) so this exercises the dangling-group check, not the
    // data-after-padding one.
    let text = String::from_utf8(armor_to_vec("SIGNER", &[5u8; 48])).unwrap();
    let text = text.replace(
        "\n-----END ALOECRYPT SIGNER-----\n",
        "AB\n-----END ALOECRYPT SIGNER-----\n",
    );
    assert_eq!(
        dearmor_to_vec(text.as_bytes(), "SIGNER"),
        Err(code(StatusCodeEnum::BadEncoding))
    );
}

#[test]
fn armor_validates_its_label() {
    let mut out = [0u8; 256];
    for label in ["", "signer", "SIGNER-", " SIGNER", "SIGNER ", "A B  C\t"] {
        assert_eq!(
            armor(label, b"x", &mut out),
            Err(code(StatusCodeEnum::BadArgument)),
            "label {label:?} was accepted"
        );
    }
    for label in ["SIGNER", "A", "KEY 2", "0AB"] {
        assert!(
            armor(label, b"x", &mut out).is_ok(),
            "label {label:?} was rejected"
        );
    }
}

#[test]
fn armor_reports_a_short_buffer_without_writing() {
    let needed = armored_size("SIGNER".len(), 200);
    let mut out = vec![0u8; needed - 1];
    assert_eq!(
        armor("SIGNER", &payload_200(), &mut out),
        Err(code(StatusCodeEnum::BadArgument))
    );
}

#[test]
fn dearmor_reports_a_short_output_buffer() {
    let mut out = [0u8; 100]; // payload is 200 bytes
    assert_eq!(
        dearmor(PYTHON_FIXTURE.as_bytes(), "SIGNER", &mut out),
        Err(code(StatusCodeEnum::BadArgument))
    );
}

#[test]
fn dearmor_finds_its_document_among_others() {
    // Two documents in one file, the wanted one second: the decoder skips
    // foreign delimiters the way it skips any other preamble.
    let mut text = armor_to_vec("ENVELOPE", b"the other document");
    text.extend_from_slice(&armor_to_vec("SIGNER", &payload_200()));
    assert_eq!(dearmor_to_vec(&text, "SIGNER").unwrap(), payload_200());
}

// ------------------------------------------------------------------ envelope

fn build_envelope(sections: &[(u16, &[u8])]) -> Vec<u8> {
    let lens: Vec<usize> = sections.iter().map(|(_, v)| v.len()).collect();
    let mut buf = vec![0u8; envelope_size(&lens)];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    for (tag, value) in sections {
        w.add(*tag, value).unwrap();
    }
    let n = w.finish();
    assert_eq!(n, buf.len(), "envelope_size disagrees with the writer");
    buf
}

#[test]
fn envelope_round_trips() {
    let payload = payload_200();
    let doc = build_envelope(&[
        (SectionTagEnum::Payload as u16, &payload),
        (SectionTagEnum::SignerAddress as u16, &[7u8; 32]),
        (SectionTagEnum::Signature as u16, &[9u8; 3309]),
    ]);
    let r = EnvelopeReader::new(&doc).unwrap();
    assert_eq!(r.version(), DOC_VERSION);
    assert_eq!(r.find(SectionTagEnum::Payload as u16), Some(&payload[..]));
    assert_eq!(
        r.find(SectionTagEnum::SignerAddress as u16),
        Some(&[7u8; 32][..])
    );
    assert_eq!(r.sections().count(), 3);
    assert_eq!(r.find(SectionTagEnum::KemCipher as u16), None);
}

#[test]
fn envelope_layout_is_pinned() {
    // The layout is the wire contract: magic, version LE, then per section
    // tag LE, length LE, value. Checked byte-for-byte so a change to any of
    // it is a deliberate act.
    let doc = build_envelope(&[(10, b"hi")]);
    assert_eq!(
        doc,
        [b'A', b'L', b'O', b'E', 1, 0, 10, 0, 2, 0, 0, 0, b'h', b'i']
    );
}

#[test]
fn envelope_skips_unknown_tags() {
    // A reader built before tag 500 existed still reads the rest of the
    // document. This is the additivity the format exists to provide.
    let doc = build_envelope(&[(500, b"from the future"), (10, b"payload")]);
    let r = EnvelopeReader::new(&doc).unwrap();
    assert_eq!(r.find(10), Some(&b"payload"[..]));
    assert!(!r.has_unknown_critical(&[10]));
}

#[test]
fn envelope_reports_unknown_critical_tags() {
    let doc = build_envelope(&[(SECTION_TAG_CRITICAL | 5, b"must understand"), (10, b"p")]);
    let r = EnvelopeReader::new(&doc).unwrap();
    assert!(r.has_unknown_critical(&[10]));
    assert!(!r.has_unknown_critical(&[10, SECTION_TAG_CRITICAL | 5]));
    assert!(section_tag_is_critical(SECTION_TAG_CRITICAL | 5));
    assert!(!section_tag_is_critical(5));
}

#[test]
fn envelope_yields_duplicate_tags_in_order() {
    // Multiple recipients means multiple KemCipher sections; order matters
    // and find() means "first".
    let doc = build_envelope(&[(30, b"alice"), (30, b"bob")]);
    let r = EnvelopeReader::new(&doc).unwrap();
    let values: Vec<&[u8]> = r
        .sections()
        .filter(|(t, _)| *t == 30)
        .map(|(_, v)| v)
        .collect();
    assert_eq!(values, [&b"alice"[..], &b"bob"[..]]);
    assert_eq!(r.find(30), Some(&b"alice"[..]));
}

#[test]
fn envelope_accepts_empty_sections_and_empty_documents() {
    let doc = build_envelope(&[]);
    assert_eq!(EnvelopeReader::new(&doc).unwrap().sections().count(), 0);

    let doc = build_envelope(&[(10, b"")]);
    assert_eq!(EnvelopeReader::new(&doc).unwrap().find(10), Some(&b""[..]));
}

#[test]
fn envelope_rejects_malformed_documents() {
    let good = build_envelope(&[(10, b"payload")]);

    // Truncation at every boundary short of the full document. The one
    // legitimate prefix is the bare header, which is a valid empty envelope;
    // every other cut must refuse.
    for cut in 0..good.len() {
        let got = EnvelopeReader::new(&good[..cut]).map(|_| ());
        if cut == DOC_HEADER_SZ {
            assert_eq!(got, Ok(()), "the empty envelope stopped parsing");
        } else {
            assert_eq!(
                got,
                Err(code(StatusCodeEnum::BadEncoding)),
                "truncation at {cut} parsed"
            );
        }
    }

    // Wrong magic.
    let mut bad = good.clone();
    bad[0] = b'B';
    assert_eq!(
        EnvelopeReader::new(&bad).map(|_| ()),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // A section length pointing past the end of the document.
    let mut bad = good.clone();
    bad[8] = 200;
    assert_eq!(
        EnvelopeReader::new(&bad).map(|_| ()),
        Err(code(StatusCodeEnum::BadEncoding))
    );

    // A reserved tag on the wire.
    for reserved in [0u16, u16::MAX] {
        let mut bad = good.clone();
        bad[6..8].copy_from_slice(&reserved.to_le_bytes());
        assert_eq!(
            EnvelopeReader::new(&bad).map(|_| ()),
            Err(code(StatusCodeEnum::BadEncoding)),
            "reserved tag {reserved} was read"
        );
    }
}

#[test]
fn envelope_refuses_a_future_version() {
    let mut doc = build_envelope(&[(10, b"p")]);
    doc[4] = 2;
    assert_eq!(
        EnvelopeReader::new(&doc).map(|_| ()),
        Err(code(StatusCodeEnum::Unsupported)),
        "a version this build does not know how to read must be refused"
    );
}

#[test]
fn envelope_writer_rejects_what_it_cannot_hold() {
    let mut tiny = [0u8; DOC_HEADER_SZ - 1];
    assert!(EnvelopeWriter::new(&mut tiny).is_err());

    let mut small = [0u8; DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ + 4];
    let mut w = EnvelopeWriter::new(&mut small).unwrap();
    assert_eq!(
        w.add(10, b"12345"),
        Err(code(StatusCodeEnum::BadArgument)),
        "a section that does not fit was written"
    );
    // The failed add must not have corrupted the envelope.
    w.add(10, b"1234").unwrap();
    let n = w.finish();
    let r = EnvelopeReader::new(&small[..n]).unwrap();
    assert_eq!(r.find(10), Some(&b"1234"[..]));
}

#[test]
fn envelope_writer_rejects_reserved_tags() {
    let mut buf = [0u8; 64];
    let mut w = EnvelopeWriter::new(&mut buf).unwrap();
    for reserved in [0u16, u16::MAX] {
        assert_eq!(
            w.add(reserved, b"x"),
            Err(code(StatusCodeEnum::BadArgument)),
            "reserved tag {reserved} was written"
        );
    }
}

// --------------------------------------------------------- armored envelope

#[test]
fn an_armored_envelope_survives_the_full_path() {
    let payload = payload_200();
    let doc = build_envelope(&[
        (SectionTagEnum::Payload as u16, &payload),
        (SectionTagEnum::KdfSalt as u16, &[3u8; 16]),
    ]);
    let text = armor_to_vec("ENVELOPE", &doc);
    let back = dearmor_to_vec(&text, "ENVELOPE").unwrap();
    let r = EnvelopeReader::new(&back).unwrap();
    assert_eq!(r.find(SectionTagEnum::Payload as u16), Some(&payload[..]));
    assert_eq!(r.find(SectionTagEnum::KdfSalt as u16), Some(&[3u8; 16][..]));
}
