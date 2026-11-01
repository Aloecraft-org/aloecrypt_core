// src/document.rs
// License: Apache-2.0 (disclaimer at bottom of file)
//
// The document layer's transport: the extensible binary envelope and the
// armored text encoding (doc/DESIGN.md sections 3 and 18). Everything here
// works over caller-provided buffers -- no allocator, no assumption about
// where the bytes came from -- and every parse failure is a `StatusCode`.
//
// None of these functions are schema exports yet: encoding into a caller
// buffer is an out-parameter, which has no representation in a wire format
// that returns bytes (the `read_u16_arr` precedent, DESIGN section 14). The
// wire surface arrives with the first fixed-size document type; the
// `document_api` namespace already carries the tag vocabulary and layout
// constants so the other generators stay in step.

use super::document_api::*;

use crate::aloecrypt_api::{
    ALOECRYPT_ADDRESS_SZ, AloecryptAddress, AloecryptAlgorithmEnum, ENCRYPTED_TAG_SZ,
};
use crate::dsa_api::*;
use crate::error::{AloecryptResult, StatusCodeEnum};
use crate::hash::domain_hash;
use crate::hash_api::Hash256;
use crate::kem_api::*;
use data_encoding::BASE64;

fn err<T>(code: StatusCodeEnum) -> AloecryptResult<T> {
    Err(code.into())
}

// ------------------------------------------------------------------ envelope
//
// Layout, all integers little-endian:
//
//   [0..4)  magic  "ALOE"
//   [4..6)  format version, u16 -- currently 1
//   [6.. )  sections: (tag u16, length u32, value) repeated to the end
//
// A reader skips sections whose tag it does not recognize -- that is what
// keeps the format additive -- unless the tag has the top bit set, which
// marks it must-understand: `has_unknown_critical` reports those and the
// consumer refuses the document. Tags 0 and 0xFFFF are reserved and never
// valid on the wire in either direction.

pub const DOC_MAGIC: [u8; DOC_MAGIC_SZ] = *b"ALOE";
pub const DOC_VERSION: u16 = 1;
pub const SECTION_TAG_CRITICAL: u16 = 0x8000;

pub const fn section_tag_is_critical(tag: u16) -> bool {
    tag & SECTION_TAG_CRITICAL != 0
}

/// Bytes an envelope with sections of the given value lengths occupies.
pub fn envelope_size(section_lens: &[usize]) -> usize {
    let mut total = DOC_HEADER_SZ;
    let mut i = 0;
    while i < section_lens.len() {
        total += DOC_SECTION_HEADER_SZ + section_lens[i];
        i += 1;
    }
    total
}

pub struct EnvelopeWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> EnvelopeWriter<'a> {
    /// Starts an envelope in `buf`. `BadArgument` if the buffer cannot hold
    /// even the header.
    pub fn new(buf: &'a mut [u8]) -> AloecryptResult<Self> {
        if buf.len() < DOC_HEADER_SZ {
            return err(StatusCodeEnum::BadArgument);
        }
        buf[..DOC_MAGIC_SZ].copy_from_slice(&DOC_MAGIC);
        buf[DOC_MAGIC_SZ..DOC_HEADER_SZ].copy_from_slice(&DOC_VERSION.to_le_bytes());
        Ok(Self {
            buf,
            pos: DOC_HEADER_SZ,
        })
    }

    /// Appends one section. `BadArgument` for a reserved tag, a value that
    /// cannot be length-prefixed, or a buffer without room; on error the
    /// envelope is unchanged and remains valid.
    pub fn add(&mut self, tag: u16, value: &[u8]) -> AloecryptResult<()> {
        self.add_parts(tag, &[value])
    }

    /// `add`, with the section value assembled from `parts` in order --
    /// so a composite value never needs an intermediate buffer.
    pub fn add_parts(&mut self, tag: u16, parts: &[&[u8]]) -> AloecryptResult<()> {
        let mut value_len = 0usize;
        for part in parts {
            let Some(total) = value_len.checked_add(part.len()) else {
                return err(StatusCodeEnum::BadArgument);
            };
            value_len = total;
        }
        let value = self.add_reserved(tag, value_len)?;
        let mut pos = 0;
        for part in parts {
            value[pos..pos + part.len()].copy_from_slice(part);
            pos += part.len();
        }
        Ok(())
    }

    /// Appends a zeroed section of `value_len` bytes and returns its value
    /// slice for the caller to fill in place -- so a value that is produced
    /// rather than copied (a ciphertext, say) never needs its own buffer.
    pub fn add_reserved(&mut self, tag: u16, value_len: usize) -> AloecryptResult<&mut [u8]> {
        if tag == 0 || tag == u16::MAX {
            return err(StatusCodeEnum::BadArgument);
        }
        if u32::try_from(value_len).is_err() {
            return err(StatusCodeEnum::BadArgument);
        }
        let end = self
            .pos
            .checked_add(DOC_SECTION_HEADER_SZ)
            .and_then(|p| p.checked_add(value_len));
        let Some(end) = end else {
            return err(StatusCodeEnum::BadArgument);
        };
        if end > self.buf.len() {
            return err(StatusCodeEnum::BadArgument);
        }
        self.buf[self.pos..self.pos + 2].copy_from_slice(&tag.to_le_bytes());
        self.buf[self.pos + 2..self.pos + 6].copy_from_slice(&(value_len as u32).to_le_bytes());
        let value = &mut self.buf[self.pos + DOC_SECTION_HEADER_SZ..end];
        value.fill(0);
        self.pos = end;
        Ok(value)
    }

    /// Ends the envelope, returning how many bytes of the buffer it holds.
    pub fn finish(self) -> usize {
        self.pos
    }
}

pub struct EnvelopeReader<'a> {
    sections: &'a [u8],
    version: u16,
}

impl<'a> EnvelopeReader<'a> {
    /// Parses and fully validates an envelope: magic, version, and the
    /// structure of every section, so iteration afterwards cannot fail.
    /// `BadEncoding` for anything malformed; `Unsupported` for a version this
    /// build does not read (the version only moves when the layout itself
    /// changes -- new section tags do not bump it).
    pub fn new(doc: &'a [u8]) -> AloecryptResult<Self> {
        if doc.len() < DOC_HEADER_SZ || doc[..DOC_MAGIC_SZ] != DOC_MAGIC {
            return err(StatusCodeEnum::BadEncoding);
        }
        let version = u16::from_le_bytes([doc[DOC_MAGIC_SZ], doc[DOC_MAGIC_SZ + 1]]);
        if version != DOC_VERSION {
            return err(StatusCodeEnum::Unsupported);
        }
        let sections = &doc[DOC_HEADER_SZ..];
        let mut pos = 0usize;
        while pos < sections.len() {
            let Some(header_end) = pos.checked_add(DOC_SECTION_HEADER_SZ) else {
                return err(StatusCodeEnum::BadEncoding);
            };
            if header_end > sections.len() {
                return err(StatusCodeEnum::BadEncoding);
            }
            let tag = u16::from_le_bytes([sections[pos], sections[pos + 1]]);
            if tag == 0 || tag == u16::MAX {
                return err(StatusCodeEnum::BadEncoding);
            }
            let len = u32::from_le_bytes([
                sections[pos + 2],
                sections[pos + 3],
                sections[pos + 4],
                sections[pos + 5],
            ]);
            // On a 32-bit target a u32 length can exceed what a slice can
            // address; checked arithmetic turns that into BadEncoding rather
            // than a wrap.
            let Ok(len) = usize::try_from(len) else {
                return err(StatusCodeEnum::BadEncoding);
            };
            let Some(value_end) = header_end.checked_add(len) else {
                return err(StatusCodeEnum::BadEncoding);
            };
            if value_end > sections.len() {
                return err(StatusCodeEnum::BadEncoding);
            }
            pos = value_end;
        }
        Ok(Self { sections, version })
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    /// Every section in document order, unknown tags included.
    pub fn sections(&self) -> Sections<'a> {
        Sections {
            rest: self.sections,
        }
    }

    /// The value of the first section carrying `tag`, if any.
    pub fn find(&self, tag: u16) -> Option<&'a [u8]> {
        self.sections().find(|(t, _)| *t == tag).map(|(_, v)| v)
    }

    /// True if any section carries a must-understand tag that is not in
    /// `known`. A consumer that gets `true` refuses the document as
    /// `Unsupported` -- skipping a critical section it cannot interpret is
    /// exactly what the critical bit exists to prevent.
    pub fn has_unknown_critical(&self, known: &[u16]) -> bool {
        self.sections()
            .any(|(tag, _)| section_tag_is_critical(tag) && !known.contains(&tag))
    }
}

pub struct Sections<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Sections<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // The reader validated the structure, so a well-formed remainder is
        // an invariant here, not a condition to report.
        if self.rest.is_empty() {
            return None;
        }
        let tag = u16::from_le_bytes([self.rest[0], self.rest[1]]);
        let len =
            u32::from_le_bytes([self.rest[2], self.rest[3], self.rest[4], self.rest[5]]) as usize;
        let value = &self.rest[DOC_SECTION_HEADER_SZ..DOC_SECTION_HEADER_SZ + len];
        self.rest = &self.rest[DOC_SECTION_HEADER_SZ + len..];
        Some((tag, value))
    }
}

// -------------------------------------------------------------------- armor
//
// RFC 7468-shaped: `-----BEGIN ALOECRYPT {LABEL}-----`, base64 (standard
// alphabet, 64 characters per line), `-----END ALOECRYPT {LABEL}-----`. The
// crate brands every delimiter; the label parameter is only the document
// type. Leniency on decode is deliberate and small: anything before BEGIN
// and after END is ignored (documents travel inside email and logs), CRLF
// and LF both work, and any line width decodes -- but within the body only
// base64 bytes are accepted, padding is canonical-and-final, and the
// delimiter lines must match exactly.

const BEGIN_PREFIX: &[u8] = b"-----BEGIN ALOECRYPT ";
const END_PREFIX: &[u8] = b"-----END ALOECRYPT ";
const DELIM_SUFFIX: &[u8] = b"-----";
/// Bytes of payload per armored line: 48 bytes encode to 64 characters.
const ARMOR_LINE_BYTES: usize = 48;

/// A label is 1..=DOC_LABEL_MAX_SZ characters of A-Z, 0-9 and interior
/// spaces -- the uppercase RFC 7468 style the delimiters already use.
fn label_is_valid(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= DOC_LABEL_MAX_SZ
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b' ')
        && bytes[0] != b' '
        && bytes[bytes.len() - 1] != b' '
}

/// Exact size of the armored form of `payload_len` bytes under a
/// `label_len`-byte label, newlines included.
pub const fn armored_size(label_len: usize, payload_len: usize) -> usize {
    let full_lines = payload_len / ARMOR_LINE_BYTES;
    let rem = payload_len % ARMOR_LINE_BYTES;
    let mut body = full_lines * 65; // 64 characters + newline
    if rem > 0 {
        body += rem.div_ceil(3) * 4 + 1;
    }
    // BEGIN line + body + END line, one newline each.
    (BEGIN_PREFIX.len() + label_len + DELIM_SUFFIX.len() + 1)
        + body
        + (END_PREFIX.len() + label_len + DELIM_SUFFIX.len() + 1)
}

/// Upper bound on the payload a `text_len`-byte armored document can carry.
/// For buffer sizing only -- the true length comes back from `dearmor`.
pub const fn dearmored_size_bound(text_len: usize) -> usize {
    (text_len / 4) * 3
}

struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

/// Armors `payload` under `label` into `out`, returning the text length.
/// `BadArgument` for an invalid label or a buffer smaller than
/// `armored_size` says this call needs.
pub fn armor(label: &str, payload: &[u8], out: &mut [u8]) -> AloecryptResult<usize> {
    if !label_is_valid(label) {
        return err(StatusCodeEnum::BadArgument);
    }
    if out.len() < armored_size(label.len(), payload.len()) {
        return err(StatusCodeEnum::BadArgument);
    }
    let mut cur = Cursor { buf: out, pos: 0 };

    cur.put(BEGIN_PREFIX);
    cur.put(label.as_bytes());
    cur.put(DELIM_SUFFIX);
    cur.put(b"\n");

    let mut line = [0u8; 64];
    for chunk in payload.chunks(ARMOR_LINE_BYTES) {
        let encoded = BASE64.encode_len(chunk.len());
        BASE64.encode_mut(chunk, &mut line[..encoded]);
        cur.put(&line[..encoded]);
        cur.put(b"\n");
    }

    cur.put(END_PREFIX);
    cur.put(label.as_bytes());
    cur.put(DELIM_SUFFIX);
    cur.put(b"\n");
    Ok(cur.pos)
}

/// A delimiter line for `label`, assembled into a fixed buffer so it can be
/// compared against input lines without allocating.
struct DelimLine {
    buf: [u8; 64],
    len: usize,
}

impl DelimLine {
    fn new(prefix: &[u8], label: &str) -> Self {
        let mut buf = [0u8; 64];
        let mut pos = 0;
        for part in [prefix, label.as_bytes(), DELIM_SUFFIX] {
            buf[pos..pos + part.len()].copy_from_slice(part);
            pos += part.len();
        }
        Self { buf, len: pos }
    }

    fn matches(&self, line: &[u8]) -> bool {
        line == &self.buf[..self.len]
    }
}

/// Removes the armor from `text`, writing the payload into `out` and
/// returning its length. The label must match the delimiters exactly --
/// callers state what they expect rather than trusting the input to say
/// what it is. `BadEncoding` for anything that does not parse as armor;
/// `BadArgument` for an invalid label or an `out` that cannot hold the
/// payload (`dearmored_size_bound` sizes it).
pub fn dearmor(text: &[u8], label: &str, out: &mut [u8]) -> AloecryptResult<usize> {
    if !label_is_valid(label) {
        return err(StatusCodeEnum::BadArgument);
    }
    let begin = DelimLine::new(BEGIN_PREFIX, label);
    let end = DelimLine::new(END_PREFIX, label);

    let mut lines = text.split(|b| *b == b'\n').map(|line| {
        // Accept CRLF transport without accepting stray carriage returns
        // anywhere else.
        line.strip_suffix(b"\r").unwrap_or(line)
    });

    // Anything before BEGIN is transport preamble: skipped, never parsed.
    if !lines.any(|line| begin.matches(line)) {
        return err(StatusCodeEnum::BadEncoding);
    }

    let mut quad = [0u8; 4];
    let mut quad_len = 0usize;
    let mut decoded = [0u8; 3];
    let mut written = 0usize;
    let mut padded = false;
    for line in lines {
        if end.matches(line) {
            if quad_len != 0 {
                // A dangling partial group means the base64 was truncated.
                return err(StatusCodeEnum::BadEncoding);
            }
            return Ok(written);
        }
        for &b in line {
            // Base64 groups are self-delimiting, so any wrapping width
            // decodes identically; after canonical padding the body is over
            // and anything further is not armor.
            if padded {
                return err(StatusCodeEnum::BadEncoding);
            }
            quad[quad_len] = b;
            quad_len += 1;
            if quad_len < 4 {
                continue;
            }
            quad_len = 0;
            let Ok(n) = BASE64.decode_mut(&quad, &mut decoded) else {
                return err(StatusCodeEnum::BadEncoding);
            };
            if n < 3 {
                padded = true;
            }
            if written + n > out.len() {
                return err(StatusCodeEnum::BadArgument);
            }
            out[written..written + n].copy_from_slice(&decoded[..n]);
            written += n;
        }
    }
    // The input ran out before the END delimiter: truncated document.
    err(StatusCodeEnum::BadEncoding)
}

// ------------------------------------------------------ detached signatures
//
// A detached signature is an envelope (label SIGNATURE when armored) whose
// attestations are Signature sections, each self-contained:
//
//   alg u16 LE | signer address (32 bytes) | signature bytes
//
// One section is one complete attestation, so several signers -- of the same
// or different parameter sets -- are just several sections, and nothing
// pairs by position. What is signed is not the raw message but its
// domain-separated hash (`aloecrypt.detached.v1`): a detached signature can
// then never be replayed as some other protocol's signature over the same
// bytes, the ML-DSA call never sees an unbounded message on a bounded
// stack, and the domain string versions the construction.

pub const SIGNATURE_LABEL: &str = "SIGNATURE";
const DETACHED_SIG_DOMAIN: &str = "aloecrypt.detached.v1";
/// Algorithm id + signer address, ahead of the signature bytes.
const SIG_VALUE_HEADER_SZ: usize = 2 + ALOECRYPT_ADDRESS_SZ;

/// Bytes a single-signer detached signature document occupies, given the
/// algorithm's signature size (`MLDSA_44_SIGNATURE_SZ` and friends).
pub const fn detached_signature_size(signature_sz: usize) -> usize {
    DOC_HEADER_SZ + DOC_SECTION_HEADER_SZ + SIG_VALUE_HEADER_SZ + signature_sz
}

fn detached_signing_material(message: &[u8]) -> Hash256 {
    domain_hash(message, DETACHED_SIG_DOMAIN)
}

fn build_detached(
    alg: AloecryptAlgorithmEnum,
    address: &AloecryptAddress,
    signature: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let mut writer = EnvelopeWriter::new(out)?;
    writer.add_parts(
        SectionTagEnum::Signature as u16,
        &[&(alg as u16).to_le_bytes(), address, signature],
    )?;
    Ok(writer.finish())
}

/// Finds the attestation by (`alg`, `address`) and returns its signature
/// bytes. `AuthFailed` when the document carries no attestation by that key
/// -- absence answers the caller's question ("did this key sign this?")
/// rather than describing the document.
fn find_attestation<'a>(
    doc: &'a [u8],
    alg: u16,
    address: &AloecryptAddress,
    signature_sz: usize,
) -> AloecryptResult<&'a [u8]> {
    let reader = EnvelopeReader::new(doc)?;
    // No critical tags exist yet, so any critical section is from a future
    // this build cannot judge -- refuse rather than half-verify.
    if reader.has_unknown_critical(&[]) {
        return err(StatusCodeEnum::Unsupported);
    }
    for (tag, value) in reader.sections() {
        if tag != SectionTagEnum::Signature as u16 {
            continue;
        }
        if value.len() < SIG_VALUE_HEADER_SZ {
            return err(StatusCodeEnum::BadEncoding);
        }
        if u16::from_le_bytes([value[0], value[1]]) != alg {
            continue;
        }
        if value.len() != SIG_VALUE_HEADER_SZ + signature_sz {
            return err(StatusCodeEnum::BadEncoding);
        }
        if value[2..SIG_VALUE_HEADER_SZ] != address[..] {
            continue;
        }
        return Ok(&value[SIG_VALUE_HEADER_SZ..]);
    }
    err(StatusCodeEnum::AuthFailed)
}

pub fn sign_detached_44(
    keypair: &MlDsa44Keypair,
    message: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let material = detached_signing_material(message);
    let signature = keypair.sign(&material);
    build_detached(
        AloecryptAlgorithmEnum::MlDsa44,
        &keypair.address(),
        &signature,
        out,
    )
}

pub fn sign_detached_65(
    keypair: &MlDsa65Keypair,
    message: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let material = detached_signing_material(message);
    let signature = keypair.sign(&material);
    build_detached(
        AloecryptAlgorithmEnum::MlDsa65,
        &keypair.address(),
        &signature,
        out,
    )
}

pub fn sign_detached_87(
    keypair: &MlDsa87Keypair,
    message: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let material = detached_signing_material(message);
    let signature = keypair.sign(&material);
    build_detached(
        AloecryptAlgorithmEnum::MlDsa87,
        &keypair.address(),
        &signature,
        out,
    )
}

pub fn verify_detached_44(
    verifier: &MlDsa44Verifier,
    message: &[u8],
    doc: &[u8],
) -> AloecryptResult<()> {
    let bytes = find_attestation(
        doc,
        AloecryptAlgorithmEnum::MlDsa44 as u16,
        &verifier.address(),
        MLDSA_44_SIGNATURE_SZ,
    )?;
    let Ok(signature) = <&MlDsa44Signature>::try_from(bytes) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    let material = detached_signing_material(message);
    if verifier.verify(&material, signature) {
        Ok(())
    } else {
        err(StatusCodeEnum::AuthFailed)
    }
}

pub fn verify_detached_65(
    verifier: &MlDsa65Verifier,
    message: &[u8],
    doc: &[u8],
) -> AloecryptResult<()> {
    let bytes = find_attestation(
        doc,
        AloecryptAlgorithmEnum::MlDsa65 as u16,
        &verifier.address(),
        MLDSA_65_SIGNATURE_SZ,
    )?;
    let Ok(signature) = <&MlDsa65Signature>::try_from(bytes) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    let material = detached_signing_material(message);
    if verifier.verify(&material, signature) {
        Ok(())
    } else {
        err(StatusCodeEnum::AuthFailed)
    }
}

pub fn verify_detached_87(
    verifier: &MlDsa87Verifier,
    message: &[u8],
    doc: &[u8],
) -> AloecryptResult<()> {
    let bytes = find_attestation(
        doc,
        AloecryptAlgorithmEnum::MlDsa87 as u16,
        &verifier.address(),
        MLDSA_87_SIGNATURE_SZ,
    )?;
    let Ok(signature) = <&MlDsa87Signature>::try_from(bytes) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    let material = detached_signing_material(message);
    if verifier.verify(&material, signature) {
        Ok(())
    } else {
        err(StatusCodeEnum::AuthFailed)
    }
}

// ---------------------------------------------------- encrypt-to-recipient
//
// An encrypted document is an envelope (label ENCRYPTED when armored) of a
// recipient block and a sealed payload. The recipient block mirrors a
// signature attestation -- self-contained, one section:
//
//   alg u16 LE | recipient address (32 bytes) | ML-KEM ciphertext
//
// and the AeadCipher section is the payload sealed with ChaCha20-Poly1305:
//
//   ciphertext (payload length) | tag (16 bytes)
//
// The AEAD key is the domain-separated hash of the encapsulated shared
// secret (`aloecrypt.encrypt.mlkem768.v1`, ...), and the nonce is zero:
// every encapsulation yields a fresh single-use secret, so the (key, nonce)
// pair can never repeat, and a nonce on the wire would only be a decision
// for an attacker to make. One tag covers the whole payload, so the
// document cannot be truncated at any boundary and still authenticate.
// One recipient per document for now: several recipients need a wrapped
// content key, which is recorded as the open half of this design.

pub const ENCRYPTED_LABEL: &str = "ENCRYPTED";
const MLKEM_512_ENCRYPT_DOMAIN: &str = "aloecrypt.encrypt.mlkem512.v1";
const MLKEM_768_ENCRYPT_DOMAIN: &str = "aloecrypt.encrypt.mlkem768.v1";
const MLKEM_1024_ENCRYPT_DOMAIN: &str = "aloecrypt.encrypt.mlkem1024.v1";
/// Algorithm id + recipient address, ahead of the KEM ciphertext.
const KEM_VALUE_HEADER_SZ: usize = 2 + ALOECRYPT_ADDRESS_SZ;

/// Bytes an encrypted document occupies, given the KEM's ciphertext size
/// (`MLKEM_768_CIPHER_SZ` and friends) and the payload length.
pub const fn encrypted_document_size(kem_cipher_sz: usize, payload_len: usize) -> usize {
    DOC_HEADER_SZ
        + DOC_SECTION_HEADER_SZ
        + KEM_VALUE_HEADER_SZ
        + kem_cipher_sz
        + DOC_SECTION_HEADER_SZ
        + payload_len
        + ENCRYPTED_TAG_SZ
}

/// Builds the envelope and seals `payload` in place inside `out`.
fn seal_document(
    alg: AloecryptAlgorithmEnum,
    address: &AloecryptAddress,
    kem_cipher: &[u8],
    key: &Hash256,
    payload: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{AeadInPlace, KeyInit},
    };
    let mut writer = EnvelopeWriter::new(out)?;
    writer.add_parts(
        SectionTagEnum::KemCipher as u16,
        &[&(alg as u16).to_le_bytes(), address, kem_cipher],
    )?;
    let value = writer.add_reserved(
        SectionTagEnum::AeadCipher as u16,
        payload.len() + ENCRYPTED_TAG_SZ,
    )?;
    let (data, tag_out) = value.split_at_mut(payload.len());
    data.copy_from_slice(payload);
    let aead = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    let Ok(tag) = aead.encrypt_in_place_detached(&Nonce::default(), b"", data) else {
        return err(StatusCodeEnum::BadArgument);
    };
    tag_out.copy_from_slice(&tag);
    Ok(writer.finish())
}

/// Finds the recipient block by (`alg`, `address`) and returns its KEM
/// ciphertext. As with attestations, `AuthFailed` when the document names
/// no such recipient -- absence answers "is this for me?".
fn find_recipient_block<'a>(
    reader: &EnvelopeReader<'a>,
    alg: u16,
    address: &AloecryptAddress,
    kem_cipher_sz: usize,
) -> AloecryptResult<&'a [u8]> {
    for (tag, value) in reader.sections() {
        if tag != SectionTagEnum::KemCipher as u16 {
            continue;
        }
        if value.len() < KEM_VALUE_HEADER_SZ {
            return err(StatusCodeEnum::BadEncoding);
        }
        if u16::from_le_bytes([value[0], value[1]]) != alg {
            continue;
        }
        if value.len() != KEM_VALUE_HEADER_SZ + kem_cipher_sz {
            return err(StatusCodeEnum::BadEncoding);
        }
        if value[2..KEM_VALUE_HEADER_SZ] != address[..] {
            continue;
        }
        return Ok(&value[KEM_VALUE_HEADER_SZ..]);
    }
    err(StatusCodeEnum::AuthFailed)
}

/// Opens the sealed payload into `out`, returning its length.
fn open_document(reader: &EnvelopeReader, key: &Hash256, out: &mut [u8]) -> AloecryptResult<usize> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce, Tag,
        aead::{AeadInPlace, KeyInit},
    };
    let Some(value) = reader.find(SectionTagEnum::AeadCipher as u16) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    if value.len() < ENCRYPTED_TAG_SZ {
        return err(StatusCodeEnum::BadEncoding);
    }
    let payload_len = value.len() - ENCRYPTED_TAG_SZ;
    if out.len() < payload_len {
        return err(StatusCodeEnum::BadArgument);
    }
    let (data, tag) = value.split_at(payload_len);
    out[..payload_len].copy_from_slice(data);
    let aead = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    if aead
        .decrypt_in_place_detached(
            &Nonce::default(),
            b"",
            &mut out[..payload_len],
            Tag::from_slice(tag),
        )
        .is_err()
    {
        out[..payload_len].fill(0);
        return err(StatusCodeEnum::AuthFailed);
    }
    Ok(payload_len)
}

pub fn encrypt_to_recipient_512(
    recipient: &MlKem512Encapsulator,
    prk: MlKemPrkSeed,
    payload: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let result = recipient.encapsulate(prk);
    let key = domain_hash(&result.secret, MLKEM_512_ENCRYPT_DOMAIN);
    seal_document(
        AloecryptAlgorithmEnum::MlKem512,
        &recipient.address(),
        &result.cipher,
        &key,
        payload,
        out,
    )
}

pub fn encrypt_to_recipient_768(
    recipient: &MlKem768Encapsulator,
    prk: MlKemPrkSeed,
    payload: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let result = recipient.encapsulate(prk);
    let key = domain_hash(&result.secret, MLKEM_768_ENCRYPT_DOMAIN);
    seal_document(
        AloecryptAlgorithmEnum::MlKem768,
        &recipient.address(),
        &result.cipher,
        &key,
        payload,
        out,
    )
}

pub fn encrypt_to_recipient_1024(
    recipient: &MlKem1024Encapsulator,
    prk: MlKemPrkSeed,
    payload: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let result = recipient.encapsulate(prk);
    let key = domain_hash(&result.secret, MLKEM_1024_ENCRYPT_DOMAIN);
    seal_document(
        AloecryptAlgorithmEnum::MlKem1024,
        &recipient.address(),
        &result.cipher,
        &key,
        payload,
        out,
    )
}

pub fn decrypt_as_recipient_512(
    keypair: &MlKem512Keypair,
    doc: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let reader = EnvelopeReader::new(doc)?;
    if reader.has_unknown_critical(&[]) {
        return err(StatusCodeEnum::Unsupported);
    }
    let kem_cipher = find_recipient_block(
        &reader,
        AloecryptAlgorithmEnum::MlKem512 as u16,
        &keypair.get_encapsulator().address(),
        MLKEM_512_CIPHER_SZ,
    )?;
    let Ok(kem_cipher) = <&MlKem512Cipher>::try_from(kem_cipher) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    let secret = keypair.decapsulate(kem_cipher);
    let key = domain_hash(&secret, MLKEM_512_ENCRYPT_DOMAIN);
    open_document(&reader, &key, out)
}

pub fn decrypt_as_recipient_768(
    keypair: &MlKem768Keypair,
    doc: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let reader = EnvelopeReader::new(doc)?;
    if reader.has_unknown_critical(&[]) {
        return err(StatusCodeEnum::Unsupported);
    }
    let kem_cipher = find_recipient_block(
        &reader,
        AloecryptAlgorithmEnum::MlKem768 as u16,
        &keypair.get_encapsulator().address(),
        MLKEM_768_CIPHER_SZ,
    )?;
    let Ok(kem_cipher) = <&MlKem768Cipher>::try_from(kem_cipher) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    let secret = keypair.decapsulate(kem_cipher);
    let key = domain_hash(&secret, MLKEM_768_ENCRYPT_DOMAIN);
    open_document(&reader, &key, out)
}

pub fn decrypt_as_recipient_1024(
    keypair: &MlKem1024Keypair,
    doc: &[u8],
    out: &mut [u8],
) -> AloecryptResult<usize> {
    let reader = EnvelopeReader::new(doc)?;
    if reader.has_unknown_critical(&[]) {
        return err(StatusCodeEnum::Unsupported);
    }
    let kem_cipher = find_recipient_block(
        &reader,
        AloecryptAlgorithmEnum::MlKem1024 as u16,
        &keypair.get_encapsulator().address(),
        MLKEM_1024_CIPHER_SZ,
    )?;
    let Ok(kem_cipher) = <&MlKem1024Cipher>::try_from(kem_cipher) else {
        return err(StatusCodeEnum::BadEncoding);
    };
    let secret = keypair.decapsulate(kem_cipher);
    let key = domain_hash(&secret, MLKEM_1024_ENCRYPT_DOMAIN);
    open_document(&reader, &key, out)
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
