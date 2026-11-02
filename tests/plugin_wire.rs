// tests/plugin_wire.rs
// License: Apache-2.0
//
// The plugin's wire adapters, exercised natively (no wasm runtime): the same
// bytes the Python and TypeScript bindings send. generator/check_plugin.py
// drives the built .wasm end to end through the real bindings.
#![cfg(feature = "plugin")]

use aloecrypt_core::dsa_api::*;
use aloecrypt_core::plugin::exports::*;

const OK: [u8; 2] = [0, 0];
const BAD_ENCODING: [u8; 2] = [2, 0];

fn varlen(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

fn ok_payload(reply: Vec<u8>) -> Vec<u8> {
    assert_eq!(
        reply[..2],
        OK,
        "expected an Ok status, got {:?}",
        &reply[..2.min(reply.len())]
    );
    reply[2..].to_vec()
}

#[test]
fn every_export_is_listed_once() {
    let mut names: Vec<_> = EXPORTS.iter().map(|(n, _)| *n).collect();
    let total = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), total, "duplicate export names");
    assert!(total >= 100, "only {total} exports generated");
}

#[test]
fn sign_and_verify_across_the_wire_match_native() {
    let seed = [7u8; MLDSA_SEED_SZ];
    let kp = ok_payload(dsa_api___mldsa65keypair__from_seed(&seed));
    assert_eq!(kp.len(), core::mem::size_of::<MlDsa65Keypair>());

    let mut req = kp.clone();
    req.extend(varlen(b"message"));
    let sig = ok_payload(dsa_api___mldsa65keypair__sign(&req));
    let native = MlDsa65Keypair::from_seed(&seed).sign(b"message");
    assert_eq!(sig, native.to_vec(), "wire signature differs from native");

    let verifier = ok_payload(dsa_api___mldsa65keypair__get_verifier(&kp));
    for (msg, want) in [(&b"message"[..], 1u8), (&b"massage"[..], 0u8)] {
        let mut req = verifier.clone();
        req.extend(varlen(msg));
        req.extend_from_slice(&sig);
        assert_eq!(ok_payload(dsa_api___mldsa65verifier__verify(&req)), [want]);
    }
}

#[test]
fn mut_self_builder_returns_the_updated_struct() {
    let empty = ok_payload(otp_api___otpcredential__empty(&[]));
    let mut req = empty.clone();
    req.extend(varlen(b"Aloecraft"));
    let named = ok_payload(otp_api___otpcredential__with_issuer(&req));
    assert_eq!(named.len(), empty.len());
    assert_ne!(named, empty);
}

#[test]
fn malformed_requests_are_bad_encoding_with_no_payload() {
    let seed = [0u8; MLDSA_SEED_SZ];
    let cases: [(&str, fn(&[u8]) -> Vec<u8>, Vec<u8>); 5] = [
        (
            "short fixed field",
            dsa_api___mldsa65keypair__from_seed,
            seed[..31].to_vec(),
        ),
        (
            "trailing bytes",
            dsa_api___mldsa65keypair__from_seed,
            [&seed[..], &[0]].concat(),
        ),
        (
            "length prefix overruns",
            hash_api___simple_hash,
            vec![9, 0, 0, 0, 1, 2],
        ),
        (
            "truncated length prefix",
            hash_api___simple_hash,
            vec![1, 0],
        ),
        (
            "invalid UTF-8",
            otp_api___otpcredential__from_string,
            varlen(&[0xff, 0xfe]),
        ),
    ];
    for (what, export, req) in cases {
        assert_eq!(export(&req), BAD_ENCODING, "{what}");
    }
}

#[test]
fn fallible_export_sends_its_status_and_no_payload() {
    // A VarChar255 holds at most 255 bytes; 256 is a BadArgument from the
    // fallible builder, with the payload absent.
    let empty = ok_payload(otp_api___otpcredential__empty(&[]));
    let mut req = empty;
    req.extend(varlen(&[b'a'; 256]));
    let reply = otp_api___otpcredential__with_issuer(&req);
    assert_eq!(reply.len(), 2, "a non-Ok reply carries no payload");
    assert_ne!(reply[..2], OK);
}
