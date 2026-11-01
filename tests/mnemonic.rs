// tests/mnemonic.rs
// BIP-39 against the canonical vectors from the specification, plus round-trip
// properties for both mnemonic schemes.

use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::bip39::*;
use aloecrypt_core::slip39::*;

/// Decode a VarU16_255 into an owned Vec. `to_u16_arr` was removed because it
/// handed out a `&[u16]` borrowed from an align-1 packed buffer, which is
/// undefined behaviour; `read_u16_arr` decodes into a caller buffer instead.
fn words(v: &VarU16_255) -> Vec<u16> {
    let mut buf = [0u16; 255];
    let n = v.read_u16_arr(&mut buf);
    buf[..n].to_vec()
}

/// Canonical BIP-39 vectors (entropy -> mnemonic), from the specification's
/// English test set. These are external ground truth: if they fail, the
/// implementation is not BIP-39 compatible regardless of whether it round trips.
#[cfg(feature = "bip39_words")]
const BIP39_VECTORS: &[(&[u8], &str)] = &[
    (
        &[0x00; 16],
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ),
    (
        &[0x7f; 16],
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    ),
    (
        &[0x80; 16],
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ),
    (
        &[0xff; 16],
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ),
    (
        &[0x00; 32],
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    ),
];

#[cfg(feature = "bip39_words")]
#[test]
fn bip39_matches_specification_vectors() {
    for (entropy, expected) in BIP39_VECTORS {
        let indices = to_bip39_secret(entropy);
        let mnemonic = to_bip39_mnemonic(&words(&indices));
        assert_eq!(
            mnemonic.to_str(),
            *expected,
            "BIP-39 mnemonic mismatch for {}-byte entropy {:#04x}",
            entropy.len(),
            entropy[0]
        );
    }
}

#[cfg(feature = "bip39_words")]
#[test]
fn bip39_mnemonic_parses_back_to_entropy() {
    for (entropy, _) in BIP39_VECTORS {
        let indices = to_bip39_secret(entropy);
        let mnemonic = to_bip39_mnemonic(&words(&indices));
        let parsed = from_bip39_mnemonic(&mnemonic);
        assert_eq!(&words(&parsed), &words(&indices), "index round trip");
        let recovered = from_bip39_secret(&words(&parsed));
        assert_eq!(
            recovered.to_byte_arr(),
            *entropy,
            "entropy round trip through the mnemonic"
        );
    }
}

#[test]
fn bip39_secret_roundtrips_without_wordlist() {
    // The arithmetic half must work with the wordlists compiled out.
    for len in [16usize, 20, 24, 28, 32] {
        let entropy: Vec<u8> = (0..len).map(|i| (i * 11 % 256) as u8).collect();
        let indices = to_bip39_secret(&entropy);
        let recovered = from_bip39_secret(&words(&indices));
        assert_eq!(
            recovered.to_byte_arr(),
            &entropy[..],
            "bip39 secret round trip at {len} bytes"
        );
    }
}

#[cfg(feature = "bip39_words")]
#[test]
fn bip39_indices_are_all_within_the_wordlist() {
    let entropy: Vec<u8> = (0..32).map(|i| (i * 29 % 256) as u8).collect();
    for &idx in words(&to_bip39_secret(&entropy)).iter() {
        assert!(idx < 2048, "index {idx} outside the 2048-word BIP-39 list");
    }
}

#[test]
fn slip39_secret_roundtrips_without_wordlist() {
    for len in [16usize, 20, 32] {
        let data: Vec<u8> = (0..len).map(|i| (i * 17 % 256) as u8).collect();
        let secret = to_slip39_secret(&data);
        let recovered = from_slip39_secret(&words(&secret));
        assert_eq!(
            recovered.to_byte_arr(),
            &data[..],
            "slip39 secret round trip at {len} bytes"
        );
    }
}

#[cfg(feature = "slip39_words")]
#[test]
fn slip39_mnemonic_roundtrips() {
    let data: Vec<u8> = (0..32).map(|i| (i * 23 % 256) as u8).collect();
    let secret = to_slip39_secret(&data);
    let mnemonic = to_slip39_mnemonic(&words(&secret));
    let parsed = from_slip39_mnemonic(&mnemonic);
    assert_eq!(&words(&parsed), &words(&secret));
    assert_eq!(from_slip39_secret(&words(&parsed)).to_byte_arr(), &data[..]);
}

#[cfg(feature = "slip39_words")]
#[test]
fn slip39_indices_are_all_within_the_wordlist() {
    let data: Vec<u8> = (0..32).map(|i| (i * 31 % 256) as u8).collect();
    for &idx in words(&to_slip39_secret(&data)).iter() {
        assert!(idx < 1024, "index {idx} outside the 1024-word SLIP-39 list");
    }
}
