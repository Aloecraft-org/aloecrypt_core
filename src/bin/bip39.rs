use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::bip39::*;
use aloecrypt_core::fixed_byte::*;
use aloecrypt_core::rng::*;
use aloecrypt_core::rng_api::*;

use rand_core::{Rng, RngCore};
fn _make_rng() -> impl CryptoRngCore {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    AloeRng::new(seed)
}

fn main() {
    let mut rng = _make_rng();

    // --- Path 1: 16 bytes (12-word mnemonic) ---
    let mut orig_16 = [0u8; 16];
    rng.fill_bytes(&mut orig_16);
    let enc_16 = to_bip39(&orig_16);

    println!("--- 16-byte (12 words) BIP39 ---");
    #[cfg(feature = "bip39_words")]
    {
        let mnemonic = to_bip39_mnemonic(enc_16.to_u16_arr());
        println!("Mnemonic: {}", mnemonic.to_str());

        // Roundtrip through mnemonic string back to indices
        let parsed = from_bip39_mnemonic(&mnemonic);
        assert_eq!(
            enc_16.to_u16_arr(),
            parsed.to_u16_arr(),
            "Mnemonic parsing mismatch"
        );

        let decoded = from_bip39(parsed.to_u16_arr());
        assert_eq!(&decoded.value[1..1 + orig_16.len()], &orig_16);
        println!("SUCCESS: 16-byte hex fully round-tripped!\n");
    }
    #[cfg(not(feature = "bip39_words"))]
    {
        let decoded = from_bip39(enc_16.to_u16_arr());
        assert_eq!(&decoded.value[1..1 + orig_16.len()], &orig_16);
        println!("SUCCESS: 16-byte hex fully round-tripped! (Mnemonics disabled)\n");
    }

    // --- Path 2: 32 bytes (24-word mnemonic) ---
    let mut orig_32 = [0u8; 32];
    rng.fill_bytes(&mut orig_32);
    let enc_32 = to_bip39(&orig_32);

    println!("--- 32-byte (24 words) BIP39 ---");
    #[cfg(feature = "bip39_words")]
    {
        let mnemonic = to_bip39_mnemonic(enc_32.to_u16_arr());
        println!("Mnemonic: {}", mnemonic.to_str());

        let parsed = from_bip39_mnemonic(&mnemonic);
        assert_eq!(
            enc_32.to_u16_arr(),
            parsed.to_u16_arr(),
            "Mnemonic parsing mismatch"
        );

        let decoded = from_bip39(parsed.to_u16_arr());
        assert_eq!(&decoded.value[1..1 + orig_32.len()], &orig_32);
        println!("SUCCESS: 32-byte hex fully round-tripped!");
    }
    #[cfg(not(feature = "bip39_words"))]
    {
        let decoded = from_bip39(enc_32.to_u16_arr());
        assert_eq!(&decoded.value[1..1 + orig_32.len()], &orig_32);
        println!("SUCCESS: 32-byte hex fully round-tripped! (Mnemonics disabled)");
    }
}
