use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::rng::*;
use aloecrypt_core::rng_api::*;
use aloecrypt_core::slip39::*;

use rand_core::Rng;

/// Decode a VarU16_255 into an owned Vec. `to_u16_arr` was removed because it
/// handed out a `&[u16]` borrowed from an align-1 packed buffer, which is
/// undefined behaviour; `read_u16_arr` decodes into a caller buffer instead.
fn words(v: &VarU16_255) -> Vec<u16> {
    let mut buf = [0u16; 255];
    let n = v.read_u16_arr(&mut buf);
    buf[..n].to_vec()
}

fn _make_rng() -> impl CryptoRngCore {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("host entropy source failed");
    AloeRng::new(seed)
}

fn main() {
    let mut rng = _make_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // 1. Setup the original secret
    let original_data = b"Keep it secret, keep it safe !";
    println!("Original: {:?}", String::from_utf8_lossy(original_data));
    println!("--------------------------------------------------");

    let secret = to_slip39_secret(original_data);
    let threshold = 3;
    let shares = create_5_slip39_shares(secret, threshold, seed);

    let mut parsed_shares = Vec::new();
    for (i, share) in shares.iter().enumerate() {
        #[cfg(feature = "slip39_words")]
        {
            let mnemonic = to_slip39_mnemonic(&words(&share));
            let loc = u16::from_le_bytes([share.value[2], share.value[3]]);
            println!("Share {} (Loc {}): {}", i + 1, loc, mnemonic.to_str());

            // Exercise mnemonic parsing path
            let parsed_share = from_slip39_mnemonic(&mnemonic);
            assert_eq!(
                &words(&share),
                &words(&parsed_share),
                "Mnemonic parsing mismatch"
            );
            parsed_shares.push(parsed_share);
        }
        #[cfg(not(feature = "slip39_words"))]
        {
            println!("Enable feature `slip39_words` to print mnemonic");
            parsed_shares.push(*share);
        }
    }
    println!("--------------------------------------------------");

    // 2. Test Recovery with exactly the threshold (3 shares)
    println!("Attempting recovery with exactly 3 shares...");
    let recovery_3 = vec![parsed_shares[0], parsed_shares[2], parsed_shares[4]];
    let recovered_secret_3 = combine_slip39_shares(&recovery_3);

    let decoded_3 = from_slip39_secret(&words(&recovered_secret_3));
    let len_3 = decoded_3.value[0] as usize;
    assert_eq!(&decoded_3.value[1..1 + len_3], original_data);
    println!("SUCCESS: 3-share secret reconstructed perfectly!\n");

    // 3. Test Recovery with more than the threshold (4 shares)
    println!("Attempting recovery with surplus (4) shares...");
    let recovery_4 = vec![
        parsed_shares[0],
        parsed_shares[1],
        parsed_shares[3],
        parsed_shares[4],
    ];
    let recovered_secret_4 = combine_slip39_shares(&recovery_4);

    let decoded_4 = from_slip39_secret(&words(&recovered_secret_4));
    let len_4 = decoded_4.value[0] as usize;
    assert_eq!(&decoded_4.value[1..1 + len_4], original_data);
    println!("SUCCESS: 4-share secret reconstructed perfectly!");
}
