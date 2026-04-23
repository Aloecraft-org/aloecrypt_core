use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::fixed_byte::*;
use aloecrypt_core::shamir::*;

fn main() {
    let original_data = b"Keep it secret, keep it safe.";
    let secret = VarByte255::from_byte_arr(original_data);

    let threshold = 3;
    let seed = [0xAA; 32]; // Pseudo-random seed for test

    println!(
        "Original Secret: {:?}",
        String::from_utf8_lossy(original_data)
    );
    println!("--------------------------------------------------");

    let shares = create_5_shamir_shares(secret, threshold, seed);

    for (i, share) in shares.iter().enumerate() {
        let len = share.value[0] as usize;
        let loc = share.value[1];
        let data = &share.value[2..1 + len];
        println!("Share {}: (Location: {}) Data: {:02x?}", i + 1, loc, data);
    }
    println!("--------------------------------------------------");

    // Test exactly 3 shares
    println!("Attempting recovery with exactly 3 shares...");
    let recovery_3 = [shares[0], shares[2], shares[4]];
    let recovered_secret_3 = combine_shamir_shares(&recovery_3);
    assert_eq!(recovered_secret_3.to_byte_arr(), original_data);
    println!("SUCCESS: 3-share secret reconstructed perfectly!\n");

    // Test surplus shares
    println!("Attempting recovery with surplus (4) shares...");
    let recovery_4 = [shares[0], shares[1], shares[3], shares[4]];
    let recovered_secret_4 = combine_shamir_shares(&recovery_4);
    assert_eq!(recovered_secret_4.to_byte_arr(), original_data);
    println!("SUCCESS: 4-share secret reconstructed perfectly!");
}
