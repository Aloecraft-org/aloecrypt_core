// tests/secret_sharing.rs
// Threshold properties for the Shamir and SLIP-39 share schemes: exact
// threshold recovers, surplus recovers, and sub-threshold does not.

use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::rng_api::*;
use aloecrypt_core::shamir::*;
use aloecrypt_core::slip39::*;

fn seed(n: u8) -> RngSeed {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = n.wrapping_add(i as u8).wrapping_mul(31);
    }
    s
}

fn secret_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 19 % 256) as u8).collect()
}

// ------------------------------------------------------------------- Shamir

#[test]
fn shamir_recovers_from_exactly_the_threshold() {
    let data = secret_bytes(32);
    let shares = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(1));
    let subset = [shares[0], shares[2], shares[4]];
    assert_eq!(combine_shamir_shares(&subset).to_byte_arr(), &data[..]);
}

#[test]
fn shamir_recovers_from_surplus_shares() {
    let data = secret_bytes(32);
    let shares = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(2));
    let subset = [shares[0], shares[1], shares[3], shares[4]];
    assert_eq!(combine_shamir_shares(&subset).to_byte_arr(), &data[..]);
}

#[test]
fn shamir_recovers_from_every_threshold_subset() {
    let data = secret_bytes(24);
    let shares = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(3));
    for a in 0..5 {
        for b in (a + 1)..5 {
            for c in (b + 1)..5 {
                let subset = [shares[a], shares[b], shares[c]];
                assert_eq!(
                    combine_shamir_shares(&subset).to_byte_arr(),
                    &data[..],
                    "shamir subset ({a},{b},{c}) failed to recover"
                );
            }
        }
    }
}

#[test]
fn shamir_sub_threshold_does_not_recover() {
    let data = secret_bytes(32);
    let shares = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(4));
    let subset = [shares[0], shares[1]];
    assert_ne!(
        combine_shamir_shares(&subset).to_byte_arr(),
        &data[..],
        "two shares recovered a 3-of-5 secret"
    );
}

#[test]
fn shamir_shares_are_not_the_secret() {
    let data = secret_bytes(32);
    let shares = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(5));
    for (i, share) in shares.iter().enumerate() {
        assert_ne!(
            share.to_byte_arr(),
            &data[..],
            "share {i} is the plaintext secret"
        );
    }
}

#[test]
fn shamir_different_seeds_give_different_shares() {
    let data = secret_bytes(32);
    let a = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(6));
    let b = create_5_shamir_shares(VarByte255::from_byte_arr(&data), 3, seed(7));
    assert_ne!(
        a[0].to_byte_arr(),
        b[0].to_byte_arr(),
        "share generation ignored the seed"
    );
}

#[test]
fn shamir_works_across_share_counts() {
    let data = secret_bytes(16);
    let s = VarByte255::from_byte_arr(&data);
    let three = create_3_shamir_shares(s, 2, seed(8));
    assert_eq!(
        combine_shamir_shares(&[three[0], three[2]]).to_byte_arr(),
        &data[..]
    );
    let eight = create_8_shamir_shares(s, 5, seed(9));
    let subset = [eight[1], eight[2], eight[4], eight[6], eight[7]];
    assert_eq!(combine_shamir_shares(&subset).to_byte_arr(), &data[..]);
}

// ------------------------------------------------------------------ SLIP-39

#[test]
fn slip39_recovers_from_exactly_the_threshold() {
    let data = secret_bytes(32);
    let secret = to_slip39_secret(&data);
    let shares = create_5_slip39_shares(secret, 3, seed(11));
    let subset = [shares[0], shares[2], shares[4]];
    let combined = combine_slip39_shares(&subset);
    assert_eq!(
        from_slip39_secret(combined.to_u16_arr()).to_byte_arr(),
        &data[..]
    );
}

#[test]
fn slip39_recovers_from_surplus_shares() {
    let data = secret_bytes(32);
    let secret = to_slip39_secret(&data);
    let shares = create_5_slip39_shares(secret, 3, seed(12));
    let subset = [shares[0], shares[1], shares[3], shares[4]];
    let combined = combine_slip39_shares(&subset);
    assert_eq!(
        from_slip39_secret(combined.to_u16_arr()).to_byte_arr(),
        &data[..]
    );
}

#[test]
fn slip39_recovers_from_every_threshold_subset() {
    let data = secret_bytes(16);
    let secret = to_slip39_secret(&data);
    let shares = create_5_slip39_shares(secret, 3, seed(13));
    for a in 0..5 {
        for b in (a + 1)..5 {
            for c in (b + 1)..5 {
                let subset = [shares[a], shares[b], shares[c]];
                let combined = combine_slip39_shares(&subset);
                assert_eq!(
                    from_slip39_secret(combined.to_u16_arr()).to_byte_arr(),
                    &data[..],
                    "slip39 subset ({a},{b},{c}) failed to recover"
                );
            }
        }
    }
}

#[test]
fn slip39_sub_threshold_does_not_recover() {
    let data = secret_bytes(32);
    let secret = to_slip39_secret(&data);
    let shares = create_5_slip39_shares(secret, 3, seed(14));
    let subset = [shares[0], shares[1]];
    let combined = combine_slip39_shares(&subset);
    assert_ne!(
        combined.to_u16_arr(),
        secret.to_u16_arr(),
        "two shares recovered a 3-of-5 secret"
    );
}
