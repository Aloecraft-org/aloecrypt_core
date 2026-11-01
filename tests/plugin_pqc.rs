// tests/plugin_pqc.rs
// The flat seed-and-bytes wrappers in src/plugin/pqc.rs must agree with the
// struct API they delegate to.

use aloecrypt_core::error::StatusCodeEnum;
use aloecrypt_core::kem_api::*;
use aloecrypt_core::plugin::pqc::*;

#[test]
fn mldsa_flat_wrappers_sign_and_verify() {
    let seed = [7u8; 32];
    let msg = b"flat wrappers";
    let pk44 = mldsa__dsa44__pubkey(&seed);
    assert!(mldsa__dsa44__verify(
        &pk44,
        msg,
        &mldsa__dsa44__sign(&seed, msg)
    ));
    let pk65 = mldsa__dsa65__pubkey(&seed);
    let sig65 = mldsa__dsa65__sign(&seed, msg);
    assert!(mldsa__dsa65__verify(&pk65, msg, &sig65));
    assert!(!mldsa__dsa65__verify(&pk65, b"other message", &sig65));
    let pk87 = mldsa__dsa87__pubkey(&seed);
    assert!(mldsa__dsa87__verify(
        &pk87,
        msg,
        &mldsa__dsa87__sign(&seed, msg)
    ));
}

#[test]
fn mlkem_flat_wrappers_agree_on_the_secret() {
    let seed = [9u8; 64];
    let prk = [3u8; MLKEM_PRK_SEED_SZ];

    let r = mlkem__kem512__encapsulate(&mlkem__kem512__pubkey(&seed), &prk).unwrap();
    assert_eq!(mlkem__kem512__decapsulate(&seed, &r.cipher), r.secret);
    let r = mlkem__kem768__encapsulate(&mlkem__kem768__pubkey(&seed), &prk).unwrap();
    assert_eq!(mlkem__kem768__decapsulate(&seed, &r.cipher), r.secret);
    let r = mlkem__kem1024__encapsulate(&mlkem__kem1024__pubkey(&seed), &prk).unwrap();
    assert_eq!(mlkem__kem1024__decapsulate(&seed, &r.cipher), r.secret);
}

#[test]
fn mlkem_flat_wrappers_refuse_a_malformed_key() {
    let prk = [3u8; MLKEM_PRK_SEED_SZ];
    let bad = Some(StatusCodeEnum::BadEncoding.into());
    assert_eq!(
        mlkem__kem512__encapsulate(&[0xFF; MLKEM_512_ENCAP_KEY_SZ], &prk).err(),
        bad
    );
    assert_eq!(
        mlkem__kem768__encapsulate(&[0xFF; MLKEM_768_ENCAP_KEY_SZ], &prk).err(),
        bad
    );
    assert_eq!(
        mlkem__kem1024__encapsulate(&[0xFF; MLKEM_1024_ENCAP_KEY_SZ], &prk).err(),
        bad
    );
}
