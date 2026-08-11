// tests/pqc.rs
// ML-DSA signing and ML-KEM encapsulation: determinism from a seed, round
// trips, and the negative cases that matter.

use aloecrypt_core::dsa::*;
use aloecrypt_core::dsa_api::*;
use aloecrypt_core::kem::*;
use aloecrypt_core::kem_api::*;
use aloecrypt_core::recovery::*;
use aloecrypt_core::recovery_api::*;

fn seed(n: u8) -> MlDsaPrivateSeed {
    let mut s = [0u8; MLDSA_SEED_SZ];
    for (i, b) in s.iter_mut().enumerate() {
        *b = n.wrapping_add(i as u8).wrapping_mul(37);
    }
    s
}

// ------------------------------------------------------------------- ML-DSA

macro_rules! dsa_suite {
    ($modname:ident, $kp:ident) => {
        mod $modname {
            use super::*;

            #[test]
            fn sign_verify_roundtrip() {
                let kp = $kp::from_seed(&seed(1));
                let msg = b"aloecrypt signature test";
                let sig = kp.sign(msg);
                assert!(
                    kp.get_verifier().verify(msg, &sig),
                    "valid signature rejected"
                );
            }

            #[test]
            fn keygen_is_deterministic_in_the_seed() {
                let a = $kp::from_seed(&seed(2));
                let b = $kp::from_seed(&seed(2));
                assert_eq!(
                    a.get_verifier().pack_bytes(),
                    b.get_verifier().pack_bytes(),
                    "same seed produced different public keys"
                );
                let c = $kp::from_seed(&seed(3));
                assert_ne!(
                    a.get_verifier().pack_bytes(),
                    c.get_verifier().pack_bytes(),
                    "different seeds produced the same public key"
                );
            }

            #[test]
            fn a_modified_message_does_not_verify() {
                let kp = $kp::from_seed(&seed(4));
                let sig = kp.sign(b"transfer 100 to alice");
                assert!(
                    !kp.get_verifier().verify(b"transfer 900 to alice", &sig),
                    "signature verified against a different message"
                );
            }

            #[test]
            fn a_modified_signature_does_not_verify() {
                let kp = $kp::from_seed(&seed(5));
                let msg = b"aloecrypt signature test";
                let mut sig = kp.sign(msg);
                sig[0] ^= 0x01;
                assert!(
                    !kp.get_verifier().verify(msg, &sig),
                    "tampered signature still verified"
                );
            }

            #[test]
            fn another_key_does_not_verify() {
                let signer = $kp::from_seed(&seed(6));
                let other = $kp::from_seed(&seed(7));
                let msg = b"aloecrypt signature test";
                let sig = signer.sign(msg);
                assert!(
                    !other.get_verifier().verify(msg, &sig),
                    "signature verified under an unrelated key"
                );
            }

            #[test]
            fn keypair_survives_pack_unpack() {
                let kp = $kp::from_seed(&seed(8));
                let restored = $kp::unpack_bytes(kp.pack_bytes());
                let msg = b"aloecrypt signature test";
                assert!(restored.get_verifier().verify(msg, &kp.sign(msg)));
            }
        }
    };
}

dsa_suite!(dsa44, MlDsa44Keypair);
dsa_suite!(dsa65, MlDsa65Keypair);
dsa_suite!(dsa87, MlDsa87Keypair);

// ------------------------------------------------------------------- ML-KEM

macro_rules! kem_suite {
    ($modname:ident, $kp:ident) => {
        mod $modname {
            use super::*;

            fn kem_seed(n: u8) -> [u8; 64] {
                let mut s = [0u8; 64];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = n.wrapping_add(i as u8).wrapping_mul(53);
                }
                s
            }

            fn prk(n: u8) -> MlKemPrkSeed {
                let mut s = [0u8; MLKEM_PRK_SEED_SZ];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = n.wrapping_add(i as u8).wrapping_mul(97);
                }
                s
            }

            #[test]
            fn encapsulate_decapsulate_agree() {
                let kp = $kp::from_seed(&kem_seed(1));
                let result = kp.get_encapsulator().encapsulate(prk(1));
                assert_eq!(
                    kp.decapsulate(&result.cipher),
                    result.secret,
                    "decapsulated secret disagrees with the encapsulated one"
                );
            }

            #[test]
            fn keygen_is_deterministic_in_the_seed() {
                let a = $kp::from_seed(&kem_seed(2));
                let b = $kp::from_seed(&kem_seed(2));
                assert_eq!(
                    a.public_key, b.public_key,
                    "same seed, different public key"
                );
                let c = $kp::from_seed(&kem_seed(3));
                assert_ne!(
                    a.public_key, c.public_key,
                    "different seeds, same public key"
                );
            }

            #[test]
            fn a_different_keypair_does_not_recover_the_secret() {
                let kp = $kp::from_seed(&kem_seed(4));
                let other = $kp::from_seed(&kem_seed(5));
                let result = kp.get_encapsulator().encapsulate(prk(4));
                assert_ne!(
                    other.decapsulate(&result.cipher),
                    result.secret,
                    "an unrelated key recovered the shared secret"
                );
            }

            #[test]
            fn distinct_prk_seeds_give_distinct_secrets() {
                let kp = $kp::from_seed(&kem_seed(6));
                let a = kp.get_encapsulator().encapsulate(prk(6));
                let b = kp.get_encapsulator().encapsulate(prk(7));
                assert_ne!(a.secret, b.secret, "encapsulation ignored the prk seed");
                assert_ne!(
                    a.cipher, b.cipher,
                    "encapsulation produced the same ciphertext"
                );
            }
        }
    };
}

kem_suite!(kem512, MlKem512Keypair);
kem_suite!(kem768, MlKem768Keypair);
kem_suite!(kem1024, MlKem1024Keypair);

// ------------------------------------------------------------------ recovery

#[test]
fn recoverable_secret_roundtrips_through_the_authorizer() {
    let mut authorizer_seed = [0u8; 64];
    for (i, b) in authorizer_seed.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(41);
    }
    let recovery_secret: RecoverySecret = [7u8; RECOVERY_PRIVKEY_SZ];
    let prk_seed: MlKemPrkSeed = [11u8; MLKEM_PRK_SEED_SZ];
    let ikm = b"recovery input keying material";
    let domain = "aloecrypt.test.recovery";

    let authorizer = MlKem512Keypair::from_seed(&authorizer_seed);
    let recoverable = RecoverableSecret::create(
        authorizer.get_encapsulator(),
        recovery_secret,
        prk_seed,
        ikm,
        domain,
    );
    let recovery_key = recoverable.recovery_key;

    let authorization = authorize_recovery(
        authorizer,
        &recovery_key.cipher,
        recovery_key.mac,
        ikm,
        domain,
    );
    let recovered = RecoverableSecret::recover(authorization, &recovery_key.secret);

    assert_eq!(
        recovered, recoverable.secret,
        "recovery did not reproduce the inner secret"
    );
}
