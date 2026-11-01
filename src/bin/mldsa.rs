// src/bin/mldsa.rs
// License: Apache-2.0
//
// Smoke test: ML-DSA-65 sign, verify, and verify again from the bare public key.
//
//   cargo run --bin mldsa

use aloecrypt_core::dsa_api::*;
use aloecrypt_core::rng::CryptoRngCore;
use aloecrypt_core::rng_api::*;
use rand_core::Rng;

fn _make_rng() -> impl CryptoRngCore {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("host RNG unavailable");
    AloeRng::new(seed)
}

fn main() {
    let mut rng = _make_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let sign_key = MlDsa65Keypair::from_seed(&seed);
    dbg!(seed);

    dbg!(sign_key.private_seed);

    let secret_msg = b"Hello!";
    dbg!(secret_msg);

    let signature = sign_key.sign(secret_msg);
    dbg!(signature);

    let verifier = sign_key.get_verifier();
    if verifier.verify(secret_msg, &signature) {
        println!("OK!");
    } else {
        println!("bad news");
    }

    let reconstructed_verifier = MlDsa65Verifier::from_public_key(&verifier.public_key);
    if reconstructed_verifier.verify(secret_msg, &signature) {
        println!("OK!");
    } else {
        println!("bad news");
    }
}
