// src/bin/mlkem.rs
// License: Apache-2.0
//
// Smoke test: ML-KEM-768 encapsulate to a bare public key, then decapsulate.
//
//   cargo run --bin mlkem

use aloecrypt_core::kem_api::*;
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
    let mut seed = [0u8; 64];
    let mut kem_prk = EMPTY_KEM_PRK_SEED;

    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut kem_prk);

    let kem_keypair = MlKem768Keypair::from_seed(&seed);
    dbg!(seed);

    let public_key = kem_keypair.public_key;
    let encapsulator = MlKem768Encapsulator::from_public_key(&public_key);

    let kem_encap_result = encapsulator.encapsulate(kem_prk);
    let secret = kem_encap_result.secret;
    let cipher = kem_encap_result.cipher;

    let decapsulated = kem_keypair.decapsulate(&cipher);

    dbg!(decapsulated);
    dbg!(secret);
}
