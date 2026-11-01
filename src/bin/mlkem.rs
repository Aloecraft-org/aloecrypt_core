use aloecrypt_core::dsa_api::IMlDsa65Keypair;
use aloecrypt_core::dsa_api::IMlDsa65Verifier;
use aloecrypt_core::dsa_api::MlDsa65Keypair;
use aloecrypt_core::dsa_api::MlDsaKeypair;
use aloecrypt_core::dsa_api::MlDsa65Verifier;
use aloecrypt_core::rng_api::AloeRng;
use aloecrypt_core::rng_api::IAloeRng;
use aloecrypt_core::mlkem::*;
use aloecrypt_core::kem_api::*;
use aloecrypt_core::rng::CryptoRngCore;
use rand_core::{Rng, RngCore};

fn _make_rng() -> impl CryptoRngCore {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    AloeRng::new(seed)
}

fn main() {
    let mut rng = _make_rng();
    let mut seed = [0u8;64];
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