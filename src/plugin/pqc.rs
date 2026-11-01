#![allow(non_snake_case)]
use super::dsa_api::*;
use super::kem_api::*;

// use extism_pdk::{FnResult, plugin_fn};

// Cargo.toml has:
//
// [dependencies]
// ...
// extism-pdk = { version = "1.0", optional = true }

// ML-DSA functions

// Included for quick reference (actual implementations in api_core.rs):
// pub type MlDsa44KeypairRaw = [u8; MLDSA_44_KEYPAIR_SZ];
// pub type MlDsa65KeypairRaw = [u8; MLDSA_65_KEYPAIR_SZ];
// pub type MlDsa87KeypairRaw = [u8; MLDSA_87_KEYPAIR_SZ];
// pub type MlDsaPrivateSeed = [u8; MLDSA_SEED_SZ];
// pub type MlDsa44Pubkey = [u8; MLDSA_44_PUBKEY_SZ];
// pub type MlDsa65Pubkey = [u8; MLDSA_65_PUBKEY_SZ];
// pub type MlDsa87Pubkey = [u8; MLDSA_87_PUBKEY_SZ];
// pub type MlDsa44Signature = [u8; MLDSA_44_SIGNATURE_SZ];
// pub type MlDsa65Signature = [u8; MLDSA_65_SIGNATURE_SZ];
// pub type MlDsa87Signature = [u8; MLDSA_87_SIGNATURE_SZ];
pub fn mldsa__dsa44__sign(seed_bytes: &MlDsaPrivateSeed, msg: &[u8]) -> MlDsa44Signature {
    MlDsa44Keypair::from_seed(seed_bytes).sign(msg)
}
pub fn mldsa__dsa65__sign(seed_bytes: &MlDsaPrivateSeed, msg: &[u8]) -> MlDsa65Signature {
    MlDsa65Keypair::from_seed(seed_bytes).sign(msg)
}
pub fn mldsa__dsa87__sign(seed_bytes: &MlDsaPrivateSeed, msg: &[u8]) -> MlDsa87Signature {
    MlDsa87Keypair::from_seed(seed_bytes).sign(msg)
}

pub fn mldsa__dsa44__pubkey(seed_bytes: &MlDsaPrivateSeed) -> MlDsa44Pubkey {
    MlDsa44Keypair::from_seed(seed_bytes)
        .get_verifier()
        .public_key
}
pub fn mldsa__dsa65__pubkey(seed_bytes: &MlDsaPrivateSeed) -> MlDsa65Pubkey {
    MlDsa65Keypair::from_seed(seed_bytes)
        .get_verifier()
        .public_key
}
pub fn mldsa__dsa87__pubkey(seed_bytes: &MlDsaPrivateSeed) -> MlDsa87Pubkey {
    MlDsa87Keypair::from_seed(seed_bytes)
        .get_verifier()
        .public_key
}

pub fn mldsa__dsa44__verify(
    public_key: &MlDsa44Pubkey,
    msg: &[u8],
    signature: &MlDsa44Signature,
) -> bool {
    MlDsa44Verifier::from_public_key(public_key).verify(msg, signature)
}
pub fn mldsa__dsa65__verify(
    public_key: &MlDsa65Pubkey,
    msg: &[u8],
    signature: &MlDsa65Signature,
) -> bool {
    MlDsa65Verifier::from_public_key(public_key).verify(msg, signature)
}
pub fn mldsa__dsa87__verify(
    public_key: &MlDsa87Pubkey,
    msg: &[u8],
    signature: &MlDsa87Signature,
) -> bool {
    MlDsa87Verifier::from_public_key(public_key).verify(msg, signature)
}

// ML-KEM functions

// Included for quick reference (actual implementation in api_core.rs):
// pub type MlKemPrkSeed = [u8; MLKEM_PRK_SEED_SZ];
// pub type MlKem512Pubkey = [u8; MLKEM_512_ENCAP_KEY_SZ];
// pub type MlKem768Pubkey = [u8; MLKEM_768_ENCAP_KEY_SZ];
// pub type MlKem1024Pubkey = [u8; MLKEM_1024_ENCAP_KEY_SZ];
// pub type MlKemPrivateSeed = [u8; MLKEM_DECAP_KEY_SZ];
// pub type MlKemSecret = [u8; MLKEM_SECRET_SZ];
// pub type MlKem512Cipher = [u8; MLKEM_512_CIPHER_SZ];
// pub type MlKem768Cipher = [u8; MLKEM_768_CIPHER_SZ];
// pub type MlKem1024Cipher = [u8; MLKEM_1024_CIPHER_SZ];
pub fn mlkem__kem512__decapsulate(
    seed_bytes: &MlKemPrivateSeed,
    cipher: &MlKem512Cipher,
) -> MlKemSecret {
    MlKem512Keypair::from_seed(&seed_bytes).decapsulate(cipher)
}
pub fn mlkem__kem768__decapsulate(
    seed_bytes: &MlKemPrivateSeed,
    cipher: &MlKem768Cipher,
) -> MlKemSecret {
    MlKem768Keypair::from_seed(&seed_bytes).decapsulate(cipher)
}
pub fn mlkem__kem1024__decapsulate(
    seed_bytes: &MlKemPrivateSeed,
    cipher: &MlKem1024Cipher,
) -> MlKemSecret {
    MlKem1024Keypair::from_seed(&seed_bytes).decapsulate(cipher)
}

pub fn mlkem__kem512__pubkey(seed_bytes: &MlKemPrivateSeed) -> MlKem512Pubkey {
    MlKem512Keypair::from_seed(&seed_bytes).public_key
}
pub fn mlkem__kem768__pubkey(seed_bytes: &MlKemPrivateSeed) -> MlKem768Pubkey {
    MlKem768Keypair::from_seed(&seed_bytes).public_key
}
pub fn mlkem__kem1024__pubkey(seed_bytes: &MlKemPrivateSeed) -> MlKem1024Pubkey {
    MlKem1024Keypair::from_seed(&seed_bytes).public_key
}

pub fn mlkem__kem512__encapsulate(
    public_key: &MlKem512Pubkey,
    prk: &MlKemPrkSeed,
) -> MlKem512EncapsulatorResult {
    MlKem512Encapsulator::from_public_key(public_key).encapsulate(prk.clone())
}
pub fn mlkem__kem768__encapsulate(
    public_key: &MlKem768Pubkey,
    prk: &MlKemPrkSeed,
) -> MlKem768EncapsulatorResult {
    MlKem768Encapsulator::from_public_key(public_key).encapsulate(prk.clone())
}
pub fn mlkem__kem1024__encapsulate(
    public_key: &MlKem1024Pubkey,
    prk: &MlKemPrkSeed,
) -> MlKem1024EncapsulatorResult {
    MlKem1024Encapsulator::from_public_key(public_key).encapsulate(prk.clone())
}
