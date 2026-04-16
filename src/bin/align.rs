// src/bin/align.rs
// License: Apache-2.0 (disclaimer at bottom of file)
#![allow(warnings)]


// use ml_dsa::{
    //     ExpandedSigningKey, KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey,
    //     signature::{Keypair, Signer, Verifier},
    // };
    
    // use ml_kem::{
        //     B32, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, ExpandedKeyEncoding,
        //     KeyExport, MlKem512, MlKem768, MlKem1024, SharedKey, array::Array,
        // };
        
        use rand_core::{Rng, RngCore};
        
fn _make_rng() -> impl CryptoRngCore {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed);
    AloeRng::new(seed)
}

use hmac::{Hmac, KeyInit, Mac};
use sha3::{Keccak256, Sha3_256};

type HmacShake256 = Hmac<Keccak256>;
type HmacSha3_256 = Hmac<Sha3_256>;

use aloecrypt_core::dsa::*;
use aloecrypt_core::dsa_api::*;
use aloecrypt_core::hash::*;
use aloecrypt_core::kem::*;
use aloecrypt_core::kem_api::*;
use aloecrypt_core::password::*;
use aloecrypt_core::recovery;
use aloecrypt_core::recovery_api::*;
use aloecrypt_core::password_api::*;
use aloecrypt_core::rng::*;
use aloecrypt_core::rng_api::*;

fn main() {
    println!("align.rs - starting.");
    let mut rng = _make_rng();
    let mut sign_seed = EMPTY_MLDSA_SEED;
    let mut kem_seed_1 = EMPTY_KEM_DECAP_SEED;
    let mut kem_seed_2 = EMPTY_KEM_DECAP_SEED;
    
    let mut aloe_rng = AloeRng::from_rng(&mut rng);
    let mut kem_512_prk = EMPTY_KEM_PRK_SEED;
    let mut kem_768_prk = EMPTY_KEM_PRK_SEED;
    let mut kem_1024_prk = EMPTY_KEM_PRK_SEED;
    let mut aloe_rng_512_kem = aloe_rng.with_stream(512 as u64).clone();
    let mut aloe_rng_768_kem = aloe_rng.with_stream(768 as u64).clone();
    let mut aloe_rng_1024_kem = aloe_rng.with_stream(1024 as u64).clone();

    aloe_rng_512_kem.fill_bytes(&mut kem_512_prk);
    aloe_rng_768_kem.fill_bytes(&mut kem_768_prk);
    aloe_rng_1024_kem.fill_bytes(&mut kem_1024_prk);

    rng.fill_bytes(&mut sign_seed);
    rng.fill_bytes(&mut kem_seed_1);
    rng.fill_bytes(&mut kem_seed_2);

    let kem_512_keypair_1 = MlKem512Keypair::from_seed(&kem_seed_1);
    let kem_768_keypair_1 = MlKem768Keypair::from_seed(&kem_seed_1);
    let kem_1024_keypair_1 = MlKem1024Keypair::from_seed(&kem_seed_1);
    let kem_512_keypair_2 = MlKem512Keypair::from_seed(&kem_seed_2);
    let kem_768_keypair_2 = MlKem768Keypair::from_seed(&kem_seed_2);
    let kem_1024_keypair_2 = MlKem1024Keypair::from_seed(&kem_seed_2);

    let kem_512_encap_1_result = kem_512_keypair_1
        .get_encapsulator()
        .encapsulate(kem_512_prk);
    let kem_768_encap_1_result = kem_768_keypair_1
        .get_encapsulator()
        .encapsulate(kem_768_prk);
    let kem_1024_encap_1_result = kem_1024_keypair_1
        .get_encapsulator()
        .encapsulate(kem_1024_prk);

    let kem_512_decap_1_secret = kem_512_keypair_1.decapsulate(&kem_512_encap_1_result.cipher);
    let kem_768_decap_1_secret = kem_768_keypair_1.decapsulate(&kem_768_encap_1_result.cipher);
    let kem_1024_decap_1_secret = kem_1024_keypair_1.decapsulate(&kem_1024_encap_1_result.cipher);

    assert_eq!(kem_512_encap_1_result.secret, kem_512_decap_1_secret);
    assert_eq!(kem_768_encap_1_result.secret, kem_768_decap_1_secret);
    assert_eq!(kem_1024_encap_1_result.secret, kem_1024_decap_1_secret);

    let dsa_44_keypair = MlDsa44Keypair::from_seed(&sign_seed);
    let dsa_65_keypair = MlDsa65Keypair::from_seed(&sign_seed);
    let dsa_87_keypair = MlDsa87Keypair::from_seed(&sign_seed);

    let message = "This is a message that needs to be signed";

    let dsa_44_signature = dsa_44_keypair.sign(&message.as_bytes());
    let dsa_65_signature = dsa_65_keypair.sign(&message.as_bytes());
    let dsa_87_signature = dsa_87_keypair.sign(&message.as_bytes());

    let dsa_44_verifier = dsa_44_keypair.get_verifier();
    let dsa_65_verifier = dsa_65_keypair.get_verifier();
    let dsa_87_verifier = dsa_87_keypair.get_verifier();

    let dsa_44_verifier_result = dsa_44_verifier.verify(&message.as_bytes(), &dsa_44_signature);
    let dsa_65_verifier_result = dsa_65_verifier.verify(&message.as_bytes(), &dsa_65_signature);
    let dsa_87_verifier_result = dsa_87_verifier.verify(&message.as_bytes(), &dsa_87_signature);

    assert!(dsa_44_verifier_result);
    assert!(dsa_65_verifier_result);
    assert!(dsa_87_verifier_result);

    let dsa_44_verifier_result2 = dsa_44_keypair.verify(&message.as_bytes(), &dsa_44_signature);
    let dsa_65_verifier_result2 = dsa_65_keypair.verify(&message.as_bytes(), &dsa_65_signature);
    let dsa_87_verifier_result2 = dsa_87_keypair.verify(&message.as_bytes(), &dsa_87_signature);

    assert!(dsa_44_verifier_result2);
    assert!(dsa_65_verifier_result2);
    assert!(dsa_87_verifier_result2);

    let dsa_44_pubkey_bytes = dsa_44_verifier.pack_bytes();
    let dsa_65_pubkey_bytes = dsa_65_verifier.pack_bytes();
    let dsa_87_pubkey_bytes = dsa_87_verifier.pack_bytes();

    let pbkdf_password = "some_password";
    let pbkdf_salt = "some_salt";
    let pbkdf_iters: u32 = 10000;

    let pbkdf_key = aloecrypt_core::pkdf::pbkdf(
        pbkdf_password.as_bytes(),
        pbkdf_salt.as_bytes(),
        pbkdf_iters,
    );

    let mut encrypt_material =
        Vec::with_capacity(MLDSA_44_PUBKEY_SZ + MLDSA_65_PUBKEY_SZ + MLDSA_87_PUBKEY_SZ);

    encrypt_material.extend_from_slice(dsa_44_pubkey_bytes);
    encrypt_material.extend_from_slice(dsa_65_pubkey_bytes);
    encrypt_material.extend_from_slice(dsa_87_pubkey_bytes);

    let mut password_nonce = EMPTY_PASSWORD_NONCE;
    rng.fill_bytes(&mut password_nonce);

    // Initialize the cipher (Note: Standard Rust positional arguments)
    let mut cipher = aloecrypt_core::password_api::PasswordCipher::new(
        &encrypt_material,
        pbkdf_key,
        password_nonce,
    );

    // ENCRYPTION EXAMPLE
    let mut encrypted_payload = Vec::new();

    loop {
        let result =
            aloecrypt_core::password::password_encrypt_next(&encrypt_material, &mut cipher);
        encrypted_payload.extend_from_slice(&result.next_chunk);

        if result.is_done != 0 {
            break;
        }
    }

    // DECRYPTION EXAMPLE
    let mut decrypt_cipher = PasswordCipher::new(&encrypt_material, pbkdf_key, password_nonce);

    let mut decrypted_payload = Vec::new();

    loop {
        let result = aloecrypt_core::password::password_decrypt_next(
            &encrypted_payload,
            &mut decrypt_cipher,
        );

        let valid_bytes = result.n_bytes as usize;
        decrypted_payload.extend_from_slice(&result.next_chunk[..valid_bytes]);

        if result.is_done != 0 {
            break;
        }
    }

    let message = "This is a message that needs to be signed";

    const EMPTY_MLDSA44_PUBKEY: MlDsa44Pubkey = [0u8; MLDSA_44_PUBKEY_SZ];
    const EMPTY_MLDSA65_PUBKEY: MlDsa65Pubkey = [0u8; MLDSA_65_PUBKEY_SZ];
    const EMPTY_MLDSA87_PUBKEY: MlDsa87Pubkey = [0u8; MLDSA_87_PUBKEY_SZ];

    let mut decrypted_mldsa44_pubkey_bytes = EMPTY_MLDSA44_PUBKEY;
    let mut decrypted_mldsa65_pubkey_bytes = EMPTY_MLDSA65_PUBKEY;
    let mut decrypted_mldsa87_pubkey_bytes = EMPTY_MLDSA87_PUBKEY;

    decrypted_mldsa44_pubkey_bytes.copy_from_slice(&decrypted_payload[0..MLDSA_44_PUBKEY_SZ]);
    decrypted_mldsa65_pubkey_bytes.copy_from_slice(
        &decrypted_payload[MLDSA_44_PUBKEY_SZ..MLDSA_44_PUBKEY_SZ + MLDSA_65_PUBKEY_SZ],
    );
    decrypted_mldsa87_pubkey_bytes.copy_from_slice(
        &decrypted_payload[MLDSA_44_PUBKEY_SZ + MLDSA_65_PUBKEY_SZ
            ..MLDSA_44_PUBKEY_SZ + MLDSA_65_PUBKEY_SZ + MLDSA_87_PUBKEY_SZ],
    );

    let decrypted_mldsa44_verifier = MlDsa44Verifier::unpack_bytes(&decrypted_mldsa44_pubkey_bytes);
    let decrypted_mldsa65_verifier = MlDsa65Verifier::unpack_bytes(&decrypted_mldsa65_pubkey_bytes);
    let decrypted_mldsa87_verifier = MlDsa87Verifier::unpack_bytes(&decrypted_mldsa87_pubkey_bytes);

    let decrypted_dsa_44_verifier_result =
        decrypted_mldsa44_verifier.verify(&message.as_bytes(), &dsa_44_signature);
    let decrypted_dsa_65_verifier_result =
        decrypted_mldsa65_verifier.verify(&message.as_bytes(), &dsa_65_signature);
    let decrypted_dsa_87_verifier_result =
        decrypted_mldsa87_verifier.verify(&message.as_bytes(), &dsa_87_signature);

    assert!(decrypted_dsa_44_verifier_result);
    assert!(decrypted_dsa_65_verifier_result);
    assert!(decrypted_dsa_87_verifier_result);

    // SECRET RECOVERY

    let mut authorizer_private_seed = EMPTY_KEM_DECAP_SEED;
    let mut prk_seed = EMPTY_KEM_PRK_SEED;
    let mut recovery_secret = EMPTY_RECOVERY_PRIVKEY;
    rng.fill_bytes(&mut authorizer_private_seed);
    rng.fill_bytes(&mut recovery_secret);
    rng.fill_bytes(&mut prk_seed);

    // Secret holder takes authorizer keypair
    let authorizer_keypair = MlKem512Keypair::from_seed(&authorizer_private_seed);
    let recoverable_secret = RecoverableSecret::create(authorizer_keypair.get_encapsulator(), recovery_secret, prk_seed);

    // Recovery key holder keeps this
    let recovery_key = recoverable_secret.recovery_key;

    // Authorizer authorizes with recovery public key
    let recovered_authorization = authorizer_keypair.decapsulate(&recovery_key.cipher);

    // Recoverer combines private key to recover secret
    let recovered_secret = RecoverableSecret::recover(recovered_authorization, &recovery_key.secret);
    
    assert_eq!(recoverable_secret.secret, recovered_secret);

    println!("   inner_secret: {:02x}{:02x}{:02x}{:02x}", recoverable_secret.secret[0], recoverable_secret.secret[1], recoverable_secret.secret[2], recoverable_secret.secret[3]);
    println!("   recovered_secret: {:02x}{:02x}{:02x}{:02x}", recovered_secret[0], recovered_secret[1], recovered_secret[2], recovered_secret[3]);

    println!("align.rs - done.");
}
// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
