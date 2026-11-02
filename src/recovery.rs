use super::aloecrypt_api::StatusCode;
use super::hash::*;
use super::hash_api::*;
use super::kem_api::*;
use super::recovery_api::*;

impl IRecoverableSecret for RecoverableSecret {
    fn create(
        authorizer: MlKem512Encapsulator,
        recovery_secret: RecoverySecret,
        prk_seed: MlKemPrkSeed,
        ikm: &[u8],
        domain_info: &str,
    ) -> Result<Self, StatusCode> {
        let authorization = authorizer.encapsulate(prk_seed)?;
        let mac = domain_hmac(ikm, domain_info);
        let recovery_key = RecoveryKey {
            cipher: authorization.cipher,
            mac: mac,
            secret: recovery_secret,
        };
        let secret = simple_hash(&concat_secrets(&authorization.secret, &recovery_key.secret));
        Ok(RecoverableSecret {
            secret,
            recovery_key,
        })
    }
    fn recover(authorization: MlKemSecret, recovery_secret: &RecoverySecret) -> RecoverySecret {
        simple_hash(&concat_secrets(&authorization, recovery_secret))
    }
}

/// `authorization || recovery_secret`, on the stack: the hash input both
/// `create` and `recover` derive the recoverable secret from.
fn concat_secrets(
    authorization: &MlKemSecret,
    recovery_secret: &RecoverySecret,
) -> [u8; MLKEM_SECRET_SZ + RECOVERY_PRIVKEY_SZ] {
    let mut ikm = [0u8; MLKEM_SECRET_SZ + RECOVERY_PRIVKEY_SZ];
    ikm[..MLKEM_SECRET_SZ].copy_from_slice(authorization);
    ikm[MLKEM_SECRET_SZ..].copy_from_slice(recovery_secret);
    ikm
}

/// Compare two MACs in constant time: fold the XOR of every byte pair into one
/// accumulator and branch exactly once, on the final result. `black_box` keeps
/// the compiler from noticing a nonzero accumulator early and short-circuiting
/// the loop back into the timing side channel this exists to close.
fn mac_eq(a: &Hmac256, b: &Hmac256) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// Fails with `AuthFailed` when the reconstructed HMAC does not match the
/// presented one. Which input was wrong is deliberately not distinguishable.
pub fn authorize_recovery(
    authorizer: MlKem512Keypair,
    cipher: &RecoveryCipher,
    mac: Hmac256,
    ikm: &[u8],
    domain_info: &str,
) -> Result<MlKemSecret, StatusCode> {
    let authentication = domain_hmac(ikm, domain_info);
    if !mac_eq(&mac, &authentication) {
        return Err(StatusCode(StatusCode::AuthFailed));
    }
    Ok(authorizer.decapsulate(&cipher))
}
