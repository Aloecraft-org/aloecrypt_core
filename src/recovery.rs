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
    ) -> Self {
        let authorization = authorizer.encapsulate(prk_seed);
        let mac = domain_hmac(ikm, domain_info);
        let recovery_key = RecoveryKey {
            cipher: authorization.cipher,
            mac: mac,
            secret: recovery_secret,
        };
        let mut inner_secret_ikm = authorization.secret.to_vec();
        inner_secret_ikm.extend_from_slice(&recovery_key.secret);
        let secret = simple_hash(&inner_secret_ikm);
        RecoverableSecret {
            secret,
            recovery_key,
        }
    }
    fn recover(authorization: MlKemSecret, recovery_secret: &RecoverySecret) -> RecoverySecret {
        let mut recovery_secret_ikm = authorization.to_vec();
        recovery_secret_ikm.extend_from_slice(recovery_secret);
        simple_hash(&recovery_secret_ikm)
    }
}

pub fn authorize_recovery(
    authorizer: MlKem512Keypair,
    cipher: &RecoveryCipher,
    mac: Hmac256,
    ikm: &[u8],
    domain_info: &str,
) -> MlKemSecret {
    let authentication = domain_hmac(ikm, domain_info);
    assert_eq!(
        mac, authentication,
        "Reconstructed HMAC must match for ikm and domain info"
    );
    authorizer.decapsulate(&cipher)
}
