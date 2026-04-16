use super::recovery_api::*;
use super::hash::*;
use super::kem_api::*;

impl IRecoverableSecret for RecoverableSecret {
    fn create(authorizer: MlKem512Encapsulator, recovery_secret: RecoverySecret, prk_seed: MlKemPrkSeed) -> Self {
        let authorization = authorizer.encapsulate(prk_seed);
        let recovery_key = RecoveryKey{
            cipher: authorization.cipher,
            secret: recovery_secret
        };
        let mut inner_secret_ikm = authorization.secret.to_vec();
        inner_secret_ikm.extend_from_slice(&recovery_key.secret);
        let secret = simple_hash(&inner_secret_ikm);
        RecoverableSecret{
            secret,
            recovery_key
        }
    }
    fn recover(authorization: MlKemSecret, recovery_secret: &RecoverySecret) -> RecoverySecret {
        let mut recovery_secret_ikm = authorization.to_vec();
        recovery_secret_ikm.extend_from_slice(recovery_secret);
        simple_hash(&recovery_secret_ikm)
    }
}