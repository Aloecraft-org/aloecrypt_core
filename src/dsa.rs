// src/dsa.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::dsa_api::*;

use ml_dsa::{
    ExpandedSigningKey, EncodedSignature,
    KeyGen, MlDsa44 as MlDsa44Params, MlDsa65 as MlDsa65Params, MlDsa87 as MlDsa87Params,
    Signature, VerifyingKey,
    signature::{Keypair, Signer, Verifier},
};

impl MlDsa44Keypair {
    #[inline(never)]
    fn _kp(seed: &MlDsaPrivateSeed) -> <MlDsa44Params as KeyGen>::KeyPair {
        MlDsa44Params::from_seed(seed.into())
    }
    #[inline(never)]
    fn _signing_key(&self) -> ExpandedSigningKey<MlDsa44Params> {
        let kp = Self::_kp(&self.private_seed);
        kp.signing_key().clone()
    }
    #[inline(never)]
    fn _encode_pubkey(kp: &<MlDsa44Params as KeyGen>::KeyPair) -> [u8; MLDSA_44_PUBKEY_SZ] {
        kp.verifying_key().encode().into()
    }
    #[inline(never)]
    fn _sign_with_sk(sk: &ExpandedSigningKey<MlDsa44Params>, msg: &[u8]) -> EncodedSignature<MlDsa44Params> {
        sk.sign(msg).encode().into()
    }
    #[inline(never)]
    fn _verifier(&self) -> VerifyingKey<MlDsa44Params> {
        let signing_key = Self::_kp(&(self.private_seed).into());
        let public_key = Self::_encode_pubkey(&(signing_key).into());
        VerifyingKey::<MlDsa44Params>::decode((&public_key).into())
    }
}

impl MlDsa65Keypair {
    #[inline(never)]
    pub fn _kp(seed: &MlDsaPrivateSeed) -> <MlDsa65Params as KeyGen>::KeyPair {
        MlDsa65Params::from_seed(seed.into())
    }
    #[inline(never)]
    pub fn _signing_key(&self) -> ExpandedSigningKey<MlDsa65Params> {
        let kp = Self::_kp(&self.private_seed);
        kp.signing_key().clone()
    }
    #[inline(never)]
    pub fn _encode_pubkey(kp: &<MlDsa65Params as KeyGen>::KeyPair) -> [u8; MLDSA_65_PUBKEY_SZ] {
        kp.verifying_key().encode().into()
    }
    #[inline(never)]
    pub fn _sign_with_sk(sk: &ExpandedSigningKey<MlDsa65Params>, msg: &[u8]) -> EncodedSignature<MlDsa65Params> {
        sk.sign(msg).encode().into()
    }
    pub fn _verifier(&self) -> VerifyingKey<MlDsa65Params> {
        let signing_key = Self::_kp(&(self.private_seed).into());
        let public_key = Self::_encode_pubkey(&(signing_key).into());
        VerifyingKey::<MlDsa65Params>::decode((&public_key).into())
    }
}

impl MlDsa87Keypair {
    #[inline(never)]
    fn _kp(seed: &MlDsaPrivateSeed) -> <MlDsa87Params as KeyGen>::KeyPair {
        MlDsa87Params::from_seed(seed.into())
    }
    #[inline(never)]
    fn _signing_key(&self) -> ExpandedSigningKey<MlDsa87Params> {
        let kp = Self::_kp(&self.private_seed);
        kp.signing_key().clone()
    }
    #[inline(never)]
    fn _encode_pubkey(kp: &<MlDsa87Params as KeyGen>::KeyPair) -> [u8; MLDSA_87_PUBKEY_SZ] {
        kp.verifying_key().encode().into()
    }
    #[inline(never)]
    fn _sign_with_sk(sk: &ExpandedSigningKey<MlDsa87Params>, msg: &[u8]) -> EncodedSignature<MlDsa87Params> {
        sk.sign(msg).encode().into()
    }
    #[inline(never)]
    fn _verifier(&self) -> VerifyingKey<MlDsa87Params> {
        let signing_key = Self::_kp(&(self.private_seed).into());
        let public_key = Self::_encode_pubkey(&(signing_key).into());
        VerifyingKey::<MlDsa87Params>::decode((&public_key).into())
    }
}

impl MlDsa44Verifier {
    #[inline(never)]
    fn _verifier(&self) -> VerifyingKey<MlDsa44Params> {
        VerifyingKey::<MlDsa44Params>::decode((&self.public_key).into())
    }
}

impl MlDsa65Verifier {
    #[inline(never)]
    fn _verifier(&self) -> VerifyingKey<MlDsa65Params> {
        VerifyingKey::<MlDsa65Params>::decode((&self.public_key).into())
    }
}

impl MlDsa87Verifier {
    #[inline(never)]
    fn _verifier(&self) -> VerifyingKey<MlDsa87Params> {
        VerifyingKey::<MlDsa87Params>::decode((&self.public_key).into())
    }
}

impl MlDsaKeypair for MlDsa44Keypair {
    fn pack_bytes(&self) -> &MlDsaPrivateSeed {
        &self.private_seed
    }
    #[inline(never)]
    fn from_seed(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self::unpack_bytes(seed_bytes)
    }
    #[inline(never)]
    fn unpack_bytes(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self {
            private_seed: (*seed_bytes).into()
        }
    }
}

impl MlDsaKeypair for MlDsa65Keypair {
    fn pack_bytes(&self) -> &MlDsaPrivateSeed {
        &self.private_seed
    }
    #[inline(never)]
    fn from_seed(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self::unpack_bytes(seed_bytes)
    }
    #[inline(never)]
    fn unpack_bytes(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self {
            private_seed: (*seed_bytes).into()
        }
    }
}

impl MlDsaKeypair for MlDsa87Keypair {
    fn pack_bytes(&self) -> &MlDsaPrivateSeed {
        &self.private_seed
    }
    #[inline(never)]
    fn from_seed(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self::unpack_bytes(seed_bytes)
    }
    #[inline(never)]
    fn unpack_bytes(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self {
            private_seed: (*seed_bytes).into(),
        }
    }
}

impl IMlDsa44Keypair for MlDsa44Keypair {
    #[inline(never)]
    fn sign(&self, msg: &[u8]) -> MlDsa44Signature {
        let sk = self._signing_key();
        Self::_sign_with_sk(&sk, msg).into()
    }
    #[inline(never)]
    fn get_verifier(&self) -> MlDsa44Verifier {
        let public_key = {
            let signing_key = Self::_kp(&(self.private_seed).into());
            // let signing_key = MlDsa44Params::from_seed(&(self.private_seed).into());
            Self::_encode_pubkey(&signing_key)
        };
        MlDsa44Verifier { public_key }
    }
}

impl IMlDsa65Keypair for MlDsa65Keypair {
    #[inline(never)]
    fn sign(&self, msg: &[u8]) -> MlDsa65Signature {
        let sk = self._signing_key();
        Self::_sign_with_sk(&sk, msg).into()
    }
    #[inline(never)]
    fn get_verifier(&self) -> MlDsa65Verifier {
        let public_key = {
            let signing_key = Self::_kp(&(self.private_seed).into());
            Self::_encode_pubkey(&signing_key)
        };
        MlDsa65Verifier { public_key }
    }
}

impl IMlDsa87Keypair for MlDsa87Keypair {
    #[inline(never)]
    fn sign(&self, msg: &[u8]) -> MlDsa87Signature {
        let sk = self._signing_key();
        Self::_sign_with_sk(&sk, msg).into()
    }
    #[inline(never)]
    fn get_verifier(&self) -> MlDsa87Verifier {
        let public_key = {
            let signing_key = MlDsa87Params::from_seed(&(self.private_seed).into());
            Self::_encode_pubkey(&signing_key)
        };
        MlDsa87Verifier { public_key }
    }
}

impl IMlDsa44Pubkey for MlDsa44Verifier {
    fn pack_bytes(&self) -> &MlDsa44Pubkey {
        &self.public_key
    }
    fn unpack_bytes(bytes: &MlDsa44Pubkey) -> Self {
        Self {
            public_key: (*bytes).into(),
        }
    }
}

impl IMlDsa44Verifier for MlDsa44Verifier {
    #[inline(never)]
    fn verify(&self, msg: &[u8], signature: &MlDsa44Signature) -> bool {
        let sig = Signature::<MlDsa44Params>::decode(signature.into()).unwrap();
        match self._verifier().verify(msg, &sig) {
            Ok(()) => return true,
            _ => {
                return false;
            }
        }
    }
}

impl IMlDsa44Verifier for MlDsa44Keypair {
    #[inline(never)]
    fn verify(&self, msg: &[u8], signature: &MlDsa44Signature) -> bool {
        let sig = Signature::<MlDsa44Params>::decode(signature.into()).unwrap();
        match self._verifier().verify(msg, &sig) {
            Ok(()) => return true,
            _ => {
                return false;
            }
        }
    }
}

impl IMlDsa65Pubkey for MlDsa65Verifier {
    fn pack_bytes(&self) -> &MlDsa65Pubkey {
        &self.public_key
    }
    fn unpack_bytes(bytes: &MlDsa65Pubkey) -> Self {
        Self {
            public_key: (*bytes).into(),
        }
    }
}
impl IMlDsa65Verifier for MlDsa65Verifier {
    #[inline(never)]
    fn verify(&self, msg: &[u8], signature: &MlDsa65Signature) -> bool {
        let sig = Signature::<MlDsa65Params>::decode(signature.into()).unwrap();
        match self._verifier().verify(msg, &sig) {
            Ok(()) => return true,
            _ => {
                return false;
            }
        }
    }
}

impl IMlDsa65Verifier for MlDsa65Keypair {
    #[inline(never)]
    fn verify(&self, msg: &[u8], signature: &MlDsa65Signature) -> bool {
        let sig = Signature::<MlDsa65Params>::decode(signature.into()).unwrap();
        match self._verifier().verify(msg, &sig) {
            Ok(()) => return true,
            _ => {
                return false;
            }
        }
    }
}

impl IMlDsa87Pubkey for MlDsa87Verifier {
    fn pack_bytes(&self) -> &MlDsa87Pubkey {
        &self.public_key
    }
    fn unpack_bytes(bytes: &MlDsa87Pubkey) -> Self {
        Self {
            public_key: (*bytes).into(),
        }
    }
}
impl IMlDsa87Verifier for MlDsa87Verifier {
    #[inline(never)]
    fn verify(&self, msg: &[u8], signature: &MlDsa87Signature) -> bool {
        let sig = Signature::<MlDsa87Params>::decode(signature.into()).unwrap();
        match self._verifier().verify(msg, &sig) {
            Ok(()) => return true,
            _ => {
                return false;
            }
        }
    }
}

impl IMlDsa87Verifier for MlDsa87Keypair {
    #[inline(never)]
    fn verify(&self, msg: &[u8], signature: &MlDsa87Signature) -> bool {
        let sig = Signature::<MlDsa87Params>::decode(signature.into()).unwrap();
        match self._verifier().verify(msg, &sig) {
            Ok(()) => return true,
            _ => {
                return false;
            }
        }
    }
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
