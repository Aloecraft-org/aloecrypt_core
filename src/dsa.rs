// src/dsa.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::dsa_api::*;

use ml_dsa::{
    KeyGen, MlDsa44 as MlDsa44Params, MlDsa65 as MlDsa65Params, MlDsa87 as MlDsa87Params,
    Signature, SigningKey, VerifyingKey,
    signature::{Keypair, Signer, Verifier},
};

impl MlDsa44Keypair {
    fn _signing_key(&self) -> SigningKey<MlDsa44Params> {
        MlDsa44Params::from_seed((&self.private_seed).into())
    }
    fn _verifier(&self) -> VerifyingKey<MlDsa44Params> {
        VerifyingKey::<MlDsa44Params>::decode((&self.public_key).into())
    }
}

impl MlDsa65Keypair {
    fn _signing_key(&self) -> SigningKey<MlDsa65Params> {
        MlDsa65Params::from_seed((&self.private_seed).into())
    }
    fn _verifier(&self) -> VerifyingKey<MlDsa65Params> {
        VerifyingKey::<MlDsa65Params>::decode((&self.public_key).into())
    }
}

impl MlDsa87Keypair {
    fn _signing_key(&self) -> SigningKey<MlDsa87Params> {
        MlDsa87Params::from_seed((&self.private_seed).into())
    }
    fn _verifier(&self) -> VerifyingKey<MlDsa87Params> {
        VerifyingKey::<MlDsa87Params>::decode((&self.public_key).into())
    }
}

impl MlDsa44Verifier {
    fn _verifier(&self) -> VerifyingKey<MlDsa44Params> {
        VerifyingKey::<MlDsa44Params>::decode((&self.public_key).into())
    }
}

impl MlDsa65Verifier {
    fn _verifier(&self) -> VerifyingKey<MlDsa65Params> {
        VerifyingKey::<MlDsa65Params>::decode((&self.public_key).into())
    }
}

impl MlDsa87Verifier {
    fn _verifier(&self) -> VerifyingKey<MlDsa87Params> {
        VerifyingKey::<MlDsa87Params>::decode((&self.public_key).into())
    }
}

impl MlDsaKeypair for MlDsa44Keypair {
    fn to_bytes(&self) -> &MlDsaPrivateSeed {
        &self.private_seed
    }
    fn from_seed(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self::from_bytes(seed_bytes)
    }
    fn from_bytes(seed_bytes: &MlDsaPrivateSeed) -> Self {
        let signing_key = MlDsa44Params::from_seed(seed_bytes.into());
        Self {
            private_seed: (*seed_bytes).into(),
            public_key: signing_key.verifying_key().encode().into(),
        }
    }
}

impl MlDsaKeypair for MlDsa65Keypair {
    fn to_bytes(&self) -> &MlDsaPrivateSeed {
        &self.private_seed
    }
    fn from_seed(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self::from_bytes(seed_bytes)
    }
    fn from_bytes(seed_bytes: &MlDsaPrivateSeed) -> Self {
        let signing_key = MlDsa65Params::from_seed(seed_bytes.into());
        Self {
            private_seed: (*seed_bytes).into(),
            public_key: signing_key.verifying_key().encode().into(),
        }
    }
}

impl MlDsaKeypair for MlDsa87Keypair {
    fn to_bytes(&self) -> &MlDsaPrivateSeed {
        &self.private_seed
    }
    fn from_seed(seed_bytes: &MlDsaPrivateSeed) -> Self {
        Self::from_bytes(seed_bytes)
    }
    fn from_bytes(seed_bytes: &MlDsaPrivateSeed) -> Self {
        let signing_key = MlDsa87Params::from_seed(seed_bytes.into());
        Self {
            private_seed: (*seed_bytes).into(),
            public_key: signing_key.verifying_key().encode().into(),
        }
    }
}

impl IMlDsa44Keypair for MlDsa44Keypair {
    fn sign(&self, msg: &[u8]) -> MlDsa44Signature {
        self._signing_key().sign(msg).encode().into()
    }
    fn get_verifier(&self) -> MlDsa44Verifier {
        MlDsa44Verifier {
            public_key: self.public_key,
        }
    }
}

impl IMlDsa65Keypair for MlDsa65Keypair {
    fn sign(&self, msg: &[u8]) -> MlDsa65Signature {
        self._signing_key().sign(msg).encode().into()
    }
    fn get_verifier(&self) -> MlDsa65Verifier {
        MlDsa65Verifier {
            public_key: self.public_key,
        }
    }
}

impl IMlDsa87Keypair for MlDsa87Keypair {
    fn sign(&self, msg: &[u8]) -> MlDsa87Signature {
        self._signing_key().sign(msg).encode().into()
    }
    fn get_verifier(&self) -> MlDsa87Verifier {
        MlDsa87Verifier {
            public_key: self.public_key,
        }
    }
}

impl IMlDsa44Pubkey for MlDsa44Verifier {
    fn to_bytes(&self) -> &MlDsa44Pubkey {
        &self.public_key
    }
    fn from_bytes(bytes: &MlDsa44Pubkey) -> Self {
        Self {
            public_key: (*bytes).into(),
        }
    }
}

impl IMlDsa44Verifier for MlDsa44Verifier {
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
    fn to_bytes(&self) -> &MlDsa65Pubkey {
        &self.public_key
    }
    fn from_bytes(bytes: &MlDsa65Pubkey) -> Self {
        Self {
            public_key: (*bytes).into(),
        }
    }
}
impl IMlDsa65Verifier for MlDsa65Verifier {
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
    fn to_bytes(&self) -> &MlDsa87Pubkey {
        &self.public_key
    }
    fn from_bytes(bytes: &MlDsa87Pubkey) -> Self {
        Self {
            public_key: (*bytes).into(),
        }
    }
}
impl IMlDsa87Verifier for MlDsa87Verifier {
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
