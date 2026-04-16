// src/kem.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use ml_kem::{
    Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, FromSeed, KeyExport, MlKem512,
    MlKem768, MlKem1024,
};

use super::kem_api::*;
use super::rng_api::*;

impl MlKem512Keypair {
    fn _encapsulation_key(&self) -> EncapsulationKey<MlKem512> {
        EncapsulationKey::<MlKem512>::new(&self.public_key.into()).unwrap()
    }

    fn _decapsulation_key(&self) -> DecapsulationKey<MlKem512> {
        DecapsulationKey::<MlKem512>::from_seed(self.private_seed.into())
    }
}

impl MlKem768Keypair {
    fn _encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        EncapsulationKey::<MlKem768>::new(&self.public_key.into()).unwrap()
    }

    fn _decapsulation_key(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::<MlKem768>::from_seed(self.private_seed.into())
    }
}

impl MlKem1024Keypair {
    fn _encapsulation_key(&self) -> EncapsulationKey<MlKem1024> {
        EncapsulationKey::<MlKem1024>::new(&self.public_key.into()).unwrap()
    }

    fn _decapsulation_key(&self) -> DecapsulationKey<MlKem1024> {
        DecapsulationKey::<MlKem1024>::from_seed(self.private_seed.into())
    }
}

impl MlKem512Encapsulator {
    fn _encapsulation_key(&self) -> EncapsulationKey<MlKem512> {
        EncapsulationKey::<MlKem512>::new(&self.public_key.into()).unwrap()
    }
}

impl MlKem768Encapsulator {
    fn _encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        EncapsulationKey::<MlKem768>::new(&self.public_key.into()).unwrap()
    }
}

impl MlKem1024Encapsulator {
    fn _encapsulation_key(&self) -> EncapsulationKey<MlKem1024> {
        EncapsulationKey::<MlKem1024>::new(&self.public_key.into()).unwrap()
    }
}

impl MlKemKeypair for MlKem512Keypair {
    fn pack_bytes(&self) -> &MlKemPrivateSeed {
        &self.private_seed
    }
    fn from_seed(seed_bytes: &MlKemPrivateSeed) -> Self {
        MlKem512Keypair::unpack_bytes(seed_bytes)
    }
    fn unpack_bytes(seed_bytes: &MlKemPrivateSeed) -> Self {
        let (de, en) = MlKem512::from_seed(seed_bytes.into());
        Self {
            private_seed: de.to_bytes().into(),
            public_key: en.to_bytes().into(),
        }
    }
}
impl MlKemKeypair for MlKem768Keypair {
    fn pack_bytes(&self) -> &MlKemPrivateSeed {
        &self.private_seed
    }
    fn from_seed(seed_bytes: &MlKemPrivateSeed) -> Self {
        MlKem768Keypair::unpack_bytes(seed_bytes)
    }
    fn unpack_bytes(seed_bytes: &MlKemPrivateSeed) -> Self {
        let (de, en) = MlKem768::from_seed(seed_bytes.into());
        Self {
            private_seed: de.to_bytes().into(),
            public_key: en.to_bytes().into(),
        }
    }
}
impl MlKemKeypair for MlKem1024Keypair {
    fn pack_bytes(&self) -> &MlKemPrivateSeed {
        &self.private_seed
    }
    fn from_seed(seed_bytes: &MlKemPrivateSeed) -> Self {
        MlKem1024Keypair::unpack_bytes(seed_bytes)
    }
    fn unpack_bytes(seed_bytes: &MlKemPrivateSeed) -> Self {
        let (de, en) = MlKem1024::from_seed(seed_bytes.into());
        Self {
            private_seed: de.to_bytes().into(),
            public_key: en.to_bytes().into(),
        }
    }
}

impl IMlKem512Keypair for MlKem512Keypair {
    fn decapsulate(&self, encapsulated_key: &MlKem512Cipher) -> MlKemSecret {
        self._decapsulation_key()
            .decapsulate(encapsulated_key.into())
            .into()
    }
    fn get_encapsulator(&self) -> MlKem512Encapsulator {
        MlKem512Encapsulator {
            public_key: self.public_key,
        }
    }
}
impl IMlKem768Keypair for MlKem768Keypair {
    fn decapsulate(&self, encapsulated_key: &MlKem768Cipher) -> MlKemSecret {
        self._decapsulation_key()
            .decapsulate(encapsulated_key.into())
            .into()
    }
    fn get_encapsulator(&self) -> MlKem768Encapsulator {
        MlKem768Encapsulator {
            public_key: self.public_key,
        }
    }
}
impl IMlKem1024Keypair for MlKem1024Keypair {
    fn decapsulate(&self, encapsulated_key: &MlKem1024Cipher) -> MlKemSecret {
        self._decapsulation_key()
            .decapsulate(encapsulated_key.into())
            .into()
    }
    fn get_encapsulator(&self) -> MlKem1024Encapsulator {
        MlKem1024Encapsulator {
            public_key: self.public_key,
        }
    }
}

impl IMlKem512Encapsulator for MlKem512Encapsulator {
    fn encapsulate(&self, prk: MlKemPrkSeed) -> MlKem512EncapsulatorResult {
        let mut rng = AloeRng::new(prk);
        let (cipher, secret) = self._encapsulation_key().encapsulate_with_rng(&mut rng);
        MlKem512EncapsulatorResult {
            cipher: cipher.into(),
            secret: secret.into(),
        }
    }
}

impl IMlKem768Encapsulator for MlKem768Encapsulator {
    fn encapsulate(&self, prk: MlKemPrkSeed) -> MlKem768EncapsulatorResult {
        let mut rng = AloeRng::new(prk);
        let (cipher, secret) = self._encapsulation_key().encapsulate_with_rng(&mut rng);
        MlKem768EncapsulatorResult {
            cipher: cipher.into(),
            secret: secret.into(),
        }
    }
}

impl IMlKem1024Encapsulator for MlKem1024Encapsulator {
    fn encapsulate(&self, prk: MlKemPrkSeed) -> MlKem1024EncapsulatorResult {
        let mut rng = AloeRng::new(prk);
        let (cipher, secret) = self._encapsulation_key().encapsulate_with_rng(&mut rng);
        MlKem1024EncapsulatorResult {
            cipher: cipher.into(),
            secret: secret.into(),
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
