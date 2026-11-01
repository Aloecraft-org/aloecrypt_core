// src/rng.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::rng_api::*;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{CryptoRng, Infallible, Rng, SeedableRng, TryCryptoRng, TryRng};

pub trait CryptoRngCore: Rng + CryptoRng {}
impl<T: Rng + CryptoRng> CryptoRngCore for T {}
impl TryCryptoRng for AloeRng {}

impl AloeRng {
    fn _update(&mut self, _rng: ChaCha20Rng) {
        self.stream = _rng.get_stream();
        self.seed = _rng.get_seed();
        self.word_pos = _rng.get_word_pos();
    }
    fn _inner(&mut self) -> ChaCha20Rng {
        let mut _rng = ChaCha20Rng::from_seed(self.seed);
        _rng.set_stream(self.stream);
        _rng.set_word_pos(self.word_pos);
        _rng
    }
    pub fn from_rng(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::new(seed)
    }

    /// exposes rand_core::Rng fill_bytes for FFI
    pub fn _fill_bytes(&mut self, mut dst: &mut [u8]) {
        self.fill_bytes(&mut dst);
    }
}

impl IAloeRng for AloeRng {
    fn with_seed(&mut self, seed: RngSeed) -> &Self {
        self.seed = seed;
        self
    }
    fn with_stream(&mut self, stream: u64) -> &Self {
        self.stream = stream;
        self
    }
    fn with_word_pos(&mut self, word_pos: u128) -> &Self {
        self.word_pos = word_pos;
        self
    }
    fn new(seed: RngSeed) -> Self {
        Self {
            seed,
            stream: 0u64,
            word_pos: 0u128,
        }
    }
}

impl TryRng for AloeRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut rng = self._inner();
        let n = rng.try_next_u32().unwrap();
        self._update(rng);
        Ok(n)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut rng = self._inner();
        let n = rng.try_next_u64().unwrap();
        self._update(rng);
        Ok(n)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let mut rng = self._inner();
        rng.try_fill_bytes(dst).unwrap();
        self._update(rng);
        Ok(())
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
