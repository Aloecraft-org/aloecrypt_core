// src/pkdf.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::pkdf_api::*;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub const PBKDF_DEFAULT_ITERS: u32 = 10;

pub fn pbkdf(password: &[u8], salt: &[u8], iters: u32) -> PbkdfKey {
    let mut state = EMPTY_PBKDF_KEY;
    let mut h = Shake256::default();
    h.update(password);
    h.update(salt);
    h.finalize_xof().read(&mut state);
    for _ in 0..iters {
        let mut h = Shake256::default();
        h.update(&state);
        h.finalize_xof().read(&mut state);
    }
    state
}

pub fn salted_pbkdf(password: &[u8], salt: &[u8]) -> PbkdfKey {
    pbkdf(password, salt, PBKDF_DEFAULT_ITERS)
}

pub fn pbkdf_with_iters(password: &[u8], iters: u32) -> PbkdfKey {
    pbkdf(password, b"", iters)
}

pub fn simple_pbkdf(password: &[u8]) -> PbkdfKey {
    pbkdf(password, b"", PBKDF_DEFAULT_ITERS)
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
