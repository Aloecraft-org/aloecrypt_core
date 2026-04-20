// src/hash.rs
// License: Apache-2.0 (disclaimer at bottom of file)
use super::hash_api::*;

use hmac::{Hmac, KeyInit, Mac};
use sha3::{Digest, Keccak256};
type HmacKeccak256 = Hmac<sha3::Keccak256>;

// pub trait Hashable { fn hashing_material() -> &[u8]; }

pub fn hash(salt: &[u8], ikm: &[u8], domain_info: &str) -> Hash256 {
    let mut hasher = Keccak256::new();
    hasher.update(salt);
    hasher.update(ikm);
    hasher.update(domain_info.as_bytes());
    hasher.finalize().into()
}

pub fn hmac(salt: &[u8], ikm: &[u8], domain_info: &str) -> Hmac256 {
    let mut mac = HmacKeccak256::new_from_slice(ikm).expect("HMAC can take key of any size");
    mac.update(salt);
    mac.update(domain_info.as_bytes());
    let result = mac.finalize();
    (*result.as_bytes()).into()
}

pub fn salted_hmac(salt: &[u8], ikm: &[u8]) -> Hmac256 {
    hmac(salt, ikm, "")
}

pub fn domain_hmac(ikm: &[u8], domain_info: &str) -> Hmac256 {
    hmac("".as_bytes(), ikm, domain_info)
}

pub fn simple_hmac(ikm: &[u8]) -> Hmac256 {
    hmac("".as_bytes(), ikm, "")
}

pub fn salted_hash(salt: &[u8], ikm: &[u8]) -> Hash256 {
    hash(salt, ikm, "")
}

pub fn domain_hash(ikm: &[u8], domain_info: &str) -> Hash256 {
    hash("".as_bytes(), ikm, domain_info)
}

pub fn simple_hash(ikm: &[u8]) -> Hash256 {
    hash("".as_bytes(), ikm, "")
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
