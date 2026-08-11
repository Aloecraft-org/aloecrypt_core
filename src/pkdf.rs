// src/pkdf.rs
// License: Apache-2.0 (disclaimer at bottom of file)
//
// Argon2id behind the schema's pbkdf interface. `iters` is the Argon2 pass
// count (t_cost) -- the one tunable that crosses the wire. The memory cost is
// a build-profile constant, because memory-hard derivation and a 520 KB device
// are mutually exclusive (doc/DESIGN.md section 6):
//
//   host_kdf (default)  19 MiB via the allocator -- the OWASP-recommended
//                       Argon2id working set for hosted deployments.
//   without host_kdf    a fixed 64 KiB block on the stack: real (if small)
//                       memory hardness rather than none, sized so the frame
//                       stays well inside the ML-DSA-dominated stack budget
//                       (`stackcheck` measures it).
//
// The two profiles produce different keys for the same inputs. That is
// inherent -- the memory cost is an Argon2 input -- and intentional: a key
// derived at 19 MiB must not be reproducible by an attacker running at 64 KiB.
use super::pkdf_api::*;

use crate::hash::domain_hash;
use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2 memory cost in KiB (one block = 1 KiB). Profile constant, not a
/// parameter: a consumer that needs a different working set is choosing a
/// different security/hardware trade-off and should say so at build time.
#[cfg(feature = "host_kdf")]
pub const PBKDF_M_COST_KIB: u32 = 19 * 1024;
#[cfg(not(feature = "host_kdf"))]
pub const PBKDF_M_COST_KIB: u32 = 64;

/// Default pass count. OWASP pairs 19 MiB with t=2; the embedded profile
/// cannot compensate for its small memory with passes alone, but more of them
/// is still strictly better, and a Cortex-M33 finishes 4 passes over 64 KiB
/// in well under a second.
#[cfg(feature = "host_kdf")]
pub const PBKDF_DEFAULT_ITERS: u32 = 2;
#[cfg(not(feature = "host_kdf"))]
pub const PBKDF_DEFAULT_ITERS: u32 = 4;

/// Argon2 rejects salts under 8 bytes, while this API has always accepted any
/// salt including none. Normalizing through the crate's framed hash keeps that
/// contract, gives Argon2 a fixed 32-byte salt, and domain-separates the KDF:
/// bump the version suffix if the derivation ever has to change.
const PBKDF_SALT_DOMAIN: &str = "aloecrypt.pkdf.salt.v1";

// Compile-time check that the profile constants satisfy Argon2's bounds, so
// the runtime construction below cannot fail on them.
const _: Params = match Params::new(
    PBKDF_M_COST_KIB,
    PBKDF_DEFAULT_ITERS,
    Params::DEFAULT_P_COST,
    Some(PBKDF_KEY_SZ),
) {
    Ok(p) => p,
    Err(_) => panic!("profile KDF parameters do not satisfy Argon2's bounds"),
};

fn argon2id(iters: u32) -> Argon2<'static> {
    let params = Params::new(
        PBKDF_M_COST_KIB,
        iters.max(Params::MIN_T_COST),
        Params::DEFAULT_P_COST,
        Some(PBKDF_KEY_SZ),
    )
    .expect("m/p/output are validated at compile time and t is clamped to its minimum");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn pbkdf(password: &[u8], salt: &[u8], iters: u32) -> PkdfKey {
    let salt = domain_hash(salt, PBKDF_SALT_DOMAIN);
    let mut key = EMPTY_PBKDF_KEY;
    derive_into(&argon2id(iters), password, &salt, &mut key);
    key
}

/// Hosted profile: let the argon2 crate allocate its 19 MiB of blocks.
#[cfg(feature = "host_kdf")]
fn derive_into(argon: &Argon2, password: &[u8], salt: &[u8], key: &mut [u8]) {
    argon
        .hash_password_into(password, salt, key)
        // The salt is a fixed 32 bytes and the output length matches the
        // params, so the only reachable failures are a >4 GiB password or the
        // block buffer failing to allocate -- both are programmer/environment
        // errors a status code could not make recoverable.
        .expect("Argon2 block buffer allocation failed");
}

/// Embedded profile: the blocks live in this frame. #[inline(never)] pins the
/// 64 KiB to one predictable stack frame for the stackcheck guard.
#[cfg(not(feature = "host_kdf"))]
#[inline(never)]
fn derive_into(argon: &Argon2, password: &[u8], salt: &[u8], key: &mut [u8]) {
    let mut blocks = [argon2::Block::new(); PBKDF_M_COST_KIB as usize];
    argon
        .hash_password_into_with_memory(password, salt, key, &mut blocks[..])
        // The buffer length equals the memory cost by construction and the
        // salt/output constraints are as in the hosted path, so no input can
        // reach an error here.
        .expect("Argon2 rejected parameters that were validated at compile time");
}

pub fn salted_pbkdf(password: &[u8], salt: &[u8]) -> PkdfKey {
    pbkdf(password, salt, PBKDF_DEFAULT_ITERS)
}

pub fn pbkdf_with_iters(password: &[u8], iters: u32) -> PkdfKey {
    pbkdf(password, b"", iters)
}

pub fn simple_pbkdf(password: &[u8]) -> PkdfKey {
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
