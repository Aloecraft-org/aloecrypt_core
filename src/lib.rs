// src/lib.rs
// License: Apache-2.0 (disclaimer at bottom of file)
#![no_std]
// no_main is required for the WASM/bare-metal targets, but it also stops the
// test harness emitting an entry point -- with it applied unconditionally,
// `cargo test` fails to link with "undefined symbol: main" and the crate cannot
// be tested at all. Gating it on `not(test)` leaves every shipped target
// unchanged (verified against thumbv8m.main-none-eabihf and wasm32-wasip2).
#![cfg_attr(not(test), no_main)]

include!(concat!(env!("OUT_DIR"), "/api_core.rs"));

// pub mod address;
// pub mod claim;
pub mod bip39;
pub mod document;
pub mod dsa;
pub mod error;
pub mod fixed_byte;
pub mod galois;
pub mod hash;
pub mod kem;
pub mod password;
pub mod pkdf;
pub mod recovery;
pub mod reedsolomon;
pub mod rng;
pub mod shamir;
pub mod slip39;
pub mod totp;

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
