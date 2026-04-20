// src/lib.rs
// License: Apache-2.0 (disclaimer at bottom of file)
#![no_std]
#![no_main]

include!(concat!(env!("OUT_DIR"), "/api_core.rs"));

// pub mod address;
// pub mod claim;
pub mod dsa;
pub mod fixed_byte;
pub mod hash;
pub mod kem;
pub mod password;
pub mod pkdf;
pub mod recovery;
pub mod rng;
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
