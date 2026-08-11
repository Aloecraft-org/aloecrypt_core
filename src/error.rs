// src/error.rs
// License: Apache-2.0 (disclaimer at bottom of file)
//
// The error channel, on both sides of the wire.
//
// The error taxonomy is `StatusCode` in the schema (`aloecrypt_api`), so the
// same codes with the same numbering generate into Rust, Python and
// TypeScript. On the wire, every plugin export returns a 2-byte little-endian
// `StatusCode` ahead of its payload; the payload is present only when the
// status is `Ok`, so a caller that skips the check gets a short read rather
// than plausible-looking bytes. Infallible exports always send `Ok` -- the
// prefix is uniform so there is exactly one format to reason about.
//
// In Rust, a fallible function returns `Result<T, StatusCode>`; the schema
// marks it with `"fallible": "true"` and the generated trait signature
// matches. `StatusCode` is the transparent newtype that crosses the wire;
// `StatusCodeEnum` is the matching Rust enum for ergonomic construction and
// matching, converted with `.into()` in either direction.
//
// Codes are coarse on purpose. For authenticated decryption, "wrong key" and
// "altered ciphertext" share `AuthFailed` deliberately: distinguishing them
// would hand an attacker an oracle. Resist splitting codes.

pub use crate::aloecrypt_api::{StatusCode, StatusCodeEnum};

/// The `Result` shape used by every fallible function in this crate.
pub type AloecryptResult<T> = Result<T, StatusCode>;

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
