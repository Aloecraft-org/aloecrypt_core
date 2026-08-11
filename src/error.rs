// src/error.rs
// License: Apache-2.0 (disclaimer at bottom of file)
//
// Errors for operations that can fail on attacker-controlled input.
//
// Deliberately a plain Rust type and NOT a schema type. The plugin wire format
// has no error channel -- every export returns raw bytes with no discriminant --
// so giving a wire-exported function a Result would require first deciding how
// an error crosses that boundary. That decision is still open (see
// doc/DESIGN.md), and inventing a representation here would pre-empt it.
//
// Until it is settled, this type is used only on functions that are NOT
// exported through the schema. `authorize_recovery` is the one wire-exported
// function that still panics on a failed check, and it stays that way on
// purpose rather than being given a representation nobody has agreed to.

/// A cryptographic operation failed.
///
/// Carries no detail about *why* on purpose: for authenticated decryption the
/// only safe answer to a caller is that it did not authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AloecryptError {
    /// AEAD authentication failed: wrong key, wrong nonce, or altered
    /// ciphertext. These are indistinguishable to the caller by design.
    DecryptAuthFailed,
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
