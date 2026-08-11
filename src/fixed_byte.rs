// src/fixed_byte.rs
// License: Apache-2.0 (disclaimer at bottom of file)
//
// Fixed-capacity variable-length types. These cross the plugin wire boundary,
// so their byte layout is a format concern and must not depend on the host.
//
// Every generated struct is #[repr(C, packed)], which pins the wire layout but
// also forces alignment 1 on the backing buffer. That is why VarU16 cannot hand
// out a &[u16] borrowed from its own storage: the buffer may sit at an odd
// address, and a reference to a misaligned u16 is undefined behaviour even if
// it is never dereferenced. The read-into-caller-buffer shape below is the
// sound alternative, and it allocates nothing.

use super::*;

impl VarU16 for VarU16_255 {
    fn empty() -> Self {
        Self { value: EMPTY_B512 }
    }

    /// Layout: `[0]` = element count, `[1]` reserved, `[2..]` = little-endian
    /// u16 pairs. Encoded explicitly so the bytes are the same on any host.
    fn from_u16_arr(input: &[u16]) -> Self {
        assert!(input.len() <= 255, "VarU16 input max length is 255");
        let mut value = EMPTY_B512;
        for (i, word) in input.iter().enumerate() {
            let at = 2 + i * 2;
            value[at..at + 2].copy_from_slice(&word.to_le_bytes());
        }
        value[0] = input.len() as u8;
        Self { value }
    }

    fn len(&self) -> usize {
        self.value[0] as usize
    }

    fn pack_bytes(&self) -> &B512 {
        &self.value
    }

    fn unpack_bytes(bytes: &B512) -> Self {
        Self { value: *bytes }
    }
}

impl VarU16_255 {
    /// Decode into `out`, returning the number of elements written.
    ///
    /// Not part of the `VarU16` trait, and so not a plugin export: an
    /// out-parameter has no representation in the wire format, which returns
    /// bytes and cannot write into caller memory. A binding decodes the packed
    /// bytes from `pack_bytes` itself.
    pub fn read_u16_arr(&self, out: &mut [u16; 255]) -> usize {
        let len = self.len();
        for (i, slot) in out.iter_mut().enumerate().take(len) {
            let at = 2 + i * 2;
            *slot = u16::from_le_bytes([self.value[at], self.value[at + 1]]);
        }
        len
    }
}

impl VarString for VarString510 {
    fn empty() -> Self {
        Self { value: EMPTY_B512 }
    }

    /// Layout: `[0..2]` = little-endian u16 byte length, `[2..]` = payload.
    ///
    /// The previous one-byte prefix could not express a length above 255, so
    /// anything longer silently read back truncated. Two bytes in a 512-byte
    /// buffer leaves 510 of payload, which is what the type is now named for.
    fn from_str(input: &str) -> Self {
        assert!(input.len() <= 510, "VarString input max length is 510");
        let mut value = EMPTY_B512;
        value[0..2].copy_from_slice(&(input.len() as u16).to_le_bytes());
        value[2..input.len() + 2].copy_from_slice(input.as_bytes());
        Self { value }
    }

    /// Returns an empty string for a corrupt length or non-UTF-8 payload rather
    /// than panicking: this decodes attacker-reachable bytes.
    fn to_str(&self) -> &str {
        let len = (u16::from_le_bytes([self.value[0], self.value[1]]) as usize).min(510);
        core::str::from_utf8(&self.value[2..len + 2]).unwrap_or("")
    }

    fn pack_bytes(&self) -> &B512 {
        &self.value
    }

    fn unpack_bytes(bytes: &B512) -> Self {
        Self { value: *bytes }
    }
}

impl VarChar for VarChar255 {
    fn empty() -> Self {
        Self { value: EMPTY_B256 }
    }

    fn from_str(input: &str) -> Self {
        assert!(input.len() <= 255, "VarChar input max length is 255");
        let mut value = EMPTY_B256;
        value[1..input.len() + 1].copy_from_slice(input.as_bytes());
        value[0] = input.len() as u8;
        Self { value }
    }

    /// Empty string on non-UTF-8 rather than a panic; see `VarString::to_str`.
    fn to_str(&self) -> &str {
        let len = self.value[0] as usize;
        core::str::from_utf8(&self.value[1..1 + len]).unwrap_or("")
    }

    fn pack_bytes(&self) -> &B256 {
        &self.value
    }

    fn unpack_bytes(varchar_bytes: &B256) -> Self {
        Self {
            value: *varchar_bytes,
        }
    }
}

impl VarByte for VarByte255 {
    fn empty() -> Self {
        Self { value: EMPTY_B256 }
    }

    fn from_byte_arr(input: &[u8]) -> Self {
        assert!(input.len() <= 255, "VarByte input max length is 255");
        let mut value = EMPTY_B256;
        value[1..input.len() + 1].copy_from_slice(input);
        value[0] = input.len() as u8;
        Self { value }
    }

    fn to_byte_arr(&self) -> &[u8] {
        // The length is a single byte, so it cannot exceed the 255 bytes of
        // payload the buffer holds; no bounds branch is reachable here.
        let len = self.value[0] as usize;
        &self.value[1..1 + len]
    }

    fn pack_bytes(&self) -> &B256 {
        &self.value
    }

    fn unpack_bytes(varchar_bytes: &B256) -> Self {
        Self {
            value: *varchar_bytes,
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
