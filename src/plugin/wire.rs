// src/plugin/wire.rs
// License: Apache-2.0
//
// Entry points: `run` (wrap one export: decode, call, status-prefix the
// reply), `Reader` (decode a request), `fixed_out` (encode a zerocopy reply).
//
// The format is generator/wire.py's, which the Python and TypeScript bindings
// pack against: fixed-size values concatenated, primitives little-endian,
// `&[u8]`/`&str`/`&[u16]` as a u32 LE byte length then the bytes. A reply is a
// 2-byte LE StatusCode, then the payload only when the status is Ok. A
// request that does not decode exactly -- short, overlong, bad UTF-8 -- is
// answered BadEncoding with no payload, whether or not the export is fallible.

use alloc::vec::Vec;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::StatusCode;
use crate::aloecrypt_api::StatusCodeEnum;

fn bad_encoding() -> StatusCode {
    StatusCodeEnum::BadEncoding.into()
}

/// Runs one export: `f` decodes from the reader and returns the payload.
pub fn run(input: &[u8], f: impl FnOnce(&mut Reader) -> Result<Vec<u8>, StatusCode>) -> Vec<u8> {
    let mut reader = Reader { buf: input, pos: 0 };
    match f(&mut reader) {
        Ok(payload) => {
            let mut reply = Vec::with_capacity(2 + payload.len());
            reply.extend_from_slice(&0u16.to_le_bytes());
            reply.extend_from_slice(&payload);
            reply
        }
        Err(code) => code.0.to_le_bytes().to_vec(),
    }
}

/// The bytes of a fixed-size value: a struct, byte alias or enum.
pub fn fixed_out<T: IntoBytes + Immutable>(value: &T) -> Vec<u8> {
    value.as_bytes().to_vec()
}

// depth: request decoding

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

macro_rules! le_reader {
    ($($name:ident),*) => {$(
        pub fn $name(&mut self) -> Result<$name, StatusCode> {
            let raw = self.take(core::mem::size_of::<$name>())?;
            Ok($name::from_le_bytes(raw.try_into().map_err(|_| bad_encoding())?))
        }
    )*};
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StatusCode> {
        let end = self.pos.checked_add(n).ok_or_else(bad_encoding)?;
        let bytes = self.buf.get(self.pos..end).ok_or_else(bad_encoding)?;
        self.pos = end;
        Ok(bytes)
    }

    /// A fixed-size value, laid out as the generated struct is.
    pub fn fixed<T: FromBytes>(&mut self) -> Result<T, StatusCode> {
        T::read_from_bytes(self.take(core::mem::size_of::<T>())?).map_err(|_| bad_encoding())
    }

    /// A u32 LE length-prefixed byte string.
    pub fn bytes(&mut self) -> Result<&'a [u8], StatusCode> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub fn str(&mut self) -> Result<&'a str, StatusCode> {
        core::str::from_utf8(self.bytes()?).map_err(|_| bad_encoding())
    }

    /// A length-prefixed run of u16 LE values; the prefix counts bytes.
    pub fn u16s(&mut self) -> Result<Vec<u16>, StatusCode> {
        let raw = self.bytes()?;
        if raw.len() % 2 != 0 {
            return Err(bad_encoding());
        }
        Ok(raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect())
    }

    pub fn bool(&mut self) -> Result<bool, StatusCode> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad_encoding()),
        }
    }

    le_reader!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

    /// Every byte of the request must have been consumed.
    pub fn finish(&self) -> Result<(), StatusCode> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(bad_encoding())
        }
    }
}
