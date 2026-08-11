// tests/varbyte.rs
// Round-trip and boundary behaviour for the Var* fixed-capacity types.
//
// These types cross the plugin wire boundary, so their encoding is a format
// concern, not just an internal detail.

use aloecrypt_core::aloecrypt_api::*;

/// Decode a VarU16_255 into an owned Vec. `to_u16_arr` was removed because it
/// handed out a `&[u16]` borrowed from an align-1 packed buffer, which is
/// undefined behaviour; `read_u16_arr` decodes into a caller buffer instead.
fn words(v: &VarU16_255) -> Vec<u16> {
    let mut buf = [0u16; 255];
    let n = v.read_u16_arr(&mut buf);
    buf[..n].to_vec()
}

// ---------------------------------------------------------------- VarByte255

#[test]
fn varbyte_roundtrips_across_lengths() {
    for len in [0usize, 1, 2, 31, 32, 128, 254, 255] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let v = VarByte255::from_byte_arr(&data);
        assert_eq!(
            v.to_byte_arr(),
            &data[..],
            "VarByte255 round trip at len {len}"
        );
    }
}

#[test]
fn varbyte_survives_pack_unpack() {
    let data: Vec<u8> = (0..200).map(|i| (i * 7 % 256) as u8).collect();
    let v = VarByte255::from_byte_arr(&data);
    let packed = *v.pack_bytes();
    let restored = VarByte255::unpack_bytes(&packed);
    assert_eq!(restored.to_byte_arr(), v.to_byte_arr());
}

#[test]
fn varbyte_empty_is_empty() {
    assert_eq!(VarByte255::empty().to_byte_arr(), &[] as &[u8]);
}

// ---------------------------------------------------------------- VarChar255

#[test]
fn varchar_roundtrips_across_lengths() {
    for len in [0usize, 1, 32, 254, 255] {
        let s: String = core::iter::repeat('a').take(len).collect();
        let v = VarChar255::from_str(&s);
        assert_eq!(v.to_str(), s, "VarChar255 round trip at len {len}");
    }
}

#[test]
fn varchar_survives_pack_unpack() {
    let v = VarChar255::from_str("aloecrypt");
    let packed = *v.pack_bytes();
    assert_eq!(VarChar255::unpack_bytes(&packed).to_str(), "aloecrypt");
}

// -------------------------------------------------------------- VarString510

#[test]
fn varstring_roundtrips_below_256() {
    for len in [0usize, 1, 32, 254, 255] {
        let s: String = core::iter::repeat('x').take(len).collect();
        let v = VarString510::from_str(&s);
        assert_eq!(v.to_str(), s, "VarString510 round trip at len {len}");
    }
}

#[test]
fn varstring_roundtrips_up_to_capacity() {
    // The type advertises 510 bytes of capacity and asserts on more, so every
    // length it accepts must round trip. Lengths above 255 needed the two-byte
    // prefix; with a one-byte prefix they silently read back truncated.
    for len in [256usize, 300, 400, 510] {
        let s: String = core::iter::repeat('x').take(len).collect();
        let v = VarString510::from_str(&s);
        assert_eq!(v.to_str().len(), len, "VarString510 lost length at {len}");
        assert_eq!(v.to_str(), s, "VarString510 round trip at len {len}");
    }
}

// --------------------------------------------------------------- VarU16_255

#[test]
fn varu16_roundtrips_across_lengths() {
    for len in [0usize, 1, 2, 100, 254, 255] {
        let data: Vec<u16> = (0..len).map(|i| (i * 37 % 1024) as u16).collect();
        let v = VarU16_255::from_u16_arr(&data);
        assert_eq!(&words(&v), &data[..], "VarU16_255 round trip at len {len}");
    }
}

#[test]
fn varu16_encoding_is_little_endian_on_the_wire() {
    // The packed bytes cross an FFI boundary, so the encoding must be defined
    // by the format rather than by the host's byte order.
    let v = VarU16_255::from_u16_arr(&[0x0102, 0xF0E0]);
    let packed = v.pack_bytes();
    assert_eq!(packed[0], 2, "length prefix");
    assert_eq!(
        &packed[2..6],
        &[0x02, 0x01, 0xE0, 0xF0],
        "u16 elements should be little-endian regardless of host byte order"
    );
}

#[test]
fn varu16_survives_pack_unpack() {
    let data: Vec<u16> = (0..250).map(|i| (i * 13 % 2048) as u16).collect();
    let v = VarU16_255::from_u16_arr(&data);
    let packed = *v.pack_bytes();
    assert_eq!(words(&VarU16_255::unpack_bytes(&packed)), data);
}
