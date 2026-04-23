use super::*;

impl VarU16 for VarU16_255 {
    fn empty() -> Self {
        Self { value: EMPTY_B512 }
    }

    fn from_u16_arr(input: &[u16]) -> Self {
        assert!(input.len() <= 255, "VarU16 input max length is 255");
        let mut value = EMPTY_B512;
        let bytes =
            unsafe { core::slice::from_raw_parts(input.as_ptr() as *const u8, input.len() * 2) };
        value[2..bytes.len() + 2].copy_from_slice(bytes);
        value[0] = input.len() as u8;

        Self { value }
    }

    fn to_u16_arr(&self) -> &[u16] {
        let len = self.value[0] as usize;
        unsafe { core::slice::from_raw_parts(self.value[2..].as_ptr() as *const u16, len) }
    }

    fn pack_bytes(&self) -> &B512 {
        &self.value
    }

    fn unpack_bytes(bytes: &B512) -> Self {
        Self { value: *bytes }
    }
}

impl VarString for VarString511 {
    fn empty() -> Self {
        Self { value: EMPTY_B512 }
    }

    fn from_str(input: &str) -> Self {
        assert!(input.len() <= 511, "VarString input max length is 511");
        let mut value = [0u8; 512];
        value[1..input.len() + 1].copy_from_slice(input.as_bytes());
        value[0] = input.len() as u8;
        Self { value }
    }

    fn to_str(&self) -> &str {
        let len = (self.value[0] as usize).min(511);
        core::str::from_utf8(&self.value[1..len + 1]).unwrap_or("")
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
        Self { value: [0u8; 256] }
    }

    fn from_str(input: &str) -> Self {
        assert!(input.len() <= 255, "VarChar input max length is 255");
        let mut value = [0u8; 256];
        value[1..input.len() + 1].copy_from_slice(input.as_bytes());
        value[0] = input.len() as u8;
        Self { value }
    }
    fn to_str(&self) -> &str {
        let len = self.value[0] as usize;
        let end = if len > 255 { 255 } else { len };
        core::str::from_utf8(&self.value[1..1 + end]).unwrap_or("")
    }
    fn pack_bytes(&self) -> &B256 {
        &self.value
    }
    fn unpack_bytes(varchar_bytes: &B256) -> Self {
        Self {
            value: (*varchar_bytes).into(),
        }
    }
}

impl VarByte for VarByte255 {
    fn empty() -> Self {
        Self { value: [0u8; 256] }
    }

    fn from_byte_arr(input: &[u8]) -> Self {
        assert!(input.len() <= 255, "VarByte input max length is 255");
        let mut value = [0u8; 256];
        value[1..input.len() + 1].copy_from_slice(input);
        value[0] = input.len() as u8;
        Self { value }
    }
    fn to_byte_arr(&self) -> &[u8] {
        let len = self.value[0] as usize;
        if len >= 256 {
            &[]
        } else {
            &self.value[1..1 + len]
        }
    }
    fn pack_bytes(&self) -> &B256 {
        &self.value
    }
    fn unpack_bytes(varchar_bytes: &B256) -> Self {
        Self {
            value: (*varchar_bytes).into(),
        }
    }
}
