pub fn gf256_add(x1: u8, x2: u8) -> u8 {
    x1 ^ x2
}
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0;
    for _ in 0..8 {
        // If the lowest bit of b is set, add (XOR) a to the result
        if (b & 1) != 0 {
            res ^= a;
        }

        // Check if the high bit of a is set
        let high_bit_set = (a & 0x80) != 0;
        a <<= 1;

        // reduce w/ AES polynomial (0x1B)
        if high_bit_set {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    res
}

// TODO: replace w/ lookup table for efficiency
pub fn gf256_inv(n: u8) -> u8 {
    for i in 1..255 {
        if gf256_mul(n, i) == 1 {
            return i;
        }
    }
    0
}

pub fn gf1024_add(x1: u16, x2: u16) -> u16 {
    x1 ^ x2
}

pub fn gf1024_mul(mut a: u16, mut b: u16) -> u16 {
    let mut res = 0;
    for _ in 0..10 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let high_bit_set = (a & 0x200) != 0;
        a <<= 1;
        if high_bit_set {
            a ^= 0x409;
        } // SLIP39 polynomial
        b >>= 1;
    }
    res & 0x3FF
}

// TODO: replace w/ lookup table for efficiency
pub fn gf1024_inv(n: u16) -> u16 {
    for i in 1..1024 {
        if gf1024_mul(n, i) == 1 {
            return i;
        }
    }
    0
}
