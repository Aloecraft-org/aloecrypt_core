use super::aloecrypt_api::*;
use super::fixed_byte::*;
use super::galois::*;
use super::rng::*;
use super::rng_api::*;

const MAX_VARIANTS: usize = 16;
const MAX_SECRET_LEN: usize = 255;

fn _check_nonzero_unique(arr: &[u8]) -> bool {
    for element in arr {
        if *element == 0 {
            return false;
        }

        let mut match_count = 0;
        for other_element in arr {
            if other_element == element {
                match_count += 1
            }
        }
        if match_count > 1 {
            return false;
        }
    }
    return true;
}

macro_rules! impl_create_shamir_shares {
    ($($name:ident, $n:expr);*) => {
        $(
            pub fn $name(secret: VarByte255, threshold: u8, seed: RngSeed) -> [VarByte255; $n] {
                let mut coef_buf = [[0u8; MAX_VARIANTS]; MAX_SECRET_LEN];
                let mut secret_buf = [VarByte255::empty(); $n];
                let mut location_buf = [0u8; $n];
                let mut rng = AloeRng::new(seed);
                while !_check_nonzero_unique(&location_buf) {
                    rng._fill_bytes(&mut location_buf);
                }
                for idx in 0..MAX_VARIANTS {
                    rng._fill_bytes(&mut coef_buf[idx]);
                }
                let secret_len = secret.to_byte_arr().len() as u8;
                for i in 0..$n {
                    secret_buf[i].value[0] = secret_len + 1;
                    secret_buf[i].value[1] = location_buf[i];
                }
                _create_n_shares(secret, threshold, rng, coef_buf, &mut secret_buf, &location_buf);
                secret_buf
            }
        )*
    }
}

impl_create_shamir_shares! {
    create_3_shamir_shares, 3;
    create_4_shamir_shares, 4;
    create_5_shamir_shares, 5;
    create_6_shamir_shares, 6;
    create_7_shamir_shares, 7;
    create_8_shamir_shares, 8;
    create_9_shamir_shares, 9;
    create_10_shamir_shares, 10;
    create_11_shamir_shares, 11;
    create_12_shamir_shares, 12;
    create_13_shamir_shares, 13;
    create_14_shamir_shares, 14;
    create_15_shamir_shares, 15;
    create_16_shamir_shares, 16
}

fn _create_n_shares(
    secret: VarByte255,
    threshold: u8,
    mut rng: AloeRng,
    mut coef_buf: [[u8; MAX_VARIANTS]; MAX_SECRET_LEN],
    secret_buf: &mut [VarByte255],
    location_buf: &[u8],
) {
    let secret_bytes = secret.to_byte_arr();
    let n_shares = secret_buf.len();
    for byte_idx in 0..secret_bytes.len() {
        for secret_idx in 0..n_shares {
            let x = location_buf[secret_idx];

            let mut y: u8 = if threshold > 1 {
                coef_buf[byte_idx][(threshold - 2) as usize]
            } else {
                0
            };
            if threshold > 2 {
                for i in (0..(threshold - 2) as usize).rev() {
                    y = gf256_add(gf256_mul(y, x), coef_buf[byte_idx][i]);
                }
            }
            y = gf256_add(gf256_mul(y, x), secret_bytes[byte_idx]);
            secret_buf[secret_idx].value[byte_idx + 2] = y;
        }
    }
}

pub fn combine_shamir_shares(shares: &[VarByte255]) -> VarByte255 {
    let n = shares.len();
    let share_len = shares[0].value[0] as usize;
    let secret_len = share_len - 1;
    let mut result = VarByte255::empty();
    result.value[0] = secret_len as u8;

    for byte_idx in 0..secret_len {
        let mut secret_byte = 0u8;

        for i in 0..n {
            let mut li = 1u8; // The Lagrange basis polynomial evaluated at x=0
            for j in 0..n {
                if i == j {
                    continue;
                }

                let xi = shares[i].value[1];
                let xj = shares[j].value[1];

                // Formula for L_i(0): product of (xj / (xj XOR xi))
                let denominator = gf256_add(xj, xi);
                let fraction = gf256_mul(xj, gf256_inv(denominator));
                li = gf256_mul(li, fraction);
            }

            let yi = shares[i].value[byte_idx + 2];
            secret_byte = gf256_add(secret_byte, gf256_mul(yi, li));
        }
        result.value[byte_idx + 1] = secret_byte;
    }
    result
}
