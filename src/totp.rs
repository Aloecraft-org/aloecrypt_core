use super::hash_api::*;
use super::totp_api::*;
use super::*;

use data_encoding::BASE32_NOPAD;
use url::Url;

use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use sha3::{Digest as Sha3Digest, Keccak256, Sha3_256};

impl ITotpCredential for TotpCredential {
    fn error(message: &str) -> Self {
        Self {
            secret: VarByte255::empty(),
            step_seconds: 0u32,
            digits: 0u8,
            algorithm: TotpAlgorithmEnum::UNKNOWN.into(),
            issuer: VarChar255::empty(),
            context: VarChar255::from_str(message),
        }
    }
    fn invalid() -> Self {
        Self {
            secret: VarByte255::empty(),
            step_seconds: 0u32,
            digits: 0u8,
            algorithm: TotpAlgorithmEnum::UNKNOWN.into(),
            issuer: VarChar255::empty(),
            context: VarChar255::empty(),
        }
    }
    fn from_uri(uri_str: &str) -> Self {
        match Url::parse(uri_str) {
            Err(parse_error) => {
                return TotpCredential::error("Invalid URL format");
            }
            Ok(url) => {
                if url.scheme() != "otpauth" {
                    return TotpCredential::error("Not an otpauth URI");
                }
                if url.host_str() != Some("totp") {
                    return TotpCredential::error("Only TOTP is supported");
                }

                // Extract Account and Issuer from the path (Path looks like "/Issuer:AccountName")
                let path = url.path().trim_start_matches('/');
                let (issuer_label, user) = if let Some((i, u)) = path.split_once(':') {
                    (i, u)
                } else {
                    ("", path)
                };

                // Parse Query Parameters
                let mut secret_val = None;
                let mut algorithm = TotpAlgorithm(TotpAlgorithm::SHA1);
                let mut issuer = VarChar255::empty();
                let mut digits = 6;
                let mut period = 30;

                for (key, value) in url.query_pairs() {
                    match key.as_ref() {
                        "secret" => secret_val = Some(value),
                        "algorithm" => {
                            algorithm = match value.as_ref() {
                                "SHA1" => TotpAlgorithm(TotpAlgorithm::SHA1),
                                "SHA256" => TotpAlgorithm(TotpAlgorithm::SHA256),
                                "SHA512" => TotpAlgorithm(TotpAlgorithm::SHA512),
                                "SHA3-256" => TotpAlgorithm(TotpAlgorithm::SHA3_256),
                                "KECCAK256" => TotpAlgorithm(TotpAlgorithm::KECCAK256),
                                _ => algorithm, // Keep default
                            }
                        }
                        "issuer" => issuer = VarChar255::from_str(&value),
                        "digits" => digits = value.parse().unwrap_or(6),
                        "period" => period = value.parse().unwrap_or(30),
                        _ => {}
                    }
                }

                match secret_val {
                    None => TotpCredential::error("Missing secret parameter"),
                    Some(secret_str) => {
                        let secret_upper = secret_str.to_uppercase();
                        let input_bytes = secret_upper.as_bytes();
                        let expected_len = BASE32_NOPAD.decode_len(input_bytes.len()).unwrap(); // Get exact size
                        let mut secret_bytes = [0u8; 255];
                        match BASE32_NOPAD
                            .decode_mut(input_bytes, &mut secret_bytes[..expected_len])
                        {
                            Err(decode_error) => TotpCredential::error("Invalid Base32 secret"),
                            Ok(secret_len) => {
                                return TotpCredential {
                                    secret: VarByte255::from_byte_arr(&secret_bytes[0..secret_len]),
                                    step_seconds: period,
                                    digits,
                                    algorithm,
                                    issuer: issuer,
                                    context: VarChar255::from_str(user),
                                };
                            }
                        }
                    }
                }
            }
        }
    }

    fn generate(&self, time: u64) -> [i8; 8] {
        let step = self.step_seconds;
        let algo = self.algorithm.into();
        let digits = self.digits as usize;
        let secret = self.secret.to_byte_arr();
        let counter = (time / step as u64).to_be_bytes();

        // 1. Generate HMAC digest based on selected algorithm
        let digest: [u8; 64] = match algo {
            TotpAlgorithmEnum::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&secret).unwrap();
                mac.update(&counter);
                let mut out = [0u8; 64];
                out[..20].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            TotpAlgorithmEnum::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
                mac.update(&counter);
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            TotpAlgorithmEnum::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&secret).unwrap();
                mac.update(&counter);
                mac.finalize().into_bytes().into()
            }
            TotpAlgorithmEnum::SHA3_256 => {
                let mut mac = Hmac::<Sha3_256>::new_from_slice(&secret).unwrap();
                mac.update(&counter);
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            TotpAlgorithmEnum::KECCAK256 => {
                let mut mac = Hmac::<Keccak256>::new_from_slice(&secret).unwrap();
                mac.update(&counter);
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            TotpAlgorithmEnum::UNKNOWN => {
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&EMPTY_HMAC_KEY_256);
                out
            }
        };

        let hash_len = match algo {
            TotpAlgorithmEnum::SHA1 => 20,
            TotpAlgorithmEnum::SHA512 => 64,
            _ => 32,
        };

        let offset = (digest[hash_len - 1] & 0xf) as usize;
        let code_bytes = &digest[offset..offset + 4];

        let mut code = ((code_bytes[0] as u32 & 0x7f) << 24)
            | ((code_bytes[1] as u32) << 16)
            | ((code_bytes[2] as u32) << 8)
            | (code_bytes[3] as u32);

        // 3. Final Modulo and Array Conversion
        let mut result = [-1i8; 8];
        let powers = [
            1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
        ];
        let digits_idx = digits;
        let mut num = code % powers[digits_idx];

        for i in (0..digits).rev() {
            result[i] = (num % 10) as i8;
            num /= 10;
        }

        result
    }
}
