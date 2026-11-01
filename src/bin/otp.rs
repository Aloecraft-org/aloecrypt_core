// src/bin/otp.rs
// License: Apache-2.0
//
// Smoke test for OTP parsing and code generation, TOTP and HOTP.
//
//   cargo run --bin otp

use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::otp_api::*;

fn print_code(name: &str, cred: &OtpCredential, current: u64) {
    let result = cred.generate(current);
    let code: String = result
        .iter()
        .take_while(|d| **d >= 0)
        .map(|d| char::from(b'0' + *d as u8))
        .collect();
    println!("{name:<10} {code}");
}

fn main() {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Secret "JBSWY3DPEHPK3PXP" decodes to "Hello!" in Base32.
    let cred = OtpCredential::from_string(
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6",
    );
    let otp_type: OtpTypeEnum = cred.otp_type.into();
    if otp_type == OtpTypeEnum::UNKNOWN {
        // A failed parse carries its reason in `label`.
        println!("Error parsing URI: {}", cred.label.to_str());
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("TOTP for {} at {now}:", cred.account_name.to_str());
    print_code("now", &cred, now);
    println!("round-trip URI: {}\n", cred.to_uri().to_str());

    // Fixed timestamp for reproducible output, one line per algorithm.
    let test_time = 1713636000;
    for algorithm in ["SHA1", "SHA256", "SHA512", "SHA3-256", "KECCAK256"] {
        let uri = format!(
            "otpauth://totp/Test:{algorithm}?secret=JBSWY3DPEHPK3PXP&algorithm={algorithm}"
        );
        print_code(algorithm, &OtpCredential::from_string(&uri), test_time);
    }

    // HOTP: the caller owns the counter; generate() does not advance it.
    let hotp = OtpCredential::from_string("hotp/JBSWY3DPEHPK3PXP?counter=7");
    let counter = hotp.counter as u64;
    print_code("HOTP c=7", &hotp, counter);
}
