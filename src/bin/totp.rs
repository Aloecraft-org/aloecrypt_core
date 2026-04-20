use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::totp_api::*;
use aloecrypt_core::totp::*;

fn main() {
    use core::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    // 1. Example URI (Standard SHA1, 6 digits, 30s period)
    // Secret "JBSWY3DPEHPK3PXP" decodes to "Hello!" in Base32
    let uri =
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6";
    let cred = TotpCredential::from_uri(uri);

    // 2. Check for errors stored in the 'context' field
    let status = cred.context.to_str();
    if status.starts_with("Invalid") || status.contains("Missing") {
        println!("Error parsing URI: {}", status);
        return;
    }

    // 3. Generate a code for the current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    // Pass by reference is fine here as long as 'generate' handles the packed fields internally
    let result = cred.generate(now);

    // 4. Format and print the output
    print!("TOTP Code for {}: ", cred.context.to_str());
    for i in 0..cred.digits as usize {
        if result[i] != -1 {
            print!("{}", result[i]);
        }
    }
    let step = cred.step_seconds;
    println!("\n(Algorithm: {:?}, Step: {}s)", Into::<TotpAlgorithmEnum>::into(cred.algorithm), step);

    let algorithms = [
        (
            "SHA1",
            "otpauth://totp/Test:SHA1?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1",
        ),
        (
            "SHA256",
            "otpauth://totp/Test:SHA256?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
        ),
        (
            "SHA512",
            "otpauth://totp/Test:SHA512?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512",
        ),
        (
            "SHA3-256",
            "otpauth://totp/Test:SHA3?secret=JBSWY3DPEHPK3PXP&algorithm=SHA3-256",
        ),
        (
            "KECCAK256",
            "otpauth://totp/Test:Keccak?secret=JBSWY3DPEHPK3PXP&algorithm=KECCAK256",
        ),
    ];

    let test_time = 1713636000; // Fixed timestamp for reproducible results

    for (name, uri) in algorithms {
        let cred = TotpCredential::from_uri(uri);
        let result = cred.generate(test_time);

        print!("{:<10} Code: ", name);
        for i in 0..cred.digits as usize {
            if result[i] != -1 {
                print!("{}", result[i]);
            }
        }
        println!();
    }
}
