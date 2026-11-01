// use aloecrypt_core::aloecrypt_api::*;
// use aloecrypt_core::otp::*;
// use aloecrypt_core::otp_api::*;

// // Scheme: otpauth://
// // Type: totp (Time-based) or hotp (Counter-based)
// // Label: Identifies the account (e.g., Example:alice@google.com)
// // Secret (Required): Base32 encoded string
// // Issuer (Recommended): The provider name (e.g., issuer=Example)
// // Algorithm (Optional): SHA1 (default), SHA256, or SHA512
// // Digits (Optional): 6 (default) or 8
// // Period (Optional): Time in seconds for TOTP, default is 30 


// const ex1: &str = "otpauth://totp/LABEL/";

// const ex2: &str = "otpauth://totp/LABEL/";

// // to_lowercase

// // %3A
// // %20

// // The issuer prefix and account name should be separated by a literal or url-encoded colon, and optional spaces may precede the account name. Neither issuer nor account name may themselves contain a colon. Represented in ABNF according to RFC 5234

















fn main() { }
// fn main() {
//     use core::time::Duration;
//     use std::time::{SystemTime, UNIX_EPOCH};

//     // 1. Example URI (Standard SHA1, 6 digits, 30s period)
//     // Secret "JBSWY3DPEHPK3PXP" decodes to "Hello!" in Base32
//     let uri =
//         "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6";
//     let cred = OtpCredential::from_uri(uri);

//     // 2. Check for errors stored in the 'account_name' field
//     let status = cred.account_name.to_str();
//     if status.starts_with("Invalid") || status.contains("Missing") {
//         println!("Error parsing URI: {}", status);
//         return;
//     }

//     // 3. Generate a code for the current time
//     let now = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap_or(Duration::ZERO)
//         .as_secs();

//     // Pass by reference is fine here as long as 'generate' handles the packed fields internally
//     let result = cred.generate(now);

//     // 4. Format and print the output
//     print!("TOTP Code for {}: ", cred.account_name.to_str());
//     for i in 0..cred.digits as usize {
//         if result[i] != -1 {
//             print!("{}", result[i]);
//         }
//     }
//     let step = cred.step;
//     println!(
//         "\n(Algorithm: {:?}, Step: {}s)",
//         Into::<OtpAlgorithmEnum>::into(cred.algorithm),
//         step
//     );

//     let algorithms = [
//         (
//             "SHA1",
//             "otpauth://totp/Test:SHA1?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1",
//         ),
//         (
//             "SHA256",
//             "otpauth://totp/Test:SHA256?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
//         ),
//         (
//             "SHA512",
//             "otpauth://totp/Test:SHA512?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512",
//         ),
//         (
//             "SHA3-256",
//             "otpauth://totp/Test:SHA3?secret=JBSWY3DPEHPK3PXP&algorithm=SHA3-256",
//         ),
//         (
//             "KECCAK256",
//             "otpauth://totp/Test:Keccak?secret=JBSWY3DPEHPK3PXP&algorithm=KECCAK256",
//         ),
//         (
//             "SHA256",
//             "otpauth://hotp/Test:SHA256?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
//         ),
//         (
//             "SHA256",
//             "otpauth://hotp/Test:SHA256?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&counter=11",
//         ),
//     ];

//     let test_time = 1713636000;

//     for (name, uri) in algorithms {
//         let cred = OtpCredential::from_uri(uri);
//         let result = if cred.otp_type.0 == OtpType::HOTP
//         {
//             cred.generate(cred.step as u64)
//         }
//         else {
//             cred.generate(test_time)
//         };

//         print!("{:<10} Code: ", name);
//         for i in 0..cred.digits as usize {
//             if result[i] != -1 {
//                 print!("{}", result[i]);
//             }
//         }
//         println!();
//     }
// }
