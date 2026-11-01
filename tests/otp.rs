use aloecrypt_core::aloecrypt_api::*;
use aloecrypt_core::otp_api::*;

/*
OtpCredential Fields:
    counter: i64, // -1 if not hotp. Defaults to 0 if hotp and not present (this is a departure from the spec!)
    period: i64, // -1 if not totp. Defaults to 30 otherwise
    t0: u64, // RFC6238 defaults to 0
    digits: u8, // valid: 1-32 (saturates 33 to 255 saturates at 32)
    secret: [u8], // parsed from base32
    algorithm: str, // from valid_algorithms
    otp_type: str, // from valid_otp_types, default totp
    issuer: str, // if `UNKNOWN` should contain raw input that resulted in UNKNOWN credential
    account_name: str, // from label
    label: str // contents of label

Valid Base32 Secrets:
================
With and without padding:
'GEZDGNBVGY3TQOJQIFBEGRCFIY======'
'GEZDGNBVGY3TQOJQIFBEGRCFIFBEGRCFIZDUC==='
'GEZDGNBVGY3TQOJQIFBEGRCFIY'
'GEZDGNBVGY3TQOJQIFBEGRCFIFBEGRCFIZDUC'
Case Insensitive:
'GEzdgnBVGY3TQOjqifBEGRCFIFBEGRCFIZDUC==='
'GEzdgnBVGY3TQOjqifBEGRCFIY'

Invalid Secrets:
================
under min length (16 bytes)
'GEZDGNBVGY3TQOJQIFBEGRCF'
Invalid characters:
'GEZDGNBVGY3TQOJQIFBEGRC09FIY'

Valid Inputs:
================
simple valid inputs:

"otpauth://totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"otpauth://hotp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"otpauth://totp/issuerA:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=issuerA"
"otpauth://hotp/issuerA:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=issuerA"
"otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123"
"otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123&t0=4567890"
"otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=123"

Case Invariant Protocol String w/ whitespace trim:
"  OtPAUth://totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY "

Issuer/Account Name Parsing:
"  OtPAUth://totp/ABC:DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"  OtPAUth://totp/ABC:%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"  OtPAUth://totp/ABC: DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"  OtPAUth://totp/ABC%3A DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"

Issuer does not match label (e.g. label: ABC%3A%20DEF, account_name: DEF, issuer: XYZ):
"  OtPAUth://totp/ABC%3A%20DEF?issuer=XYZ"

// Valid Shorthand Inputs:
================
Minimum Valid String - Base32 String >=16 bytes:
"  GEZDGNBVGY3TQOJQIFBEGRCFIY    "
   JBSWY3DPEHPK3PXP

Valid Protocol Separator Shorthand: `//` instead of otpauth://
"  //totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY"
"  //totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123"

No label, otp_type/secret:
"  totp/GEZDGNBVGY3TQOJQIFBEGRCFIY    "
"  hotp/GEZDGNBVGY3TQOJQIFBEGRCFIY    "
"  totp/GEZDGNBVGY3TQOJQIFBEGRCFIY?period=123"
"  hotp/GEZDGNBVGY3TQOJQIFBEGRCFIY?counter=123"

invalid inputs:
================

too many separators:
"  OtPAUth://totp/something_else/ABC%3A%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=XYZ"

invalid protocol string:
"  https://totp/something_else/ABC%3A%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=XYZ"

Max length: 255 characters:
"OtPAUth://totp/somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=XYZ"

parameter mismatch:
"otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=123"
"otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123"
"otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&t0=9846123"

cannot parse parameter:
"otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=boat"
"otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=hoe"
*/

#[test]
fn test_valid_base32_secrets() {
    let valid_secrets = [
        "GEZDGNBVGY3TQOJQIFBEGRCFIY======",
        "GEZDGNBVGY3TQOJQIFBEGRCFIFBEGRCFIZDUC===",
        "GEZDGNBVGY3TQOJQIFBEGRCFIY",
        "GEZDGNBVGY3TQOJQIFBEGRCFIFBEGRCFIZDUC",
        "GEzdgnBVGY3TQOjqifBEGRCFIFBEGRCFIZDUC===",
        "GEzdgnBVGY3TQOjqifBEGRCFIY",
    ];

    for s in valid_secrets {
        let c = OtpCredential::from_string(s);
        let otp_type: OtpTypeEnum = c.otp_type.into();
        assert!(
            matches!(otp_type, OtpTypeEnum::TOTP),
            "Failed on secret: {}",
            s
        );
        assert!(c.secret.to_byte_arr().len() >= 16);
    }
}

#[test]
fn test_invalid_secrets() {
    let invalid_secrets = [
        "GEZDGNBVGY3T",                 // Under 10 bytes
        "GEZDGNBVGY3TQOJQIFBEGRC09FIY", // Invalid characters
    ];

    for s in invalid_secrets {
        let c = OtpCredential::from_string(s);
        let otp_type: OtpTypeEnum = c.otp_type.into();
        assert!(
            matches!(otp_type, OtpTypeEnum::UNKNOWN),
            "Expected failure on: {}",
            s
        );
    }
}

#[test]
fn test_valid_inputs() {
    let inputs: [(&str, OtpTypeEnum); 4] = [
        (
            "otpauth://totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY",
            OtpTypeEnum::TOTP,
        ),
        (
            "otpauth://hotp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY",
            OtpTypeEnum::HOTP,
        ),
        (
            "otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY",
            OtpTypeEnum::TOTP,
        ),
        (
            "otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY",
            OtpTypeEnum::HOTP,
        ),
    ];

    for (s, expected_type) in inputs {
        let c = OtpCredential::from_string(s);
        let otp_type: OtpTypeEnum = c.otp_type.into();
        assert_eq!(otp_type, expected_type, "Failed on: {}", s);
    }

    let test_t0 = 4567890u64;
    let test_tcurrent = 5567890u64;

    // Issuer testing
    let c = OtpCredential::from_string(
        "otpauth://totp/issuerA:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=issuerA",
    );
    assert_eq!(c.issuer.to_str(), "issuerA");
    assert_eq!(
        [4i8, 8i8, 9i8, 4i8, 9i8, 3i8, -1i8, -1i8],
        c.generate(test_tcurrent)
    );

    // Params testing
    let c = OtpCredential::from_string(
        "otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123&t0=4567890",
    );
    assert_eq!({ c.period }, 123);
    assert_eq!({ c.t0 }, test_t0);
    assert_eq!(
        [4i8, 1i8, 1i8, 6i8, 1i8, 2i8, -1i8, -1i8],
        c.generate(test_tcurrent)
    );

    // Test HOTP using counter
    let c = OtpCredential::from_string(
        "otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=123",
    );
    assert_eq!({ c.counter }, 123);
    assert_eq!(
        [7i8, 3i8, 4i8, 7i8, 0i8, 8i8, -1i8, -1i8],
        c.generate(c.counter as u64)
    );
}

#[test]
fn test_case_invariant_protocol_and_whitespace() {
    let c = OtpCredential::from_string("  OtPAUth://totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY ");
    let otp_type: OtpTypeEnum = c.otp_type.into();
    assert!(matches!(otp_type, OtpTypeEnum::TOTP));
    assert_eq!(c.label.to_str(), "LABEL");
}

#[test]
fn test_issuer_account_name_parsing() {
    let c1 =
        OtpCredential::from_string("  OtPAUth://totp/ABC:DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c1.issuer.to_str(), "ABC");
    assert_eq!(c1.account_name.to_str(), "DEF");

    let c2 =
        OtpCredential::from_string("  OtPAUth://totp/ABC:%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c2.issuer.to_str(), "ABC");
    assert_eq!(c2.account_name.to_str(), "DEF");

    let c3 =
        OtpCredential::from_string("  OtPAUth://totp/ABC: DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c3.issuer.to_str(), "ABC");
    assert_eq!(c3.account_name.to_str(), "DEF");

    let c4 =
        OtpCredential::from_string("  OtPAUth://totp/ABC%3A DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c4.issuer.to_str(), "");
    assert_eq!(c4.account_name.to_str(), "ABC: DEF");

    let c5 = OtpCredential::from_string("  OtPAUth://totp/ABC%3A%20DEF?issuer=XYZ");
    assert_eq!(c5.issuer.to_str(), "XYZ");
    assert_eq!(c5.account_name.to_str(), "ABC: DEF");
}

#[test]
fn test_shorthand_inputs() {
    let c0 = OtpCredential::from_string("  JBSWY3DPEHPK3PXP    ");
    assert!(c0.secret.to_byte_arr().len() >= 10);

    let c1 = OtpCredential::from_string("  GEZDGNBVGY3TQOJQIFBEGRCFIY    ");
    assert!(c1.secret.to_byte_arr().len() >= 16);

    let c2 = OtpCredential::from_string("  //totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    let t2: OtpTypeEnum = c2.otp_type.into();
    assert!(matches!(t2, OtpTypeEnum::TOTP));
    assert_eq!(c2.label.to_str(), "LABEL");

    let c3 =
        OtpCredential::from_string("  //totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123");
    assert_eq!({ c3.period }, 123);

    let c4 = OtpCredential::from_string("  totp/GEZDGNBVGY3TQOJQIFBEGRCFIY    ");
    let t4: OtpTypeEnum = c4.otp_type.into();
    assert!(matches!(t4, OtpTypeEnum::TOTP));

    let c5 = OtpCredential::from_string("  hotp/GEZDGNBVGY3TQOJQIFBEGRCFIY?counter=123");
    let t5: OtpTypeEnum = c5.otp_type.into();
    assert!(matches!(t5, OtpTypeEnum::HOTP));
    assert_eq!({ c5.counter }, 123);
}

#[test]
fn test_invalid_inputs() {
    let invalid_inputs = [
        "  OtPAUth://totp/something_else/ABC%3A%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=XYZ", // Too many separators
        "  https://totp/something_else/ABC%3A%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=XYZ", // Invalid protocol
        "OtPAUth://totp/somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters_somereallylonglabelthatpushespast255characters?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=XYZ", // Exceeds 255 length
        "otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=123", // Param mismatch: TOTP + counter
        "otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123", // Param mismatch: HOTP + period
        "otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&t0=9846123", // Param mismatch: HOTP + t0
        "otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=boat", // Invalid int
        "otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=hoe", // Invalid int
    ];

    for s in invalid_inputs {
        let c = OtpCredential::from_string(s);
        let otp_type: OtpTypeEnum = c.otp_type.into();
        assert!(
            matches!(otp_type, OtpTypeEnum::UNKNOWN),
            "Expected UNKNOWN on invalid input: {}",
            s
        );
    }
}
// ---------------------------------------------------------------------------
// Reference vectors. OTP is the one place the library deliberately
// interoperates with existing implementations, so the SHA-1 rows are the
// compatibility contract, not an endorsement of SHA-1.
// ---------------------------------------------------------------------------

/// RFC 4226 / RFC 6238 seeds, base32-encoded for the otpauth URI.
const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SEED_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

fn totp(secret: &str, algorithm: &str) -> OtpCredential {
    OtpCredential::from_string(&format!(
        "otpauth://totp/Example:alice@example.com?secret={secret}&algorithm={algorithm}&digits=8&period=30"
    ))
}

/// Render the digit array the way a user would read it.
fn code(result: OtpResult, digits: usize) -> String {
    result[..digits]
        .iter()
        .map(|d| char::from_digit(*d as u32, 10).expect("digit out of range"))
        .collect()
}

#[test]
fn rfc4226_hotp_vectors() {
    let c = OtpCredential::from_string(&format!("otpauth://hotp/Example:a?secret={SEED_SHA1}"));
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, want) in expected.iter().enumerate() {
        assert_eq!(
            code(c.generate(counter as u64), 6),
            *want,
            "RFC 4226 vector at C={counter}"
        );
    }
}

#[test]
fn rfc6238_sha1_vectors() {
    let c = totp(SEED_SHA1, "SHA1");
    for (time, want) in [
        (59u64, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ] {
        assert_eq!(
            code(c.generate(time), 8),
            want,
            "RFC 6238 SHA-1 vector at T={time}"
        );
    }
}

#[test]
fn rfc6238_sha256_vectors() {
    let c = totp(SEED_SHA256, "SHA256");
    for (time, want) in [
        (59u64, "46119246"),
        (1111111109, "68084774"),
        (1234567890, "91819424"),
    ] {
        assert_eq!(
            code(c.generate(time), 8),
            want,
            "RFC 6238 SHA-256 vector at T={time}"
        );
    }
}

#[test]
fn rfc6238_sha512_vectors() {
    let c = totp(SEED_SHA512, "SHA512");
    for (time, want) in [(59u64, "90693936"), (1234567890, "93441116")] {
        assert_eq!(
            code(c.generate(time), 8),
            want,
            "RFC 6238 SHA-512 vector at T={time}"
        );
    }
}

#[test]
fn totp_codes_are_stable_within_a_step_and_change_across_it() {
    let c = totp(SEED_SHA1, "SHA1");
    assert_eq!(c.generate(0), c.generate(29), "same 30s step");
    assert_ne!(c.generate(29), c.generate(30), "step boundary");
}

#[test]
fn stronger_hashes_are_selectable_and_differ_from_sha1() {
    // Not a post-quantum claim: OTP is a shared-secret HMAC scheme with no
    // asymmetric primitive, so a stronger hash is a hash upgrade only.
    let sha1 = totp(SEED_SHA1, "SHA1").generate(59);
    for algorithm in ["SHA3-256", "KECCAK256"] {
        assert_ne!(
            sha1,
            totp(SEED_SHA1, algorithm).generate(59),
            "{algorithm} produced the SHA-1 code"
        );
    }
}

#[test]
fn unused_digit_slots_stay_negative() {
    let c = OtpCredential::from_string(&format!(
        "otpauth://totp/Example:a?secret={SEED_SHA1}&digits=6&period=60"
    ));
    let (digits, period) = (c.digits, c.period);
    assert_eq!((digits, period), (6, 60));
    let result = c.generate(59);
    assert_eq!(&result[6..], &[-1, -1], "unused digit slots should stay -1");
}

#[test]
fn uri_round_trips() {
    for uri in [
        "otpauth://totp/issuerA:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=issuerA&period=45",
        "otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=123",
        "otpauth://totp/ABC%3A%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=X%26Y",
        "otpauth://totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY",
    ] {
        let a = OtpCredential::from_string(uri);
        let b = OtpCredential::from_string(a.to_uri().to_str());
        let (ta, tb): (OtpTypeEnum, OtpTypeEnum) = (a.otp_type.into(), b.otp_type.into());
        assert_eq!(ta, tb, "type survives {uri}");
        assert_ne!(
            tb,
            OtpTypeEnum::UNKNOWN,
            "re-parse of {uri} failed: {}",
            a.to_uri().to_str()
        );
        assert_eq!(a.secret.to_byte_arr(), b.secret.to_byte_arr());
        assert_eq!(a.issuer.to_str(), b.issuer.to_str());
        assert_eq!(a.account_name.to_str(), b.account_name.to_str());
        assert_eq!(
            a.generate(1_000_000),
            b.generate(1_000_000),
            "codes match after {uri}"
        );
    }
}

#[test]
fn builder_methods_set_fields() {
    let mut c = OtpCredential::from_string(&format!("totp/{SEED_SHA1}"));
    c.with_period(60);
    c.with_issuer("Example").unwrap();
    c.with_account_name("alice").unwrap();
    c.with_algorithm(OtpAlgorithm(OtpAlgorithm::SHA256));
    let (period, algorithm): (i64, OtpAlgorithmEnum) = (c.period, c.algorithm.into());
    assert_eq!(period, 60);
    assert_eq!(algorithm, OtpAlgorithmEnum::SHA256);
    assert_eq!(c.issuer.to_str(), "Example");
    assert_eq!(c.account_name.to_str(), "alice");
}

#[test]
fn builders_reject_oversized_input_instead_of_panicking() {
    let mut c = OtpCredential::from_string(&format!("totp/{SEED_SHA1}"));
    let long = "x".repeat(256);
    let bad: StatusCodeEnum = StatusCodeEnum::BadArgument;
    for r in [
        c.with_issuer(&long).err(),
        c.with_account_name(&long).err(),
        c.with_label(&long).err(),
        c.with_secret(long.as_bytes()).err(),
    ] {
        let code: StatusCodeEnum = r.expect("oversized input must be rejected").into();
        assert_eq!(code, bad);
    }
    assert!(c.with_issuer(&"x".repeat(255)).is_ok());
}

#[test]
fn digits_beyond_the_result_width_are_rejected() {
    // OtpResult holds 8 digits. A 9+ digit code cannot be represented, and
    // truncating it would yield a valid-looking wrong code.
    for d in [0u8, 9, 10, 32, 255] {
        let c =
            OtpCredential::from_string(&format!("otpauth://hotp/a?secret={SEED_SHA1}&digits={d}"));
        let t: OtpTypeEnum = c.otp_type.into();
        assert_eq!(t, OtpTypeEnum::UNKNOWN, "digits={d} should not parse");
    }
    let mut c =
        OtpCredential::from_string(&format!("otpauth://hotp/a?secret={SEED_SHA1}&digits=8"));
    c.digits = 9;
    assert_eq!(
        c.generate(0),
        [-1i8; 8],
        "an out-of-range digits field yields no code"
    );
}

#[test]
fn overlong_multibyte_input_does_not_panic() {
    // The 255-byte cut must land on a char boundary.
    let s = format!("otpauth://totp/{}", "é".repeat(200));
    let c = OtpCredential::from_string(&s);
    let t: OtpTypeEnum = c.otp_type.into();
    assert_eq!(t, OtpTypeEnum::UNKNOWN);
}
