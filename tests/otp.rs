use aloecrypt_core::otp::*;
use aloecrypt_core::otp_api::*;
use aloecrypt_core::aloecrypt_api::*;

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
        assert!(matches!(otp_type, OtpTypeEnum::TOTP), "Failed on secret: {}", s);
        assert!(c.secret.to_byte_arr().len() >= 16);
    }
}

#[test]
fn test_invalid_secrets() {
    let invalid_secrets = [
        "GEZDGNBVGY3T",     // Under 10 bytes
        "GEZDGNBVGY3TQOJQIFBEGRC09FIY", // Invalid characters
    ];

    for s in invalid_secrets {
        let c = OtpCredential::from_string(s);
        let otp_type: OtpTypeEnum = c.otp_type.into();
        assert!(matches!(otp_type, OtpTypeEnum::UNKNOWN), "Expected failure on: {}", s);
    }
}

#[test]
fn test_valid_inputs() {
    let inputs: [(&str, OtpTypeEnum); 4] = [
        ("otpauth://totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY", OtpTypeEnum::TOTP),
        ("otpauth://hotp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY", OtpTypeEnum::HOTP),
        ("otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY", OtpTypeEnum::TOTP),
        ("otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY", OtpTypeEnum::HOTP),
    ];

    for (s, expected_type) in inputs {
        let c = OtpCredential::from_string(s);
        let otp_type: OtpTypeEnum = c.otp_type.into();
        assert!(matches!(otp_type, expected_type), "Failed on: {}", s);
    }

    let test_t0 = 4567890u64;
    let test_tcurrent = 5567890u64;

    // Issuer testing
    let c = OtpCredential::from_string("otpauth://totp/issuerA:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&issuer=issuerA");
    assert_eq!(c.issuer.to_str(), "issuerA");
    assert_eq!([4i8, 8i8, 9i8, 4i8, 9i8, 3i8, -1i8, -1i8], c.generate(test_tcurrent));

    // Params testing
    let c = OtpCredential::from_string("otpauth://totp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123&t0=4567890");
    assert_eq!({c.period}, 123);
    assert_eq!({c.t0}, test_t0);
    assert_eq!([4i8, 1i8, 1i8, 6i8, 1i8, 2i8, -1i8, -1i8], c.generate(test_tcurrent));
    
    // Test HOTP using counter
    let c = OtpCredential::from_string("otpauth://hotp/issuer:account_name?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&counter=123");
    assert_eq!({c.counter}, 123);
    assert_eq!([7i8, 3i8, 4i8, 7i8, 0i8, 8i8, -1i8, -1i8], c.generate(c.counter as u64));

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
    let c1 = OtpCredential::from_string("  OtPAUth://totp/ABC:DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c1.issuer.to_str(), "ABC");
    assert_eq!(c1.account_name.to_str(), "DEF");

    let c2 = OtpCredential::from_string("  OtPAUth://totp/ABC:%20DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c2.issuer.to_str(), "ABC");
    assert_eq!(c2.account_name.to_str(), "DEF");

    let c3 = OtpCredential::from_string("  OtPAUth://totp/ABC: DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c3.issuer.to_str(), "ABC");
    assert_eq!(c3.account_name.to_str(), "DEF");

    let c4 = OtpCredential::from_string("  OtPAUth://totp/ABC%3A DEF?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    assert_eq!(c4.issuer.to_str(), "");
    assert_eq!(c4.account_name.to_str(), "ABC: DEF");

    let c5 = OtpCredential::from_string("  OtPAUth://totp/ABC%3A%20DEF?issuer=XYZ");
    assert_eq!(c5.issuer.to_str(), "XYZ");
    assert_eq!(c5.account_name.to_str(), "ABC: DEF");
}

#[test]
fn test_shorthand_inputs() {
    let c0 = OtpCredential::from_string("  JBSWY3DPEHPK3PXP    ");
    let n_bytes = c0.secret.to_byte_arr().len();
    assert!(c0.secret.to_byte_arr().len() >= 10);

    let c1 = OtpCredential::from_string("  GEZDGNBVGY3TQOJQIFBEGRCFIY    ");
    assert!(c1.secret.to_byte_arr().len() >= 16);

    let c2 = OtpCredential::from_string("  //totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY");
    let t2: OtpTypeEnum = c2.otp_type.into();
    assert!(matches!(t2, OtpTypeEnum::TOTP));
    assert_eq!(c2.label.to_str(), "LABEL");

    let c3 = OtpCredential::from_string("  //totp/LABEL?secret=GEZDGNBVGY3TQOJQIFBEGRCFIY&period=123");
    assert_eq!({c3.period}, 123);

    let c4 = OtpCredential::from_string("  totp/GEZDGNBVGY3TQOJQIFBEGRCFIY    ");
    let t4: OtpTypeEnum = c4.otp_type.into();
    assert!(matches!(t4, OtpTypeEnum::TOTP));

    let c5 = OtpCredential::from_string("  hotp/GEZDGNBVGY3TQOJQIFBEGRCFIY?counter=123");
    let t5: OtpTypeEnum = c5.otp_type.into();
    assert!(matches!(t5, OtpTypeEnum::HOTP));
    assert_eq!({c5.counter}, 123);
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
        assert!(matches!(otp_type, OtpTypeEnum::UNKNOWN), "Expected UNKNOWN on invalid input: {}", s);
    }
}