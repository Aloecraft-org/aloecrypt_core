use super::hash_api::*;
use super::otp_api::*;
use super::*;

use data_encoding::BASE32_NOPAD;
use url::Url;

use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use sha3::{Digest as Sha3Digest, Keccak256, Sha3_256};

impl IOtpCredential for OtpCredential {
    fn empty() -> Self {
        Self {
            counter: -1i64,
            period: -1i64,
            t0: 0u64,
            digits: 0u8,
            secret: VarByte255::empty(),
            algorithm: OtpAlgorithmEnum::UNKNOWN.into(),
            otp_type: OtpTypeEnum::UNKNOWN.into(),
            issuer: VarChar255::empty(),
            account_name: VarChar255::empty(),
            label: VarChar255::empty(),
        }
    }
    fn error(message: &str) -> Self {
        Self {
            counter: -1i64,
            period: -1i64,
            t0: 0u64,
            digits: 0u8,
            secret: VarByte255::empty(),
            algorithm: OtpAlgorithmEnum::UNKNOWN.into(),
            otp_type: OtpTypeEnum::UNKNOWN.into(),
            issuer: VarChar255::empty(),
            account_name: VarChar255::empty(),
            label: VarChar255::from_str(message),
        }
    }
    fn invalid(message: &str, input_str: &str) -> Self {
        Self {
            counter: -1i64,
            period: -1i64,
            t0: 0u64,
            digits: 0u8,
            secret: VarByte255::empty(),
            algorithm: OtpAlgorithmEnum::UNKNOWN.into(),
            otp_type: OtpTypeEnum::UNKNOWN.into(),
            issuer: VarChar255::from_str(input_str),
            account_name: VarChar255::empty(),
            label: VarChar255::from_str(message),
        }
    }

    fn from_string(input_str: &str) -> Self {
        let s = input_str.trim();
        let s = if s.len() >= 2 && ((s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('`') && s.ends_with('`'))) {
            // unwrap quoted otp input
            s[1..s.len() - 1].trim()
        } else {
            s
        };

        if s.len() > 255 {
            return OtpCredential::invalid("input exceeds 255 characters", &s[0..255]);
        }

        // Branch 1: bare base32 — only [A-Za-z2-7=]
        if s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7' | b'=')) {
            return parse_secret_only(s);
        }

        // Branch 2: totp/SECRET or hotp/SECRET shorthand (no :// present)
        if !s.contains("://") && !s.starts_with("//") {
            if let Some(otp_type) = shorthand_type_prefix(s) {
                let rest = &s[s.find('/').unwrap() + 1..];
                return parse_shorthand(rest, otp_type, s);
            }
        }

        // Build a normalized URI with lowercase scheme into a stack buffer.
        // Accepted forms: `//...` and `otpauth://...` (case-insensitive scheme).
        let mut uri_buf = [0u8; 256];
        let uri_len;

        if let Some(rest) = s.strip_prefix("//") {
            // Prepend "otpauth:"
            let prefix = b"otpauth:";
            let total = prefix.len() + 2 + rest.len(); // "otpauth:" + "//" + rest
            if total > 256 { return OtpCredential::invalid("uri too long", s); }
            uri_buf[..prefix.len()].copy_from_slice(prefix);
            uri_buf[prefix.len()..prefix.len() + 2].copy_from_slice(b"//");
            uri_buf[prefix.len() + 2..total].copy_from_slice(rest.as_bytes());
            uri_len = total;
        } else {
            // Must start with otpauth:// case-insensitively
            if s.len() < 10 { return OtpCredential::invalid("invalid protocol string", s); }
            let scheme_end = match s.find("://") {
                Some(i) => i,
                None => return OtpCredential::invalid("invalid protocol string", s),
            };
            let scheme = &s[..scheme_end];
            // Compare scheme case-insensitively
            if scheme.len() != 7 { return OtpCredential::invalid("invalid protocol string", s); }
            let mut scheme_lower = [0u8; 7];
            for (i, b) in scheme.bytes().enumerate() {
                scheme_lower[i] = b.to_ascii_lowercase();
            }
            if &scheme_lower != b"otpauth" {
                return OtpCredential::invalid("invalid protocol string", s);
            }
            let rest = &s[scheme_end..]; // includes "://..."
            let total = 7 + rest.len();
            if total > 256 { return OtpCredential::invalid("uri too long", s); }
            uri_buf[..7].copy_from_slice(b"otpauth");
            uri_buf[7..total].copy_from_slice(rest.as_bytes());
            uri_len = total;
        }

        let uri_str = match core::str::from_utf8(&uri_buf[..uri_len]) {
            Ok(s) => s,
            Err(_) => return OtpCredential::invalid("invalid utf8 in uri", s),
        };

        parse_full_uri(uri_str, s)
    }

    fn to_uri(&self) -> VarString511 {
        let otp_type_str: &str = match self.otp_type.into() {
            OtpTypeEnum::TOTP => "totp",
            OtpTypeEnum::HOTP => "hotp",
            OtpTypeEnum::UNKNOWN => return VarString511::from_str(self.label.to_str()),
        };

        let algo_str: &str = match self.algorithm.into() {
            OtpAlgorithmEnum::SHA1     => "SHA1",
            OtpAlgorithmEnum::SHA256   => "SHA256",
            OtpAlgorithmEnum::SHA512   => "SHA512",
            OtpAlgorithmEnum::SHA3_256 => "SHA3-256",
            OtpAlgorithmEnum::KECCAK256=> "KECCAK256",
            OtpAlgorithmEnum::UNKNOWN  => return VarString511::from_str(self.label.to_str()),
        };

        // Encode the secret to base32
        let secret_bytes = self.secret.to_byte_arr();
        let mut secret_b32 = [0u8; 408]; // ceil(255 * 8 / 5) = 408
        let secret_b32_len = BASE32_NOPAD.encode_len(secret_bytes.len());
        BASE32_NOPAD.encode_mut(secret_bytes, &mut secret_b32[..secret_b32_len]);
        let secret_str = match core::str::from_utf8(&secret_b32[..secret_b32_len]) {
            Ok(s) => s,
            Err(_) => return VarString511::from_str(self.label.to_str()),
        };

        let label = self.label.to_str();
        let issuer = self.issuer.to_str();
        let digits = self.digits;
        let period = self.period;
        let counter = self.counter;
        let t0 = self.t0;

        // Build into a 512-byte stack buffer. Try full URI first, then drop
        // issuer param, then minimal form.
        let mut buf = [0u8; 512];

        // Helper: write URI into buf, returns Some(len) or None on overflow.
        // Full form: otpauth://TYPE/ISSUER:LABEL?secret=S&issuer=I&digits=D&period=P&t0=T0
        //        or: otpauth://TYPE/ISSUER:LABEL?secret=S&issuer=I&digits=D&counter=C

        for pass in 0u8..3 {
            let mut pos = 0usize;

            macro_rules! write_str {
                ($s:expr) => {{
                    let b = $s.as_bytes();
                    if pos + b.len() > 511 { pos = 512; break; }
                    buf[pos..pos + b.len()].copy_from_slice(b);
                    pos += b.len();
                }};
            }
            macro_rules! write_u64 {
                ($v:expr) => {{
                    let mut tmp = [0u8; 20];
                    let n = fmt_u64($v, &mut tmp);
                    if pos + n > 511 { pos = 512; break; }
                    buf[pos..pos + n].copy_from_slice(&tmp[..n]);
                    pos += n;
                }};
            }

            write_str!("otpauth://");
            write_str!(otp_type_str);
            write_str!("/");

            // pass 0 and 1: include label prefix if issuer non-empty
            if !issuer.is_empty() && pass < 2 {
                write_str!(issuer);
                write_str!(":");
            }
            if !label.is_empty() {
                write_str!(label);
            }

            write_str!("?secret=");
            write_str!(secret_str);
            write_str!("&algorithm=");
            write_str!(algo_str);
            write_str!("&digits=");
            write_u64!(digits as u64);

            match self.otp_type.into() {
                OtpTypeEnum::TOTP => {
                    write_str!("&period=");
                    write_u64!(period as u64);
                    if t0 != 0 {
                        write_str!("&t0=");
                        write_u64!(t0);
                    }
                }
                OtpTypeEnum::HOTP => {
                    write_str!("&counter=");
                    write_u64!(counter as u64);
                }
                _ => {}
            }

            // pass 0: also append &issuer=
            if pass == 0 && !issuer.is_empty() {
                write_str!("&issuer=");
                write_str!(issuer);
            }

            if pos <= 511 {
                return VarString511::from_str(
                    core::str::from_utf8(&buf[..pos]).unwrap_or("")
                );
            }
            // overflow: try next pass
        }

        VarString511::empty()
    }

    fn generate(&self, current: u64) -> OtpResult {
        let otp_type: OtpTypeEnum = self.otp_type.into();
        let algo: OtpAlgorithmEnum = self.algorithm.into();

        if matches!(otp_type, OtpTypeEnum::UNKNOWN) { return [-1i8; OTP_RESULT_SZ]; }
        if matches!(algo, OtpAlgorithmEnum::UNKNOWN) { return [-1i8; OTP_RESULT_SZ]; }

        let secret = self.secret.to_byte_arr();
        if secret.is_empty() { return [-1i8; OTP_RESULT_SZ]; }

        // Derive counter value
        let hotp_counter: u64 = match otp_type {
            OtpTypeEnum::TOTP => {
                let period = if self.period <= 0 { 30u64 } else { self.period as u64 };
                (current.saturating_sub(self.t0)) / period
            }
            OtpTypeEnum::HOTP => current,
            _ => return [-1i8; OTP_RESULT_SZ],
        };

        let counter_bytes = hotp_counter.to_be_bytes();

        let digest: [u8; 64] = match algo {
            OtpAlgorithmEnum::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
                mac.update(&counter_bytes);
                let mut out = [0u8; 64];
                out[..20].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            OtpAlgorithmEnum::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
                mac.update(&counter_bytes);
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            OtpAlgorithmEnum::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(secret).unwrap();
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().into()
            }
            OtpAlgorithmEnum::SHA3_256 => {
                let mut mac = Hmac::<Sha3_256>::new_from_slice(secret).unwrap();
                mac.update(&counter_bytes);
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            OtpAlgorithmEnum::KECCAK256 => {
                let mut mac = Hmac::<Keccak256>::new_from_slice(secret).unwrap();
                mac.update(&counter_bytes);
                let mut out = [0u8; 64];
                out[..32].copy_from_slice(&mac.finalize().into_bytes());
                out
            }
            OtpAlgorithmEnum::UNKNOWN => return [-1i8; OTP_RESULT_SZ],
        };

        // RFC 4226 dynamic truncation
        let digest_len: usize = match algo {
            OtpAlgorithmEnum::SHA1     => 20,
            OtpAlgorithmEnum::SHA256   => 32,
            OtpAlgorithmEnum::SHA512   => 64,
            OtpAlgorithmEnum::SHA3_256 => 32,
            OtpAlgorithmEnum::KECCAK256=> 32,
            OtpAlgorithmEnum::UNKNOWN  => return [-1i8; OTP_RESULT_SZ],
        };

        let offset = (digest[digest_len - 1] & 0x0f) as usize;
        let p = ((digest[offset]     as u32 & 0x7f) << 24)
              | ((digest[offset + 1] as u32)         << 16)
              | ((digest[offset + 2] as u32)         <<  8)
              |  (digest[offset + 3] as u32);

        // digits: saturate 33-255 to 32, clamp to 1 minimum
        let digits = match self.digits {
            0        => 6u8,  // default
            1..=32   => self.digits,
            _        => 32u8,
        };

        // Extract individual decimal digits, left-packed, -1 padded
        // We need `digits` decimal digits from p. For digits <= 9 we use
        // modulo; for digits 10-32 we use the full 32-bit value split into
        // individual digits.
        let mut result = [-1i8; OTP_RESULT_SZ];
        let d = digits as usize;

        if d <= 9 {
            // Standard path: p % 10^d
            let mut modulus = 1u32;
            for _ in 0..d { modulus = modulus.saturating_mul(10); }
            let code = p % modulus;
            // left-pack digits
            let mut tmp = [0u8; 9];
            let mut v = code;
            for i in (0..d).rev() {
                tmp[i] = (v % 10) as u8;
                v /= 10;
            }
            for i in 0..d.min(OTP_RESULT_SZ) {
                result[i] = tmp[i] as i8;
            }
        } else {
            // Extended path for d 10-32: treat p as a 32-bit value,
            // zero-extend to `d` decimal digits
            let mut tmp = [0u8; 32];
            let mut v = p;
            for i in (0..d).rev() {
                tmp[i] = (v % 10) as u8;
                v /= 10;
            }
            for i in 0..d.min(OTP_RESULT_SZ) {
                result[i] = tmp[i] as i8;
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn decode_base32(secret_str: &str, out: &mut [u8; 255]) -> Option<usize> {
    let mut upper = [0u8; 255];
    let stripped = {
        let b = secret_str.trim_end_matches('=').as_bytes();
        if b.len() > 255 { return None; }
        for (i, &byte) in b.iter().enumerate() {
            upper[i] = byte.to_ascii_uppercase();
        }
        &upper[..b.len()]
    };
    let decoded_len = BASE32_NOPAD.decode_len(stripped.len()).ok()?;
    if decoded_len > 255 { return None; }
    let n = BASE32_NOPAD.decode_mut(stripped, &mut out[..decoded_len]).ok()?;
    Some(n)
}

fn shorthand_type_prefix(s: &str) -> Option<OtpTypeEnum> {
    let b = s.as_bytes();
    if b.len() < 5 { return None; }
    let mut lower5 = [0u8; 5];
    for i in 0..5 { lower5[i] = b[i].to_ascii_lowercase(); }
    if &lower5 == b"totp/" { return Some(OtpTypeEnum::TOTP); }
    if &lower5 == b"hotp/" { return Some(OtpTypeEnum::HOTP); }
    None
}

fn parse_secret_only(s: &str) -> OtpCredential {
    let mut buf = [0u8; 255];
    let n = match decode_base32(s, &mut buf) {
        Some(n) => n,
        None => return OtpCredential::invalid("invalid base32 secret", s),
    };
    if n < 10 { return OtpCredential::invalid("secret too short (min 10 bytes)", s); }
    let mut cred = OtpCredential::empty();
    cred.otp_type = OtpTypeEnum::TOTP.into();
    cred.secret = VarByte255::from_byte_arr(&buf[..n]);
    cred.period = 30;
    cred.counter = -1;
    cred.digits = 6;
    cred.algorithm = OtpAlgorithmEnum::SHA1.into();
    cred
}

fn parse_shorthand(rest: &str, otp_type: OtpTypeEnum, raw: &str) -> OtpCredential {
    let (secret_str, query) = match rest.find('?') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None    => (rest.trim(), None),
    };
    let secret_str = secret_str.trim();
    let mut buf = [0u8; 255];
    let n = match decode_base32(secret_str, &mut buf) {
        Some(n) => n,
        None => return OtpCredential::invalid("invalid base32 secret", raw),
    };
    if n < 10 { return OtpCredential::invalid("secret too short (min 10 bytes)", raw); }

    let mut cred = OtpCredential::empty();
    cred.otp_type = otp_type.into();
    cred.secret = VarByte255::from_byte_arr(&buf[..n]);
    match otp_type {
        OtpTypeEnum::TOTP => { cred.period = 30; cred.counter = -1; }
        OtpTypeEnum::HOTP => { cred.counter = 0;  cred.period = -1; }
        _ => {}
    }
    cred.digits = 6;
    cred.algorithm = OtpAlgorithmEnum::SHA1.into();

    if let Some(q) = query {
        if let Err(e) = apply_query_params(&mut cred, q, otp_type, raw) {
            return e;
        }
    }
    cred
}

fn parse_full_uri(uri_str: &str, raw: &str) -> OtpCredential {
    let url = match Url::parse(uri_str) {
        Ok(u)  => u,
        Err(_) => return OtpCredential::invalid("failed to parse URI", raw),
    };

    if url.scheme() != "otpauth" {
        return OtpCredential::invalid("invalid protocol string", raw);
    }

    let otp_type = match url.host_str() {
        Some("totp") => OtpTypeEnum::TOTP,
        Some("hotp") => OtpTypeEnum::HOTP,
        _            => return OtpCredential::invalid("unknown otp type", raw),
    };

    // Raw path from the url crate still has percent-encoding intact
    let raw_path = url.path();
    let raw_label = match raw_path.strip_prefix('/') {
        Some(l) => l,
        None    => return OtpCredential::invalid("missing label", raw),
    };

    if raw_label.contains('/') {
        return OtpCredential::invalid("too many path segments", raw);
    }

    // Decode label for length check and storage
    let mut label_buf = [0u8; 255];
    let label_len = percent_decode(raw_label.as_bytes(), &mut label_buf);
    if label_len > 255 {
        return OtpCredential::invalid("label exceeds 255 characters", raw);
    }
    let decoded_label = core::str::from_utf8(&label_buf[..label_len]).unwrap_or("");

    // Split issuer:account_name on first unencoded ':'
    let mut issuer_buf   = [0u8; 255];
    let mut account_buf  = [0u8; 255];
    let (issuer_len, account_len) = split_label(
        raw_label.as_bytes(), &mut issuer_buf, &mut account_buf
    );
    let label_issuer  = core::str::from_utf8(&issuer_buf[..issuer_len]).unwrap_or("");
    let account_name  = core::str::from_utf8(&account_buf[..account_len]).unwrap_or("");

    // Parse query parameters
    let query_str = url.query().unwrap_or("");
    let mut secret_buf  = [0u8; 255];
    let mut secret_len  = 0usize;
    let mut has_secret  = false;
    let mut param_issuer_buf = [0u8; 255];
    let mut param_issuer_len = 0usize;
    let mut has_param_issuer = false;
    let mut period:  Option<i64> = None;
    let mut t0:      Option<u64> = None;
    let mut counter: Option<i64> = None;
    let mut digits:  Option<u8>  = None;
    let mut algorithm = OtpAlgorithmEnum::SHA1;

    for pair in query_str.split('&') {
        if pair.is_empty() { continue; }
        let (key, val) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None    => continue,
        };
        match key {
            "secret" => {
                let n = match decode_base32(val, &mut secret_buf) {
                    Some(n) => n,
                    None    => return OtpCredential::invalid("invalid base32 secret", raw),
                };
                if n < 10 { return OtpCredential::invalid("secret too short (min 10 bytes)", raw); }
                secret_len = n;
                has_secret = true;
            }
            "issuer" => {
                let n = percent_decode(val.as_bytes(), &mut param_issuer_buf);
                param_issuer_len = n.min(255);
                has_param_issuer = true;
            }
            "period" => {
                match parse_i64(val) {
                    Some(v) => period = Some(v),
                    None    => return OtpCredential::invalid("cannot parse period", raw),
                }
            }
            "t0" => {
                match parse_u64(val) {
                    Some(v) => t0 = Some(v),
                    None    => return OtpCredential::invalid("cannot parse t0", raw),
                }
            }
            "counter" => {
                match parse_i64(val) {
                    Some(v) => counter = Some(v),
                    None    => return OtpCredential::invalid("cannot parse counter", raw),
                }
            }
            "digits" => {
                match parse_u8(val) {
                    Some(v) => digits = Some(v),
                    None    => return OtpCredential::invalid("cannot parse digits", raw),
                }
            }
            "algorithm" => {
                let mut tmp = [0u8; 10];
                let vb = val.as_bytes();
                let n = vb.len().min(10);
                for i in 0..n { tmp[i] = vb[i].to_ascii_uppercase(); }
                algorithm = match &tmp[..n] {
                    b"SHA1"      => OtpAlgorithmEnum::SHA1,
                    b"SHA256"    => OtpAlgorithmEnum::SHA256,
                    b"SHA512"    => OtpAlgorithmEnum::SHA512,
                    b"SHA3-256"  => OtpAlgorithmEnum::SHA3_256,
                    b"KECCAK256" => OtpAlgorithmEnum::KECCAK256,
                    _            => return OtpCredential::invalid("unknown algorithm", raw),
                };
            }
            _ => {}
        }
    }

    // Parameter mismatch
    match otp_type {
        OtpTypeEnum::TOTP => {
            if counter.is_some() {
                return OtpCredential::invalid("counter parameter invalid for totp", raw);
            }
        }
        OtpTypeEnum::HOTP => {
            if period.is_some() {
                return OtpCredential::invalid("period parameter invalid for hotp", raw);
            }
            if t0.is_some() {
                return OtpCredential::invalid("t0 parameter invalid for hotp", raw);
            }
        }
        _ => {}
    }

    let mut cred = OtpCredential::empty();
    cred.otp_type = otp_type.into();
    cred.label = VarChar255::from_str(decoded_label);

    let resolved_issuer = if has_param_issuer {
        core::str::from_utf8(&param_issuer_buf[..param_issuer_len]).unwrap_or("")
    } else {
        label_issuer
    };
    cred.issuer       = VarChar255::from_str(resolved_issuer);
    cred.account_name = VarChar255::from_str(account_name);

    if has_secret {
        cred.secret = VarByte255::from_byte_arr(&secret_buf[..secret_len]);
    }

    match otp_type {
        OtpTypeEnum::TOTP => {
            cred.period = period.unwrap_or(30);
            cred.t0     = t0.unwrap_or(0);
            cred.counter = -1;
        }
        OtpTypeEnum::HOTP => {
            cred.counter = counter.unwrap_or(0);
            cred.period  = -1;
        }
        _ => {}
    }
    cred.digits    = digits.unwrap_or(6);
    cred.algorithm = algorithm.into();
    cred
}

/// Decode percent-encoded bytes into `out`, returning number of bytes written.
/// Silently truncates at out.len().
fn percent_decode(src: &[u8], out: &mut [u8]) -> usize {
    let mut i = 0;
    let mut j = 0;
    while i < src.len() && j < out.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(h), Some(l)) = (hex_val(src[i+1]), hex_val(src[i+2])) {
                out[j] = (h << 4) | l;
                j += 1; i += 3;
                continue;
            }
        }
        out[j] = if src[i] == b'+' { b' ' } else { src[i] };
        j += 1; i += 1;
    }
    j
}

/// Split raw percent-encoded label on first unencoded ':', writing decoded
/// issuer and account_name into the provided buffers.
fn split_label(
    raw: &[u8],
    issuer_out: &mut [u8],
    account_out: &mut [u8],
) -> (usize, usize) {
    // Find first unencoded ':'
    let mut i = 0;
    let mut colon = None;
    while i < raw.len() {
        if raw[i] == b'%' && i + 2 < raw.len() { i += 3; continue; }
        if raw[i] == b':' { colon = Some(i); break; }
        i += 1;
    }
    match colon {
        Some(pos) => {
            let issuer_len  = percent_decode(&raw[..pos], issuer_out);
            // strip leading space or %20 from account name
            let account_raw = &raw[pos + 1..];
            let account_raw = if account_raw.starts_with(b"%20") {
                &account_raw[3..]
            } else if account_raw.first() == Some(&b' ') {
                &account_raw[1..]
            } else {
                account_raw
            };
            let account_len = percent_decode(account_raw, account_out);
            (issuer_len, account_len)
        }
        None => {
            let account_len = percent_decode(raw, account_out);
            (0, account_len)
        }
    }
}

fn apply_query_params(
    cred: &mut OtpCredential,
    query: &str,
    otp_type: OtpTypeEnum,
    raw: &str,
) -> Result<(), OtpCredential> {
    for pair in query.split('&') {
        if pair.is_empty() { continue; }
        let (key, val) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None    => continue,
        };
        match key {
            "period" => {
                if otp_type == OtpTypeEnum::HOTP {
                    return Err(OtpCredential::invalid("period parameter invalid for hotp", raw));
                }
                match parse_i64(val) {
                    Some(v) => cred.period = v,
                    None    => return Err(OtpCredential::invalid("cannot parse period", raw)),
                }
            }
            "t0" => {
                if otp_type == OtpTypeEnum::HOTP {
                    return Err(OtpCredential::invalid("t0 parameter invalid for hotp", raw));
                }
                match parse_u64(val) {
                    Some(v) => cred.t0 = v,
                    None    => return Err(OtpCredential::invalid("cannot parse t0", raw)),
                }
            }
            "counter" => {
                if otp_type == OtpTypeEnum::TOTP {
                    return Err(OtpCredential::invalid("counter parameter invalid for totp", raw));
                }
                match parse_i64(val) {
                    Some(v) => cred.counter = v,
                    None    => return Err(OtpCredential::invalid("cannot parse counter", raw)),
                }
            }
            "digits" => {
                match parse_u8(val) {
                    Some(v) => cred.digits = v,
                    None    => return Err(OtpCredential::invalid("cannot parse digits", raw)),
                }
            }
            "algorithm" => {
                let mut tmp = [0u8; 10];
                let vb = val.as_bytes();
                let n = vb.len().min(10);
                for i in 0..n { tmp[i] = vb[i].to_ascii_uppercase(); }
                cred.algorithm = match &tmp[..n] {
                    b"SHA1"      => OtpAlgorithmEnum::SHA1.into(),
                    b"SHA256"    => OtpAlgorithmEnum::SHA256.into(),
                    b"SHA512"    => OtpAlgorithmEnum::SHA512.into(),
                    b"SHA3-256"  => OtpAlgorithmEnum::SHA3_256.into(),
                    b"KECCAK256" => OtpAlgorithmEnum::KECCAK256.into(),
                    _ => return Err(OtpCredential::invalid("unknown algorithm", raw)),
                };
            }
            _ => {}
        }
    }
    Ok(())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _           => None,
    }
}

/// no_std integer parsers
fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut v = 0u64;
    for b in s.bytes() {
        if !b.is_ascii_digit() { return None; }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

fn parse_i64(s: &str) -> Option<i64> {
    if s.is_empty() { return None; }
    let (neg, digits) = if s.as_bytes()[0] == b'-' { (true, &s[1..]) } else { (false, s) };
    let v = parse_u64(digits)?;
    if neg {
        if v > i64::MAX as u64 + 1 { return None; }
        Some(-(v as i64))
    } else {
        if v > i64::MAX as u64 { return None; }
        Some(v as i64)
    }
}

fn parse_u8(s: &str) -> Option<u8> {
    let v = parse_u64(s)?;
    if v > 255 { None } else { Some(v as u8) }
}

/// Format a u64 into a stack buffer, returns number of bytes written.
fn fmt_u64(mut v: u64, buf: &mut [u8; 20]) -> usize {
    if v == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    while v > 0 { tmp[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    for i in 0..n { buf[i] = tmp[n - 1 - i]; }
    n
}