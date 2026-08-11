// tests/galois.rs
// Field axioms for GF(256) (AES polynomial) and GF(1024) (SLIP-39 polynomial).
// These underpin every share scheme in the crate, so they are checked
// exhaustively rather than sampled.

use aloecrypt_core::galois::*;

#[test]
fn gf256_every_nonzero_element_has_an_inverse() {
    let mut broken = Vec::new();
    for n in 1u16..256 {
        let n = n as u8;
        let inv = gf256_inv(n);
        if gf256_mul(n, inv) != 1 {
            broken.push((n, inv));
        }
    }
    assert!(
        broken.is_empty(),
        "gf256_inv wrong for {} element(s); first few: {:?}",
        broken.len(),
        &broken[..broken.len().min(8)]
    );
}

#[test]
fn gf256_inverse_is_an_involution() {
    for n in 1u16..256 {
        let n = n as u8;
        assert_eq!(gf256_inv(gf256_inv(n)), n, "inv(inv({n})) != {n}");
    }
}

#[test]
fn gf256_multiplication_has_identity_and_is_commutative() {
    for a in 0u16..256 {
        let a = a as u8;
        assert_eq!(
            gf256_mul(a, 1),
            a,
            "1 is not the multiplicative identity for {a}"
        );
        assert_eq!(gf256_mul(a, 0), 0, "0 does not annihilate {a}");
        for b in 0u16..256 {
            let b = b as u8;
            assert_eq!(
                gf256_mul(a, b),
                gf256_mul(b, a),
                "mul not commutative at ({a},{b})"
            );
        }
    }
}

#[test]
fn gf256_is_distributive() {
    for a in (0u16..256).step_by(7) {
        for b in (0u16..256).step_by(11) {
            for c in (0u16..256).step_by(13) {
                let (a, b, c) = (a as u8, b as u8, c as u8);
                assert_eq!(
                    gf256_mul(a, gf256_add(b, c)),
                    gf256_add(gf256_mul(a, b), gf256_mul(a, c)),
                    "distributivity failed at ({a},{b},{c})"
                );
            }
        }
    }
}

#[test]
fn gf1024_every_nonzero_element_has_an_inverse() {
    let mut broken = Vec::new();
    for n in 1u16..1024 {
        let inv = gf1024_inv(n);
        if gf1024_mul(n, inv) != 1 {
            broken.push((n, inv));
        }
    }
    assert!(
        broken.is_empty(),
        "gf1024_inv wrong for {} element(s); first few: {:?}",
        broken.len(),
        &broken[..broken.len().min(8)]
    );
}

#[test]
fn gf1024_inverse_is_an_involution() {
    for n in 1u16..1024 {
        assert_eq!(gf1024_inv(gf1024_inv(n)), n, "inv(inv({n})) != {n}");
    }
}

#[test]
fn gf1024_multiplication_has_identity() {
    for a in 0u16..1024 {
        assert_eq!(
            gf1024_mul(a, 1),
            a,
            "1 is not the multiplicative identity for {a}"
        );
        assert_eq!(gf1024_mul(a, 0), 0, "0 does not annihilate {a}");
    }
}
