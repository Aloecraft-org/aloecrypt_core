// guard/noalloc/src/lib.rs
// License: Apache-2.0
//
// Entry point: none to call. This cdylib exists to be linked. It declares no
// #[global_allocator], so if anything in aloecrypt_core's minimal profile (or
// a dependency feature it enables) pulls in `alloc`, the link fails with "no
// global memory allocator found". DESIGN section 6: minimal is no_std with no
// allocator. Each export below keeps one part of the API alive through LTO.
//
// Build: cargo build -p aloecrypt_noalloc_guard --release --target wasm32-unknown-unknown

#![no_std]

use aloecrypt_core::dsa_api::*;
use aloecrypt_core::kem_api::*;
use aloecrypt_core::otp_api::*;
use aloecrypt_core::recovery_api::*;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn guard_dsa(seed: &MlDsaPrivateSeed, msg: *const u8, len: usize) -> bool {
    let msg = unsafe { core::slice::from_raw_parts(msg, len) };
    let kp = MlDsa65Keypair::from_seed(seed);
    kp.get_verifier().verify(msg, &kp.sign(msg))
}

#[unsafe(no_mangle)]
pub extern "C" fn guard_kem(seed: &MlKemPrivateSeed, prk: &MlKemPrkSeed) -> bool {
    let kp = MlKem768Keypair::from_seed(seed);
    match kp.get_encapsulator().encapsulate(*prk) {
        Ok(r) => kp.decapsulate(&r.cipher) == r.secret,
        Err(_) => false,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn guard_otp(uri: *const u8, len: usize, now: u64) -> i8 {
    let uri = unsafe { core::slice::from_raw_parts(uri, len) };
    let cred = OtpCredential::from_string(core::str::from_utf8(uri).unwrap_or(""));
    cred.generate(now)[0]
}

#[unsafe(no_mangle)]
pub extern "C" fn guard_recover(auth: &MlKemSecret, secret: &RecoverySecret) -> u8 {
    RecoverableSecret::recover(*auth, secret)[0]
}
