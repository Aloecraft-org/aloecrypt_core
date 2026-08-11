// src/bin/stackcheck.rs
// License: Apache-2.0 (disclaimer at bottom of file)
//
// Regression guard for stack consumption of the PQC operations.
//
// Commit 39ad574 decomposed the ML-DSA paths with #[inline(never)] to keep the
// stack high-water mark predictable and bounded. Nothing guarded that work, so
// a refactor could silently reintroduce a deep path and only fail on a device
// with no room to absorb it.
//
// Each operation runs on a thread with an explicit stack size. If it needs more
// than the ceiling, the guard page trips and the child aborts; the parent
// reports which operation regressed. Ceilings are measured values plus roughly
// 20% headroom -- see the table below.
//
//   cargo run --release --bin stackcheck
//
// CAVEAT: these are host-architecture numbers (measured on x86-64). A 32-bit
// ARM target generally uses less, because pointers and spilled registers are
// half the width. This is a REGRESSION guard, not a device budget -- it answers
// "did this change make the stack worse", not "will this fit in 520 KB".
//
// Measured on x86-64, release profile (opt-level="z", lto, panic="abort"),
// against ml-dsa 0.1.1 / ml-kem 0.3.2:
//
//     ml-kem-768  keygen + encapsulate + decapsulate      ~45 KB
//     ml-dsa-44   keygen + sign + verify                 ~175 KB
//     ml-dsa-65   keygen + sign + verify                 ~274 KB
//     ml-dsa-87   keygen + sign + verify                 ~425 KB
//
// The upgrade from ml-dsa 0.1.0-rc.8 moved these by 3% at most (283 -> 274 KB
// for ml-dsa-65). Upstream now holds the expanded signing key behind MaybeBox,
// which heap-allocates only when the `alloc` feature is on; without an
// allocator it falls back to stack allocation, so there was nothing to gain.
// Relocating these bytes would not help regardless -- 520 KB of SRAM is 520 KB
// wherever the bytes live, and an allocator would add nondeterminism. Reducing
// peak *live* bytes is the only thing that moves this number.
//
// Re-measure with: cargo run --release --bin stackcheck -- <op> <bytes>
// which runs a single operation at an exact stack size and exits non-zero if it
// does not fit. Binary-search that to find a new floor before moving a ceiling.

#![allow(warnings)]

use aloecrypt_core::dsa::*;
use aloecrypt_core::dsa_api::*;
use aloecrypt_core::kem::*;
use aloecrypt_core::kem_api::*;

const KB: usize = 1024;

/// (operation, ceiling in bytes, measured floor in bytes)
const BUDGET: &[(&str, usize, usize)] = &[
    ("kem768", 64 * KB, 45 * KB),
    ("dsa44", 224 * KB, 175 * KB),
    ("dsa65", 352 * KB, 274 * KB),
    ("dsa87", 528 * KB, 425 * KB),
];

fn run_op(op: &str) {
    let seed = [7u8; MLDSA_SEED_SZ];
    let msg = b"aloecrypt stackcheck";
    match op {
        "dsa44" => {
            let kp = MlDsa44Keypair::from_seed(&seed);
            let sig = kp.sign(msg);
            assert!(kp.get_verifier().verify(msg, &sig), "dsa44 verify failed");
        }
        "dsa65" => {
            let kp = MlDsa65Keypair::from_seed(&seed);
            let sig = kp.sign(msg);
            assert!(kp.get_verifier().verify(msg, &sig), "dsa65 verify failed");
        }
        "dsa87" => {
            let kp = MlDsa87Keypair::from_seed(&seed);
            let sig = kp.sign(msg);
            assert!(kp.get_verifier().verify(msg, &sig), "dsa87 verify failed");
        }
        "kem768" => {
            let kem_seed = [9u8; 64];
            let prk = [9u8; MLKEM_PRK_SEED_SZ];
            let kp = MlKem768Keypair::from_seed(&kem_seed);
            let result = kp.get_encapsulator().encapsulate(prk);
            let shared = kp.decapsulate(&result.cipher);
            assert_eq!(shared, result.secret, "kem768 secrets disagree");
        }
        other => {
            eprintln!("unknown operation: {}", other);
            std::process::exit(2);
        }
    }
}

/// Child mode: run one operation on a thread with an exact stack size.
fn child(op: &str, stack: usize) -> ! {
    let op = op.to_string();
    let handle = std::thread::Builder::new()
        .stack_size(stack)
        .spawn(move || run_op(&op))
        .expect("failed to spawn probe thread");
    match handle.join() {
        Ok(()) => std::process::exit(0),
        Err(_) => std::process::exit(1),
    }
}

/// Parent mode: re-execute self once per operation so that a stack overflow --
/// which aborts the process and cannot be caught in-process -- is observable.
fn parent() -> ! {
    let exe = std::env::current_exe().expect("current_exe");
    let mut failures = 0;

    println!(
        "{:<10} {:>10} {:>10} {:>10}   {}",
        "op", "ceiling", "measured", "headroom", "result"
    );

    for (op, ceiling, measured) in BUDGET {
        let status = std::process::Command::new(&exe)
            .arg(op)
            .arg(ceiling.to_string())
            .status()
            .expect("failed to spawn child");

        let ok = status.success();
        if !ok {
            failures += 1;
        }
        println!(
            "{:<10} {:>9}K {:>9}K {:>9}K   {}",
            op,
            ceiling / KB,
            measured / KB,
            (ceiling - measured) / KB,
            if ok { "ok" } else { "OVERFLOWED" }
        );
    }

    if failures > 0 {
        eprintln!(
            "\n{} operation(s) exceeded their stack ceiling.\n\
             Either the change under test regressed stack usage, or the ceiling is\n\
             genuinely too tight -- re-measure before raising it:\n\
             \n    cargo run --release --bin stackcheck -- dsa65 <bytes>\n",
            failures
        );
        std::process::exit(1);
    }
    println!("\nall operations within budget");
    std::process::exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        1 => parent(),
        3 => {
            let stack: usize = args[2]
                .parse()
                .expect("stack size must be a number of bytes");
            child(&args[1], stack)
        }
        _ => {
            eprintln!("usage: stackcheck [<op> <stack-bytes>]");
            std::process::exit(2);
        }
    }
}

// Copyright Michael Godfrey 2026 | aloecraft.org <michael@aloecraft.org>
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
