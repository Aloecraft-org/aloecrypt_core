# Working on aloecrypt_core

Read `doc/DESIGN.md` before changing anything cryptographic — it records settled
decisions and the reasoning, and is the file to update when a decision changes.

`aloecrypt_core` is becoming `aloecrypt`: a small post-quantum cryptography
library whose document layer grows into certificates, CSRs, and a tool usable in
place of GPG. Sessions, authenticators, aloelite and the RP2350 firmware are
**consumers**; they take a dependency on this crate and do not shape it.

## Build and check

```sh
cargo build --lib                      # build.rs merges the schema itself; no prep step
cargo test                             # 85 tests
cargo run --release --bin align        # integration smoke test
cargo run --release --bin stackcheck   # stack budget guard
make generate                          # Python bindings (needs pydantic)
```

`build.rs` reads `config/api_core.json` and `doc/api_core_docs.json`, merges
them, and writes both `OUT_DIR/api_core.rs` and `.generated/api_core_merged.json`
(which the Python and TypeScript generators read). There is no `jq` dependency
and no preparatory `make` step. `doc/merge_docs.jq` is superseded and unused.

Before pushing, this is what CI runs:

```sh
export RUSTFLAGS="-D warnings"
cargo fmt --check
cargo test && cargo test --no-default-features
cargo build --all-targets && cargo build --all-targets --no-default-features
for t in wasm32-wasip2 wasm32-unknown-unknown thumbv8m.main-none-eabihf thumbv7em-none-eabihf; do
  cargo build --lib --target $t --no-default-features
  cargo build --lib --target $t --no-default-features --features slip39_words,bip39_words
done
```

The tree is warning-clean in every configuration. `-D warnings` is on in CI, so
a new warning fails the build.

## Invariants worth knowing before you edit

**Post-quantum only on the spine.** No classical asymmetric algorithm belongs in
this crate — not ECDSA, RSA, X25519 or Ed25519, including verify-only paths. A
consumer needing to verify a foreign classical chain does it in a separate
crate. Legacy hash interop is allowed at the *edge*, chosen per use: `TotpAlgorithm`
carrying SHA-1 for compatibility is the reference example.

**Every feature must be switchable.** `--no-default-features` has to build, for
every target. The wordlists are opt-in and the recovery arithmetic works without
them. `host_rng` gates `getrandom`, which has no bare-metal backend — the
library itself never needs entropy, since `AloeRng` is seeded by the caller.

**The schema is the source of truth**, and it is matched by name with no
validation. A transposed `impls` pair silently drops every export for a
namespace and the Rust build stays green. CI asserts each namespace emits at
least one export, and that every generated struct packs to its declared `SIZE`.
Both checks exist because that class of bug has bitten three times.

**Generated structs are `#[repr(C, packed)]`.** Two consequences that will
surprise you: a field cannot be referenced (`assert_eq!(x.field, 1)` is a
compile error, E0793 — copy to a local first), and no buffer inside one can be
assumed aligned. That is why `VarU16_255` decodes into a caller buffer rather
than handing out a `&[u16]`.

**The wire format has no error channel.** Exports return raw bytes with no
discriminant, so a wire-exported function cannot return a `Result` yet. `src/error.rs`
is a plain Rust type used only on functions the schema does *not* export. Do not
add a `Result` to an exported function until the error-code work lands.

**Stack is the binding constraint, not heap.** The downstream target has 520 KB
of SRAM total and ML-DSA-65 wants ~274 KB of stack. Moving allocations to a heap
does not help — it is the same bytes at a different address, plus
nondeterminism. Only reducing peak *live* bytes moves the number.
`cargo run --release --bin stackcheck` guards against regressions.

## Layout

| Path | What |
|---|---|
| `config/api_core.json` | Schema: the source of truth for types, traits, exports |
| `doc/api_core_docs.json` | Descriptions merged onto the schema at build time |
| `doc/DESIGN.md` | Settled decisions and known gaps — **read this** |
| `build.rs` | Schema merge + Rust codegen |
| `generator/` | Python (`gen_py.py`) and TypeScript (`gen_ts.py`) generators |
| `src/` | Hand-written implementations of the generated traits |
| `src/bin/align.rs` | Integration smoke test |
| `src/bin/stackcheck.rs` | Stack high-water guard |
| `tests/` | 85 tests; external vectors where they exist |

## Testing conventions

External ground truth is preferred over self-consistency, and exhaustive over
sampled where the domain is small — an exhaustive GF(256) check is what found a
one-element bug in `gf256_inv` that a random sample would have missed 99.6% of
the time. BIP-39 is checked against the specification vectors and TOTP against
RFC 6238.

An `#[ignore]`d test names the decision or defect it is waiting on, so the gap
cannot be quietly lost. It should fail deliberately once that lands. One
remains: `pbkdf_default_cost_is_defensible`.

## Where to pick up

See "Next" in `doc/DESIGN.md`. In short: the password KDF is decided in
principle (the crate ships one) but not implemented; the wire error-code
convention is agreed but not built; and the document layer — armour, envelope,
canonical signing bytes — is the next substantive phase.
