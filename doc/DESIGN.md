# Aloecrypt — Design Decisions

Status: settled unless marked **Open**. This file records decisions, not history —
it should stay short enough to read before touching the code.

`aloecrypt_core` is becoming `aloecrypt`. The original `aloecrypt` repo is superseded;
its concepts are being carried forward, its code largely is not.

## 1. What this is

A small, post-quantum cryptography library with several entrypoints, whose document
layer grows into certificates, CSRs, and a tool usable in place of GPG.

**Layering.** Each layer depends only on those above it.

| Layer | Contents |
|---|---|
| Primitives | ML-KEM, ML-DSA, ChaCha20-Poly1305, Keccak/SHAKE, CSPRNG, Shamir / SLIP-39 / BIP-39, TOTP |
| Documents | Canonical bytes, extensible envelope, armored text, detached signatures, encrypt-to-recipient |
| Identity | Keys, delegation, claims, certificates, CSRs, revocation |
| Entrypoints | Rust crate, CLI, native bindings, extism plugin |

Sessions, authenticators, `aloelite`, and any hardware integration are **consumers**.
They take a dependency on this crate; they do not shape it.

Documents come before identity. A certificate is a signed document, a CSR is a signed
document, a revocation is a signed document. The envelope is built once.

## 2. Post-quantum only, on the spine

No classical asymmetric algorithm belongs in this crate. Not ECDSA, not RSA, not
X25519, not Ed25519 — including verify-only paths.

If a consumer must verify a foreign classical trust chain (a WebAuthn attestation
statement, an Apple or Android attestation certificate), that lives in a **separate
crate** with its own dependency graph. The moment `aloecrypt` carries P-256, "PQC
library" becomes "library that also does P-256" in every dependency audit that
matters.

### Legacy interop at the edges

Interoperability with existing standards is allowed where the standard itself is the
product, and only at the edge of the API, chosen explicitly per use.

`TotpAlgorithm` is the reference example: it carries SHA1/SHA256/SHA512 so we
interoperate with every existing authenticator, plus SHA3-256/Keccak-256 for callers
who want them. The legacy option is selected per credential and never appears in the
middle of a construction.

### No overclaiming

Ship a **claims matrix**, generated from the schema, stating per primitive what it is,
what it resists, and what it does not.

This must be honest about cases where a post-quantum option buys less than it appears
to. TOTP is the standing example: it is a shared-secret HMAC scheme with no
quantum-vulnerable asymmetric primitive in it, so choosing Keccak-256 over SHA1 is a
hash-strength upgrade and not a post-quantum one. A library pitched on getting ahead of
the curve is judged on precisely this kind of precision.

## 3. Document format

### Armor

- **Base64**, standard alphabet (not URL-safe — these live in files and email), 64
  characters per line, via `data-encoding` (already a dependency, works in `no_std`).
  Roughly a third smaller than the hex encoding it replaces.
- **RFC 7468 delimiters**: `-----BEGIN ALOECRYPT SIGNER-----`, uppercase label, no
  spaces. Existing tooling can then extract and transport documents without
  understanding them.
- **No version in the label.** The version lives inside the envelope. A version in the
  delimiter is a string you must match exactly before you can locate the document at
  all.
- **No checksum.** GPG's armor carries a CRC24; RFC 7468 carries nothing. Every
  document here is signature-bearing or AEAD-sealed, so integrity is already covered,
  and a checksum that disagrees with the signature is a second source of truth to
  reconcile.

### Framing

**Tagged, length-prefixed sections, with skip-on-unknown-tag.**

This replaces the previous `bytes.len() == byte_sz()` check, which made every document
format final on first release. The schema is deliberately additive — pure JSON so
fields and objects can be bolted on without breaking existing functionality — and the
wire format must have the same property, or the schema's extensibility stops at the
serialization boundary.

### Canonical signing bytes

Exactly one byte encoding per object, used for signing. `#[repr(C, packed)]` on
generated structs gives this nearly for free, which is a real advantage over DER
canonicalisation. It must be written down as a guarantee and tested, not left as an
emergent property.

Requires an `AloecryptSignable` trait in the schema — `signing_material`, `signature`,
`signed_by`. It exists in the original aloecrypt and is the one missing hook in the
current base traits.

## 4. Verification returns a verdict

**Cryptography is a `Result`. Trust is a verdict.**

```rust
fn verify(..) -> Result<Assurance, VerifyError>
```

- `Err` is reserved for things no policy can accept: an invalid signature, a malformed
  document. These are not policy questions.
- Everything that could make a verifier hesitate — no revocation information, an
  unrecognised anchor, a self-issued certificate, an expired validity window — is a
  **finding** on a successful verification, not a failure of it.

```
Assurance {
    signature   : Established     // issuer signature over canonical bytes
    chain       : Established     // reaches a configured anchor
    validity    : Established     // now within active_from..expires_at
    generation  : Established     // depth and refresh within parent's limits
    claims      : Established     // requested claims present, in scope
    revocation  : Unavailable     // no source reachable
    freshness   : Unavailable
}

level()            // Verified when nothing is open, else Provisional
satisfies(&policy) // the only route to a yes/no
```

The model is the one a browser uses for a self-signed certificate: the same outcome is
unremarkable on an internal host and alarming on a bank. The library reports what it
established; the caller supplies the stakes.

Two rules keep this from degrading into click-through fatigue:

1. **Findings are machine-readable, never strings.** A policy must be able to
   distinguish "self-issued, which I expected" from "chains to an anchor I have never
   seen". Both are "not chained to a public root" and they mean entirely different
   things. A UI can only render that distinction if the library made it first.
2. **There is no `is_valid()`.** The only path to a boolean is `satisfies(&policy)`,
   which forces the caller to name their stakes. `Assurance` is `#[must_use]`.

A three-state outcome is *more* dangerous than a boolean if the middle state is the
default and nobody configures policy. The CLI therefore ships opinionated defaults —
strict wherever there is a named issuer, permissive only when explicitly asked — so the
library's flexibility does not become the tool's laxity.

This uses vocabulary already declared in `proof_api`. `AloecryptValidityScope` is the
slot for "in what scope was this claim asserted, and therefore what could be checked".
`AloecryptAuthenticationType` records *how* a fact was established, including `Merkle`
for a log inclusion proof.

## 5. Keys and lifetimes

Key custody is scope-dependent, and the types should say which scope they are in
rather than leaving it to documentation.

- A **root identity** is a seed. It may live offline and must never serialize private
  material by accident.
- A **working delegate** is session- or task-scoped and zeroizes on drop.

Storage is seed-first throughout: derive expanded keys on use rather than storing them.
In the original aloecrypt, 60% of the 13,333-byte signer struct was derivable from its
32-byte seed or replaceable by a 32-byte address. Smaller keys are also smaller
certificates.

`zeroize` and `subtle::ConstantTimeEq` are dependencies of the identity layer. Neither
is present today and both are far cheaper to add before that layer exists than after.

## 6. Build profiles

Feature-gated profiles, so a consumer takes only what it needs:

- **minimal** — `no_std`, no allocator, no wordlists. The floor.
- **wordlists** — BIP-39 / SLIP-39 mnemonics. Opt-in; the arithmetic underneath
  (GF(256), Reed–Solomon, share splitting) stays available without them.
- **std** — host conveniences.
- **plugin** — the extism wire format.

Every profile must build in CI. A feature flag that cannot be turned off is not a
feature flag.

Password-based key derivation is a **profile** decision, not a library one. Memory-hard
derivation and a 520 KB device are mutually exclusive; a consumer that needs Argon2id
is a hosted consumer, and a consumer with hardware-backed key storage and retry
counting needs no password stretching at all. (This is now the `host_kdf`
feature — section 17.)

## 7. Decided, not yet built

**The crate ships a password KDF.** The alternative was to export none and let
each consumer bring its own; the decision is that a cryptography library people
reach for should not make them source a KDF separately. This was agreed here
and is now built — Argon2id, profile-gated behind the unchanged `pbkdf`
interface; the parameters and the profile split are section 17.

**Errors cross the wire as codes** — likewise agreed here and now built;
the convention as it exists is section 16.

**Still genuinely open:** whether the Var types move to their own `no_std`
crate (kept in-tree for now, and fixed in place, so the extraction is easier
than it was); extism versus native bindings, where the answer is probably both;
and whether the document format aims at RFC 7468 transport compatibility or
full PKCS interop, where the answer is possibly both.

## 8. Known gaps

**Schema entries are matched by name with no validation in the pipeline
itself.** A mismatched `impls` pair — `{"trait": "VarString511", "struct":
"VarString"}` instead of the other way round — resolves to nothing and silently
drops every export for that namespace. That cost all twenty `aloecrypt_api`
exports until it was found. `generator/lint_schema.py` now guards this class of
bug (`make generate` runs it first, CI runs it separately), but the underlying
pipeline still resolves by lookup with no errors of its own — the lint is a
checkpoint, not a cure, and new generator features need new lint rules to stay
guarded.

**The TypeScript generator cannot run.** `TypeScriptGenerator` leaves
`emit_namespace_wrappers` unimplemented and its `main()` reads a path that does
not exist. Pre-existing, and matches the original repo's "partial for
typescript" note; `make generate` only runs the Python generator.

## 9. Upstream, and where the stack actually goes

`ml-dsa` and `ml-kem` are now on their first stable releases (0.1.1 and 0.3.2)
rather than release candidates. The migration is contained: `KeyGen` is gone,
`SigningKey<P>` replaces the old associated `KeyPair` type, and `from_seed` is
an inherent method on it. Six private helpers in `src/dsa.rs` changed.

**It is wire compatible.** Public keys, signatures, KEM public keys, ciphertexts
and shared secrets are byte-identical across the two versions for the same
seeds, verified directly. Existing keys and signatures are unaffected.

**It did not solve the memory problem, and was never going to.** Upstream now
holds the expanded signing key behind `MaybeBox`, described as "opportunistic
heap allocation when the `alloc` feature is available that falls back to stack
allocation when it's unavailable". Without an allocator it falls back, so there
was nothing to collect. And relocating would not have helped anyway: 520 KB of
SRAM is 520 KB wherever the bytes live, and an allocator adds nondeterminism
that a device like this does not want. Only reducing peak *live* bytes moves
this number.

Measured on x86-64, release profile, by binary search:

| operation | 0.1.0-rc.8 | 0.1.1 | change |
|---|---:|---:|---:|
| ml-kem-768 keygen + encapsulate + decapsulate | 47.9 KB | 45.4 KB | −2.5 KB |
| ml-dsa-44 keygen + sign + verify | 181.9 KB | 175.1 KB | −6.8 KB |
| ml-dsa-65 keygen + sign + verify | 282.8 KB | 273.8 KB | −9.0 KB |
| ml-dsa-87 keygen + sign + verify | 435.2 KB | 424.5 KB | −10.7 KB |

Read those with care. About 2.5 KB of each is a constant offset in the shared
path, not the lattice code — three of the four first-pass deltas were exactly
2559 bytes, across operations that share no algorithm. The genuine saving in
the ML-DSA paths is roughly 4–8 KB, or 3%.

One counter-intuitive result worth keeping: deriving the expanded key directly
via `ExpandedSigningKey::from_seed` costs *more* stack than building the
`SigningKey` and cloning its expanded key — 279.8 KB against 273.8 KB for
ML-DSA-65. `ExpandedSigningKey::from_seed` does exactly that internally and is
`#[inline]`, so inlining extends the live range rather than shortening it.
`src/dsa.rs` uses the cheaper form; a comment there says why, because it reads
like the more wasteful option.

So the pins are worth updating for being out of RC and for costing nothing, not
for memory. ML-DSA-65 still wants ~274 KB of stack against 520 KB of SRAM, and
that is the number any embedded design has to plan around.

## 10. Bugs found and fixed by the first test suite

The suite that landed with this section found two correctness bugs in the
secret-sharing stack. Both are fixed; the tests that caught them are the
regression guards.

**`gf256_inv` was wrong for exactly one element.** The search loop ran
`for i in 1..255`, which stops at 254. GF(256) has 255 non-zero elements, so the
one element whose inverse is 255 — that is 28 — fell off the end and the
function returned 0 instead.

A zero inverse collapses the Lagrange denominator, so `combine_shamir_shares`
silently produced garbage for any share subset containing two locations whose
XOR was 28. Measured before the fix: **5 of 256 seeds** for 3-of-5 produced
share sets with failing subsets, 3 of 10 subsets failing in each. It is
seed-dependent and therefore intermittent, which is the worst way for a
recovery scheme to be broken. `gf1024_inv` has the same shape but its
`1..1024` bound happens to be correct, since GF(1024) has 1023 non-zero
elements.

**Shamir coefficients were only generated for the first 16 secret bytes.**
`coef_buf` is `[[u8; MAX_VARIANTS]; MAX_SECRET_LEN]` — 16 wide, 255 tall — and
the fill loop iterated `0..MAX_VARIANTS`, the width, instead of
`0..MAX_SECRET_LEN`, the height. Every row past the 16th stayed zero, so for a
secret longer than 16 bytes the remaining bytes were shared with a degree-0
polynomial whose value at every x is the secret byte itself.

Measured before the fix: for a 32-byte secret, **16 of 32 bytes appeared
verbatim in every share**. Any single share disclosed half the key. This is the
more serious of the two, because nothing fails — recovery still works, so no
amount of round-trip testing would have caught it. The test that does catch it
asserts that no secret byte appears identically across all shares.

Shares for secrets of 16 bytes or fewer are bit-identical before and after the
fix: locations are drawn from the RNG first, and rows 0..16 receive the same
stream either way. Only the previously-unprotected bytes change.

## 11. Test coverage

90 tests, none ignored. The convention stands: an `#[ignore]`d test names the
bug it is waiting on and fails deliberately when that bug is fixed, so a gap
cannot be quietly lost — the list is simply empty right now.

(`varstring_roundtrips_up_to_capacity` and `hash_inputs_are_unambiguously_framed`
were on this list and now pass: the two-byte VarString prefix and length-prefixed
hash inputs both landed. `wrong_key_returns_an_error_rather_than_aborting` was
`#[should_panic]` until the decryptor returned `Result`, and now asserts
`Err(AuthFailed)`. `pbkdf_default_cost_is_defensible`, the last holdout, was
un-ignored when Argon2id landed and now asserts the profile floors of
section 17.)

External ground truth, rather than self-consistency, where it exists:

- **BIP-39** against five canonical vectors from the specification, including
  both 128-bit and 256-bit entropy. All pass — the implementation is spec
  compatible.
- **TOTP** against the RFC 6238 Appendix B vectors for SHA-1, SHA-256 and
  SHA-512. All pass.
- **GF(256) and GF(1024)** checked exhaustively for inverses, involution,
  identity and commutativity rather than sampled. This is what found the
  `gf256_inv` bug.
- **The password KDF** pinned per profile against `phc-winner-argon2`, the
  Argon2 reference implementation (via argon2-cffi), including the salt
  normalization — the full composition, not just the argon2 crate's own KATs.

One ergonomic note worth knowing before writing more tests: generated structs
are `#[repr(C, packed)]`, so a field cannot be referenced directly.
`assert_eq!(cred.digits, 6)` is a compile error (E0793), not a lint — copy the
field to a local first.

## 12. Enum codegen

Enums are now first class in the generator. `meta.py` gained an enum pass that
runs before structs and registers each enum's `repr_type` size in
`type_sizes`, so a struct containing an enum field resolves instead of being
silently dropped.

The representation mirrors the Rust decision rather than reinterpreting it. The
generated Rust is `#[repr(transparent)] struct X(pub u16)` — a flat newtype
chosen so the value crosses the FFI boundary unchanged — so:

- **Python** emits an `int` subclass with the members as class constants, plus
  a `name_of()` helper for display. It packs as its repr primitive.
- **TypeScript** emits `export type X = number` with a `const` object of
  members.

Neither introduces a richer enum type that would need converting at the
boundary. `totp_api` now emits its four exports; generated Python went from
101,642 to 110,866 bytes.

Two things surfaced while fixing it:

**Nested struct fields defaulted to raw bytes.** `_field_default` returned
`bytes(N)` for any type with a known size, including nested structs, while
`_field_pack_expr` emitted `.pack()` for them — so a default-constructed struct
with a nested struct field raised `'bytes' object has no attribute 'pack'`. This
predates the enum work and affected `AloeRngU8Result`, `RecoverableSecret`,
`RecoveryKey` and `AloecryptAttribute`. Fixed by defaulting to an instance of
the nested type.

**The TypeScript generator is not runnable.** `TypeScriptGenerator` leaves
`emit_namespace_wrappers` unimplemented, so the class cannot be instantiated,
and its `main()` reads `"../api_core.json"`, a path that does not exist. Both
predate this work and match the original repo's "partial for typescript" note.
`make generate` only runs the Python generator, so nothing depends on it today.

CI now asserts that every one of the nine namespaces emits at least one export,
and separately that every generated struct default-constructs, packs to exactly
its declared `SIZE`, and survives an unpack — 31 structs at present. Between
them those two checks catch a struct being dropped and a field default that
disagrees with the packing code, neither of which breaks the Rust build.

## 13. Hardening pass

**The tree is warning-clean** across every feature configuration and target, so
CI now sets `RUSTFLAGS: -D warnings` and a new warning is a build failure. Of
the 69 warnings this started with, 48 were in generated code: schema enum
members are PascalCase, which is the right reading for a variant but trips
`non_upper_case_globals` once emitted as an associated const. The naming is a
schema decision, so `build.rs` emits an `allow` for that block rather than
shouting the API.

Two of the hand-written warnings were worth more than a lint fix. Both
`_create_n_shares` functions took their coefficient buffer **by value** — 4,080
bytes for Shamir, 8,160 for SLIP-39 — copied onto the stack purely to be read.
Both now take it by reference. Both also took an `rng` parameter they never
used, since coefficients are drawn by the caller. On a part with 520 KB of SRAM
an 8 KB gratuitous copy is worth removing.

**Authenticated decryption returns an error instead of aborting.**
`password_decrypt_next_chunk` ended in `.expect("Decryption failed")`, so a
wrong password took the module down under `panic = "abort"`. It now returns
`Result<_, StatusCode>` (originally via an interim `AloecryptError` type,
folded into the generated `StatusCode` when the wire error channel landed —
section 16). The error carries no detail about *why* on purpose — for
authenticated decryption the only safe answer is that it did not
authenticate. The encrypt path keeps its `expect` with a comment explaining why
it is unreachable: `encrypt_in_place_detached` only fails when the buffer
exceeds the AEAD limit, and the chunk is a fixed size.

**Hash inputs are length-prefixed.** `hash(salt, ikm, domain)` was a bare
concatenation, so `hash("ab","c",d)` and `hash("a","bc",d)` produced the same
digest from different logical inputs. Every field now carries a `u64`
little-endian length. `hmac` gets the same treatment for its salt and domain.
This changes every derived value in the crate — addresses, recovery secrets —
which is why it was worth doing before anything is persisted.

## 14. The Var types

Kept in-tree for now rather than extracted, and fixed in place.

**`VarU16_255` no longer hands out a `&[u16]`.** `to_u16_arr` cast a byte
pointer at offset 2 inside the struct's own `[u8; 512]` to `*const u16`. Every
generated struct is `#[repr(C, packed)]`, which pins the wire layout but also
forces alignment 1 on that buffer — so the struct may sit at an odd address and
the reference is misaligned. That is undefined behaviour in Rust even if the
reference is never dereferenced, and no amount of care at the call site fixes
it: you cannot soundly borrow a `&[u16]` out of an align-1 buffer.

The trait now exposes `len()`, and decoding is `read_u16_arr(&mut [u16; 255])`,
which writes into a caller buffer and returns the count. It allocates nothing,
which matters on the embedded profile. `from_u16_arr` also stopped
reinterpreting `&[u16]` as bytes — that made the encoding host-endian in a type
whose entire purpose is crossing a wire boundary. Both directions are now
explicit little-endian.

`read_u16_arr` is deliberately **not** in the schema, so it is not a plugin
export: an out-parameter has no representation in a wire format that returns
bytes and cannot write into caller memory. A binding decodes `pack_bytes`
itself. This is the first case where a Rust-side ergonomic and a wire-expressible
API genuinely had to differ, and it will not be the last.

**`VarString511` became `VarString510`.** It stored its length in one byte while
advertising 511 bytes of capacity, so anything from 256 upward silently read
back truncated. The prefix is now a two-byte little-endian length, which leaves
510 bytes of payload in the 512-byte buffer — hence the rename, since the old
name was wrong either way. The mnemonic writers in `bip39.rs` and `slip39.rs`
index around that prefix by hand and were updated with it.

**Smaller things.** `VarByte255::to_byte_arr` had an unreachable bounds branch
(a one-byte length cannot exceed the payload); the string decoders now document
that they return an empty string rather than panicking on non-UTF-8, which is
the right call for attacker-reachable bytes but should be a deliberate one.

The extraction into a separate `no_std` crate is still worth doing. It is easier
now than it was: the types are sound, the encoding is explicit, and the only
schema coupling left is the four struct definitions and their traits.

## 15. Key material is no longer `Copy`; zeroizing it is now possible

Key-bearing structs and every struct that contains one no longer derive
`Copy`: the ML-DSA and ML-KEM keypairs, the KEM encapsulation results (they
hold the shared secret), `PasswordCipher` and both chunk results, `AloeRng`
and its four step results, `RecoveryKey`/`RecoverableSecret`, and
`TotpCredential`. Twenty structs in all. Public-key-only types — the
verifiers and encapsulators — and the general-purpose Var types keep `Copy`.

The reason `Copy` had to go: `Copy` and `Drop` are mutually exclusive in
Rust, so `ZeroizeOnDrop` could not be implemented on any of them, and a
`Copy` seed is silently duplicated on every assignment and pass-by-value —
there is no way to know how many copies of a private seed exist or to clear
them. For a 32-byte ML-DSA seed that is the entire private key.

One codegen consequence: `derive(Clone)` on a `#[repr(C, packed)]` struct
clones by *moving* each field (the derive refuses references to packed
fields), which fails as soon as a field is itself a non-Copy struct. So for
any schema struct whose derives lack `Copy`, `build.rs` strips `Clone` from
the derive list and emits a manual field-wise impl instead — sound because
hand-written code may reference a packed field whose type has alignment 1,
which every generated struct does.

Removing `Copy` is the prerequisite; the wipe itself is still future work.
`zeroize` remains a to-be-added dependency of the identity layer (section 5),
and the Var types inside `TotpCredential` are still `Copy` at their own
level. (`zeroize` and `subtle` are already in the tree transitively via
`chacha20poly1305` — RustCrypto wipes its own internal key material.) The
recovery MAC comparison, previously a variable-time `assert_eq!`, is now a
dependency-free constant-time fold — see section 16.

## 16. The wire error channel

Built as agreed in section 7, with the details that surfaced in the doing:

- **`StatusCode` is a schema enum** (`aloecrypt_api`, `repr_type: u16`), so
  the same codes with the same numbering generate into every language. Codes
  are coarse on purpose: `Ok`, `AuthFailed`, `BadEncoding`, `BadArgument`,
  `Unsupported`, `Unspecified`. For authenticated decryption, "wrong key" and
  "altered ciphertext" share `AuthFailed` deliberately — distinguishing them
  is an oracle. The schema descriptions say so, so nobody helpfully splits
  them.
- **Every export returns a uniform 2-byte little-endian status prefix** ahead
  of its payload. On any non-`Ok` status the payload is *absent*, not zeroed:
  a caller that skips the check gets a short read, never plausible-looking
  key bytes. Infallible exports always send `Ok`, so there is exactly one
  format to reason about.
- **`Unspecified` (65535) is the enum's default member**, which is what an
  unrecognized code decodes to — an unknown status can never read as success.
  The lint enforces this contract: `StatusCode` must exist, `Ok` must be 0,
  and `Ok` must not be the default.
- **Fixed-size returns are length-checked.** An Ok reply whose payload is not
  exactly the declared size decodes as `Unspecified`, never as truncated key
  material — the "payload absent, not zeroed" rule would otherwise only hold
  for callers that also check lengths themselves. Generated `unpack` rejects
  short input for the same reason. Variable-length returns (`&str`, `&[u8]`)
  are delimited by the payload extent and are the one unchecked case; `usize`
  returns cross as u64 LE.
- **The schema marks fallible functions** with `"fallible": "true"`. In Rust
  a fallible *trait* function's generated signature becomes
  `Result<T, StatusCode>`; a fallible *standalone* function is hand-written,
  so `build.rs` emits a fn-pointer assertion
  (`const _: fn(..) -> Result<T, StatusCode> = crate::module::name;`) for
  every namespace-level function, making any drift between the schema
  signature and the Rust implementation a compile error naming the function.
  In Python the wrapper raises `AloecryptStatusError`. Infallible functions
  keep their bare return — the prefix is uniform on the wire, but only a
  function that can actually fail forces callers through a `Result`.
- **`src/error.rs` folded into the generated type**, as planned. It now
  re-exports `StatusCode`/`StatusCodeEnum` and defines `AloecryptResult<T>`;
  the hand-written `AloecryptError` is gone.
- **`authorize_recovery` returns `Err(AuthFailed)`** instead of ending in
  `assert_eq!` on the MAC, and the comparison is now constant time — a
  dependency-free XOR fold with a `core::hint::black_box` on the
  accumulator, branch-once-at-the-end. (`subtle::ConstantTimeEq` remains the
  right tool once the identity layer adds the dependency.)
- **The password chunk functions are exported** (`password_api`), which makes
  the decryptor the reference fallible export: it was the function that could
  not cross the wire while failure meant `panic` under `panic = "abort"`.
- CI exercises the decode path with a stub plugin: `Ok` strips the prefix, a
  non-`Ok` raises, and a short or empty reply raises `Unspecified` rather
  than being indexed blindly.

## 17. The password KDF

Built as agreed in section 7: Argon2id behind the schema's existing `pbkdf`
interface, with the details that surfaced in the doing.

- **`iters` is the Argon2 pass count** (t_cost), clamped to a minimum of 1 —
  the one tunable that crosses the wire, so the schema signature and every
  binding are unchanged. The memory cost is **not** a parameter: it is a
  security parameter fixed by the build profile, and a consumer that wants a
  different working set is making a build-time decision, not a call-time one.
- **Two profiles, one interface.** `host_kdf` (a default feature, mirroring
  `host_rng`) runs the OWASP-recommended tier — 19 MiB, default 2 passes —
  with the block buffer heap-allocated by the `argon2` crate. Without it the
  blocks are a fixed 64 KiB array in one `#[inline(never)]` stack frame,
  default 4 passes: real (if small) memory hardness rather than none, exactly
  the "worth measuring" outcome section 7 hoped for. Measured on x86-64 the
  embedded frame is 92 KB against a 112 KB ceiling, guarded by `stackcheck`
  in both profiles — comfortably inside a budget whose binding constraint is
  ML-DSA-65's 274 KB.
- **The profiles derive different keys from the same inputs.** Inherent —
  memory cost is an Argon2 input — and correct: a key derived at 19 MiB must
  not be reproducible by an attacker willing to run at 64 KiB. A document
  format that stores password-encrypted material will need to record the
  derivation parameters alongside the salt; that belongs to the envelope
  design (section 3).
- **Salts are normalized, not passed through.** Argon2 rejects salts under 8
  bytes; this API has always accepted any salt including none, and the wire
  cannot retroactively forbid short ones. Every salt is therefore hashed to a
  fixed 32 bytes through the crate's length-framed hash under the domain
  string `aloecrypt.pkdf.salt.v1` — which also domain-separates the KDF from
  every other use of the hash, and gives the derivation a version to bump if
  it ever has to change.
- **The profile constants are validated at compile time** — `Params::new` is
  `const fn`, so a profile whose constants violate Argon2's bounds fails to
  build rather than panicking on first use. The functions stay infallible in
  the schema: with the constants proven and the pass count clamped, the only
  reachable runtime failure is the hosted profile failing to allocate 19 MiB,
  which no status code makes recoverable.
- **Outputs are pinned per profile** against the Argon2 reference
  implementation (section 11). The old SHAKE-256 chain's outputs are gone,
  which changes every password-derived key — the last of the
  "worth doing before anything is persisted" breaks, and the reason it
  shipped ahead of the document layer.

## Next

In rough order of value, and roughly independent of each other:

1. ~~Password KDF~~ — **done**, section 17. Argon2id, profile-gated, closed
   the last `#[ignore]`d test.
2. ~~Wire error codes~~ — **done**, section 16. `authorize_recovery` and the
   password decryptor return errors across the wire; the lint guards the
   status contract.
3. ~~Remove `Copy` from key structs~~ — **done**, section 15. The zeroize
   wipe itself is still open and belongs to the identity layer's type split.
4. **The document layer** (section 3). Armour, extensible envelope, canonical
   signing bytes, `AloecryptSignable`. This is the phase that makes certs, CSRs
   and revocations one problem instead of four, and nothing after it can start
   until it exists.
5. ~~Schema lint pass~~ — **done**. `generator/lint_schema.py` (925 checks
   now, grown with the status contract): every `impls` pair resolving, every
   referenced type existing, enum discriminants unique and defaults present,
   no name shadowed across namespaces, and a cross-check against what
   `meta.py` actually loaded, which is what catches a silently dropped
   struct. `make generate` runs it first; CI runs it separately.
6. **Finish or delete `gen_ts.py`** (section 8). It cannot run today, which
   makes the TypeScript half of "multiple entrypoints" further away than the
   file's presence suggests. If kept, its first real feature is the status
   prefix from section 16.
