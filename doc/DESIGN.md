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
counting needs no password stretching at all.

## 7. Open

| Question | Blocks | Current thinking |
|---|---|---|
| Extism bindings or native bindings? | Entrypoints | Probably both — extism for reach, native for the ones people build on. Needs research. |
| RFC 7468 transport-compatibility, or full PKCS interop? | Document layer | Possibly both. Full interop drags ASN.1 into the crate; needs research. |
| Revocation mechanism | Identity layer | Start with short expiry plus reissue — `dlt_refresh_count` / `dlt_max_refresh` only mean anything under a reissue model. Revocation certificates and a Merkle log layer on afterwards without another format break. |

Revocation is no longer a blocking decision. It was, while the wire format was
fixed-length and had nowhere to put a proof. With tagged extensible sections a proof
slot can be added later without breaking documents already written, and with
verification returning an `Assurance`, "revocation unavailable" is already a
representable outcome rather than a hole in the type.

## 8. Known gaps

Recorded here because they are silent — nothing fails loudly, the output is just
missing or untested.

**The crate cannot be tested.** `cargo test` does not fail on an assertion, it
fails to link: `rust-lld: error: undefined symbol: main`. `lib.rs` carries
`#![no_main]`, so the test harness cannot emit an entry point. There is no
`tests/` directory and no unit test anywhere; the only verification the repo has
had is three example binaries that print SUCCESS. That is why both mnemonic
binaries were broken on `main` without anyone noticing.

`#![cfg_attr(not(test), no_main)]` fixes it — verified: an integration test
compiles and passes, and the host, `thumbv8m.main-none-eabihf` and
`wasm32-wasip2` builds are unaffected. `no_main` is meaningful for a bare-metal
binary, not for an rlib. This should be the first change of the next phase,
because everything else planned is a change to cryptographic code.

**`generator/meta.py` has no enum handling.** The Rust representation is
deliberate and correct — `#[repr(transparent)] struct X(pub u16)` is unambiguous
across the FFI boundary. The generator simply never learned about it: with no
entry in `type_sizes` for an enum type, any struct containing one fails size
resolution and is dropped from `meta_structs` entirely, taking its trait impl
and every generated export with it. Today that is `TotpCredential` via
`TotpAlgorithm`, which is why `totp_api` emits zero plugin exports.

The fix is parity, not redesign: register enum names with their `repr_type` size
and mirror the same flat representation in the Python and TypeScript output. CI
asserts every other namespace exports something and prints this one as a known
gap.

**Schema entries are matched by name with no validation.** A mismatched `impls`
pair — `{"trait": "VarString511", "struct": "VarString"}` instead of the other
way round — resolves to nothing and silently drops every export for that
namespace. That cost all twenty `aloecrypt_api` exports until it was found. A
schema that is also a specification wants a lint pass: every `impls` pair
resolving, every referenced type existing, every struct's size known.

## 9. Upstream

`ml-dsa` and `ml-kem` are pinned to release candidates (`0.1.0-rc.8`,
`0.3.0-rc.0`) while `0.1.1` and `0.3.2` are released. The bump is a contained
migration rather than a version change: `KeyGen` is gone and `from_seed` is now
an inherent method on `SigningKey<P>`.

Worth doing for a specific reason. `ml-dsa 0.1.1` holds the expanded signing key
behind `MaybeBox`, described upstream as "opportunistic heap allocation when the
`alloc` feature is available that falls back to stack allocation when it's
unavailable". Stack pressure on the lattice paths is a known problem and
upstream has addressed it — but the benefit is gated on `alloc`, which this
crate does not have, so in the current configuration the bump buys nothing.

That makes it a measurable experiment rather than a guess: migrate, then try a
small arena or bump allocator on the embedded profile and measure with
`cargo run --release --bin stackcheck`. Current baseline, x86-64 release:

| operation | stack |
|---|---|
| ml-kem-768 keygen + encapsulate + decapsulate | ~48 KB |
| ml-dsa-44 keygen + sign + verify | ~182 KB |
| ml-dsa-65 keygen + sign + verify | ~283 KB |
| ml-dsa-87 keygen + sign + verify | ~436 KB |

Do the migration after the test suite exists. It is the change most likely to
break something quietly.
