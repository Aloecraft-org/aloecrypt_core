# aloecrypt_core

<div align="center">

<img src="doc/icon.png" style="height:96px; width:96px;"/>

**Post-quantum cryptographic primitives with auto-generated language bindings**

[![GitHub](https://img.shields.io/badge/GitHub-%23121011.svg?logo=github&logoColor=white)](https://github.com/Aloecraft-org/aloecrypt_core)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Implements ML-KEM (FIPS 203), ML-DSA (FIPS 204), ChaCha20-Poly1305 password encryption, SHAKE-256 key derivation, and Keccak-256 hashing.
</div>

## Status

Mid-migration: `aloecrypt_core` is becoming `aloecrypt`, absorbing the identity
and session concepts from the original `aloecrypt` repository. See
[`doc/DESIGN.md`](doc/DESIGN.md) for settled decisions, known gaps and what is
next, and [`CLAUDE.md`](CLAUDE.md) for build invariants.

## Structure

```
api_core.json          Schema driving all code generation
build.rs               Generates src/api_core.rs at compile time (Rust types, traits, consts)
generator/gen_py.py    Generates Python bindings from the same schema
src/
  lib.rs               no_std library; includes generated api_core.rs
  dsa.rs               ML-DSA 44/65/87 signing and verification
  kem.rs               ML-KEM 512/768/1024 encapsulation/decapsulation
  password.rs          ChaCha20-Poly1305 chunked encryption
  pkdf.rs              SHAKE-256 key derivation
  rng.rs               ChaCha20-based CSPRNG (AloeRng)
  hash.rs              Keccak-256 hash and HMAC
src/bin/align.rs       Integration smoke test (requires std)
```

The `no_std` + `no_main` attributes on `lib.rs` are intentional -- the library targets WASM/WASI. The `align.rs` binary links against std and is not part of the published crate surface.

## Codegen pipeline

`api_core.json` is the single source of truth. It defines namespaces, constants, byte-alias types, structs, traits, and function signatures in a language-neutral schema.

- `build.rs` reads the schema at compile time and emits `api_core.rs`, which contains the Rust modules, types, and trait definitions the `src/` implementations depend on.
- `generator/gen_py.py` reads the same schema and emits Python dataclasses, ABC trait classes, wire-format pack/unpack helpers, and Extism call wrappers.

To regenerate Python bindings:

```sh
make generate
```

Output is written to `.generated/gen_py/aloecrypt.py`.

## Build

`build.rs` merges the schema and generates the Rust API, so a clean checkout
builds with no preparatory step:

```sh
cargo build --lib
cargo test
cargo build --lib --target wasm32-wasip2 --no-default-features
cargo build --lib --target thumbv8m.main-none-eabihf --no-default-features
```

Features: `slip39_words` and `bip39_words` add the mnemonic wordlists (the
recovery arithmetic works without them), and `host_rng` pulls in `getrandom` for
the example binaries. All are opt-out; `--no-default-features` builds for every
supported target.

## Wire format

All plugin calls use a packed binary wire format. Parameters are concatenated as little-endian bytes. Variable-length parameters (`&[u8]`, `&str`) are prefixed with a `u32` LE length. Instance methods prepend the serialized struct before the parameters. Return values are raw bytes.

Export naming:
- Instance/static trait methods: `{namespace}___{struct_lower}__{fn_name}`
- Standalone functions: `{namespace}___{fn_name}`

## Algorithms

| Primitive | Standard | Variants |
|-----------|----------|---------|
| ML-KEM | FIPS 203 | 512, 768, 1024 |
| ML-DSA | FIPS 204 | 44, 65, 87 |
| Symmetric encryption | ChaCha20-Poly1305 | -- |
| KDF | SHAKE-256 | -- |
| Hash / HMAC | Keccak-256 | -- |
| CSPRNG | ChaCha20 | stream-partitioned via AloeRng |

## License

Apache-2.0. Copyright Michael Godfrey [2026] | aloecraft.org [michael@aloecraft.org]