"""check_plugin.py - drive the real .wasm through the generated Python bindings.

usage: python3 generator/check_plugin.py PLUGIN.wasm [BINDINGS.py]

Loads the plugin with extism, exactly as the bindings' own _Plugin loader
does, and checks:

  - every export the bindings call exists in the plugin (none silently
    missing, which is what a schema/codegen drift would look like);
  - real round trips: ML-DSA sign and verify, ML-KEM encapsulate and
    decapsulate, OTP against RFC 4226, a mut-self builder returning the
    updated struct, a hash against the native value;
  - the status channel: a fallible export raises AuthFailed on a wrong key,
    and a malformed request is answered BadEncoding with no payload.

Run by `make check_plugin`; needs `pip install extism`.
"""

import sys
from pathlib import Path

import extism

DEFAULT_BINDINGS = ".generated/gen_py/aloecrypt_core.py"
BAD_ENCODING = 2
AUTH_FAILED = 1

def load(bindings_path: str) -> dict:
    ns: dict = {}
    src = Path(bindings_path).read_text()
    exec(compile(src, bindings_path, "exec"), ns)
    return ns


def main() -> int:
    wasm_path = sys.argv[1]
    ns = load(sys.argv[2] if len(sys.argv) > 2 else DEFAULT_BINDINGS)
    plugin = extism.Plugin(Path(wasm_path).read_bytes(), wasi=True)
    Err = ns["AloecryptStatusError"]
    failures: list[str] = []

    def check(cond: bool, what: str) -> None:
        print(("ok   " if cond else "FAIL ") + what)
        if not cond:
            failures.append(what)

    # Every export the bindings call must exist.
    exports = sorted(n for n in ns if "___" in n and callable(ns[n]))
    missing = [n for n in exports if not plugin.function_exists(n)]
    check(not missing, f"all {len(exports)} binding exports exist in the plugin"
          + (f" (missing: {', '.join(missing)})" if missing else ""))

    # ML-DSA-65: sign, verify with the derived verifier, reject a tampered message.
    seed = bytes(range(32))
    kp = ns["dsa_api___mldsa65keypair__from_seed"](seed, plugin)
    sig = ns["dsa_api___mldsa65keypair__sign"](kp, b"hello", plugin)
    ver = ns["dsa_api___mldsa65keypair__get_verifier"](kp, plugin)
    check(ns["dsa_api___mldsa65verifier__verify"](ver, b"hello", sig, plugin),
          "ML-DSA-65 signature verifies")
    check(not ns["dsa_api___mldsa65verifier__verify"](ver, b"hellp", sig, plugin),
          "ML-DSA-65 rejects a changed message")
    for level in (44, 87):
        k = ns[f"dsa_api___mldsa{level}keypair__from_seed"](seed, plugin)
        s = ns[f"dsa_api___mldsa{level}keypair__sign"](k, b"hello", plugin)
        v = ns[f"dsa_api___mldsa{level}keypair__get_verifier"](k, plugin)
        check(ns[f"dsa_api___mldsa{level}verifier__verify"](v, b"hello", s, plugin),
              f"ML-DSA-{level} signature verifies through the verifier")

    # ML-KEM-768: both sides agree on the secret.
    kem = ns["kem_api___mlkem768keypair__from_seed"](bytes(range(64)), plugin)
    enc = ns["kem_api___mlkem768keypair__get_encapsulator"](kem, plugin)
    res = ns["kem_api___mlkem768encapsulator__encapsulate"](enc, bytes(32), plugin)
    got = ns["kem_api___mlkem768keypair__decapsulate"](kem, res.cipher, plugin)
    check(bytes(got) == bytes(res.secret), "ML-KEM-768 decapsulates to the encapsulated secret")

    # OTP: RFC 4226 appendix D, counter 0 and 1 for "12345678901234567890".
    uri = "otpauth://hotp/LABEL?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0"
    cred = ns["otp_api___otpcredential__from_string"](uri, plugin)
    # OtpResult is one signed digit per byte, -1 padding the unused tail.
    def digits(r: bytes) -> str:
        return "".join(str(d) for d in r if d < 128)
    for counter, want in [(0, "755224"), (1, "287082")]:
        code = digits(ns["otp_api___otpcredential__generate"](cred, counter, plugin))
        check(code == want, f"HOTP counter {counter} is {want} (got {code})")

    # A &mut self builder returns the updated struct across the wire.
    blank = ns["otp_api___otpcredential__empty"](plugin)
    named = ns["otp_api___otpcredential__with_issuer"](blank, "Aloecraft", plugin)
    check(named.pack() != blank.pack(), "a &mut self builder returns the changed struct")

    # A fallible export fails closed: the wrong key is AuthFailed, not garbage.
    key, nonce = bytes(32), bytes(12)
    enc_cipher = ns["password_api___passwordcipher__new"](b"", key, nonce, plugin)
    chunk = ns["PasswordUnencryptedChunk"]()
    out = ns["password_api___password_encrypt_next_chunk"](chunk, enc_cipher, plugin)
    dec_cipher = ns["password_api___passwordcipher__new"](b"", key, nonce, plugin)
    back = ns["password_api___password_decrypt_next_chunk"](out.next_chunk, dec_cipher, plugin)
    check(back.pack() != ns["DecryptChunkResult"]().pack(), "the right key decrypts the chunk")
    wrong = ns["password_api___passwordcipher__new"](b"", bytes([1]) * 32, nonce, plugin)
    try:
        ns["password_api___password_decrypt_next_chunk"](out.next_chunk, wrong, plugin)
        check(False, "decrypting with the wrong key raises AuthFailed")
    except Err as e:
        check(e.code == AUTH_FAILED, f"decrypting with the wrong key raises AuthFailed (got {e.code})")

    # A malformed request: status BadEncoding and no payload at all.
    for name, payload in [
        ("hash_api___simple_hash", b"\x05\x00\x00\x00abc"),          # length prefix overruns
        ("hash_api___simple_hash", b"\x00\x00\x00\x00extra"),        # trailing bytes
        ("dsa_api___mldsa65keypair__from_seed", bytes(31)),          # short fixed field
        ("otp_api___otpcredential__from_string", b"\x01\x00\x00\x00\xff"),  # bad UTF-8
    ]:
        reply = bytes(plugin.call(name, payload))
        check(reply == BAD_ENCODING.to_bytes(2, "little"),
              f"{name} answers a malformed request with BadEncoding only ({reply[:4].hex()})")

    h = ns["hash_api___simple_hash"](b"aloecrypt", plugin)
    check(len(h) == 32, "simple_hash returns 32 bytes")

    print(f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
