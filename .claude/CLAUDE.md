# Operator

This repo is `aloecrypt_core`: a no_std post-quantum cryptography library
(ML-DSA, ML-KEM, and the hashing, KDF, recovery, OTP and document layers
around them) whose API schema in `config/api_core.json` also generates the
Python and TypeScript bindings. It produces the crate and those bindings.
The owner is Michael Godfrey (`aloecraft`). Build, test and CI commands,
and the invariants to know before editing, are in the root `CLAUDE.md`;
settled design decisions are in `doc/DESIGN.md`.

DO NOT use `doc/` as a scratchpad.
Use `.claude/doc` for claude's working memory.

The operating protocol is .claude/rules/operating.md. It and every
other file in .claude/rules/ apply to every run.
