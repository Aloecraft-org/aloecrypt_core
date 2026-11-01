"""
lint_schema.py - Validate the schema before anything is generated from it.

The schema is matched by name, with no validation anywhere in the pipeline. A
name that does not resolve does not fail: the entry is silently skipped and the
Rust build stays green, so the loss only shows up as a missing export in a
binding nobody has run yet. Three separate bugs of exactly this shape have
already reached main:

  * `aloecrypt_api.impls` had its trait and struct keys transposed, dropping all
    twenty Var* exports.
  * `meta.py` had no enum pass, so `TotpCredential` failed size resolution and
    took `totp_api`'s exports with it.
  * A nested struct field defaulted to raw bytes while the packer called
    `.pack()` on it.

This lints the raw schema and then cross-checks it against what `meta.py`
actually loaded, which is what catches the silent drops.

Usage:  python3 generator/lint_schema.py [path-to-merged-schema]
Exit code is non-zero if anything fails.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from meta import PRIMITIVE_TYPES, VARLEN_TYPES, load_meta, strip_ref  # noqa: E402

DEFAULT_SCHEMA = ".generated/api_core_merged.json"


class Findings:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checked = 0

    def check(self, ok: bool, message: str) -> None:
        self.checked += 1
        if not ok:
            self.errors.append(message)


def known_types(schema: dict) -> set[str]:
    names = set(PRIMITIVE_TYPES) | set(VARLEN_TYPES) | {"usize", "Self", "bool"}
    for ns in schema.values():
        if not isinstance(ns, dict):
            continue
        for key in ("byte_aliases", "structs", "enums"):
            for entry in ns.get(key, []):
                names.add(entry["name"])
    return names


def lint(schema_path: str) -> int:
    schema = json.loads(Path(schema_path).read_text())
    f = Findings()
    types = known_types(schema)

    # ── Raw schema checks ────────────────────────────────────────────────
    seen_names: dict[str, str] = {}
    for ns_name, ns in schema.items():
        if not isinstance(ns, dict):
            continue

        traits = {t["name"] for t in ns.get("traits", [])}
        structs = {s["name"] for s in ns.get("structs", [])}

        # An impls pair that does not resolve is skipped in silence.
        for imp in ns.get("impls", []):
            f.check(
                imp["trait"] in traits,
                f"{ns_name}.impls: trait {imp['trait']!r} is not a trait in this "
                f"namespace (are trait and struct transposed?)",
            )
            f.check(
                imp["struct"] in structs,
                f"{ns_name}.impls: struct {imp['struct']!r} is not a struct in "
                f"this namespace (are trait and struct transposed?)",
            )

        # Every field type must resolve, or the whole struct is dropped.
        for s in ns.get("structs", []):
            for field in s.get("fields", []):
                f.check(
                    field["type"].strip() in types,
                    f"{ns_name}.{s['name']}.{field['name']}: unknown type "
                    f"{field['type']!r}",
                )

        # Trait signatures reference types too.
        for t in ns.get("traits", []):
            for fn in t.get("functions", []):
                ret = fn.get("return")
                if ret:
                    # &str and &[u8] are varlen wire types and resolve as-is;
                    # anything else is looked up with the reference stripped.
                    resolved = ret.strip() in VARLEN_TYPES or strip_ref(ret).strip() in types
                    f.check(
                        resolved,
                        f"{ns_name}.{t['name']}.{fn['name']}: unknown return "
                        f"type {ret!r}",
                    )
                for p in fn.get("params", []):
                    if not p.get("name"):
                        continue
                    f.check(
                        "type" in p,
                        f"{ns_name}.{t['name']}.{fn['name']}: param "
                        f"{p.get('name')!r} has no type",
                    )

        # Enum discriminants must be unique, or the generated match arms
        # collide and later members become unreachable.
        for e in ns.get("enums", []):
            discs = [m["discriminant"] for m in e.get("members", [])]
            f.check(
                len(discs) == len(set(discs)),
                f"{ns_name}.{e['name']}: duplicate discriminants "
                f"{sorted({d for d in discs if discs.count(d) > 1})}",
            )
            f.check(
                e.get("repr_type", "u16") in PRIMITIVE_TYPES,
                f"{ns_name}.{e['name']}: repr_type "
                f"{e.get('repr_type')!r} is not a primitive",
            )
            # The u16 -> enum conversion needs a fallback arm, which comes
            # from the default member; without exactly one, the generated
            # match is non-exhaustive (rustc error) or ambiguous.
            defaults = [
                m["name"] for m in e.get("members", [])
                if str(m.get("default", "")).strip() == "true"
            ]
            f.check(
                len(defaults) == 1,
                f"{ns_name}.{e['name']}: needs exactly one default member, "
                f"found {defaults or 'none'}",
            )
            # build.rs unwraps every member's description into a doc comment,
            # so a missing one panics the Rust build with no context.
            for m in e.get("members", []):
                f.check(
                    isinstance(m.get("description"), str),
                    f"{ns_name}.{e['name']}.{m['name']}: member has no "
                    f"description (build.rs requires one after the doc merge)",
                )

        # Standalone functions get the same signature validation as trait
        # functions: their types resolve by the same silent lookup, and they
        # are where the fallible exports live.
        for fn in ns.get("functions", []):
            ret = fn.get("return")
            if ret:
                resolved = ret.strip() in VARLEN_TYPES or strip_ref(ret).strip() in types
                f.check(
                    resolved,
                    f"{ns_name}.{fn['name']}: unknown return type {ret!r}",
                )
            for p in fn.get("params", []):
                if not p.get("name"):
                    continue
                f.check(
                    "type" in p,
                    f"{ns_name}.{fn['name']}: param {p.get('name')!r} has no type",
                )
                if "type" in p:
                    pt = p["type"]
                    resolved = pt.strip() in VARLEN_TYPES or strip_ref(pt).strip() in types
                    f.check(
                        resolved,
                        f"{ns_name}.{fn['name']}: param {p['name']!r} has "
                        f"unknown type {pt!r}",
                    )

        # `fallible` gates the wire error channel; anything but the strings
        # "true"/"false" would be silently read as false. A misspelled key
        # would too -- with no diagnostic at all -- so function entries also
        # reject keys outside the known set.
        known_fn_keys = {
            "name", "return", "params", "fallible", "description",
            "instance", "constraints", "unimplemented_functions",
        }
        for holder in ns.get("traits", []) + [ns]:
            for fn in holder.get("functions", []):
                if "fallible" in fn:
                    f.check(
                        fn["fallible"] in ("true", "false"),
                        f"{ns_name}.{fn['name']}: fallible must be the string "
                        f"'true' or 'false', not {fn['fallible']!r}",
                    )
                for key in fn:
                    f.check(
                        key in known_fn_keys,
                        f"{ns_name}.{fn['name']}: unknown key {key!r} "
                        f"(misspelled 'fallible'?)",
                    )

        # A duplicated type name across namespaces silently shadows.
        for key in ("byte_aliases", "structs", "enums"):
            for entry in ns.get(key, []):
                prior = seen_names.get(entry["name"])
                f.check(
                    prior is None,
                    f"{ns_name}.{entry['name']}: name already defined in {prior}",
                )
                seen_names.setdefault(entry["name"], ns_name)

    # ── The wire status contract ─────────────────────────────────────────
    # Every export's return is prefixed with a 2-byte StatusCode. The enum
    # must exist, Ok must be 0 (the value infallible exports always send),
    # and Ok must NOT be the default member: the default is what an
    # unrecognized code decodes to, and an unknown code must never read as
    # success.
    status = next(
        (
            e
            for e in schema.get("aloecrypt_api", {}).get("enums", [])
            if e["name"] == "StatusCode"
        ),
        None,
    )
    f.check(status is not None, "aloecrypt_api.StatusCode: enum is missing")
    if status is not None:
        members = {m["name"]: m for m in status.get("members", [])}
        ok = members.get("Ok")
        f.check(
            ok is not None and str(ok["discriminant"]).strip() == "0",
            "aloecrypt_api.StatusCode: needs an Ok member with discriminant 0",
        )
        f.check(
            ok is not None and str(ok.get("default", "")).strip() != "true",
            "aloecrypt_api.StatusCode: Ok must not be the default member -- "
            "an unrecognized code would decode as success",
        )
        f.check(
            status.get("repr_type") == "u16",
            "aloecrypt_api.StatusCode: repr_type must be u16 (the wire "
            "prefix is 2 bytes)",
        )

    # ── Cross-check against what meta.py actually loaded ─────────────────
    # This is the check that catches silent drops: the raw schema can be
    # well-formed by the rules above and still lose a struct to size
    # resolution.
    meta = load_meta(schema_path)
    for ns_name, ns in schema.items():
        if not isinstance(ns, dict):
            continue
        for s in ns.get("structs", []):
            f.check(
                s["name"] in meta.meta_structs,
                f"{ns_name}.{s['name']}: declared in the schema but dropped by "
                f"meta.py (a field type has no known size?)",
            )
            f.check(
                meta.type_sizes.get(s["name"]) is not None,
                f"{ns_name}.{s['name']}: size could not be resolved",
            )
        for t in ns.get("traits", []):
            f.check(
                t["name"] in meta.meta_traits,
                f"{ns_name}.{t['name']}: declared in the schema but dropped by "
                f"meta.py",
            )
        for fn in ns.get("functions", []):
            f.check(
                fn["name"] in meta.meta_functions,
                f"{ns_name}.{fn['name']}: declared in the schema but dropped "
                f"by meta.py",
            )

    # ── Report ───────────────────────────────────────────────────────────
    if f.errors:
        print(f"schema lint: {len(f.errors)} problem(s) in {f.checked} checks\n")
        for e in f.errors:
            print(f"  ERROR  {e}")
        return 1

    print(
        f"schema lint: {f.checked} checks passed "
        f"({len(meta.meta_structs)} structs, {len(meta.meta_traits)} traits, "
        f"{len(meta.meta_enums)} enums, {len(meta.meta_trait_impls)} impls)"
    )
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SCHEMA
    if not Path(path).exists():
        print(f"schema lint: {path} not found -- run `cargo build --lib` first")
        raise SystemExit(2)
    raise SystemExit(lint(path))
