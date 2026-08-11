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

        # A duplicated type name across namespaces silently shadows.
        for key in ("byte_aliases", "structs", "enums"):
            for entry in ns.get(key, []):
                prior = seen_names.get(entry["name"])
                f.check(
                    prior is None,
                    f"{ns_name}.{entry['name']}: name already defined in {prior}",
                )
                seen_names.setdefault(entry["name"], ns_name)

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
