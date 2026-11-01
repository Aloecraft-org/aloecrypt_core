"""
gen_ts.py - TypeScript code generator.

Emits:
  - TypeScript interfaces for each trait
  - TypeScript classes for each struct (with to_bytes / from_bytes)
  - Pack/unpack helpers for the wire format
  - Extism call wrapper functions for each plugin export
"""

from meta import (
    APIMetaData, MetaStruct, MetaTrait, MetaFunction, MetaFnParam,
    MetaByteAlias, MetaConst, MetaEnum, MetaField,
    is_varlen, is_primitive, strip_ref, PRIMITIVE_TYPES, load_meta
)
from wire import WireCall, PackedField, STATUS_PREFIX_SZ, USIZE_WIRE_SZ
from gen_base import LangGenerator
from pathlib import Path

GEN_DIR = Path(".generated", "gen_ts")
MERGED_SCHEMA = Path(".generated", "api_core_merged.json")


# ── Type mapping ─────────────────────────────────────────────────────────────

TS_TYPE_MAP = {
    "u8": "number",
    "u16": "number",
    "u32": "number",
    "u64": "bigint",
    "u128": "bigint",
    "i8": "number",
    "i16": "number",
    "i32": "number",
    "i64": "bigint",
    "i128": "bigint",
    "bool": "boolean",
    "&[u8]": "Uint8Array",
    # No wire encoding is defined for &[u16] yet; like gen_py, the caller
    # passes the little-endian bytes through unchanged.
    "&[u16]": "Uint8Array",
    "&str": "string",
    "Vec<u8>": "Uint8Array",
    "String": "string",
    "usize": "number",
}


def ts_map_type(canonical: str) -> str:
    t = canonical.strip()
    if t in TS_TYPE_MAP:
        return TS_TYPE_MAP[t]
    inner = strip_ref(t)
    if inner in TS_TYPE_MAP:
        return TS_TYPE_MAP[inner]
    return inner


# Signed integers: (byte size, pack helper, DataView getter).
TS_SIGNED = {
    "i8": (1, "packI8", "getInt8"),
    "i16": (2, "packI16", "getInt16"),
    "i32": (4, "packI32", "getInt32"),
    "i64": (8, "packI64", "getBigInt64"),
}


def ts_map_return(canonical: str, struct_context: str | None) -> str:
    if strip_ref(canonical.strip()) == "Self":
        return struct_context if struct_context else "unknown"
    return ts_map_type(canonical)


# ── Generator ────────────────────────────────────────────────────────────────

class TypeScriptGenerator(LangGenerator):

    def map_type(self, canonical_type: str) -> str:
        return ts_map_type(canonical_type)

    def map_return_type(self, canonical_type: str, struct_context: str | None) -> str:
        return ts_map_return(canonical_type, struct_context)

    def file_header(self) -> list[str]:
        return [
            "/**",
            " * Auto-generated TypeScript bindings for aloecrypt_core Extism plugin.",
            " * Do not edit manually.",
            " */",
            "",
            "/**",
            " * The slice of the Extism JS SDK's Plugin these bindings use:",
            " * `call` resolves to a PluginOutput (which has `bytes()`) or null.",
            " */",
            "export interface ExtismPlugin {",
            "  call(funcName: string, input?: Uint8Array): Promise<{ bytes(): Uint8Array } | null>;",
            "}",
            "",
        ]

    def file_footer(self) -> list[str]:
        return []

    def section_comment(self, title: str) -> str:
        return f"// {'=' * 60}\n// {title}\n// {'=' * 60}"

    # ── Constants ─────────────────────────────────────────────────────────

    def emit_constants(self, consts: dict[str, MetaConst]) -> list[str]:
        lines = []
        for c in consts.values():
            lines.append(f"export const {c.name}: number = {c.value};")
        return lines

    # ── Byte aliases ──────────────────────────────────────────────────────

    def emit_byte_aliases(self, aliases: dict[str, MetaByteAlias]) -> list[str]:
        lines = []
        for a in aliases.values():
            lines.append(f"/** {a.name}: {a.length} bytes ({a.len_str}) */")
            lines.append(f"export type {a.name} = Uint8Array;")
            lines.append(f"export const {a.name}_SZ: number = {a.length};")
            lines.append("")
        return lines

    # ── Enums ─────────────────────────────────────────────────────────────

    def emit_enum(self, enum: MetaEnum) -> list[str]:
        """Flat numeric constants, mirroring the Rust #[repr(transparent)] newtype."""
        lines = []
        if enum.description:
            lines.append(f"/** {enum.description} */")
        lines.append(f"/** Flat {enum.repr_type} ({enum.size} bytes) on the wire. */")
        lines.append(f"export type {enum.name} = number;")
        lines.append(f"export const {enum.name} = {{")
        for m in enum.members:
            note = f"  // {m.description}" if m.description else ""
            lines.append(f"  {m.name}: {m.discriminant},{note}")
        lines.append("} as const;")
        lines.append(f"export const {enum.name}_SZ: number = {enum.size};")
        return lines

    # ── Traits ────────────────────────────────────────────────────────────

    def emit_trait(self, trait: MetaTrait) -> list[str]:
        lines = []
        lines.append(f"export interface {trait.name} {{")
        for func in trait.functions.values():
            sig = self._ts_interface_method(func, trait.name)
            lines.append(f"  {sig}")
        lines.append("}")
        return lines

    def _ts_interface_method(self, func: MetaFunction, trait_name: str) -> str:
        params = []
        for p in func.params.values():
            if not p.is_rng:
                ts_type = self.map_type(p.type_str)
                params.append(f"{p.name}: {ts_type}")

        ret = "void"
        if func.ret_str:
            ret = self.map_return_type(func.ret_str, trait_name)

        return f"{func.name}({', '.join(params)}): {ret};"

    # ── Structs ───────────────────────────────────────────────────────────

    def emit_struct(self, struct: MetaStruct) -> list[str]:
        lines = []
        sz = self.meta.type_sizes.get(struct.name)
        # No `implements`: the trait interfaces mirror the Rust signatures,
        # while here each method is an async wire call taking a plugin.
        impl_list = [tn for tn in struct.traits if tn in self.meta.meta_traits]
        implements = ""
        if impl_list:
            lines.append(f"/** Rust traits: {', '.join(impl_list)}. Methods are the {struct.name.lower()}__* wrappers. */")

        if struct.description:
            lines.append(f"/** {struct.description} */")
        lines.append(f"export class {struct.name}{implements} {{")

        if sz is not None:
            lines.append(f"  static readonly SIZE: number = {sz};")
            lines.append("")

        # Fields
        for f in struct.fields:
            ts_type = self.map_type(f.type_name)
            desc = f"  /** {f.description} */" if f.description else None
            if desc:
                lines.append(desc)
            lines.append(f"  {f.name}: {ts_type};")
        lines.append("")

        # Constructor
        lines += self._emit_constructor(struct)
        lines.append("")

        # toBytes
        lines += self._emit_to_bytes(struct)
        lines.append("")

        # fromBytes
        lines += self._emit_from_bytes(struct)

        lines.append("}")
        return lines

    def _emit_constructor(self, struct: MetaStruct) -> list[str]:
        lines = []
        params = []
        for f in struct.fields:
            ts_type = self.map_type(f.type_name)
            params.append(f"{f.name}: {ts_type}")
        lines.append(f"  constructor({', '.join(params)}) {{")
        for f in struct.fields:
            lines.append(f"    this.{f.name} = {f.name};")
        lines.append("  }")
        return lines

    def _emit_to_bytes(self, struct: MetaStruct) -> list[str]:
        sz = self.meta.type_sizes.get(struct.name)
        lines = []
        lines.append("  toBytes(): Uint8Array {")
        lines.append("    const parts: Uint8Array[] = [];")

        for f in struct.fields:
            lines.append(f"    parts.push({self._field_pack_ts(f)});")

        lines.append("    return concatBytes(parts);")
        lines.append("  }")
        return lines

    def _emit_from_bytes(self, struct: MetaStruct) -> list[str]:
        lines = []
        lines.append(f"  static fromBytes(data: Uint8Array): {struct.name} {{")
        lines.append("    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);")
        lines.append("    let offset = 0;")

        for f in struct.fields:
            lines += self._field_unpack_ts(f, indent="    ")

        args = ", ".join(f.name for f in struct.fields)
        lines.append(f"    return new {struct.name}({args});")
        lines.append("  }")
        return lines

    def _enum_repr(self, type_name: str) -> str | None:
        """If this type is a schema enum, the primitive it is represented as."""
        enum = self.meta.meta_enums.get(type_name.strip())
        return enum.repr_type if enum else None

    def _field_pack_ts(self, f: MetaField) -> str:
        t = f.type_name.strip()
        # Enums are flat values over their repr type on the wire.
        t = self._enum_repr(t) or t
        if t == "u8":
            return f"new Uint8Array([this.{f.name}])"
        elif t == "u16":
            return f"packU16(this.{f.name})"
        elif t == "u32":
            return f"packU32(this.{f.name})"
        elif t == "u64":
            return f"packU64(this.{f.name})"
        elif t == "u128":
            return f"packU128(this.{f.name})"
        elif t == "bool":
            return f"new Uint8Array([this.{f.name} ? 1 : 0])"
        elif t in TS_SIGNED:
            return f"{TS_SIGNED[t][1]}(this.{f.name})"
        elif t in self.meta.meta_structs:
            return f"this.{f.name}.toBytes()"
        else:
            return f"this.{f.name}"

    def _field_unpack_ts(self, f: MetaField, indent: str) -> list[str]:
        lines = []
        t = f.type_name.strip()
        t = self._enum_repr(t) or t
        if t == "u8":
            lines.append(f"{indent}const {f.name} = data[offset];")
            lines.append(f"{indent}offset += 1;")
        elif t == "u16":
            lines.append(f"{indent}const {f.name} = view.getUint16(offset, true);")
            lines.append(f"{indent}offset += 2;")
        elif t == "u32":
            lines.append(f"{indent}const {f.name} = view.getUint32(offset, true);")
            lines.append(f"{indent}offset += 4;")
        elif t == "u64":
            lines.append(f"{indent}const {f.name} = view.getBigUint64(offset, true);")
            lines.append(f"{indent}offset += 8;")
        elif t == "u128":
            lines.append(f"{indent}const {f.name}_lo = view.getBigUint64(offset, true);")
            lines.append(f"{indent}const {f.name}_hi = view.getBigUint64(offset + 8, true);")
            lines.append(f"{indent}const {f.name} = {f.name}_lo | ({f.name}_hi << 64n);")
            lines.append(f"{indent}offset += 16;")
        elif t == "bool":
            lines.append(f"{indent}const {f.name} = data[offset] !== 0;")
            lines.append(f"{indent}offset += 1;")
        elif t in TS_SIGNED:
            sz, _, getter = TS_SIGNED[t]
            lines.append(f"{indent}const {f.name} = view.{getter}(offset, true);")
            lines.append(f"{indent}offset += {sz};")
        else:
            sz = self.meta.type_sizes.get(t)
            if t in self.meta.meta_structs:
                lines.append(f"{indent}const {f.name} = {t}.fromBytes(data.slice(offset, offset + {sz}));")
            else:
                lines.append(f"{indent}const {f.name} = data.slice(offset, offset + {sz});")
            lines.append(f"{indent}offset += {sz};")
        return lines

    # ── Wire format helpers ───────────────────────────────────────────────

    def emit_pack_helpers(self) -> list[str]:
        return [
            "export class AloecryptStatusError extends Error {",
            "  readonly code: number;",
            "  constructor(code: number) {",
            "    super(`plugin returned status ${code}`);",
            "    this.code = code;",
            "  }",
            "}",
            "",
            "// Every export replies with a little-endian u16 StatusCode ahead of its",
            "// payload; the payload is absent on any non-Ok status. A reply shorter",
            "// than the prefix, or an Ok payload of the wrong fixed size, is",
            "// Unspecified rather than short or shifted bytes. expectedSize is",
            "// undefined only for variable-length returns.",
            "function checkStatus(output: { bytes(): Uint8Array } | null, expectedSize?: number): Uint8Array {",
            "  const result = output ? output.bytes() : new Uint8Array(0);",
            f"  if (result.length < {STATUS_PREFIX_SZ}) throw new AloecryptStatusError(StatusCode.Unspecified);",
            "  const status = new DataView(result.buffer, result.byteOffset, result.byteLength).getUint16(0, true);",
            "  if (status !== StatusCode.Ok) throw new AloecryptStatusError(status);",
            f"  const payload = result.slice({STATUS_PREFIX_SZ});",
            "  if (expectedSize !== undefined && payload.length !== expectedSize) {",
            "    throw new AloecryptStatusError(StatusCode.Unspecified);",
            "  }",
            "  return payload;",
            "}",
            "",
            "function readUint(data: Uint8Array): bigint {",
            "  let v = 0n;",
            "  for (let i = data.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(data[i]);",
            "  return v;",
            "}",
            "",
            "function concatBytes(arrays: Uint8Array[]): Uint8Array {",
            "  const totalLen = arrays.reduce((acc, a) => acc + a.length, 0);",
            "  const result = new Uint8Array(totalLen);",
            "  let offset = 0;",
            "  for (const arr of arrays) {",
            "    result.set(arr, offset);",
            "    offset += arr.length;",
            "  }",
            "  return result;",
            "}",
            "",
            "function packVarlen(data: Uint8Array): Uint8Array {",
            "  const len = packU32(data.length);",
            "  return concatBytes([len, data]);",
            "}",
            "",
            "function packStr(s: string): Uint8Array {",
            "  const encoded = new TextEncoder().encode(s);",
            "  return packVarlen(encoded);",
            "}",
            "",
            "function unpackVarlen(data: Uint8Array, offset: number): [Uint8Array, number] {",
            "  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);",
            "  const len = view.getUint32(offset, true);",
            "  const start = offset + 4;",
            "  return [data.slice(start, start + len), start + len];",
            "}",
            "",
            "function unpackStr(data: Uint8Array, offset: number): [string, number] {",
            "  const [raw, newOffset] = unpackVarlen(data, offset);",
            "  return [new TextDecoder().decode(raw), newOffset];",
            "}",
            "",
            "function packU16(v: number): Uint8Array {",
            "  const buf = new Uint8Array(2);",
            "  new DataView(buf.buffer).setUint16(0, v, true);",
            "  return buf;",
            "}",
            "",
            "function packU32(v: number): Uint8Array {",
            "  const buf = new Uint8Array(4);",
            "  new DataView(buf.buffer).setUint32(0, v, true);",
            "  return buf;",
            "}",
            "",
            "function packU64(v: bigint): Uint8Array {",
            "  const buf = new Uint8Array(8);",
            "  new DataView(buf.buffer).setBigUint64(0, v, true);",
            "  return buf;",
            "}",
            "",
            "function packI8(v: number): Uint8Array {",
            "  const buf = new Uint8Array(1);",
            "  new DataView(buf.buffer).setInt8(0, v);",
            "  return buf;",
            "}",
            "",
            "function packI16(v: number): Uint8Array {",
            "  const buf = new Uint8Array(2);",
            "  new DataView(buf.buffer).setInt16(0, v, true);",
            "  return buf;",
            "}",
            "",
            "function packI32(v: number): Uint8Array {",
            "  const buf = new Uint8Array(4);",
            "  new DataView(buf.buffer).setInt32(0, v, true);",
            "  return buf;",
            "}",
            "",
            "function packI64(v: bigint): Uint8Array {",
            "  const buf = new Uint8Array(8);",
            "  new DataView(buf.buffer).setBigInt64(0, v, true);",
            "  return buf;",
            "}",
            "",
            "function packU128(v: bigint): Uint8Array {",
            "  const buf = new Uint8Array(16);",
            "  const view = new DataView(buf.buffer);",
            "  view.setBigUint64(0, v & 0xFFFFFFFFFFFFFFFFn, true);",
            "  view.setBigUint64(8, v >> 64n, true);",
            "  return buf;",
            "}",
            "",
        ]

    # ── Call wrappers ─────────────────────────────────────────────────────

    def emit_call_wrapper(self, call: WireCall) -> list[str]:
        lines = []

        # Build TS function signature
        ts_params = []
        if call.struct_name and call.instance_field:
            ts_params.append(f"instance: {call.struct_name}")
        for pf in call.param_fields:
            ts_params.append(f"{pf.name}: {self.map_type(pf.type_str)}")
        ts_params.append("plugin: ExtismPlugin")

        ret_ts = "void"
        if call.return_type:
            ret_ts = self.map_return_type(call.return_type, call.struct_name)

        sig = f"export async function {call.export_name}({', '.join(ts_params)}): Promise<{ret_ts}> {{"
        if call.fallible:
            lines.append("/** Throws AloecryptStatusError on a non-Ok status. */")
        lines.append(sig)

        # Pack
        lines.append("  const parts: Uint8Array[] = [];")
        if call.instance_field:
            lines.append("  parts.push(instance.toBytes());")

        for pf in call.param_fields:
            lines.append(f"  parts.push({self._pack_expr_ts(pf)});")

        lines.append("  const payload = concatBytes(parts);")
        expected = self._expected_payload_size(call)
        expected_arg = "" if expected is None else f", {expected}"
        lines.append(
            f"  const result = checkStatus(await plugin.call('{call.export_name}', payload){expected_arg});"
        )

        # Unpack
        rt = (call.return_type or "").strip()
        inner = strip_ref(rt).strip()
        if call.return_type is None:
            pass
        elif rt == "bool":
            lines.append("  return result[0] !== 0;")
        elif inner == "Self" and call.struct_name:
            lines.append(f"  return {call.struct_name}.fromBytes(result);")
        elif rt == "&str":
            lines.append("  return new TextDecoder().decode(result);")
        elif inner in self.meta.meta_structs:
            lines.append(f"  return {inner}.fromBytes(result);")
        elif inner in self.meta.meta_enums or inner in ("u8", "u16", "u32", "usize"):
            lines.append("  return Number(readUint(result));")
        elif inner in ("u64", "u128"):
            lines.append("  return readUint(result);")
        elif inner in TS_SIGNED:
            sz, _, getter = TS_SIGNED[inner]
            lines.append(f"  return new DataView(result.buffer, result.byteOffset, result.byteLength).{getter}(0, true);")
        else:
            # byte alias, &[u8]
            lines.append("  return result;")

        lines.append("}")
        return lines

    def _expected_payload_size(self, call: WireCall) -> int | None:
        """Exact Ok payload length, or None for &str / &[u8]. Mirrors gen_py."""
        rt = (call.return_type or "").strip()
        if not rt:
            return 0
        if rt in ("&str", "&[u8]"):
            return None
        if rt == "bool":
            return 1
        inner = strip_ref(rt).strip()
        if inner == "Self":
            return self.meta.type_sizes.get(call.struct_name)
        if inner == "usize":
            return USIZE_WIRE_SZ
        return self.meta.type_sizes.get(inner)

    def _pack_expr_ts(self, pf: PackedField) -> str:
        t = pf.type_str
        if is_varlen(t):
            if t == "&str":
                return f"packStr({pf.name})"
            return f"packVarlen({pf.name})"
        inner = strip_ref(t)
        # Enums are flat values over their repr type on the wire.
        inner = self._enum_repr(inner) or inner
        if inner in TS_SIGNED:
            return f"{TS_SIGNED[inner][1]}({pf.name})"
        if inner == "usize":
            return f"packU64(BigInt({pf.name}))"
        if inner == "u8":
            return f"new Uint8Array([{pf.name}])"
        elif inner == "u16":
            return f"packU16({pf.name})"
        elif inner == "u32":
            return f"packU32({pf.name})"
        elif inner == "u64":
            return f"packU64({pf.name})"
        elif inner == "u128":
            return f"packU128({pf.name})"
        elif inner in self.meta.meta_structs:
            return f"{pf.name}.toBytes()"
        else:
            return pf.name

    # ── Signature helper (for interfaces) ─────────────────────────────────

    def _ts_signature(self, func: MetaFunction, context_name: str) -> str:
        params = []
        for p in func.params.values():
            if not p.is_rng:
                params.append(f"{p.name}: {self.map_type(p.type_str)}")
        ret = "void"
        if func.ret_str:
            ret = self.map_return_type(func.ret_str, context_name)
        return f"{func.name}({', '.join(params)}): {ret}"


    # ── Namespaces ────────────────────────────────────────────────────────

    def emit_namespace_wrappers(self) -> list[str]:
        """Struct classes at top level, then one TS namespace per schema
        namespace re-exporting its standalone functions."""
        lines = []
        for struct in self.meta.meta_structs.values():
            lines += self.emit_struct(struct)
            lines.append("")

        ns_functions: dict[str, list[str]] = {}
        for func in self.meta.meta_functions.values():
            ns_functions.setdefault(func.namespace, []).append(func.name)

        for ns in self.meta.namespaces:
            fnames = ns_functions.get(ns, [])
            if not fnames:
                continue
            lines.append(f"export namespace {ns} {{")
            for fname in fnames:
                func = self.meta.meta_functions[fname]
                params, call_args = [], []
                for param in func.params.values():
                    if not param.is_rng:
                        params.append(f"{param.name}: {self.map_type(param.type_str)}")
                        call_args.append(param.name)
                params.append("plugin: ExtismPlugin")
                call_args.append("plugin")
                ret_ts = self.map_return_type(func.ret_str, None) if func.ret_str else "void"
                lines.append(f"  export function {fname}({', '.join(params)}): Promise<{ret_ts}> {{")
                lines.append(f"    return {ns}___{fname}({', '.join(call_args)});")
                lines.append("  }")
            lines.append("}")
            lines.append("")
        return lines


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    meta = load_meta(str(MERGED_SCHEMA))
    gen = TypeScriptGenerator(meta)
    output = gen.generate()
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    outpath = GEN_DIR / "aloecrypt_core.ts"
    outpath.write_text(output)
    print(f"Generated {outpath} ({len(output)} bytes)")


if __name__ == "__main__":
    main()