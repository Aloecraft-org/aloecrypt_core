"""
gen_py.py - Python code generator.

Emits:
  - Pydantic BaseModel classes for each struct
  - ABC abstract classes for each trait
  - Pack/unpack helpers for the wire format
  - Extism call wrapper functions for each plugin export
"""

from meta import (
    APIMetaData, MetaStruct, MetaTrait, MetaFunction, MetaFnParam,
    MetaByteAlias, MetaConst, MetaField, MetaEnum,
    is_varlen, is_primitive, strip_ref, PRIMITIVE_TYPES, load_meta
)
from wire import WireCall, PackedField, build_wire_calls
from gen_base import LangGenerator
from pathlib import Path

GEN_DIR = Path(".generated", "gen_py")
API_DIR = GEN_DIR / "api"

# ── Type mapping ─────────────────────────────────────────────────────────────

PY_TYPE_MAP = {
    "u8": "int",
    "u16": "int",
    "u32": "int",
    "u64": "int",
    "u128": "int",
    "i8": "int",
    "i16": "int",
    "i32": "int",
    "i64": "int",
    "i128": "int",
    "bool": "bool",
    "&[u8]": "bytes",
    "&str": "str",
    "Vec<u8>": "bytes",
    "String": "str",
    "usize": "int",
}


def py_map_type(canonical: str) -> str:
    t = canonical.strip()
    # Check direct map
    if t in PY_TYPE_MAP:
        return PY_TYPE_MAP[t]
    # Strip reference
    inner = strip_ref(t)
    if inner in PY_TYPE_MAP:
        return PY_TYPE_MAP[inner]
    # Struct/alias name passes through
    return inner


def py_map_return(canonical: str, struct_context: str | None) -> str:
    if canonical == "Self":
        return struct_context if struct_context else "Self"
    return py_map_type(canonical)


# ── Generator ────────────────────────────────────────────────────────────────

class PythonGenerator(LangGenerator):

    def map_type(self, canonical_type: str) -> str:
        return py_map_type(canonical_type)

    def map_return_type(self, canonical_type: str, struct_context: str | None) -> str:
        return py_map_return(canonical_type, struct_context)

    def file_header(self) -> list[str]:
        return [
            '"""',
            "Auto-generated Python bindings for aloecrypt_core Extism plugin.",
            "Do not edit manually.",
            '"""',
            "",
            "from __future__ import annotations",
            "import struct as _struct",
            "from abc import ABC, abstractmethod",
            "from dataclasses import dataclass, field",
            "from typing import Optional, ClassVar",
            "from enum import IntEnum",
        ]

    def file_footer(self) -> list[str]:
        return []

    def emit_namespace_wrappers(self) -> list[str]:
        lines = []

        # Collect structs and standalone functions per namespace
        ns_structs: dict[str, list[str]] = {}
        ns_functions: dict[str, list[str]] = {}

        for struct in self.meta.meta_structs.values():
            ns_structs.setdefault(struct.namespace, []).append(struct.name)

        for func in self.meta.meta_functions.values():
            ns_functions.setdefault(func.namespace, []).append(func.name)

        all_ns = set(ns_structs.keys()) | set(ns_functions.keys())
        for ns in self.meta.namespaces:
            if ns not in all_ns:
                all_ns.add(ns)

        for ns in sorted(all_ns):
            lines.append(f"class {ns}:")
            has_content = False

            # Emit structs as inner classes (indented one level)
            for sname in ns_structs.get(ns, []):
                struct = self.meta.meta_structs[sname]
                struct_lines = self.emit_struct(struct)
                for sl in struct_lines:
                    lines.append(f"    {sl}" if sl.strip() else "")
                lines.append("")
                has_content = True

            # Emit standalone functions as static methods
            for fname in ns_functions.get(ns, []):
                func = self.meta.meta_functions[fname]
                export_name = f"{ns}___{fname}"

                params = []
                for param in func.params.values():
                    if not param.is_rng:
                        py_type = self.map_type(param.type_str)
                        params.append(f"{param.name}: \"{py_type}\"")

                ret = ""
                if func.ret_str:
                    ret_type = self.map_return_type(func.ret_str, None)
                    ret = f" -> \"{ret_type}\""

                call_args = [p.name for p in func.params.values() if not p.is_rng]
                call_args.append("_Plugin().plugin")

                lines.append(f"    @staticmethod")
                lines.append(f"    def {fname}({', '.join(params)}){ret}:")
                lines.append(f"        return {export_name}({', '.join(call_args)})")
                lines.append("")
                has_content = True

            if not has_content:
                lines.append("    pass")

            lines.append("")

        # Top-level aliases for convenience imports
        lines.append(self.section_comment("Top-level Aliases"))
        for ns in sorted(all_ns):
            for sname in ns_structs.get(ns, []):
                lines.append(f"{sname} = {ns}.{sname}")

        lines.append("")
        return lines

    def section_comment(self, title: str) -> str:
        bar = "=" * 60
        return f"# {bar}\n# {title}\n# {bar}"

    # ── Constants ─────────────────────────────────────────────────────────

    def emit_constants(self, consts: dict[str, MetaConst]) -> list[str]:
        lines = []
        for c in consts.values():
            lines.append(f"{c.name}: int = {c.value}")
        return lines

    # ── Enums ─────────────────────────────────────────────────────────────

    def emit_enums(self, enums: dict[str, MetaEnum]) -> list[str]:
        lines = []
        for e in enums.values():
            lines.append(f"class {e.name}(IntEnum):")
            if e.description:
                lines.append(f'    """{e.description}"""')
            for m in e.members:
                desc = f"  # {m.description}" if m.description else ""
                lines.append(f"    {m.name} = {m.discriminant}{desc}")
            lines.append("")
        return lines

    # ── Byte aliases ──────────────────────────────────────────────────────

    def emit_byte_aliases(self, aliases: dict[str, MetaByteAlias]) -> list[str]:
        lines = []
        for a in aliases.values():
            lines.append(f"class {a.name}(bytes):")
            lines.append(f'    """{a.length} bytes ({a.len_str})"""')
            lines.append(f"    SZ: ClassVar[int] = {a.length}")
            lines.append(f"    def __new__(cls, data: bytes = None) -> \"{a.name}\":")
            lines.append(f"        if data is None:")
            lines.append(f"            return super().__new__(cls, bytes({a.length}))")
            lines.append(f"        return super().__new__(cls, data)")
            lines.append(f"    @classmethod")
            lines.append(f"    def newrand(cls) -> \"{a.name}\":")
            lines.append(f"        import random")
            lines.append(f"        return cls(random.randbytes({a.length}))")
            lines.append(f"{a.name}_SZ: int = {a.length}")
            lines.append("")
        return lines

    # ── Traits ────────────────────────────────────────────────────────────

    def emit_trait(self, trait: MetaTrait) -> list[str]:
        lines = []
        generics = f"[{', '.join(trait.generics)}]" if trait.generics else ""
        lines.append(f"class {trait.name}{generics}(ABC):")
        if not trait.functions:
            lines.append("    pass")
            return lines

        for func in trait.functions.values():
            lines += self._emit_trait_method(func, trait.name)
            lines.append("")
        return lines

    def _emit_trait_method(self, func: MetaFunction, trait_name: str) -> list[str]:
        lines = []
        if func.is_class_function:
            lines.append("    @classmethod")
        lines.append("    @abstractmethod")
        lines.append(f"    {self._py_signature(func, trait_name)}")
        lines.append("        pass")
        return lines

    # ── Structs ───────────────────────────────────────────────────────────

    def emit_struct(self, struct: MetaStruct) -> list[str]:
        lines = []

        # Build base class list — traits already extend ABC, so don't duplicate
        trait_names = [
            tn for tn in struct.traits if tn in self.meta.meta_traits
        ]
        bases = trait_names if trait_names else []

        bases_str = f"({', '.join(bases)})" if bases else ""

        lines.append(f"@dataclass")
        lines.append(f"class {struct.name}{bases_str}:")
        if struct.description:
            lines.append(f'    """{struct.description}"""')

        # Size class var
        sz = self.meta.type_sizes.get(struct.name)
        if sz is not None:
            lines.append(f"    SIZE: ClassVar[int] = {sz}")
            lines.append("")

        # Fields
        for f in struct.fields:
            py_type = self.map_type(f.type_name)
            default = self._field_default(f)
            desc = f"  # {f.description}" if f.description else ""
            lines.append(f"    {f.name}: {py_type}{default}{desc}")

        lines.append("")

        # to_bytes / from_bytes
        lines += self._emit_struct_pack_methods(struct)
        lines.append("")

        # Trait method stubs (skip methods already defined as pack/unpack)
        builtin_methods = {"to_bytes", "from_bytes"}
        for tn in trait_names:
            trait = self.meta.meta_traits[tn]
            for func in trait.functions.values():
                if func.name in builtin_methods:
                    continue
                lines += self._emit_struct_trait_method(func, struct.name, tn)
                lines.append("")

        return lines

    def _field_default(self, f: MetaField) -> str:
        t = f.type_name.strip()
        if t in PRIMITIVE_TYPES:
            return " = 0"
        if t in self.meta.meta_enums:
            e = self.meta.meta_enums[t]
            default_member = next((m for m in e.members if m.is_default), e.members[0])
            return f" = {t}.{default_member.name}"
        # Byte alias or struct — default to empty bytes
        sz = self.meta.type_sizes.get(t)
        if sz is not None:
            return f" = field(default_factory=lambda: bytes({sz}))"
        return f" = field(default_factory=bytes)"

    def _emit_struct_trait_method(self, func: MetaFunction, struct_name: str, trait_name: str) -> list[str]:
        lines = []
        export_name = f"{func.namespace}___{struct_name.lower()}__{func.name}"

        if func.is_class_function:
            lines.append("    @classmethod")

        sig = self._py_signature(func, struct_name)
        lines.append(f"    {sig}")
        lines.append(f'        """Trait: {trait_name}"""')

        # Build the call: delegate to the standalone wrapper
        call_args = []
        if func.is_instance_function:
            call_args.append("self")
        for param in func.params.values():
            if not param.is_rng:
                call_args.append(param.name)
        call_args.append("_Plugin().plugin")

        if func.is_class_function and func.returns_self:
            # Constructor-style: cls wraps the result
            lines.append(f"        return {export_name}({', '.join(call_args)})")
        else:
            lines.append(f"        return {export_name}({', '.join(call_args)})")
        return lines

    def _emit_struct_pack_methods(self, struct: MetaStruct) -> list[str]:
        lines = []
        sz = self.meta.type_sizes.get(struct.name)
        if sz is None:
            return lines

        # pack
        lines.append("    def pack(self) -> bytes:")
        lines.append("        parts = []")
        for f in struct.fields:
            lines.append(f"        parts.append({self._field_pack_expr(f)})")
        lines.append("        return b''.join(parts)")
        lines.append("")

        # unpack
        lines.append("    @classmethod")
        lines.append(f"    def unpack(cls, data: bytes) -> \"{struct.name}\":")
        lines.append("        offset = 0")
        for f in struct.fields:
            lines += self._field_unpack_lines(f, indent="        ")
        lines.append(f"        return cls({self._from_bytes_args(struct)})")
        return lines

    def _field_pack_expr(self, f: MetaField) -> str:
        t = f.type_name.strip()
        if t in self.meta.meta_enums:
            t = self.meta.meta_enums[t].repr_type
        if t == "u8":
            return f"_struct.pack('<B', self.{f.name})"
        elif t == "u16":
            return f"_struct.pack('<H', self.{f.name})"
        elif t == "u32":
            return f"_struct.pack('<I', self.{f.name})"
        elif t == "u64":
            return f"_struct.pack('<Q', self.{f.name})"
        elif t == "u128":
            return f"self.{f.name}.to_bytes(16, 'little')"
        elif t == "bool":
            return f"_struct.pack('<B', 1 if self.{f.name} else 0)"
        else:
            # byte alias or nested struct — already bytes
            sz = self.meta.type_sizes.get(t)
            if sz and t in self.meta.meta_structs:
                return f"self.{f.name}.pack()"
            return f"self.{f.name}"

    def _field_unpack_lines(self, f: MetaField, indent: str) -> list[str]:
        lines = []
        t = f.type_name.strip()
        enum_type = None
        if t in self.meta.meta_enums:
            enum_type = t
            t = self.meta.meta_enums[t].repr_type

        if t == "u8":
            val_expr = "data[offset]"
            offset_inc = 1
        elif t == "u16":
            val_expr = "_struct.unpack_from('<H', data, offset)[0]"
            offset_inc = 2
        elif t == "u32":
            val_expr = "_struct.unpack_from('<I', data, offset)[0]"
            offset_inc = 4
        elif t == "u64":
            val_expr = "_struct.unpack_from('<Q', data, offset)[0]"
            offset_inc = 8
        elif t == "u128":
            val_expr = "int.from_bytes(data[offset:offset+16], 'little')"
            offset_inc = 16
        elif t == "bool":
            val_expr = "data[offset] != 0"
            offset_inc = 1
        else:
            sz = self.meta.type_sizes.get(t)
            if sz and t in self.meta.meta_structs:
                val_expr = f"{t}.unpack(data[offset:offset+{sz}])"
            else:
                val_expr = f"bytes(data[offset:offset+{sz}])"
            offset_inc = sz

        assign_expr = f"{enum_type}({val_expr})" if enum_type else val_expr
        lines.append(f"{indent}{f.name} = {assign_expr}")
        lines.append(f"{indent}offset += {offset_inc}")
        return lines

    def _from_bytes_args(self, struct: MetaStruct) -> str:
        return ", ".join(f"{f.name}={f.name}" for f in struct.fields)

    # ── Wire format helpers ───────────────────────────────────────────────

    def emit_pack_helpers(self) -> list[str]:
        return [
            "def _pack_varlen(data: bytes) -> bytes:",
            "    return _struct.pack('<I', len(data)) + data",
            "",
            "def _pack_str(s: str) -> bytes:",
            "    encoded = s.encode('utf-8')",
            "    return _struct.pack('<I', len(encoded)) + encoded",
            "",
            "def _unpack_varlen(data: bytes, offset: int) -> tuple[bytes, int]:",
            "    length = _struct.unpack_from('<I', data, offset)[0]",
            "    start = offset + 4",
            "    return bytes(data[start:start+length]), start + length",
            "",
            "def _unpack_str(data: bytes, offset: int) -> tuple[str, int]:",
            "    raw, new_offset = _unpack_varlen(data, offset)",
            "    return raw.decode('utf-8'), new_offset",
            "",
            "def _pack_u32(v: int) -> bytes:",
            "    return _struct.pack('<I', v)",
            "",
            "def _pack_u64(v: int) -> bytes:",
            "    return _struct.pack('<Q', v)",
            "",
            "def _pack_u16(v: int) -> bytes:",
            "    return _struct.pack('<H', v)",
            "",
            "def _pack_u128(v: int) -> bytes:",
            "    return v.to_bytes(16, 'little')",
            "",
        ]

    # ── Call wrappers ─────────────────────────────────────────────────────

    def emit_call_wrapper(self, call: WireCall) -> list[str]:
        lines = []

        # Build Python function signature
        py_params = []
        if call.struct_name and call.instance_field:
            py_params.append(f"instance: {call.struct_name}")
        for pf in call.param_fields:
            py_params.append(f"{pf.name}: {self.map_type(pf.type_str)}")
        py_params.append("plugin: 'ExtismPlugin'")

        ret_py = "None"
        if call.return_type:
            ret_py = self.map_return_type(call.return_type, call.struct_name)

        sig = f"def {call.export_name}({', '.join(py_params)}) -> {ret_py}:"
        lines.append(sig)

        # Pack args
        lines.append("    parts: list[bytes] = []")
        if call.instance_field:
            lines.append("    parts.append(instance.pack())")

        for pf in call.param_fields:
            lines.append(f"    parts.append({self._pack_expr(pf)})")

        lines.append("    payload = b''.join(parts)")
        lines.append(f"    result = plugin.call('{call.export_name}', payload)")

        # Unpack result
        if call.return_type is None:
            lines.append("    return")
        elif call.return_type == "bool":
            lines.append("    return result[0] != 0")
        elif call.return_type == "Self" and call.struct_name:
            lines.append(f"    return {call.struct_name}.unpack(result)")
        elif call.return_type.startswith("&"):
            inner = strip_ref(call.return_type)
            if inner in self.meta.meta_structs:
                lines.append(f"    return {inner}.unpack(result)")
            else:
                lines.append("    return bytes(result)")
        elif call.return_type in self.meta.meta_structs:
            lines.append(f"    return {call.return_type}.unpack(result)")
        elif call.return_type in self.meta.meta_enums:
            e = self.meta.meta_enums[call.return_type]
            if e.repr_type == "u8":
                lines.append(f"    return {call.return_type}(result[0])")
            else:
                fmt = {'u16': '<H', 'u32': '<I', 'u64': '<Q'}.get(e.repr_type, '<I')
                lines.append(f"    return {call.return_type}(_struct.unpack('{fmt}', result)[0])")
        else:
            # byte alias
            lines.append("    return bytes(result)")


        return lines

    def _pack_expr(self, pf: PackedField) -> str:
        t = pf.type_str
        if is_varlen(t):
            if t == "&str":
                return f"_pack_str({pf.name})"
            return f"_pack_varlen({pf.name})"
        inner = strip_ref(t)
        if inner in self.meta.meta_enums:
            inner = self.meta.meta_enums[inner].repr_type
        if inner == "u32":
            return f"_pack_u32({pf.name})"
        elif inner == "u64":
            return f"_pack_u64({pf.name})"
        elif inner == "u16":
            return f"_pack_u16({pf.name})"
        elif inner == "u128":
            return f"_pack_u128({pf.name})"
        elif inner == "u8":
            return f"bytes([{pf.name}])"
        elif inner in self.meta.meta_structs:
            return f"{pf.name}.pack()"
        else:
            # byte alias — already bytes
            return pf.name

    # ── Signature helper ──────────────────────────────────────────────────

    def _py_signature(self, func: MetaFunction, context_name: str) -> str:
        args = []
        if func.is_instance_function:
            args.append("self")
        elif func.is_class_function:
            args.append("cls")

        for param in func.params.values():
            if not param.is_rng:
                py_type = self.map_type(param.type_str)
                args.append(f"{param.name}: \"{py_type}\"")
        for param in func.params.values():
            if param.is_rng:
                args.append("seed: int = -1")

        ret = ""
        if func.ret_str:
            ret_type = self.map_return_type(func.ret_str, context_name)
            ret = f" -> \"{ret_type}\""

        return f"def {func.name}({', '.join(args)}){ret}:"


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    API_DIR.mkdir(parents=True, exist_ok=True)

    meta = load_meta(".generated/api_core_merged.json")
    gen = PythonGenerator(meta)
    output = gen.generate()
    outpath = GEN_DIR / "aloecrypt_core.py"
    outpath.write_text(output)
    print(f"Generated {outpath} ({len(output)} bytes)")
    
    # ==========================
    outpath = GEN_DIR / "constants.py"
    # ==========================
    lines = []
    lines.append(gen.section_comment("Constants"))
    lines += gen.emit_constants(gen.meta.meta_consts)
    lines.append("")
    outpath.write_text("\n".join(lines))

    # ==========================
    outpath = GEN_DIR / "types.py"
    # ==========================
    lines = []
    
    # Byte aliases
    lines.append(gen.section_comment("Byte Aliases"))
    lines += gen.emit_byte_aliases(gen.meta.meta_byte_aliases)
    lines.append("")

    # Enums
    lines.append(gen.section_comment("Enums"))
    lines += gen.emit_enums(gen.meta.meta_enums)
    lines.append("")
    outpath.write_text("\n".join(lines))
    
    # ==========================
    outpath = GEN_DIR / "traits.py"
    # ==========================
    lines = []
    
    # Traits / Interfaces
    lines.append(gen.section_comment("Traits"))
    for trait in gen.meta.meta_traits.values():
        lines += gen.emit_trait(trait)
        lines.append("")
    outpath.write_text("\n".join(lines))
    
    # Call wrappers (before namespaces so struct methods can delegate)
    # ==========================
    outpath = GEN_DIR / "ffi.py"
    # ==========================
    lines = []
    
    lines.append(gen.section_comment("Wire Format Helpers"))
    lines += gen.emit_pack_helpers()
    lines.append("")

    lines.append(gen.section_comment("Plugin Call Wrappers"))
    for call in gen.wire_calls:
        lines += gen.emit_call_wrapper(call)
        lines.append("")

    outpath.write_text("\n".join(lines))
    
    
    
    outpath = API_DIR / f"__init__.py"
    outpath.write_text("\n")

    for ns in meta.namespaces:
        
        outpath = API_DIR / f"{ns}.py"
        
        lines = []
        outpath.write_text("\n".join(lines))
    
    
    
    # lines.append(self.section_comment("Namespaces"))
    # lines += self.emit_namespace_wrappers()
    # lines.append("")
    
if __name__ == "__main__":
    main()