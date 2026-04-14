"""
meta.py - Language-agnostic API metadata model.

Reads api_core.json (namespace-keyed) and produces a clean APIMetaData
with resolved constants, byte aliases, structs, traits, impls, and functions.

No language-specific logic lives here.
"""

from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum
import json
import re


# ─── Canonical type classification ───────────────────────────────────────────

PRIMITIVE_TYPES = {
    "u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16,
    "i8": 1, "i16": 2, "i32": 4, "i64": 8, "i128": 16,
    "bool": 1,
}

VARLEN_TYPES = {"&[u8]", "&str"}


def is_varlen(typ: str) -> bool:
    return typ.strip() in VARLEN_TYPES


def is_primitive(typ: str) -> bool:
    return typ.strip() in PRIMITIVE_TYPES


def is_fixed_ref(typ: str) -> bool:
    t = typ.strip()
    return t.startswith("&") and t not in VARLEN_TYPES and not t.startswith("&mut ")


def strip_ref(typ: str) -> str:
    t = typ.strip()
    if t.startswith("&mut "):
        return t[5:]
    if t.startswith("&"):
        return t[1:]
    return t


# ─── Value types ─────────────────────────────────────────────────────────────

class MetaValueType(Enum):
    usize = 10
    byte_arr = 20


# ─── Data model classes ──────────────────────────────────────────────────────

class MetaConst(BaseModel):
    name: str
    namespace: str
    val_str: str
    value: int
    value_type: MetaValueType


class MetaByteAlias(BaseModel):
    name: str
    namespace: str
    len_str: str
    length: int


class MetaFnParam(BaseModel):
    name: str
    type_str: str

    @property
    def is_varlen(self) -> bool:
        return is_varlen(self.type_str)

    @property
    def is_fixed_ref(self) -> bool:
        return is_fixed_ref(self.type_str)

    @property
    def is_primitive(self) -> bool:
        return is_primitive(self.type_str)

    @property
    def inner_type(self) -> str:
        return strip_ref(self.type_str)

    @property
    def is_rng(self):
        return (self.name.strip().lower() == "rng"
                and self.type_str.strip().lower().endswith("rngcore"))


class MetaFunction(BaseModel):
    name: str
    namespace: Optional[str] = Field(None)
    params: dict[str, MetaFnParam]
    ret_str: Optional[str] = Field(None)
    instance_str: Optional[str] = Field(None)
    instance_of: Optional[str] = Field(None)
    pure: Optional[bool] = Field(False)

    @property
    def is_class_function(self) -> bool:
        if self.pure:
            return False
        return self.instance_str is None or "self" not in self.instance_str.lower()

    @property
    def is_instance_function(self) -> bool:
        if self.pure:
            return False
        return self.instance_str is not None and "self" in self.instance_str.lower()

    @property
    def is_mut_self(self) -> bool:
        return self.instance_str is not None and "&mut self" in self.instance_str

    @property
    def returns_ref(self) -> bool:
        return self.ret_str is not None and self.ret_str.startswith("&")

    @property
    def returns_self(self) -> bool:
        return self.ret_str == "Self"

    @property
    def return_inner_type(self) -> Optional[str]:
        if self.ret_str is None:
            return None
        return strip_ref(self.ret_str)


class MetaTrait(BaseModel):
    name: str
    namespace: str
    generics: list[str] = Field(default_factory=list)
    functions: dict[str, MetaFunction]


class MetaTraitImpl(BaseModel):
    trait_name: str
    struct_name: str
    namespace: str


class MetaField(BaseModel):
    name: str
    type_name: str
    description: Optional[str] = Field(None)


class MetaStruct(BaseModel):
    name: str
    namespace: str
    description: Optional[str] = Field(None)
    fields: list[MetaField]
    derives: Optional[str] = Field(None)
    traits: list[str] = Field(default_factory=list)


class APIMetaData(BaseModel):
    """Complete language-agnostic representation of the API."""
    namespaces: list[str]
    const_literals: dict[str, int]
    meta_consts: dict[str, MetaConst]
    meta_byte_aliases: dict[str, MetaByteAlias]
    meta_structs: dict[str, MetaStruct]
    meta_traits: dict[str, MetaTrait]
    meta_trait_impls: list[MetaTraitImpl]
    meta_functions: dict[str, MetaFunction]
    type_sizes: dict[str, int]

    def struct_size(self, name: str) -> Optional[int]:
        return self.type_sizes.get(name)

    def param_size(self, param: MetaFnParam) -> Optional[int]:
        if param.is_varlen:
            return None
        inner = param.inner_type
        return self.type_sizes.get(inner)

    def return_size(self, func: MetaFunction) -> Optional[int]:
        if func.ret_str is None:
            return None
        inner = func.return_inner_type
        if inner == "Self":
            return None  # Caller must resolve from struct context
        if inner == "bool":
            return 1
        return self.type_sizes.get(inner)

    def traits_for_struct(self, struct_name: str) -> list[MetaTrait]:
        """Get all traits implemented by a struct."""
        trait_names = [
            impl.trait_name for impl in self.meta_trait_impls
            if impl.struct_name == struct_name
        ]
        return [
            self.meta_traits[tn] for tn in trait_names
            if tn in self.meta_traits
        ]

    def impls_for_struct(self, struct_name: str) -> list[MetaTraitImpl]:
        return [
            impl for impl in self.meta_trait_impls
            if impl.struct_name == struct_name
        ]

    def structs_for_trait(self, trait_name: str) -> list[MetaStruct]:
        struct_names = [
            impl.struct_name for impl in self.meta_trait_impls
            if impl.trait_name == trait_name
        ]
        return [
            self.meta_structs[sn] for sn in struct_names
            if sn in self.meta_structs
        ]


# ─── Loader ──────────────────────────────────────────────────────────────────

def _resolve_expr(expr: str, literals: dict[str, int]) -> Optional[int]:
    """Evaluate a simple additive expression like 'A + B + 32'."""
    parts = [p.strip() for p in expr.split("+")]
    total = 0
    for part in parts:
        if part.isdigit():
            total += int(part)
        elif part in literals:
            total += literals[part]
        else:
            return None
    return total


def load_meta(filename: str) -> APIMetaData:
    with open(filename) as f:
        schema = json.load(f)

    namespaces: list[str] = []
    const_literals: dict[str, int] = {}
    meta_consts: dict[str, MetaConst] = {}
    meta_byte_aliases: dict[str, MetaByteAlias] = {}
    meta_structs: dict[str, MetaStruct] = {}
    meta_traits: dict[str, MetaTrait] = {}
    meta_trait_impls: list[MetaTraitImpl] = []
    meta_functions: dict[str, MetaFunction] = {}
    type_sizes: dict[str, int] = dict(PRIMITIVE_TYPES)

    # ── Pass 1: Collect all sz_consts (may need multiple passes for exprs) ──
    all_sz_consts = []
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        for sc in ns_val.get("sz_consts", []):
            all_sz_consts.append((ns_name, sc))

    # Resolve numeric literals first
    for ns_name, sc in all_sz_consts:
        val = sc["value"].strip()
        if val.isdigit():
            const_literals[sc["name"]] = int(val)
            meta_consts[sc["name"]] = MetaConst(
                name=sc["name"], namespace=ns_name,
                val_str=val, value=int(val),
                value_type=MetaValueType.usize)

    # Resolve expressions iteratively
    changed = True
    while changed:
        changed = False
        for ns_name, sc in all_sz_consts:
            if sc["name"] in const_literals:
                continue
            resolved = _resolve_expr(sc["value"], const_literals)
            if resolved is not None:
                const_literals[sc["name"]] = resolved
                meta_consts[sc["name"]] = MetaConst(
                    name=sc["name"], namespace=ns_name,
                    val_str=sc["value"], value=resolved,
                    value_type=MetaValueType.usize)
                changed = True

    # ── Pass 2: Byte aliases ──
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        for ba in ns_val.get("byte_aliases", []):
            length_expr = ba["length"].strip()
            resolved = _resolve_expr(length_expr, const_literals)
            if resolved is not None:
                meta_byte_aliases[ba["name"]] = MetaByteAlias(
                    name=ba["name"], namespace=ns_name,
                    len_str=length_expr, length=resolved)
                type_sizes[ba["name"]] = resolved

    # ── Pass 3: Structs ──
    all_structs = []
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        if ns_name not in namespaces and (
            ns_val.get("structs") or ns_val.get("functions") or ns_val.get("traits")
        ):
            namespaces.append(ns_name)
        for s in ns_val.get("structs", []):
            all_structs.append((ns_name, s))

    # Resolve struct sizes iteratively (handles nested structs)
    pending_structs = list(all_structs)
    changed = True
    while changed:
        changed = False
        still_pending = []
        for ns_name, s in pending_structs:
            fields = s.get("fields", [])
            total = 0
            all_known = True
            for field in fields:
                ft = field["type"].strip()
                if ft in type_sizes:
                    total += type_sizes[ft]
                else:
                    all_known = False
                    break
            if all_known:
                sname = s["name"]
                type_sizes[sname] = total
                meta_structs[sname] = MetaStruct(
                    name=sname, namespace=ns_name,
                    description=s.get("description"),
                    derives=s.get("derives"),
                    fields=[
                        MetaField(
                            name=f["name"],
                            type_name=f["type"].strip(),
                            description=f.get("description"))
                        for f in fields
                    ])
                changed = True
            else:
                still_pending.append((ns_name, s))
        pending_structs = still_pending

    # ── Pass 4: Traits ──
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        for t in ns_val.get("traits", []):
            tname = t["name"]
            generics = t.get("generics", [])
            functions = {}
            for func in t.get("functions", []):
                fname = func["name"]
                params = {}
                for p in func.get("params", []):
                    pname = p["name"]
                    params[pname] = MetaFnParam(
                        name=pname, type_str=p["type"].strip())
                functions[fname] = MetaFunction(
                    name=fname,
                    namespace=ns_name,
                    instance_str=func.get("instance"),
                    instance_of=tname,
                    params=params,
                    ret_str=func.get("return"))
            meta_traits[tname] = MetaTrait(
                name=tname, namespace=ns_name,
                generics=generics, functions=functions)

    # ── Pass 5: Impls ──
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        for imp in ns_val.get("impls", []):
            if isinstance(imp, dict):
                ti = MetaTraitImpl(
                    trait_name=imp["trait"],
                    struct_name=imp["struct"],
                    namespace=ns_name)
                meta_trait_impls.append(ti)
                # Attach trait name to struct
                if imp["struct"] in meta_structs:
                    if imp["trait"] not in meta_structs[imp["struct"]].traits:
                        meta_structs[imp["struct"]].traits.append(imp["trait"])

    # ── Pass 6: Standalone functions ──
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        for func in ns_val.get("functions", []):
            fname = func["name"]
            params = {}
            for p in func.get("params", []):
                pname = p["name"]
                params[pname] = MetaFnParam(
                    name=pname, type_str=p["type"].strip())
            meta_functions[fname] = MetaFunction(
                name=fname,
                namespace=ns_name,
                params=params,
                ret_str=func.get("return"),
                pure=True)

    # ── Pass 7: Empty consts (informational, not critical for codegen) ──
    for ns_name, ns_val in schema.items():
        if not isinstance(ns_val, dict):
            continue
        for ec in ns_val.get("empty_consts", []):
            size_expr = ec["size"].strip()
            resolved = _resolve_expr(size_expr, const_literals)
            if resolved is not None:
                meta_consts[ec["name"]] = MetaConst(
                    name=ec["name"], namespace=ns_name,
                    val_str=size_expr, value=resolved,
                    value_type=MetaValueType.byte_arr)

    return APIMetaData(
        namespaces=namespaces,
        const_literals=const_literals,
        meta_consts=meta_consts,
        meta_byte_aliases=meta_byte_aliases,
        meta_structs=meta_structs,
        meta_traits=meta_traits,
        meta_trait_impls=meta_trait_impls,
        meta_functions=meta_functions,
        type_sizes=type_sizes)