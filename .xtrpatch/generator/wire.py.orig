"""
wire.py - Wire format specification for Extism plugin calls.

Defines how parameters are packed into a byte buffer for plugin calls
and how return values are unpacked. Each language generator uses these
definitions to emit packing/unpacking code in the target language.

Wire Format:
  - Fixed-size params: concatenated at sequential offsets, primitives in LE
  - Variable-length params (&[u8], &str): u32 LE length prefix + bytes
  - Instance methods: struct bytes first, then params in declaration order
  - Static methods: params only
  - Returns: raw bytes (structs via zerocopy, primitives LE, bool as u8)

Export naming: {namespace}___{struct_lower}__{fn_name}  (instance/static trait methods)
              {namespace}___{fn_name}                   (standalone functions)
"""

from dataclasses import dataclass
from typing import Optional
from meta import APIMetaData, MetaFunction, MetaFnParam, MetaStruct, is_varlen, is_primitive, PRIMITIVE_TYPES


@dataclass
class PackedField:
    """A single field in a packed wire buffer."""
    name: str
    type_str: str
    offset: Optional[int]  # None if variable-length (offset depends on runtime)
    size: Optional[int]    # None if variable-length
    is_varlen: bool
    is_le_primitive: bool  # u16/u32/u64/u128 needing LE encoding
    prim_byte_size: Optional[int]  # size for LE primitives

    @property
    def is_fixed(self) -> bool:
        return not self.is_varlen


@dataclass
class WireCall:
    """Complete wire format for a single plugin export."""
    export_name: str
    namespace: str
    struct_name: Optional[str]  # None for standalone functions
    fn_name: str
    instance_field: Optional[PackedField]  # The &self struct, if instance method
    param_fields: list[PackedField]
    return_type: Optional[str]
    return_size: Optional[int]  # None if bool (1) or void (0) or varlen
    is_mut_self: bool
    has_varlen_params: bool  # True if any param is variable-length
    module_name: Optional[str]  # For standalone fns: e.g. "hash" from "hash_api"


def export_name_method(namespace: str, struct_name: str, fn_name: str) -> str:
    return f"{namespace}___{struct_name.lower()}__{fn_name}"


def export_name_standalone(namespace: str, fn_name: str) -> str:
    return f"{namespace}___{fn_name}"


def build_packed_field(
    name: str, type_str: str, offset: Optional[int], meta: APIMetaData
) -> tuple[PackedField, Optional[int]]:
    """Build a PackedField and return (field, next_offset).
    next_offset is None if this field is variable-length."""
    t = type_str.strip()

    if is_varlen(t):
        return PackedField(
            name=name, type_str=t, offset=offset, size=None,
            is_varlen=True, is_le_primitive=False, prim_byte_size=None
        ), None

    # Strip reference for size lookup
    inner = t.lstrip("&").strip()
    if inner.startswith("mut "):
        inner = inner[4:].strip()

    sz = meta.type_sizes.get(inner)
    is_prim = inner in PRIMITIVE_TYPES and inner not in ("u8", "bool")
    prim_sz = PRIMITIVE_TYPES.get(inner) if is_prim else None

    next_off = (offset + sz) if (offset is not None and sz is not None) else None

    return PackedField(
        name=name, type_str=t, offset=offset, size=sz,
        is_varlen=False, is_le_primitive=is_prim, prim_byte_size=prim_sz
    ), next_off


def build_wire_calls(meta: APIMetaData) -> list[WireCall]:
    """Build WireCall descriptors for every export the plugin generates."""
    calls: list[WireCall] = []

    # ── Impl methods (trait functions on structs) ──
    for impl in meta.meta_trait_impls:
        trait = meta.meta_traits.get(impl.trait_name)
        struct = meta.meta_structs.get(impl.struct_name)
        if not trait or not struct:
            continue

        struct_sz = meta.type_sizes.get(impl.struct_name)

        for func in trait.functions.values():
            ename = export_name_method(impl.namespace, impl.struct_name, func.name)

            offset = 0
            instance_field = None
            is_mut = func.is_mut_self

            if func.is_instance_function:
                instance_field = PackedField(
                    name="instance", type_str=impl.struct_name,
                    offset=0, size=struct_sz,
                    is_varlen=False, is_le_primitive=False, prim_byte_size=None)
                offset = struct_sz if struct_sz else 0

            param_fields = []
            has_varlen = False
            for param in func.params.values():
                pf, next_off = build_packed_field(param.name, param.type_str, offset, meta)
                param_fields.append(pf)
                if pf.is_varlen:
                    has_varlen = True
                    offset = None  # Can't predict offsets after varlen
                else:
                    offset = next_off

            # Return info
            ret_type = func.ret_str
            ret_size = None
            if ret_type:
                if ret_type == "bool":
                    ret_size = 1
                elif ret_type == "Self":
                    ret_size = struct_sz
                else:
                    inner = ret_type.lstrip("&").strip()
                    ret_size = meta.type_sizes.get(inner)

            calls.append(WireCall(
                export_name=ename, namespace=impl.namespace,
                struct_name=impl.struct_name, fn_name=func.name,
                instance_field=instance_field, param_fields=param_fields,
                return_type=ret_type, return_size=ret_size,
                is_mut_self=is_mut, has_varlen_params=has_varlen,
                module_name=None))

    # ── Standalone functions ──
    for func in meta.meta_functions.values():
        ns = func.namespace
        mod_name = ns.removesuffix("_api") if ns else None
        ename = export_name_standalone(ns, func.name)

        offset = 0
        param_fields = []
        has_varlen = False
        for param in func.params.values():
            pf, next_off = build_packed_field(param.name, param.type_str, offset, meta)
            param_fields.append(pf)
            if pf.is_varlen:
                has_varlen = True
                offset = None
            else:
                offset = next_off

        ret_type = func.ret_str
        ret_size = None
        if ret_type:
            if ret_type == "bool":
                ret_size = 1
            else:
                inner = ret_type.lstrip("&").strip()
                ret_size = meta.type_sizes.get(inner)

        calls.append(WireCall(
            export_name=ename, namespace=ns,
            struct_name=None, fn_name=func.name,
            instance_field=None, param_fields=param_fields,
            return_type=ret_type, return_size=ret_size,
            is_mut_self=False, has_varlen_params=has_varlen,
            module_name=mod_name))

    return calls