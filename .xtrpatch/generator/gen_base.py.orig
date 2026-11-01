"""
gen_base.py - Abstract base for language-specific code generators.

Each language generator subclasses LangGenerator and implements the
abstract methods for type mapping, struct rendering, trait rendering,
and FFI call wrapper generation.
"""

from abc import ABC, abstractmethod
from meta import APIMetaData, MetaStruct, MetaTrait, MetaFunction, MetaFnParam, MetaByteAlias, MetaConst
from wire import WireCall, PackedField, build_wire_calls


class LangGenerator(ABC):
    """Base class for all language generators."""

    def __init__(self, meta: APIMetaData):
        self.meta = meta
        self.wire_calls = build_wire_calls(meta)

    # ── Type mapping ──────────────────────────────────────────────────────

    @abstractmethod
    def map_type(self, canonical_type: str) -> str:
        """Map a canonical Rust type string to the target language type."""
        ...

    @abstractmethod
    def map_return_type(self, canonical_type: str, struct_context: str | None) -> str:
        """Map a return type, resolving 'Self' to the struct name if needed."""
        ...

    # ── File structure ────────────────────────────────────────────────────

    @abstractmethod
    def file_header(self) -> list[str]:
        """Emit imports, preamble, etc."""
        ...

    @abstractmethod
    def file_footer(self) -> list[str]:
        """Emit any closing code."""
        ...

    # ── Constants & aliases ───────────────────────────────────────────────

    @abstractmethod
    def emit_constants(self, consts: dict[str, MetaConst]) -> list[str]:
        """Emit constant definitions."""
        ...

    @abstractmethod
    def emit_byte_aliases(self, aliases: dict[str, MetaByteAlias]) -> list[str]:
        """Emit byte alias type definitions."""
        ...

    # ── Structs / Models ──────────────────────────────────────────────────

    @abstractmethod
    def emit_struct(self, struct: MetaStruct) -> list[str]:
        """Emit a struct/class/model definition."""
        ...

    # ── Traits / Interfaces ───────────────────────────────────────────────

    @abstractmethod
    def emit_trait(self, trait: MetaTrait) -> list[str]:
        """Emit a trait/interface/protocol definition."""
        ...

    # ── Wire format: packing/unpacking ────────────────────────────────────

    @abstractmethod
    def emit_pack_helpers(self) -> list[str]:
        """Emit helper functions for packing/unpacking wire format."""
        ...

    @abstractmethod
    def emit_call_wrapper(self, call: WireCall) -> list[str]:
        """Emit a function that packs args, calls the plugin, unpacks result."""
        ...

    @abstractmethod
    def emit_namespace_wrappers(self) -> list[str]:
        """Emit namespace wrapper classes that attach structs and functions."""
        ...

    # ── Top-level orchestration ───────────────────────────────────────────

    def generate(self) -> str:
        lines: list[str] = []
        lines += self.file_header()
        lines.append("")

        # Constants
        lines.append(self.section_comment("Constants"))
        lines += self.emit_constants(self.meta.meta_consts)
        lines.append("")

        # Byte aliases
        lines.append(self.section_comment("Byte Aliases"))
        lines += self.emit_byte_aliases(self.meta.meta_byte_aliases)
        lines.append("")

        # Traits / Interfaces
        lines.append(self.section_comment("Traits"))
        for trait in self.meta.meta_traits.values():
            lines += self.emit_trait(trait)
            lines.append("")

        # Wire helpers (before namespaces so they're available)
        lines.append(self.section_comment("Wire Format Helpers"))
        lines += self.emit_pack_helpers()
        lines.append("")

        # Call wrappers (before namespaces so struct methods can delegate)
        lines.append(self.section_comment("Plugin Call Wrappers"))
        for call in self.wire_calls:
            lines += self.emit_call_wrapper(call)
            lines.append("")

        # Namespace classes with inner structs and standalone functions
        lines.append(self.section_comment("Namespaces"))
        lines += self.emit_namespace_wrappers()
        lines.append("")

        lines += self.file_footer()
        return "\n".join(lines)

    def section_comment(self, title: str) -> str:
        """Override per-language for comment syntax."""
        return f"# {'=' * 60}\n# {title}\n# {'=' * 60}"