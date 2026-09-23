"""Data model for a parsed ELF binary."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "DT_NAMES",
    "MACHINE_NAMES",
    "SECTION_TYPE_NAMES",
    "SEGMENT_TYPE_NAMES",
    "SYMBOL_BIND_NAMES",
    "SYMBOL_TYPE_NAMES",
    "TYPE_NAMES",
    "ElfFile",
    "Section",
    "Segment",
    "Symbol",
]

TYPE_NAMES: dict[int, str] = {
    1: "可重定位",
    2: "可执行",
    3: "共享库",
    4: "核心转储",
}

SEGMENT_TYPE_NAMES: dict[int, str] = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
    0x6474e550: "GNU_EH_FRAME",
    0x6474e551: "GNU_STACK",
    0x6474e552: "GNU_RELRO",
    0x6474e553: "GNU_PROPERTY",
}

SECTION_TYPE_NAMES: dict[int, str] = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    10: "SHLIB",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
}

DT_NAMES: dict[int, str] = {
    0: "NULL",
    1: "NEEDED",
    2: "PLTRELSZ",
    3: "PLTGOT",
    4: "HASH",
    5: "STRTAB",
    6: "SYMTAB",
    7: "RELA",
    8: "RELASZ",
    9: "RELAENT",
    10: "STRSZ",
    11: "SYMENT",
    12: "INIT",
    13: "FINI",
    14: "SONAME",
    15: "RPATH",
    16: "SYMBOLIC",
    17: "REL",
    20: "PLTREL",
    21: "DEBUG",
    23: "JMPREL",
    24: "BIND_NOW",
}

SYMBOL_BIND_NAMES: dict[int, str] = {
    0: "局部",
    1: "全局",
    2: "弱",
}

SYMBOL_TYPE_NAMES: dict[int, str] = {
    0: "未类型",
    1: "对象",
    2: "函数",
    3: "节区",
    4: "文件",
    5: "COMMON",
    6: "TLS",
}

MACHINE_NAMES: dict[int, str] = {
    0: "未指定",
    3: "x86",
    40: "ARM",
    62: "x86_64",
    183: "AArch64",
    243: "RISC-V",
}


@dataclass
class Section:
    """One ELF section header."""

    name: str
    type: int
    type_name: str
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int

    @property
    def flags_text(self) -> str:
        return "".join(
            char
            for bit, char in (
                (0x1, "W"),
                (0x2, "A"),
                (0x4, "X"),
                (0x10, "M"),
                (0x20, "S"),
                (0x40, "I"),
                (0x80, "L"),
            )
            if self.flags & bit
        )

    @property
    def is_nobits(self) -> bool:
        return self.type == 8


@dataclass
class Segment:
    """One ELF program header."""

    type: int
    type_name: str
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int

    @property
    def flags_text(self) -> str:
        return "".join(
            char
            for bit, char in ((0x4, "R"), (0x2, "W"), (0x1, "X"))
            if self.flags & bit
        )


@dataclass
class Symbol:
    """One symbol from .symtab or .dynsym."""

    name: str
    bind: int
    type: int
    shndx: int
    value: int
    size: int

    @property
    def bind_name(self) -> str:
        return SYMBOL_BIND_NAMES.get(self.bind, str(self.bind))

    @property
    def type_name(self) -> str:
        return SYMBOL_TYPE_NAMES.get(self.type, str(self.type))


@dataclass
class ElfFile:
    """Parsed view of an ELF binary."""

    path: str
    size: int
    is_64: bool
    little_endian: bool
    type: int
    machine: int
    entry: int
    flags: int
    segments: list[Segment] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    soname: str = ""

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"0x{self.type:x}")

    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.machine, f"0x{self.machine:x}")

    @property
    def dynamic_symbols(self) -> list[Symbol]:
        # Symbols parsed from .dynsym carry non-empty names from .dynstr.
        return [sym for sym in self.symbols if sym.name]

    @property
    def functions(self) -> list[Symbol]:
        return [sym for sym in self.dynamic_symbols if sym.type == 2]

    @property
    def imported_functions(self) -> list[Symbol]:
        # Undefined dynamic symbols (shndx == 0 / UNDEF) are imports.
        return [sym for sym in self.functions if sym.shndx == 0]

    @property
    def exported_functions(self) -> list[Symbol]:
        return [sym for sym in self.functions if sym.shndx != 0]
