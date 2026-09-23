"""Pure-stdlib ELF parser (32/64-bit, little/big-endian)."""

from __future__ import annotations

import struct

from .model import (
    SECTION_TYPE_NAMES,
    SEGMENT_TYPE_NAMES,
    ElfFile,
    Section,
    Segment,
    Symbol,
)

__all__ = ["ParseError", "parse"]

MAGIC = b"\x7fELF"

EHDR_FMT_64 = "HHIQQQIHHHHHH"
EHDR_FMT_32 = "HHIIIIIHHHHHH"
PHDR_FMT_64 = "IIQQQQQQ"
PHDR_FMT_32 = "IIIIIIII"
SHDR_FMT_64 = "IIQQQQIIQQ"
SHDR_FMT_32 = "IIIIIIIIII"
SYM_FMT_64 = "IBBHQQ"
SYM_FMT_32 = "IIIBBH"

SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHT_SYMTAB = 2
SHT_STRTAB = 3

DT_NULL = 0
DT_NEEDED = 1
DT_SONAME = 14


class ParseError(ValueError):
    """Raised when a file is not a valid ELF binary."""


def _label(table: dict[int, str], key: int) -> str:
    return table.get(key, f"0x{key:x}")


def _unpack(fmt: str, data: bytes, endian: str, offset: int) -> tuple:
    return struct.unpack_from(endian + fmt, data, offset)


def _slice(data: bytes, offset: int, size: int) -> bytes:
    if offset == 0 or size == 0:
        return b""
    end = min(offset + size, len(data))
    if offset >= len(data):
        return b""
    return data[offset:end]


def _read_str(blob: bytes, offset: int) -> str:
    if not blob or offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


def parse(data: bytes, path: str = "<bytes>") -> ElfFile:
    """Parse ``data`` into an :class:`ElfFile`."""
    if len(data) < 16 or data[:4] != MAGIC:
        raise ParseError("不是 ELF 文件（魔数不匹配）")

    ei_class = data[4]
    if ei_class == 1:
        is_64 = False
    elif ei_class == 2:
        is_64 = True
    else:
        raise ParseError(f"未知的 ELF 类别：{ei_class}")

    ei_data = data[5]
    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        raise ParseError(f"未知的数据编码：{ei_data}")

    ehdr_fmt = EHDR_FMT_64 if is_64 else EHDR_FMT_32
    if len(data) < 16 + struct.calcsize(endian + ehdr_fmt):
        raise ParseError("ELF 头部不完整")
    (
        e_type,
        e_machine,
        _version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        _ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = _unpack(ehdr_fmt, data, endian, 16)

    elf = ElfFile(
        path=path,
        size=len(data),
        is_64=is_64,
        little_endian=(endian == "<"),
        type=e_type,
        machine=e_machine,
        entry=e_entry,
        flags=e_flags,
    )

    _parse_program_headers(data, elf, endian, e_phoff, e_phentsize, e_phnum)
    _parse_section_headers(data, elf, endian, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    _parse_dynamic(data, elf, endian)
    _parse_symbols(data, elf, endian)
    return elf


def _parse_program_headers(
    data: bytes, elf: ElfFile, endian: str, e_phoff: int, e_phentsize: int, e_phnum: int
) -> None:
    if e_phoff == 0 or e_phnum == 0:
        return
    fmt = PHDR_FMT_64 if elf.is_64 else PHDR_FMT_32
    step = struct.calcsize(endian + fmt)
    for i in range(e_phnum):
        offset = e_phoff + i * (e_phentsize or step)
        if len(data) < offset + step:
            break
        fields = _unpack(fmt, data, endian, offset)
        if elf.is_64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = fields
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = fields
        elf.segments.append(
            Segment(
                type=p_type,
                type_name=_label(SEGMENT_TYPE_NAMES, p_type),
                flags=p_flags,
                offset=p_offset,
                vaddr=p_vaddr,
                paddr=p_paddr,
                filesz=p_filesz,
                memsz=p_memsz,
                align=p_align,
            )
        )


def _parse_section_headers(
    data: bytes,
    elf: ElfFile,
    endian: str,
    e_shoff: int,
    e_shentsize: int,
    e_shnum: int,
    e_shstrndx: int,
) -> None:
    if e_shoff == 0 or e_shnum == 0:
        return
    fmt = SHDR_FMT_64 if elf.is_64 else SHDR_FMT_32
    step = struct.calcsize(endian + fmt)
    raw_names: list[int] = []
    sections: list[Section] = []
    for i in range(e_shnum):
        offset = e_shoff + i * (e_shentsize or step)
        if len(data) < offset + step:
            break
        fields = _unpack(fmt, data, endian, offset)
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = fields
        raw_names.append(sh_name)
        sections.append(
            Section(
                name="",
                type=sh_type,
                type_name=_label(SECTION_TYPE_NAMES, sh_type),
                flags=sh_flags,
                addr=sh_addr,
                offset=sh_offset,
                size=sh_size,
                link=sh_link,
                info=sh_info,
                addralign=sh_addralign,
                entsize=sh_entsize,
            )
        )
    elf.sections = sections

    if e_shstrndx == 0 or e_shstrndx >= len(sections):
        return
    strtab = sections[e_shstrndx]
    blob = _slice(data, strtab.offset, strtab.size)
    for i, section in enumerate(sections):
        section.name = _read_str(blob, raw_names[i]) if blob else ""


def _parse_dynamic(data: bytes, elf: ElfFile, endian: str) -> None:
    dyn_section = None
    for section in elf.sections:
        if section.type == SHT_DYNAMIC:
            dyn_section = section
            break
    if dyn_section is None:
        return
    blob = _slice(data, dyn_section.offset, dyn_section.size)
    str_blob = _section_blob(data, elf, ".dynstr")
    if elf.is_64:
        entry_size = 16
        dyn_fmt = "qQ"
    else:
        entry_size = 8
        dyn_fmt = "iI"
    for i in range(0, len(blob) - entry_size + 1, entry_size):
        d_tag, d_val = _unpack(dyn_fmt, blob, endian, i)
        if d_tag == DT_NULL:
            break
        if d_tag == DT_NEEDED and str_blob:
            name = _read_str(str_blob, d_val)
            if name:
                elf.needed.append(name)
        elif d_tag == DT_SONAME and str_blob:
            elf.soname = _read_str(str_blob, d_val)


def _section_blob(data: bytes, elf: ElfFile, name: str) -> bytes:
    for section in elf.sections:
        if section.type == SHT_STRTAB and section.name == name:
            return _slice(data, section.offset, section.size)
    return b""


def _parse_symbols(data: bytes, elf: ElfFile, endian: str) -> None:
    sym_section = None
    str_blob = b""
    for section in elf.sections:
        if section.type == SHT_DYNSYM and section.name == ".dynsym":
            sym_section = section
            str_blob = _section_blob(data, elf, ".dynstr")
            break
    if sym_section is None:
        for section in elf.sections:
            if section.type == SHT_SYMTAB and section.name == ".symtab":
                sym_section = section
                str_blob = _section_blob(data, elf, ".strtab")
                break
    if sym_section is None or not str_blob:
        return
    blob = _slice(data, sym_section.offset, sym_section.size)
    fmt = SYM_FMT_64 if elf.is_64 else SYM_FMT_32
    entry_size = struct.calcsize(endian + fmt)
    for i in range(0, len(blob) - entry_size + 1, entry_size):
        fields = _unpack(fmt, blob, endian, i)
        if elf.is_64:
            st_name, st_info, _st_other, st_shndx, st_value, st_size = fields
        else:
            st_name, st_value, st_size, st_info, _st_other, st_shndx = fields
        elf.symbols.append(
            Symbol(
                name=_read_str(str_blob, st_name),
                bind=st_info >> 4,
                type=st_info & 0xF,
                shndx=st_shndx,
                value=st_value,
                size=st_size,
            )
        )
