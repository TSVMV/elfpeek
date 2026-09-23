"""Test fixtures: a builder for minimal but valid ELF binaries."""

from __future__ import annotations

import struct

import pytest

from elfpeek.parse import parse  # noqa: F401  (re-exported for convenience)


def build_elf64(
    *,
    needed: tuple[str, ...] = ("libc.so.6",),
    imports: tuple[str, ...] = ("foo",),
    exports: tuple[str, ...] = ("bar",),
    e_type: int = 2,
    e_machine: int = 62,
    e_entry: int = 0x401000,
) -> bytes:
    """Build a minimal little-endian 64-bit ELF as bytes."""
    endian = "<"

    # --- string tables ---
    dynstr_names = [""] + list(needed) + list(imports) + list(exports)
    dynstr_offsets: list[int] = []
    dynstr = bytearray()
    for name in dynstr_names:
        dynstr_offsets.append(len(dynstr))
        dynstr += name.encode() + b"\x00"
    dynstr = bytes(dynstr)

    # --- symbols (.dynsym) ---
    dynsym = bytearray()
    dynsym += b"\x00" * 24  # null symbol (index 0)
    symbol_names = list(imports) + list(exports)
    for i, name in enumerate(symbol_names):
        st_name = dynstr_offsets[1 + len(needed) + i]  # skip "" and needed entries
        is_import = i < len(imports)
        st_info = (1 << 4) | 2  # GLOBAL | FUNC
        st_shndx = 0 if is_import else 1  # .text section index
        st_value = 0 if is_import else 0x401000
        dynsym += struct.pack(endian + SYM_FMT_64, st_name, st_info, 0, st_shndx, st_value, 0)
    dynsym = bytes(dynsym)

    # --- dynamic section ---
    dynamic = bytearray()
    for i, _ in enumerate(needed):
        dynamic += struct.pack(endian + "qQ", 1, dynstr_offsets[1 + i])  # DT_NEEDED
    dynamic += struct.pack(endian + "qQ", 0, 0)  # DT_NULL
    dynamic = bytes(dynamic)

    # --- section contents ---
    text = b"\xcc" * 8
    data = b"\x01\x02\x03\x04"

    # shstrtab: collect section names in table order.
    section_names = ["", ".text", ".data", ".dynstr", ".dynsym", ".dynamic", ".shstrtab"]
    shstrtab = bytearray()
    name_offsets: list[int] = []
    for name in section_names:
        name_offsets.append(len(shstrtab))
        shstrtab += name.encode() + b"\x00"
    shstrtab = bytes(shstrtab)

    # --- layout offsets ---
    ehdr_size = 16 + struct.calcsize(endian + EHDR_FMT_64)  # 64
    phdr_size = struct.calcsize(endian + PHDR_FMT_64)  # 56
    phdr_off = ehdr_size
    text_off = phdr_off + phdr_size
    data_off = text_off + len(text)
    dynstr_off = data_off + len(data)
    dynsym_off = dynstr_off + len(dynstr)
    dynamic_off = dynsym_off + len(dynsym)
    shstrtab_off = dynamic_off + len(dynamic)
    shdr_off = shstrtab_off + len(shstrtab)
    # Align shdr_off to 8.
    if shdr_off % 8:
        pad = 8 - (shdr_off % 8)
        shstrtab += b"\x00" * pad
        shdr_off = shstrtab_off + len(shstrtab)
    total = shdr_off + 7 * struct.calcsize(endian + SHDR_FMT_64)

    # --- program header (single LOAD covering the whole file) ---
    phdr = struct.pack(
        endian + PHDR_FMT_64,
        1,  # PT_LOAD
        0x5,  # R | X
        0,  # offset
        0x400000,  # vaddr
        0x400000,  # paddr
        total,  # filesz
        total,  # memsz
        0x1000,  # align
    )

    # --- section headers ---
    def shdr(name_i, sh_type, flags, addr, offset, size, link=0, info=0, align=1, entsize=0):
        return struct.pack(
            endian + SHDR_FMT_64,
            name_offsets[name_i],
            sh_type,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            align,
            entsize,
        )

    shdrs = b"".join(
        [
            shdr(0, 0, 0, 0, 0, 0),  # NULL
            shdr(1, 1, 0x6, 0x401000, text_off, len(text), align=16),  # .text AX
            shdr(2, 1, 0x3, 0x402000, data_off, len(data), align=4),  # .data WA
            shdr(3, 3, 0x2, 0, dynstr_off, len(dynstr)),  # .dynstr A
            shdr(4, 11, 0x2, 0, dynsym_off, len(dynsym), link=3, align=8, entsize=24),  # .dynsym
            shdr(5, 6, 0x3, 0x403000, dynamic_off, len(dynamic), link=3, align=8, entsize=16),  # .dynamic WA
            shdr(6, 3, 0, 0, shstrtab_off, len(shstrtab), align=1),  # .shstrtab
        ]
    )

    ehdr = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])  # 64, little, ELF version, OS/ABI
        + b"\x00" * 8
        + struct.pack(
            endian + EHDR_FMT_64,
            e_type,
            e_machine,
            1,  # version
            e_entry,
            phdr_off,  # e_phoff
            shdr_off,  # e_shoff
            0,  # flags
            ehdr_size,
            phdr_size,
            1,  # e_phnum
            struct.calcsize(endian + SHDR_FMT_64),  # e_shentsize
            7,  # e_shnum
            6,  # e_shstrndx
        )
    )

    return (
        ehdr + phdr + text + data + dynstr + dynsym + dynamic + shstrtab + shdrs
    ).ljust(total, b"\x00")


# Format constants mirrored from elfpeek.parse to avoid importing internals here.
EHDR_FMT_64 = "HHIQQQIHHHHHH"
PHDR_FMT_64 = "IIQQQQQQ"
SHDR_FMT_64 = "IIQQQQIIQQ"
SYM_FMT_64 = "IBBHQQ"


@pytest.fixture
def elf_bytes() -> bytes:
    return build_elf64()


def build_pe32plus(
    *,
    dlls: tuple[str, ...] = ("KERNEL32.dll",),
    imports: tuple[str, ...] = ("GetProcAddress", "ExitProcess"),
    exports: tuple[str, ...] = ("MyExport",),
    machine: int = 0x8664,
    entry: int = 0x1000,
    image_base: int = 0x140000000,
    characteristics: int = 0x0002,
    dll_characteristics: int = 0x0040 | 0x0020 | 0x0100 | 0x0080 | 0x4000,
) -> bytes:
    """Build a minimal but valid 64-bit PE with import and export directories."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack(
        "<HHIIIHH", machine, 2, 0, 0, 0, 240, characteristics
    )

    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<HH", opt, 2, 14, 0)
    struct.pack_into("<I", opt, 4, 0x80)
    struct.pack_into("<I", opt, 8, 0x200)
    struct.pack_into("<I", opt, 16, entry)
    struct.pack_into("<I", opt, 20, 0x1000)
    struct.pack_into("<Q", opt, 24, image_base)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<H", opt, 70, dll_characteristics)
    struct.pack_into("<Q", opt, 72, 0x100000)
    struct.pack_into("<Q", opt, 80, 0x1000)
    struct.pack_into("<Q", opt, 88, 0x100000)
    struct.pack_into("<Q", opt, 96, 0x1000)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112, 0x2100, 0x40)  # export directory
    struct.pack_into("<II", opt, 120, 0x2000, 0x40)  # import directory

    prefix = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt)
    text = b"\xcc" * 0x80
    data_size = 0x200

    # Section headers sit right after the optional header; raw data is page-aligned.
    text_off = (len(prefix) + 80 + 0xFF) & ~0xFF
    rdata_off = text_off + len(text)
    pad = text_off - (len(prefix) + 80)

    text_hdr = struct.pack(
        "<8sIIIIIIHHI", b".text", 0x80, 0x1000, len(text), text_off, 0, 0, 0, 0, 0x60000060
    )
    rdata_hdr = struct.pack(
        "<8sIIIIIIHHI", b".rdata", data_size, 0x2000, data_size, rdata_off, 0, 0, 0, 0, 0x40000040
    )

    rdata = bytearray(data_size)
    base = 0x2000
    desc_off, ilt_off, dll_off = 0x00, 0x30, 0x60
    # Import lookup table entries point at hint/name pairs laid out dynamically.
    hint_name_rvas: list[int] = []
    cursor = 0x70
    for name in imports:
        hint_name_rvas.append(base + cursor)
        struct.pack_into("<H", rdata, cursor, 0)
        cursor += 2
        rdata[cursor : cursor + len(name) + 1] = (name + "\x00").encode()
        cursor += len(name) + 1
        cursor = (cursor + 3) & ~3
    for i, rva in enumerate(hint_name_rvas):
        struct.pack_into("<Q", rdata, ilt_off + i * 8, rva)
    struct.pack_into("<Q", rdata, ilt_off + len(hint_name_rvas) * 8, 0)
    rdata[dll_off : dll_off + 12] = (dlls[0] + "\x00").encode()[:12]
    struct.pack_into(
        "<IIIII", rdata, desc_off, ilt_off + base, 0, 0, dll_off + base, ilt_off + base
    )
    # Export directory (rva 0x2100).
    struct.pack_into(
        "<IIHHIIIIIII",
        rdata,
        0x100,
        0,
        0,
        0,
        0,
        0x2140,
        0,
        len(exports),
        len(exports),
        0x2148,
        0x2150,
        0x2158,
    )
    rdata[0x140 : 0x140 + 16] = (dlls[0] + "\x00").encode()[:16]
    struct.pack_into("<I", rdata, 0x148, 0x1000)
    struct.pack_into("<I", rdata, 0x150, 0x2160)
    struct.pack_into("<I", rdata, 0x158, 0)
    rdata[0x160 : 0x160 + 16] = (exports[0] + "\x00").encode()[:16]

    return prefix + text_hdr + rdata_hdr + b"\x00" * pad + text + bytes(rdata)
