"""Tests for the ELF parser core."""

from __future__ import annotations

import pytest
from conftest import build_elf64

from elfpeek.parse import ParseError, parse


def test_header_fields(elf_bytes):
    elf = parse(elf_bytes, "demo")
    assert elf.is_64
    assert elf.little_endian
    assert elf.type == 2
    assert elf.type_name == "可执行"
    assert elf.machine == 62
    assert elf.machine_name == "x86_64"
    assert elf.entry == 0x401000
    assert elf.size == len(elf_bytes)


def test_segments_parsed(elf_bytes):
    elf = parse(elf_bytes)
    assert len(elf.segments) == 1
    seg = elf.segments[0]
    assert seg.type == 1  # PT_LOAD
    assert seg.type_name == "LOAD"
    assert seg.offset == 0
    assert seg.vaddr == 0x400000
    assert seg.flags_text == "RX"


def test_sections_with_names(elf_bytes):
    elf = parse(elf_bytes)
    names = [sec.name for sec in elf.sections]
    assert names == ["", ".text", ".data", ".dynstr", ".dynsym", ".dynamic", ".shstrtab"]
    text = elf.sections[1]
    assert text.type_name == "PROGBITS"
    assert text.flags_text == "AX"
    assert text.size == 8


def test_dynamic_needed(elf_bytes):
    elf = parse(elf_bytes)
    assert elf.needed == ["libc.so.6"]


def test_symbols_imports_and_exports(elf_bytes):
    elf = parse(elf_bytes)
    assert len(elf.symbols) == 3  # null + foo + bar
    imports = elf.imported_functions
    exports = elf.exported_functions
    assert [sym.name for sym in imports] == ["foo"]
    assert [sym.name for sym in exports] == ["bar"]
    assert imports[0].bind_name == "全局"
    assert imports[0].type_name == "函数"


def test_non_elf_raises(tmp_path):
    path = tmp_path / "notelf.bin"
    path.write_bytes(b"not an elf file at all")
    with pytest.raises(ParseError):
        parse(path.read_bytes())


def test_truncated_header_raises():
    with pytest.raises(ParseError):
        parse(b"\x7fELF" + b"\x02\x01" + b"\x00" * 4)


def test_custom_needed_and_symbols():
    data = build_elf64(needed=("liba.so", "libb.so"), imports=("malloc",), exports=("my_init",))
    elf = parse(data)
    assert elf.needed == ["liba.so", "libb.so"]
    assert [sym.name for sym in elf.imported_functions] == ["malloc"]
    assert [sym.name for sym in elf.exported_functions] == ["my_init"]


def test_shared_object_type():
    data = build_elf64(e_type=3)
    elf = parse(data)
    assert elf.type_name == "共享库"
