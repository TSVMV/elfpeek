"""Tests for the PE parser and PE security feature detection."""

from __future__ import annotations

from conftest import build_pe32plus

from elfpeek.model import PESection
from elfpeek.pe import ParseError, parse_pe, security_features


def test_parse_pe32plus_headers():
    pe = parse_pe(build_pe32plus(), "fixture.exe")
    assert pe.is_64
    assert pe.entry == 0x1000
    assert pe.image_base == 0x140000000
    assert pe.machine_name == "x86_64"
    assert pe.subsystem_name == "Windows 控制台"
    assert pe.little_endian


def test_parse_pe_sections():
    pe = parse_pe(build_pe32plus(), "fixture.exe")
    names = [sec.name for sec in pe.sections]
    assert names == [".text", ".rdata"]
    text, rdata = pe.sections
    assert text.virtual_address == 0x1000
    assert text.raw_offset == 0x200
    assert "X" in text.flags_text and "R" in text.flags_text
    assert rdata.raw_size == 0x200
    assert set(rdata.flags_text) == {"D", "R"}


def test_parse_pe_imports_and_exports():
    pe = parse_pe(build_pe32plus(), "fixture.exe")
    assert "KERNEL32.dll" in pe.needed
    assert "GetProcAddress" in pe.imports
    assert "ExitProcess" in pe.imports
    assert "MyExport" in pe.exports


def test_pe_security_features():
    pe = parse_pe(build_pe32plus(), "fixture.exe")
    by_name = {f.name: f.status for f in security_features(pe)}
    assert by_name["ASLR"] == "yes"
    assert by_name["DEP"] == "yes"
    assert by_name["CFG"] == "yes"
    assert by_name["高熵VA"] == "yes"
    assert by_name["SEHOP"] == "yes"
    assert by_name["RWX节区"] == "no"


def test_pe_security_features_reject_weak_flags():
    pe = parse_pe(
        build_pe32plus(dll_characteristics=0),
        "fixture.exe",
    )
    by_name = {f.name: f.status for f in security_features(pe)}
    assert by_name["ASLR"] == "no"
    assert by_name["DEP"] == "no"
    assert by_name["CFG"] == "no"


def test_pe_rwx_section_warns():
    pe = parse_pe(build_pe32plus(characteristics=0x2000), "fixture.dll")
    assert pe.type_name == "动态链接库"
    pe.sections.append(PESection(".shell", 0x3000, 0x40, 0x400, 0x40, 0xA0000000))
    by_name = {f.name: f for f in security_features(pe)}
    assert by_name["RWX节区"].status == "warn"
    assert ".shell" in by_name["RWX节区"].detail


def test_parse_pe_rejects_non_pe():
    import pytest

    with pytest.raises(ParseError):
        parse_pe(b"\x00" * 0x80, "bad")
    with pytest.raises(ParseError):
        parse_pe(b"MZ" + b"\x00" * 0x3E + b"\x00" * 24, "bad")
