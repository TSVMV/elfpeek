"""Tests for checksec rules, entropy and string classification."""

from __future__ import annotations

from conftest import build_elf64, build_pe32plus

from elfpeek.checks import (
    extract_strings,
    fill_entropy,
    section_entropy,
    security_features,
)
from elfpeek.model import ElfFile, Section, Segment, Symbol
from elfpeek.parse import parse

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552


def make_elf(**overrides) -> ElfFile:
    base = {
        "path": "fixture",
        "size": 256,
        "is_64": True,
        "little_endian": True,
        "type": 2,
        "machine": 62,
        "entry": 0x401000,
        "flags": 0,
    }
    base.update(overrides)
    return ElfFile(**base)


def stack_seg(flags: int = 0x2) -> Segment:
    return Segment(
        type=PT_GNU_STACK, type_name="GNU_STACK", flags=flags, offset=0,
        vaddr=0, paddr=0, filesz=0, memsz=0x1000, align=0x1000,
    )


def relro_seg() -> Segment:
    return Segment(
        type=PT_GNU_RELRO, type_name="GNU_RELRO", flags=0x4, offset=0,
        vaddr=0, paddr=0, filesz=0, memsz=0x1000, align=0,
    )


def features_by_name(elf: ElfFile) -> dict:
    return {f.name: f for f in security_features(elf)}


def test_pie_flagged_from_type():
    assert features_by_name(make_elf(type=3))["PIE"].status == "yes"
    assert features_by_name(make_elf(type=2))["PIE"].status == "no"


def test_nx_flagged_from_gnu_stack():
    assert features_by_name(make_elf(segments=[stack_seg(0x2)]))["NX"].status == "yes"
    assert features_by_name(make_elf(segments=[stack_seg(0x7)]))["NX"].status == "no"
    assert features_by_name(make_elf(segments=[]))["NX"].status == "unknown"


def test_relro_full_partial_and_none():
    full = make_elf(segments=[relro_seg()], dt_flags_1=0x1)
    partial = make_elf(segments=[relro_seg()])
    none = make_elf(segments=[])
    assert features_by_name(full)["RELRO"].status == "full"
    assert features_by_name(partial)["RELRO"].status == "partial"
    assert features_by_name(none)["RELRO"].status == "no"


def test_relro_bind_now_via_dt_flags():
    elf = make_elf(segments=[relro_seg()], dt_flags=0x8)
    assert features_by_name(elf)["RELRO"].status == "full"


def test_canary_and_fortify_detected_by_symbol_name():
    elf = make_elf(
        symbols=[Symbol("__memset_chk", 1, 2, 0, 0, 0), Symbol("strcpy", 1, 2, 0, 0, 0)]
    )
    assert features_by_name(elf)["FORTIFY"].status == "yes"
    assert features_by_name(elf)["Canary"].status == "no"
    elf.symbols.append(Symbol("__stack_chk_fail", 1, 2, 0, 0, 0))
    assert features_by_name(elf)["Canary"].status == "yes"


def test_rwx_segment_warns():
    rwx = Segment(
        type=1, type_name="LOAD", flags=0x7, offset=0, vaddr=0x400000, paddr=0,
        filesz=0x100, memsz=0x100, align=0x1000,
    )
    result = features_by_name(make_elf(segments=[rwx]))["RWX段"]
    assert result.status == "warn"
    assert "LOAD" in result.detail


def test_real_elf_fixture_is_hardenable():
    elf = parse(build_elf64(), "fixture")
    result = features_by_name(elf)
    assert result["RELRO"].status == "no"
    assert result["Canary"].status == "no"
    assert result["FORTIFY"].status == "no"
    assert result["RWX段"].status == "no"


def test_entropy_uniform_vs_diverse():
    assert section_entropy(b"\x00" * 32, 0, 32) == 0.0
    assert section_entropy(b"\xcc" * 32, 0, 32) == 0.0
    diverse = bytes(range(256))
    assert abs(section_entropy(diverse, 0, 256) - 8.0) < 1e-9
    assert section_entropy(diverse, 5, 20) < 5.0
    assert section_entropy(b"\x00\x00", 5, 8) == 0.0


def test_fill_entropy_annotates_sections():
    data = b"\x00" * 64 + bytes(range(32)) * 2 + b"\x55" * 16
    sec_low = Section(".low", 1, "PROGBITS", 0x2, 0, 0, 64, 0, 0, 1, 0)
    sec_high = Section(".high", 1, "PROGBITS", 0x2, 0, 64, 64, 0, 0, 1, 0)
    sec_nobits = Section(".bss", 8, "NOBITS", 0x2, 0, 128, 16, 0, 0, 1, 0)
    obj = type("Holder", (), {"sections": [sec_low, sec_high, sec_nobits]})()
    fill_entropy(obj, data)
    assert sec_low.entropy == 0.0
    assert sec_high.entropy >= 5.0
    assert sec_nobits.entropy == 0.0


def test_cli_load_fills_entropy_and_strings(tmp_path):
    from elfpeek.cli import _load

    for builder in (build_elf64, build_pe32plus):
        target = tmp_path / "sample.bin"
        target.write_bytes(builder())
        obj = _load(target)
        assert all(hasattr(sec, "entropy") for sec in obj.sections)
        assert any(getattr(sec, "entropy", 0.0) > 0 for sec in obj.sections)
        assert isinstance(obj.strings, list)


def test_extract_strings_classifies_categories():
    payload = (
        b"\x00"
        b"visit https://example.com/download?x=1 for setup"
        b"\x00"
        b"connect to 192.168.1.10:4444 and wait"
        b"\x00"
        b"probe /usr/lib/libc then /etc/ld.so.cache"
        b"\x00"
        b"needs libc.so.6 loader"
        b"\x00"
        b"abcd"
        b"\x00"
    )
    by_category: dict[str, list] = {}
    for hit in extract_strings(payload):
        by_category.setdefault(hit.category, []).append(hit.value)
    assert any("https://example.com/download?x=1" in v for v in by_category["URL"])
    assert any("192.168.1.10" in v for v in by_category["IP"])
    assert any("/usr/lib/libc" in v for v in by_category["path"])
    assert any("libc.so.6" in v for v in by_category["library"])
    assert any(h.value == "abcd" for h in extract_strings(payload) if h.category == "other")


def test_extract_strings_skips_short_runs():
    assert extract_strings(b"\x00abc\x00\x00xyz\x00") == []
    hits = extract_strings(b"\x00abcd\x00")
    assert len(hits) == 1 and hits[0].offset == 1


