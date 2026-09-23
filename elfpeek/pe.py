"""Pure-stdlib PE/COFF parser."""

from __future__ import annotations

import struct

from .model import PEFile, PESection

__all__ = ["ParseError", "parse_pe", "security_features"]

DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"
PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B

IMAGE_DIRECTORY_EXPORT = 0
IMAGE_DIRECTORY_IMPORT = 1

# DllCharacteristics bits
DLL_DYNAMIC_BASE = 0x0040
DLL_HIGH_ENTROPY_VA = 0x0020
DLL_NX_COMPAT = 0x0100
DLL_NO_SEH = 0x0080
DLL_GUARD_CF = 0x4000


class ParseError(ValueError):
    """Raised when a file is not a valid PE binary."""


def parse_pe(data: bytes, path: str = "<bytes>") -> PEFile:
    """Parse ``data`` into a :class:`PEFile`."""
    if len(data) < 0x40 or data[:2] != DOS_MAGIC:
        raise ParseError("不是 PE 文件（缺少 MZ 标记）")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or len(data) < e_lfanew + 24:
        raise ParseError("PE 头部偏移无效或文件不完整")
    if data[e_lfanew : e_lfanew + 4] != PE_MAGIC:
        raise ParseError("不是 PE 文件（缺少 PE 签名）")

    coff_off = e_lfanew + 4
    (
        machine,
        number_of_sections,
        _timestamp,
        _symbol_table,
        _num_symbols,
        size_of_optional_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_off)

    opt_off = coff_off + 20
    if size_of_optional_header == 0 or len(data) < opt_off + 2:
        raise ParseError("缺少可选头")
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == PE32_MAGIC:
        is_64 = False
    elif magic == PE32PLUS_MAGIC:
        is_64 = True
    else:
        raise ParseError(f"未知可选头魔数：0x{magic:x}")

    # Optional header fixed layout (PE32: 96 bytes, PE32+: 112 bytes before dirs)
    entry = struct.unpack_from("<I", data, opt_off + 16)[0]
    if is_64:
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        subsystem_off = opt_off + 68
    else:
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        subsystem_off = opt_off + 68
    subsystem, dll_characteristics = struct.unpack_from("<HH", data, subsystem_off)
    num_rva = struct.unpack_from("<I", data, opt_off + (108 if is_64 else 92))[0]
    # Data directory table: PE32 at opt_off+96, PE32+ at opt_off+112.
    dirs_off = opt_off + (112 if is_64 else 96)
    data_dirs: list[tuple[int, int]] = []
    for i in range(max(0, min(num_rva, 16))):
        rva, size = struct.unpack_from("<II", data, dirs_off + i * 8)
        data_dirs.append((rva, size))

    sections_off = opt_off + size_of_optional_header
    sections = _parse_sections(data, sections_off, number_of_sections)

    pe = PEFile(
        path=path,
        size=len(data),
        is_64=is_64,
        type=characteristics,
        machine=machine,
        entry=entry,
        image_base=image_base,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        characteristics=characteristics,
        sections=sections,
    )

    if len(data_dirs) > IMAGE_DIRECTORY_IMPORT and data_dirs[IMAGE_DIRECTORY_IMPORT][0]:
        _parse_imports(data, pe, data_dirs[IMAGE_DIRECTORY_IMPORT][0])
    if len(data_dirs) > IMAGE_DIRECTORY_EXPORT and data_dirs[IMAGE_DIRECTORY_EXPORT][0]:
        _parse_exports(data, pe, data_dirs[IMAGE_DIRECTORY_EXPORT][0])
    return pe


def _parse_sections(data: bytes, offset: int, count: int) -> list[PESection]:
    sections: list[PESection] = []
    for i in range(count):
        base = offset + i * 40
        if len(data) < base + 40:
            break
        raw_name = data[base : base + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", "replace")
        (
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            _relocs,
            _linenums,
            _reloc_count,
            _line_count,
            characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", data, base + 8)
        sections.append(
            PESection(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                flags=characteristics,
            )
        )
    return sections


def _rva_to_offset(pe: PEFile, rva: int) -> int | None:
    for sec in pe.sections:
        if sec.virtual_address <= rva < sec.virtual_address + max(sec.virtual_size, sec.raw_size):
            return sec.raw_offset + (rva - sec.virtual_address)
    return None


def _read_cstr(data: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", "replace")


def _parse_imports(data: bytes, pe: PEFile, rva: int) -> None:
    """Walk the import descriptor table collecting DLL names and imported symbols."""
    offset = _rva_to_offset(pe, rva)
    if offset is None:
        return
    i = 0
    while len(data) >= offset + i * 20 + 20:
        fields = struct.unpack_from("<IIIII", data, offset + i * 20)
        ilt_rva, _ts, _fwd, name_rva, ft_rva = fields
        if name_rva == 0 and ilt_rva == 0 and ft_rva == 0:
            break
        name_off = _rva_to_offset(pe, name_rva)
        dll = _read_cstr(data, name_off) if name_off is not None else ""
        if dll:
            pe.needed.append(dll)
        thunk_rva = ilt_rva or ft_rva
        if thunk_rva:
            _walk_thunks(data, pe, thunk_rva, dll)
        i += 1


def _walk_thunks(data: bytes, pe: PEFile, rva: int, dll: str) -> None:
    """Collect imported function names from the import lookup/first thunk table."""
    offset = _rva_to_offset(pe, rva)
    if offset is None:
        return
    entry_size = 8 if pe.is_64 else 4
    fmt = "<Q" if pe.is_64 else "<I"
    i = 0
    while len(data) >= offset + i * entry_size + entry_size:
        value = struct.unpack_from(fmt, data, offset + i * entry_size)[0]
        if value == 0:
            break
        # High bit set => import by ordinal; otherwise low 31 bits are an RVA to hint/name.
        ordinal_flag = 1 << 63 if pe.is_64 else 1 << 31
        if not (value & ordinal_flag):
            name_rva = value & 0x7FFFFFFF
            name_off = _rva_to_offset(pe, name_rva)
            if name_off is not None and name_off + 2 < len(data):
                name = _read_cstr(data, name_off + 2)  # skip 2-byte hint
                if name:
                    pe.imports.append(name)
        i += 1


def _parse_exports(data: bytes, pe: PEFile, rva: int) -> None:
    """Read the export directory's named function list."""
    offset = _rva_to_offset(pe, rva)
    if offset is None or len(data) < offset + 40:
        return
    (
        _flags,
        _ts,
        _major,
        _minor,
        _name_rva,
        _base,
        _number_of_functions,
        number_of_names,
        _addr_funcs_rva,
        addr_names_rva,
        _addr_ordinals_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", data, offset)
    if number_of_names == 0:
        return
    names_off = _rva_to_offset(pe, addr_names_rva)
    if names_off is None:
        return
    for i in range(min(number_of_names, 2000)):
        ptr_off = names_off + i * 4
        if len(data) < ptr_off + 4:
            break
        name_ptr = struct.unpack_from("<I", data, ptr_off)[0]
        name_off = _rva_to_offset(pe, name_ptr)
        name = _read_cstr(data, name_off) if name_off is not None else ""
        if name:
            pe.exports.append(name)


def security_features(pe: PEFile) -> list:
    """Return checksec-style hardening properties for a PE binary."""
    from .checks import SecurityFeature

    dc = pe.dll_characteristics
    features = [
        SecurityFeature(
            "ASLR",
            "yes" if dc & DLL_DYNAMIC_BASE else "no",
            "DYNAMIC_BASE，基址随机化" if dc & DLL_DYNAMIC_BASE else "固定基址",
        ),
        SecurityFeature(
            "DEP",
            "yes" if dc & DLL_NX_COMPAT else "no",
            "NX_COMPAT，数据执行保护" if dc & DLL_NX_COMPAT else "未启用 DEP",
        ),
        SecurityFeature(
            "CFG",
            "yes" if dc & DLL_GUARD_CF else "no",
            "GUARD_CF，控制流保护" if dc & DLL_GUARD_CF else "未启用控制流保护",
        ),
        SecurityFeature(
            "高熵VA",
            "yes" if dc & DLL_HIGH_ENTROPY_VA else "no",
            "HIGH_ENTROPY_VA" if dc & DLL_HIGH_ENTROPY_VA else "",
        ),
        SecurityFeature(
            "SEHOP",
            "yes" if dc & DLL_NO_SEH else "no",
            "已禁用结构化异常处理" if dc & DLL_NO_SEH else "未禁用 SEH",
        ),
    ]
    rwx = [
        sec.name
        for sec in pe.sections
        if (sec.flags & 0x20000000) and (sec.flags & 0x80000000)
    ]
    features.append(
        SecurityFeature(
            "RWX节区",
            "warn" if rwx else "no",
            "存在可写可执行节区：" + ", ".join(rwx) if rwx else "无 RWX 节区",
        )
    )
    return features
