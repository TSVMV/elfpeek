"""Plain-text terminal summary of an ELF binary."""

from __future__ import annotations

from ..model import ElfFile

__all__ = ["render"]


def render(elf: ElfFile) -> str:
    """Render a compact Chinese terminal summary."""
    lines: list[str] = []
    lines.append("=" * 64)
    lines.append("elfpeek ELF 结构报告")
    lines.append("=" * 64)
    lines.append(f"文件: {elf.path}")
    lines.append(f"大小: {elf.size} 字节    位宽: {'64' if elf.is_64 else '32'}    端序: {'小端' if elf.little_endian else '大端'}")
    lines.append(f"类型: {elf.type_name}    机器: {elf.machine_name}")
    lines.append(f"入口: 0x{elf.entry:x}    标志: 0x{elf.flags:x}")
    if elf.soname:
        lines.append(f"SONAME: {elf.soname}")
    lines.append("")

    lines.append(f"程序段: {len(elf.segments)} 个")
    for seg in elf.segments:
        lines.append(
            f"  {seg.type_name:<12} 0x{seg.offset:08x} 0x{seg.vaddr:012x} "
            f"filesz {seg.filesz:<8} memsz {seg.memsz:<8} {seg.flags_text}"
        )
    lines.append("")

    lines.append(f"节区: {len(elf.sections)} 个")
    for sec in elf.sections:
        lines.append(
            f"  {sec.name:<16} {sec.type_name:<12} 0x{sec.offset:08x} "
            f"size {sec.size:<8} {sec.flags_text}"
        )
    lines.append("")

    if elf.needed:
        lines.append(f"动态依赖: {len(elf.needed)} 个")
        for name in elf.needed:
            lines.append(f"  - {name}")
        lines.append("")

    imports = elf.imported_functions
    exports = elf.exported_functions
    if imports or exports:
        lines.append(f"动态符号: 导入 {len(imports)} 个, 导出 {len(exports)} 个")
        if imports:
            lines.append("  导入函数（前 10 个）:")
            for sym in imports[:10]:
                lines.append(f"    - {sym.name}")
        if exports:
            lines.append("  导出函数（前 10 个）:")
            for sym in exports[:10]:
                lines.append(f"    + {sym.name}")
        lines.append("")

    lines.append("本报告由 elfpeek 只读解析生成，未执行二进制中的任何代码。")
    return "\n".join(lines)
