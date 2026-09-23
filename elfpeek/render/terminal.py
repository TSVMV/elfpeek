"""Plain-text terminal summary of an ELF/PE binary."""

from __future__ import annotations

from ..checks import security_features as elf_security
from ..model import PEFile
from ..pe import security_features as pe_security

__all__ = ["render"]

HIGH_ENTROPY = 7.0
STATUS_TEXT = {
    "yes": "已启用",
    "no": "未启用",
    "warn": "告警",
    "unknown": "未知",
    "full": "完整",
    "partial": "部分",
}


def render(obj) -> str:
    """Render a compact Chinese terminal summary."""
    is_pe = isinstance(obj, PEFile)
    fmt = "PE" if is_pe else "ELF"
    lines: list[str] = []
    lines.append("=" * 64)
    lines.append(f"elfpeek {fmt} 结构报告")
    lines.append("=" * 64)
    lines.append(f"文件: {obj.path}")
    lines.append(
        f"格式: {fmt}    大小: {obj.size} 字节    "
        f"位宽: {'64' if obj.is_64 else '32'}    "
        f"端序: {'小端' if obj.little_endian else '大端'}"
    )
    lines.append(f"类型: {obj.type_name}    机器: {obj.machine_name}")
    lines.append(f"入口: 0x{obj.entry:x}")
    if is_pe:
        lines.append(f"映像基址: 0x{obj.image_base:x}    子系统: {obj.subsystem_name}")
    if getattr(obj, "soname", ""):
        lines.append(f"SONAME: {obj.soname}")
    lines.append("")

    lines.extend(_security_block(obj))
    lines.append("")

    if not is_pe:
        lines.extend(_segments_block(obj))
    lines.extend(_sections_block(obj))
    lines.append("")
    lines.extend(_deps_and_symbols_block(obj))
    lines.append("")
    lines.extend(_strings_block(obj))
    lines.append("")
    lines.append("本报告由 elfpeek 只读解析生成，未加载或执行二进制中的任何代码。")
    return "\n".join(lines)


def _security_block(obj) -> list[str]:
    features = pe_security(obj) if isinstance(obj, PEFile) else elf_security(obj)
    lines = [f"安全特性 ({len(features)} 项):"]
    for feat in features:
        status = STATUS_TEXT.get(feat.status, feat.status)
        marker = (
            "!"
            if feat.status in {"warn", "partial"}
            else "."
            if feat.status in {"yes", "full"}
            else "-"
        )
        detail = f" — {feat.detail}" if feat.detail else ""
        lines.append(f"  {marker} {feat.name:<10} {status}{detail}")
    return lines


def _segments_block(obj) -> list[str]:
    lines = [f"程序段: {len(obj.segments)} 个"]
    for seg in obj.segments:
        lines.append(
            f"  {seg.type_name:<12} 偏移 0x{seg.offset:08x}  0x{seg.vaddr:012x}  "
            f"filesz {seg.filesz:<8} memsz {seg.memsz:<8} {seg.flags_text}"
        )
    lines.append("")
    return lines


def _sections_block(obj) -> list[str]:
    lines = [f"节区: {len(obj.sections)} 个"]
    for sec in obj.sections:
        if isinstance(sec.name, str):
            name = sec.name
        else:
            name = str(sec.name)
        flags = sec.flags_text
        entropy = getattr(sec, "entropy", 0.0)
        entropy_mark = f"熵 {entropy:.2f}"
        if entropy >= HIGH_ENTROPY:
            entropy_mark += "（高熵）"
        lines.append(f"  {name:<16} {flags:<4} {entropy_mark}")
    return lines


def _deps_and_symbols_block(obj) -> list[str]:
    lines: list[str] = []
    if isinstance(obj, PEFile):
        if obj.needed:
            lines.append(f"导入动态库: {len(obj.needed)} 个")
            for name in obj.needed[:15]:
                lines.append(f"  - {name}")
        if obj.imports:
            lines.append(f"导入函数: {len(obj.imports)} 个（前 10）")
            for name in obj.imports[:10]:
                lines.append(f"    - {name}")
        if obj.exports:
            lines.append(f"导出函数: {len(obj.exports)} 个（前 10）")
            for name in obj.exports[:10]:
                lines.append(f"    + {name}")
    else:
        if obj.needed:
            lines.append(f"动态依赖: {len(obj.needed)} 个")
            for name in obj.needed:
                lines.append(f"  - {name}")
        imports = obj.imported_functions
        exports = obj.exported_functions
        if imports or exports:
            lines.append(f"符号表: 导入 {len(imports)} 个, 导出 {len(exports)} 个")
            if imports:
                lines.append("  导入函数（前 10）:")
                for sym in imports[:10]:
                    lines.append(f"    - {sym.name}")
            if exports:
                lines.append("  导出函数（前 10）:")
                for sym in exports[:10]:
                    lines.append(f"    + {sym.name}")
    return lines


def _strings_block(obj) -> list[str]:
    hits = getattr(obj, "strings", [])
    if not hits:
        return []
    counts: dict[str, int] = {}
    for h in hits:
        counts[h.category] = counts.get(h.category, 0) + 1
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    lines = [f"字符串: 提取 {len(hits)} 条（{summary}）"]
    interesting = [h for h in hits if h.category != "other"]
    for h in interesting[:12]:
        lines.append(f"  [{h.category}] 0x{h.offset:08x} {h.value[:64]}")
    return lines
