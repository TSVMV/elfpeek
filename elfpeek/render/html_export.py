"""Self-contained HTML report with an SVG layout map (no JavaScript)."""

from __future__ import annotations

import html

from ..model import ElfFile, Section

__all__ = ["render"]

STYLE = """
* { box-sizing: border-box; }
body { margin: 0; background: #f4f5f7; color: #1f2430;
       font-family: "PingFang SC","Microsoft YaHei","Noto Sans CJK SC",sans-serif;
       font-size: 15px; line-height: 1.6; }
.wrap { max-width: 1040px; margin: 0 auto; padding: 32px 20px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 26px 0 10px; border-left: 4px solid #2f5f8f; padding-left: 10px; }
.muted { color: #6b7280; }
.card { background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 18px 22px; }
.meta p { margin: 3px 0; }
.meta .label { color: #6b7280; display: inline-block; min-width: 5em; }
table { width: 100%; border-collapse: collapse; background: #fff; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eceef1;
         font-size: 13px; font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace; }
th { color: #4b5563; background: #f8f9fb; border-bottom: 2px solid #e3e6ea; font-weight: 600; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 0 8px; border-radius: 999px; color: #fff; font-size: 11px; }
.footer { margin-top: 24px; color: #9aa1a9; font-size: 12px; }
.layout { overflow-x: auto; }
.layout svg { display: block; }
.legend span { display: inline-block; margin-right: 14px; font-size: 12px; }
.dot { display: inline-block; width: 12px; height: 12px; border-radius: 3px; margin-right: 5px; vertical-align: middle; }
"""

# Distinct, accessible colors keyed by section name prefix.
SECTION_COLORS = {
    ".text": "#2f5f8f",
    ".rodata": "#1f7a5e",
    ".data": "#b06a2c",
    ".bss": "#9b59b6",
    ".rela": "#8e6c8a",
    ".dynamic": "#0d7377",
    ".dynstr": "#5b7c99",
    ".dynsym": "#6a8cae",
    ".symtab": "#346b8a",
    ".strtab": "#5a7d9a",
    ".init": "#c75450",
    ".fini": "#a94340",
    ".plt": "#7a6c9e",
    ".got": "#9c7c5a",
    ".interp": "#4a7a55",
    ".note": "#6b7280",
    ".eh_frame": "#506b8c",
}


def _color_for(section: Section) -> str:
    for prefix, color in SECTION_COLORS.items():
        if section.name.startswith(prefix):
            return color
    return "#9aa3ad"


def render(elf: ElfFile) -> str:
    """Render the full report as a standalone HTML document."""
    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>elfpeek 结构报告 - {esc(elf.path)}</title>")
    parts.append(f"<style>{STYLE}</style></head><body><div class='wrap'>")
    parts.append("<h1>ELF 结构报告</h1>")
    parts.append("<p class='muted'>只读解析，报告不含可执行代码</p>")

    parts.append("<div class='card meta'>")
    parts.append(f"<p><span class='label'>文件</span>{esc(elf.path)}</p>")
    parts.append(
        f"<p><span class='label'>大小</span>{elf.size} 字节    "
        f"位宽 {'64' if elf.is_64 else '32'}    "
        f"端序 {'小端' if elf.little_endian else '大端'}</p>"
    )
    parts.append(
        f"<p><span class='label'>类型</span>{esc(elf.type_name)}    "
        f"机器 {esc(elf.machine_name)}</p>"
    )
    parts.append(f"<p><span class='label'>入口</span>0x{elf.entry:x}</p>")
    if elf.soname:
        parts.append(f"<p><span class='label'>SONAME</span>{esc(elf.soname)}</p>")
    parts.append("</div>")

    parts.append(_layout_map(elf))

    parts.append("<h2>程序段</h2>")
    parts.append(_segments_table(elf))

    parts.append("<h2>节区</h2>")
    parts.append(_sections_table(elf))

    if elf.needed:
        parts.append("<h2>动态依赖</h2>")
        parts.append("<ul>")
        for name in elf.needed:
            parts.append(f"<li><code>{esc(name)}</code></li>")
        parts.append("</ul>")

    imports = elf.imported_functions
    exports = elf.exported_functions
    if imports or exports:
        parts.append("<h2>动态符号</h2>")
        parts.append(
            f"<p class='muted'>导入函数 {len(imports)} 个, 导出函数 {len(exports)} 个</p>"
        )
        if imports:
            parts.append("<h3 style='font-size:15px'>导入函数（前 20 个）</h3>")
            parts.append("<ul>")
            for sym in imports[:20]:
                parts.append(f"<li><code>{esc(sym.name)}</code></li>")
            parts.append("</ul>")
        if exports:
            parts.append("<h3 style='font-size:15px'>导出函数（前 20 个）</h3>")
            parts.append("<ul>")
            for sym in exports[:20]:
                parts.append(f"<li><code>{esc(sym.name)}</code></li>")
            parts.append("</ul>")

    parts.append("<p class='footer'>由 elfpeek 只读解析生成。</p>")
    parts.append("</div></body></html>")
    return "".join(parts)


def _layout_map(elf: ElfFile) -> str:
    """Horizontal SVG bar showing each on-disk section proportional to size."""
    laid_out = [
        sec
        for sec in elf.sections
        if not sec.is_nobits and sec.size > 0 and sec.offset > 0
    ]
    if not laid_out:
        return ""
    total = elf.size
    bar_width = max(960, min(1600, total))
    bar_height = 26
    label_height = 14
    svg_width = bar_width + 40
    svg_height = bar_height + label_height + 16

    rects: list[str] = []
    cursor = 0
    palette_legend: dict[str, str] = {}
    for sec in laid_out:
        if total <= 0:
            continue
        width = max(1, int(bar_width * sec.size / total))
        color = _color_for(sec)
        palette_legend.setdefault(sec.name.split(".")[0] or sec.name, color)
        x = cursor
        rects.append(
            f"<rect x='{x}' y='0' width='{width}' height='{bar_height}' "
            f"fill='{color}' stroke='#fff' stroke-width='1'>"
            f"<title>{esc(sec.name)} - 偏移 0x{sec.offset:x} - 大小 {sec.size}</title></rect>"
        )
        cursor += width
    # End-to-end file ruler ticks at 0, 25%, 50%, 75%, 100%.
    ruler = ""
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        x = int(bar_width * frac)
        ruler += (
            f"<line x1='{x}' y1='{bar_height}' x2='{x}' y2='{bar_height + 5}' stroke='#cbd2d9'/>"
            f"<text x='{x}' y='{bar_height + label_height + 2}' text-anchor='middle' "
            f"font-size='10' fill='#6b7280'>{int(total * frac)}</text>"
        )

    legend = " ".join(
        f"<span><span class='dot' style='background:{color}'></span>{esc(name)}</span>"
        for name, color in palette_legend.items()
    )
    return (
        "<h2>文件布局</h2>"
        "<div class='layout'>"
        f"<svg width='{svg_width}' height='{svg_height}' viewBox='0 0 {svg_width} {svg_height}'>"
        f"<g transform='translate(20,2)'>{''.join(rects)}{ruler}</g>"
        "</svg>"
        f"<p class='legend'>{legend}</p>"
        "</div>"
        f"<p class='muted'>条带按节区在文件中的大小比例绘制，指针悬停查看偏移与大小。</p>"
    )


def _segments_table(elf: ElfFile) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{esc(seg.type_name)}</td>"
        f"<td>0x{seg.offset:x}</td>"
        f"<td>0x{seg.vaddr:x}</td>"
        f"<td>{seg.filesz}</td>"
        f"<td>{seg.memsz}</td>"
        f"<td>{esc(seg.flags_text)}</td>"
        "</tr>"
        for seg in elf.segments
    )
    return (
        "<table><thead><tr><th>类型</th><th>偏移</th><th>虚拟地址</th>"
        "<th>文件大小</th><th>内存大小</th><th>标志</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _sections_table(elf: ElfFile) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{esc(sec.name)}</td>"
        f"<td>{esc(sec.type_name)}</td>"
        f"<td>0x{sec.offset:x}</td>"
        f"<td>0x{sec.addr:x}</td>"
        f"<td>{sec.size}</td>"
        f"<td>{esc(sec.flags_text)}</td>"
        "</tr>"
        for sec in elf.sections
    )
    return (
        "<table><thead><tr><th>名称</th><th>类型</th><th>偏移</th>"
        "<th>地址</th><th>大小</th><th>标志</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def esc(value: str) -> str:
    return html.escape(str(value), quote=True)
