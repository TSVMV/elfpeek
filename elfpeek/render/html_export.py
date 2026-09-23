"""Self-contained HTML report renderer (inline CSS + SVG, no JavaScript)."""

from __future__ import annotations

from html import escape

from ..checks import security_features as elf_security
from ..model import PEFile
from ..pe import security_features as pe_security

__all__ = ["render_html"]

HIGH_ENTROPY = 7.0
MID_ENTROPY = 5.0


def _esc(text) -> str:
    return escape(str(text))


def _entropy_color(value: float) -> str:
    if value >= HIGH_ENTROPY:
        return "#f85149"
    if value >= MID_ENTROPY:
        return "#d29922"
    return "#3fb950"


def _hex(value: int) -> str:
    return f"0x{value:x}"


def render_html(obj) -> str:
    """Render the binary report as a single standalone HTML document."""
    is_pe = isinstance(obj, PEFile)
    features = pe_security(obj) if is_pe else elf_security(obj)

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="zh-CN">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append(
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
    )
    parts.append("<title>elfpeek 结构报告</title>")
    parts.append(f"<style>{_css()}</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append('<div class="wrap">')

    parts.append('<h1>elfpeek 结构报告</h1>')
    parts.append(
        '<p class="sub">二进制文件结构解析：节区布局、入口点、动态依赖与符号、安全特性、熵值与字符串。</p>'
    )

    parts.extend(_header_card(obj, is_pe))
    parts.extend(_security_card(features))

    if not is_pe:
        parts.extend(_file_layout_card(obj))
    parts.extend(_memory_map_card(obj, is_pe))
    parts.extend(_sections_card(obj, is_pe))
    parts.extend(_deps_symbols_card(obj, is_pe))
    parts.extend(_strings_card(obj))

    parts.append(
        '<p class="note">本报告由 elfpeek 只读解析生成，未加载或执行二进制中的任何代码。'
        "安全特性与熵值为启发式判断，建议复核。</p>"
    )

    parts.append("</div>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


def _header_card(obj, is_pe: bool) -> list[str]:
    fmt = "PE" if is_pe else "ELF"
    items = [
        ("文件", obj.path),
        ("格式", fmt),
        ("大小", f"{obj.size} 字节"),
        ("位宽", "64 位" if obj.is_64 else "32 位"),
        ("端序", "小端" if obj.little_endian else "大端"),
        ("类型", obj.type_name),
        ("机器", obj.machine_name),
        ("入口点", _hex(obj.entry)),
    ]
    if is_pe:
        items.append(("映像基址", _hex(obj.image_base)))
        items.append(("子系统", obj.subsystem_name))
    if getattr(obj, "soname", ""):
        items.append(("SONAME", obj.soname))

    out = ['<section class="card">', '<h2>基本信息</h2>', '<div class="grid">']
    for key, value in items:
        out.append(
            f'<div class="item"><span class="k">{_esc(key)}</span>'
            f'<span class="v"><code>{_esc(value)}</code></span></div>'
        )
    out.append("</div>")
    out.append("</section>")
    return out


def _security_card(features) -> list[str]:
    out = ['<section class="card">', "<h2>安全特性</h2>", '<div class="badges">']
    for feat in features:
        cls = f"badge badge-{feat.status}"
        detail = f" <span class='detail'>{_esc(feat.detail)}</span>" if feat.detail else ""
        label = {
            "yes": "已启用",
            "no": "未启用",
            "warn": "告警",
            "unknown": "未知",
        }.get(feat.status, feat.status)
        out.append(
            f'<span class="{cls}">{_esc(feat.name)}: {_esc(label)}{detail}</span>'
        )
    out.append("</div>")
    out.append(
        '<p class="hint">状态为启发式判断，未标记为告警不代表安全，建议复核。</p>'
    )
    out.append("</section>")
    return out


def _file_layout_card(obj) -> list[str]:
    sections = obj.sections
    total = max((sec.offset + sec.size for sec in sections), default=0)
    out = [
        '<section class="card">',
        "<h2>节区文件布局</h2>",
        "<svg class='layout' width='920' viewBox='0 0 920 132'>",
    ]
    if not sections or total == 0:
        out.append("</svg>")
        out.append("</section>")
        return out

    usable = 880
    min_w = 2.0
    x = 16.0
    y = 26.0
    h = 64.0
    for idx, sec in enumerate(sections):
        w = max(min_w, sec.size / total * usable)
        color = "#243447" if idx % 2 == 0 else "#2d4159"
        out.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'rx="3" fill="{color}" stroke="#3b5573" stroke-width="1"/>'
        )
        if w > 54:
            label = sec.name if len(sec.name) <= 9 else sec.name[:8] + "…"
            out.append(
                f'<text x="{x + 5:.1f}" y="{y + 16:.1f}" '
                f'font-size="10" fill="#c9d1d9">{_esc(label)}</text>'
            )
        out.append(
            f'<text x="{x + 4:.1f}" y="{y + h - 10:.1f}" font-size="8.5" '
            f'fill="#7d8590">{_esc(sec.flags_text)}</text>'
        )
        x += w
    out.append("</svg>")
    out.append("</section>")
    return out


def _memory_map_card(obj, is_pe: bool) -> list[str]:
    if is_pe:
        items = [
            (sec.name, sec.virtual_address, sec.virtual_address + sec.virtual_size, sec.flags_text)
            for sec in obj.sections
        ]
    else:
        items = [
            (seg.type_name, seg.vaddr, seg.vaddr + seg.memsz, seg.flags_text)
            for seg in obj.segments
            if seg.vaddr > 0 or seg.memsz > 0
        ]
    items = [it for it in items if it[2] > it[1]]

    title = "节区内存布局"
    out = [
        '<section class="card">',
        f"<h2>{title}</h2>",
        "<p class='hint'>按虚拟地址排序，条带宽度正比于占用大小，位置相对最低地址偏移。</p>",
        "<svg class='layout' width='920' viewBox='0 0 920 40'>",
    ]
    if not items:
        out.append("</svg>")
        out.append("</section>")
        return out

    min_addr = min(it[1] for it in items)
    max_addr = max(it[2] for it in items)
    span = max_addr - min_addr
    if span <= 0:
        out.append("</svg>")
        out.append("</section>")
        return out

    x0 = 150.0
    usable = 750.0
    row_h = 26.0
    height = row_h * len(items) + 12
    out[-1] = f"<svg class='layout' width='920' viewBox='0 0 920 {height:.0f}'>"
    for idx, (name, vaddr, end, flags) in enumerate(sorted(items, key=lambda it: it[1])):
        y = 8.0 + idx * row_h
        sx = x0 + (vaddr - min_addr) / span * usable
        sw = max(2.0, (end - vaddr) / span * usable)
        flags_set = set(flags)
        color = "#2d4159"
        if "X" in flags_set:
            color = "#8e3b3b"
        elif "W" in flags_set:
            color = "#6b5320"
        elif "R" in flags_set:
            color = "#2b5138"
        out.append(
            f'<text x="10" y="{y + 14:.1f}" font-size="10.5" fill="#c9d1d9">'
            f'{_esc(name)[:14]}</text>'
        )
        out.append(
            f'<rect x="{sx:.1f}" y="{y:.1f}" width="{sw:.1f}" height="18" rx="3" '
            f'fill="{color}" stroke="#3b5573" stroke-width="1"/>'
        )
        out.append(
            f'<text x="{x0 + usable + 8:.1f}" y="{y + 14:.1f}" font-size="9.5" '
            f'fill="#7d8590">{_hex(vaddr)} +{end - vaddr}</text>'
        )
    out.append(
        f'<text x="10" y="{height - 4:.1f}" font-size="9" fill="#7d8590">'
        f"地址范围 {_hex(min_addr)} - {_hex(max_addr)}，跨度 {span} 字节</text>"
    )
    out.append("</svg>")
    out.append("</section>")
    return out


def _sections_card(obj, is_pe: bool) -> list[str]:
    out = [
        '<section class="card">',
        "<h2>节区表</h2>",
        '<table><thead><tr>',
    ]
    if is_pe:
        out.append(
            "<th>节区</th><th>起始地址</th><th>虚尺寸</th><th>原始大小</th>"
            "<th>标志</th><th>熵</th>"
        )
    else:
        out.append(
            "<th>节区</th><th>偏移</th><th>地址</th><th>大小</th>"
            "<th>标志</th><th>熵</th>"
        )
    out.append("</tr></thead><tbody>")
    for sec in obj.sections:
        entropy = getattr(sec, "entropy", 0.0)
        color = _entropy_color(entropy)
        mark = "高熵" if entropy >= HIGH_ENTROPY else ""
        entropy_cell = (
            f'<span style="color:{color}">{entropy:.2f}</span>'
            + (f' <em class="warn">{mark}</em>' if mark else "")
        )
        if is_pe:
            out.append(
                "<tr>"
                f'<td class="mono">{_esc(sec.name)}</td>'
                f'<td class="mono">{_hex(sec.virtual_address)}</td>'
                f'<td class="mono">{sec.virtual_size}</td>'
                f'<td class="mono">{sec.raw_size}</td>'
                f'<td class="mono">{_esc(sec.flags_text)}</td>'
                f"<td>{entropy_cell}</td>"
                "</tr>"
            )
        else:
            out.append(
                "<tr>"
                f'<td class="mono">{_esc(sec.name)}</td>'
                f'<td class="mono">{_hex(sec.offset)}</td>'
                f'<td class="mono">{_hex(sec.addr)}</td>'
                f'<td class="mono">{sec.size}</td>'
                f'<td class="mono">{_esc(sec.flags_text)}</td>'
                f"<td>{entropy_cell}</td>"
                "</tr>"
            )
    out.append("</tbody></table>")
    out.append("</section>")
    return out


def _deps_symbols_card(obj, is_pe: bool) -> list[str]:
    out = ['<section class="card">', "<h2>依赖与符号</h2>"]
    if is_pe:
        if obj.needed:
            out.append(f"<h3>导入动态库（{len(obj.needed)}）</h3>")
            out.append('<ul class="taglist">')
            for name in obj.needed:
                out.append(f"<li>{_esc(name)}</li>")
            out.append("</ul>")
        if obj.imports:
            out.append(f"<h3>导入函数（{len(obj.imports)}）</h3>")
            out.append('<ul class="taglist">')
            for name in obj.imports[:60]:
                out.append(f"<li>{_esc(name)}</li>")
            out.append("</ul>")
        if obj.exports:
            out.append(f"<h3>导出函数（{len(obj.exports)}）</h3>")
            out.append('<ul class="taglist">')
            for name in obj.exports[:60]:
                out.append(f"<li>{_esc(name)}</li>")
            out.append("</ul>")
    else:
        if obj.needed:
            out.append(f"<h3>动态依赖（{len(obj.needed)}）</h3>")
            out.append('<ul class="taglist">')
            for name in obj.needed:
                out.append(f"<li>{_esc(name)}</li>")
            out.append("</ul>")
        imports = obj.imported_functions
        exports = obj.exported_functions
        if imports or exports:
            out.append(
                f"<h3>符号表（导入 {len(imports)}，导出 {len(exports)}）</h3>"
            )
            out.append('<ul class="taglist">')
            for sym in imports[:40]:
                out.append(f'<li class="imp">{_esc(sym.name)}</li>')
            for sym in exports[:40]:
                out.append(f'<li class="exp">{_esc(sym.name)}</li>')
            out.append("</ul>")
    out.append("</section>")
    return out


def _strings_card(obj) -> list[str]:
    hits = getattr(obj, "strings", [])
    if not hits:
        return []
    counts: dict[str, int] = {}
    for h in hits:
        counts[h.category] = counts.get(h.category, 0) + 1
    summary = ", ".join(f"{_esc(k)} {v}" for k, v in sorted(counts.items()))
    out = [
        '<section class="card">',
        f"<h2>字符串（{len(hits)} 条，{summary}）</h2>",
        '<table><thead><tr><th>偏移</th><th>分类</th><th>内容</th></tr></thead><tbody>',
    ]
    interesting = [h for h in hits if h.category != "other"]
    shown = interesting[:80]
    for h in shown:
        cls = f'cat-{h.category}' if h.category != "other" else ""
        out.append(
            "<tr>"
            f'<td class="mono">{_hex(h.offset)}</td>'
            f'<td><span class="{cls}">{_esc(h.category)}</span></td>'
            f'<td class="mono">{_esc(h.value[:120])}</td>'
            "</tr>"
        )
    if len(interesting) > len(shown):
        out.append(
            f"<tr><td colspan='3' class='more'>其余 {len(interesting) - len(shown)} "
            "条分类字符串已省略，完整清单见 JSON 导出。</td></tr>"
        )
    out.append("</tbody></table>")
    out.append("</section>")
    return out


def _css() -> str:
    return """
:root {
  color-scheme: dark;
  --bg: #0f1419;
  --card: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --muted: #7d8590;
  --accent: #58a6ff;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 32px 20px; background: var(--bg); color: var(--text);
  font-family: "PingFang SC", "Microsoft YaHei", -apple-system, "Segoe UI", sans-serif;
  line-height: 1.55;
}
.wrap { max-width: 980px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 6px; letter-spacing: .5px; }
h2 { font-size: 16px; margin: 0 0 14px; color: var(--accent); }
h3 { font-size: 13px; margin: 18px 0 8px; color: #d0d7de; }
.sub { color: var(--muted); margin: 0 0 24px; font-size: 13px; }
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: 18px 20px; margin-bottom: 18px;
}
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px 18px; }
.item { display: flex; flex-direction: column; gap: 2px; }
.item .k { font-size: 11px; color: var(--muted); }
.item .v code, code {
  font-family: "SF Mono", "JetBrains Mono", Consolas, monospace;
  font-size: 12.5px; color: #7ee787;
}
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 11.5px; letter-spacing: .4px; }
.mono { font-family: Consolas, monospace; }
.taglist { list-style: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: 6px; }
.taglist li {
  background: #21262d; border: 1px solid var(--border); border-radius: 12px;
  padding: 3px 10px; font-family: Consolas, monospace; font-size: 12px;
}
.taglist li.exp { border-color: #3fb950; color: #7ee787; }
.badges { display: flex; flex-wrap: wrap; gap: 8px; }
.badge {
  border-radius: 6px; padding: 5px 11px; font-size: 12px;
  border: 1px solid; font-weight: 600;
}
.badge .detail { font-weight: 400; opacity: .85; }
.badge-yes { color: #3fb950; border-color: #3fb950; background: rgba(63,185,80,.12); }
.badge-no { color: #f85149; border-color: #f85149; background: rgba(248,81,73,.12); }
.badge-warn { color: #d29922; border-color: #d29922; background: rgba(210,153,34,.14); }
.badge-unknown { color: var(--muted); border-color: var(--border); background: #21262d; }
.hint { color: var(--muted); font-size: 11.5px; margin: 6px 0 0; }
.note { color: var(--muted); font-size: 11.5px; margin: 22px 0 0; }
em.warn { color: #f85149; font-style: normal; font-size: 11px; }
td.more { color: var(--muted); font-style: italic; }
svg.layout { display: block; max-width: 100%; height: auto; }
span.cat-library, span.cat-url, span.cat-ip, span.cat-path {
  padding: 1px 6px; border-radius: 4px; font-family: Consolas, monospace; font-size: 11px;
}
span.cat-library { background: rgba(88,166,255,.16); color: #79c0ff; }
span.cat-url { background: rgba(210,153,34,.16); color: #e3b341; }
span.cat-ip { background: rgba(163,113,249,.16); color: #d2a8ff; }
span.cat-path { background: rgba(63,185,80,.14); color: #7ee787; }
"""
