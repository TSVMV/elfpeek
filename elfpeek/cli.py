"""Command line entry point for elfpeek."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import extract_strings, fill_entropy
from .model import PEFile
from .parse import ParseError
from .parse import parse as parse_elf
from .pe import ParseError as PEParseError
from .pe import parse_pe
from .render import render_html, render_terminal

__all__ = ["main"]


def _load(path: Path):
    """Dispatch parsing by file magic and inject entropy / strings."""
    data = path.read_bytes()
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        obj = parse_elf(data, str(path))
    elif len(data) >= 2 and data[:2] == b"MZ":
        obj = parse_pe(data, str(path))
    else:
        raise ParseError("不是 ELF 或 PE 文件（魔数不匹配）")
    fill_entropy(obj, data)
    obj.strings = extract_strings(data)
    return obj


def _to_dict(obj) -> dict:
    base = {
        "tool": "elfpeek",
        "path": obj.path,
        "size": obj.size,
        "is_64": obj.is_64,
        "type_name": obj.type_name,
        "machine_name": obj.machine_name,
        "entry": obj.entry,
        "needed": list(obj.needed),
        "strings": [
            {"value": s.value, "category": s.category, "offset": s.offset} for s in obj.strings
        ],
    }
    if isinstance(obj, PEFile):
        base.update(
            {
                "format": "PE",
                "image_base": obj.image_base,
                "subsystem": obj.subsystem_name,
                "exports": list(obj.exports),
                "imports": list(obj.imports),
                "sections": [
                    {
                        "name": sec.name,
                        "vaddr": sec.virtual_address,
                        "vsize": sec.virtual_size,
                        "raw_offset": sec.raw_offset,
                        "raw_size": sec.raw_size,
                        "flags_text": sec.flags_text,
                        "entropy": round(sec.entropy, 2),
                    }
                    for sec in obj.sections
                ],
            }
        )
    else:
        base.update(
            {
                "format": "ELF",
                "little_endian": obj.little_endian,
                "soname": obj.soname,
                "segments": [
                    {
                        "type_name": seg.type_name,
                        "offset": seg.offset,
                        "vaddr": seg.vaddr,
                        "filesz": seg.filesz,
                        "memsz": seg.memsz,
                        "flags_text": seg.flags_text,
                    }
                    for seg in obj.segments
                ],
                "sections": [
                    {
                        "name": sec.name,
                        "type_name": sec.type_name,
                        "offset": sec.offset,
                        "addr": sec.addr,
                        "size": sec.size,
                        "flags_text": sec.flags_text,
                        "entropy": round(sec.entropy, 2),
                    }
                    for sec in obj.sections
                ],
                "symbols": [
                    {"name": sym.name, "bind": sym.bind, "type": sym.type}
                    for sym in obj.symbols
                ],
            }
        )
    return base


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="elfpeek",
        description="把 ELF/PE 二进制解析成结构图：节区/段布局、入口、依赖、符号、安全特性与熵。",
    )
    parser.add_argument("file", metavar="FILE", help="待解析的 ELF 或 PE 文件路径")
    parser.add_argument("--html", metavar="PATH", help="将结构报告导出为自包含 HTML")
    parser.add_argument("--json", metavar="PATH", help="将解析结果导出为 JSON")
    parser.add_argument("--version", action="version", version=f"elfpeek {__version__}")
    args = parser.parse_args(argv)

    path = Path(args.file)
    try:
        obj = _load(path)
    except OSError as exc:
        print(f"错误：无法读取文件 {path}：{exc}", file=sys.stderr)
        return 2
    except (ParseError, PEParseError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    print(render_terminal(obj))

    status = 0
    if args.html:
        try:
            Path(args.html).write_text(render_html(obj), encoding="utf-8")
            print(f"HTML 报告已写入 {args.html}")
        except OSError as exc:
            print(f"错误：无法写入 HTML 文件 {args.html}：{exc}", file=sys.stderr)
            status = 2
    if args.json:
        payload = json.dumps(_to_dict(obj), ensure_ascii=False, indent=2)
        try:
            Path(args.json).write_text(payload + "\n", encoding="utf-8")
            print(f"JSON 报告已写入 {args.json}")
        except OSError as exc:
            print(f"错误：无法写入 JSON 文件 {args.json}：{exc}", file=sys.stderr)
            status = 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
