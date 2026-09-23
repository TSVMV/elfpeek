"""Command line entry point for elfpeek."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .parse import ParseError, parse
from .render import render_html, render_terminal

__all__ = ["main"]


def _elf_to_dict(elf) -> dict:
    return {
        "tool": "elfpeek",
        "path": elf.path,
        "size": elf.size,
        "is_64": elf.is_64,
        "little_endian": elf.little_endian,
        "type": elf.type,
        "type_name": elf.type_name,
        "machine": elf.machine,
        "machine_name": elf.machine_name,
        "entry": elf.entry,
        "soname": elf.soname,
        "needed": list(elf.needed),
        "segments": [
            {
                "type": seg.type,
                "type_name": seg.type_name,
                "offset": seg.offset,
                "vaddr": seg.vaddr,
                "filesz": seg.filesz,
                "memsz": seg.memsz,
                "flags": seg.flags,
                "flags_text": seg.flags_text,
            }
            for seg in elf.segments
        ],
        "sections": [
            {
                "name": sec.name,
                "type": sec.type,
                "type_name": sec.type_name,
                "offset": sec.offset,
                "addr": sec.addr,
                "size": sec.size,
                "flags": sec.flags,
                "flags_text": sec.flags_text,
            }
            for sec in elf.sections
        ],
        "symbols": [
            {
                "name": sym.name,
                "bind": sym.bind,
                "type": sym.type,
                "shndx": sym.shndx,
                "value": sym.value,
                "size": sym.size,
            }
            for sym in elf.symbols
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="elfpeek",
        description="把 ELF 二进制解析成结构图：节区/段布局、入口、依赖、符号摘要。",
    )
    parser.add_argument("file", metavar="FILE", help="待解析的 ELF 文件路径")
    parser.add_argument("--html", metavar="PATH", help="将结构报告导出为自包含 HTML")
    parser.add_argument("--json", metavar="PATH", help="将解析结果导出为 JSON")
    parser.add_argument("--version", action="version", version=f"elfpeek {__version__}")
    args = parser.parse_args(argv)

    path = Path(args.file)
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"错误：无法读取文件 {path}：{exc}", file=sys.stderr)
        return 2
    try:
        elf = parse(data, str(path))
    except ParseError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    print(render_terminal(elf))

    status = 0
    if args.html:
        try:
            Path(args.html).write_text(render_html(elf), encoding="utf-8")
            print(f"HTML 报告已写入 {args.html}")
        except OSError as exc:
            print(f"错误：无法写入 HTML 文件 {args.html}：{exc}", file=sys.stderr)
            status = 2
    if args.json:
        payload = json.dumps(_elf_to_dict(elf), ensure_ascii=False, indent=2)
        try:
            Path(args.json).write_text(payload + "\n", encoding="utf-8")
            print(f"JSON 报告已写入 {args.json}")
        except OSError as exc:
            print(f"错误：无法写入 JSON 文件 {args.json}：{exc}", file=sys.stderr)
            status = 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
