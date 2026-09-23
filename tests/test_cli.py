"""Tests for the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import build_elf64

from elfpeek.cli import main


def _write_elf(tmp_path: Path) -> Path:
    path = tmp_path / "demo.elf"
    path.write_bytes(build_elf64())
    return path


def test_cli_runs_and_reports(tmp_path, capsys):
    path = _write_elf(tmp_path)
    code = main([str(path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "elfpeek ELF 结构报告" in out
    assert "可执行" in out


def test_cli_exports_html_and_json(tmp_path):
    path = _write_elf(tmp_path)
    html_path = tmp_path / "out.html"
    json_path = tmp_path / "out.json"
    code = main([str(path), "--html", str(html_path), "--json", str(json_path)])
    assert code == 0
    assert html_path.exists()
    assert "<script" not in html_path.read_text(encoding="utf-8").lower()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["tool"] == "elfpeek"
    assert data["needed"] == ["libc.so.6"]
    assert len(data["sections"]) == 7
    assert len(data["segments"]) == 1


def test_cli_missing_file_returns_error(tmp_path, capsys):
    code = main([str(tmp_path / "missing.elf")])
    assert code == 2
    err = capsys.readouterr().err
    assert "无法读取" in err


def test_cli_non_elf_returns_error(tmp_path, capsys):
    path = tmp_path / "bad.bin"
    path.write_bytes(b"not elf")
    code = main([str(path)])
    assert code == 1
    err = capsys.readouterr().err
    assert "不是 ELF" in err
