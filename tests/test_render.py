"""Tests for terminal and HTML rendering."""

from __future__ import annotations

from elfpeek.parse import parse
from elfpeek.render import render_html, render_terminal


def test_terminal_summary_sections(elf_bytes):
    elf = parse(elf_bytes)
    text = render_terminal(elf)
    assert "elfpeek ELF 结构报告" in text
    assert "程序段: 1 个" in text
    assert "节区: 7 个" in text
    assert "动态依赖: 1 个" in text
    assert "libc.so.6" in text
    assert "导入 1 个" in text


def test_terminal_lists_imports(elf_bytes):
    elf = parse(elf_bytes)
    text = render_terminal(elf)
    assert "- foo" in text
    assert "+ bar" in text


def test_html_is_self_contained(elf_bytes):
    elf = parse(elf_bytes)
    html = render_html(elf)
    assert html.startswith("<!DOCTYPE html>")
    assert "<script" not in html.lower()
    assert "文件布局" in html
    assert "svg" in html.lower()


def test_html_renders_tables(elf_bytes):
    elf = parse(elf_bytes)
    html = render_html(elf)
    assert "<table>" in html
    assert ".text" in html
    assert ".dynstr" in html
    assert "libc.so.6" in html


def test_html_layout_has_section_rects(elf_bytes):
    elf = parse(elf_bytes)
    html = render_html(elf)
    assert "<rect" in html
    assert ".text" in html
