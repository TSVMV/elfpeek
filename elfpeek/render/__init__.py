"""Report rendering: terminal text and self-contained HTML."""

from __future__ import annotations

from .html_export import render_html
from .terminal import render as render_terminal

__all__ = ["render_html", "render_terminal"]
