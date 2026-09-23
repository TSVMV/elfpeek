"""elfpeek: render an ELF binary as a structural map."""

from __future__ import annotations

from .model import ElfFile
from .parse import parse

__version__ = "0.1.0"
__all__ = ["ElfFile", "__version__", "parse"]
