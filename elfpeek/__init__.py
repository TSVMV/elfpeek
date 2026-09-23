"""elfpeek: render an ELF/PE binary as a structural map."""

from __future__ import annotations

from .model import ElfFile, PEFile
from .parse import parse
from .pe import parse_pe

__version__ = "0.2.0"
__all__ = ["ElfFile", "PEFile", "__version__", "parse", "parse_pe"]
