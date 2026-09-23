"""Security feature detection, entropy and string extraction."""

from __future__ import annotations

import math
import re

from .model import ElfFile

__all__ = [
    "SecurityFeature",
    "StringHit",
    "extract_strings",
    "section_entropy",
    "security_features",
]

ET_DYN = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
MIN_STRING_LEN = 4

CANARY_SYMBOL = "__stack_chk_fail"
FORTIFY_RE = re.compile(r"__(?:\w+)_chk$")
URL_RE = re.compile(r"https?://[\w./%\-?=&#:+]+")
PATH_RE = re.compile(r"(?:/[a-zA-Z0-9._\-]+){2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SecurityFeature:
    """One checksec-style property."""

    __slots__ = ("detail", "name", "status")

    def __init__(self, name: str, status: str, detail: str = "") -> None:
        # status: "yes" / "no" / "unknown"
        self.name = name
        self.status = status
        self.detail = detail


class StringHit:
    """One extracted printable string with a best-effort category."""

    __slots__ = ("category", "offset", "value")

    def __init__(self, value: str, category: str, offset: int) -> None:
        self.value = value
        self.category = category
        self.offset = offset


def security_features(elf: ElfFile) -> list[SecurityFeature]:
    """Return checksec-style hardening properties for an ELF binary."""
    features: list[SecurityFeature] = []

    is_pie = elf.type == ET_DYN
    features.append(
        SecurityFeature(
            "PIE",
            "yes" if is_pie else "no",
            "ET_DYN，加载基址随机化" if is_pie else "ET_EXEC，固定基址",
        )
    )

    stack = next((seg for seg in elf.segments if seg.type == PT_GNU_STACK), None)
    if stack is None:
        features.append(SecurityFeature("NX", "unknown", "无 GNU_STACK 段，栈权限未知"))
    elif stack.flags & 0x1:
        features.append(SecurityFeature("NX", "no", "GNU_STACK 含可执行位，栈可执行"))
    else:
        features.append(SecurityFeature("NX", "yes", "栈不可执行"))

    has_relro = any(seg.type == PT_GNU_RELRO for seg in elf.segments)
    bind_now = bool(elf.dt_flags & DF_BIND_NOW) or bool(elf.dt_flags_1 & DF_1_NOW)
    if has_relro and bind_now:
        features.append(SecurityFeature("RELRO", "full", "GNU_RELRO + BIND_NOW，完全只读重定位"))
    elif has_relro:
        features.append(SecurityFeature("RELRO", "partial", "GNU_RELRO，部分只读重定位"))
    else:
        features.append(SecurityFeature("RELRO", "no", "无 RELRO 段"))

    names = {sym.name for sym in elf.symbols}
    features.append(
        SecurityFeature(
            "Canary",
            "yes" if CANARY_SYMBOL in names else "no",
            "检测到栈溢出保护符号" if CANARY_SYMBOL in names else "未发现栈溢出保护符号",
        )
    )
    fortified = [name for name in names if FORTIFY_RE.match(name)]
    features.append(
        SecurityFeature(
            "FORTIFY",
            "yes" if fortified else "no",
            f"检测到 {len(fortified)} 个 _chk 加固函数" if fortified else "未发现 FORTIFY 加固符号",
        )
    )

    rwx = [seg for seg in elf.segments if seg.flags & 0x7 == 0x7]
    if rwx:
        features.append(
            SecurityFeature("RWX段", "warn", f"存在可读可写可执行段：{', '.join(seg.type_name for seg in rwx)}")
        )
    else:
        features.append(SecurityFeature("RWX段", "no", "无 RWX 段"))
    return features


def section_entropy(data: bytes, offset: int, size: int) -> float:
    """Shannon entropy of a section's bytes (0-8 bits)."""
    if size <= 0 or offset < 0 or offset >= len(data):
        return 0.0
    end = min(offset + size, len(data))
    chunk = data[offset:end]
    if not chunk:
        return 0.0
    counts = [0] * 256
    for byte in chunk:
        counts[byte] += 1
    total = len(chunk)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def fill_entropy(obj, data: bytes) -> None:
    """Compute and store entropy on every section of a parsed binary."""
    for sec in obj.sections:
        offset = getattr(sec, "offset", None)
        if offset is None:
            offset = getattr(sec, "raw_offset", 0)
        size = getattr(sec, "size", None)
        if size is None:
            size = getattr(sec, "raw_size", 0)
        if getattr(sec, "is_nobits", False) or size <= 0:
            sec.entropy = 0.0
            continue
        sec.entropy = section_entropy(data, offset, size)


def extract_strings(data: bytes, *, min_len: int = MIN_STRING_LEN, limit: int = 200) -> list[StringHit]:
    """Extract printable ASCII runs and classify URL/path/IP-like ones."""
    hits: list[StringHit] = []
    start = -1
    n = len(data)
    for i in range(n):
        byte = data[i]
        if 0x20 <= byte < 0x7F:
            if start == -1:
                start = i
        else:
            if start != -1 and i - start >= min_len:
                _emit_string(hits, data[start:i], start)
                if len(hits) >= limit:
                    return hits
            start = -1
    if start != -1 and n - start >= min_len:
        _emit_string(hits, data[start:n], start)
    return hits


def _emit_string(hits: list[StringHit], raw: bytes, offset: int) -> None:
    value = raw.decode("ascii", "replace")
    category = "other"
    if URL_RE.search(value):
        category = "URL"
    elif IP_RE.search(value):
        category = "IP"
    elif PATH_RE.search(value):
        category = "path"
    elif value.strip().endswith(".so") or ".so." in value:
        category = "library"
    hits.append(StringHit(value, category, offset))
