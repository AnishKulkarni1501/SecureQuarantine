"""Bounded, byte-only static inspection. Never loads or executes a sample."""
import re
import struct
from itertools import islice


def identify(data: bytes) -> str:
    pe = extract_metadata(data)
    if pe.get("format") == "PE" and pe.get("valid_header"):
        return f"PE executable ({pe.get('architecture', 'unknown')})"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive (not classified as executable)"
    return "Unknown / non-executable format"


def _u16(data: bytes, offset: int) -> int | None:
    return struct.unpack_from("<H", data, offset)[0] if 0 <= offset <= len(data) - 2 else None


def _u32(data: bytes, offset: int) -> int | None:
    return struct.unpack_from("<I", data, offset)[0] if 0 <= offset <= len(data) - 4 else None


def extract_metadata(data: bytes) -> dict:
    """Parse a bounded subset of PE metadata without loading or executing the file."""
    if not data.startswith(b"MZ") or len(data) < 64:
        if data.startswith(b"\x7fELF") and len(data) >= 20:
            machine = int.from_bytes(data[18:20], "little")
            return {"format": "ELF", "architecture": {3: "x86", 40: "ARM", 62: "x86_64", 183: "AArch64"}.get(machine, f"machine-{machine}"), "imports": [], "sections": []}
        return {"format": "unknown", "imports": [], "sections": []}
    pe_offset = _u32(data, 0x3C)
    if pe_offset is None or pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return {"format": "PE", "valid_header": False, "imports": [], "sections": []}
    machine = _u16(data, pe_offset + 4) or 0
    section_count = min(_u16(data, pe_offset + 6) or 0, 96)
    optional_size = _u16(data, pe_offset + 20) or 0
    optional = pe_offset + 24
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B) or optional + optional_size > len(data):
        return {"format": "PE", "valid_header": False, "imports": [], "sections": []}
    arch = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "ARM", 0xAA64: "AArch64"}.get(machine, f"machine-0x{machine:04x}")
    section_table = optional + optional_size
    sections = []
    maps = []
    for index in range(section_count):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = _u32(data, offset + 8) or 0
        virtual_address = _u32(data, offset + 12) or 0
        raw_size = _u32(data, offset + 16) or 0
        raw_pointer = _u32(data, offset + 20) or 0
        characteristics = _u32(data, offset + 36) or 0
        sections.append({"name": name, "virtual_size": virtual_size, "raw_size": raw_size, "characteristics": f"0x{characteristics:08x}"})
        maps.append((virtual_address, max(virtual_size, raw_size), raw_pointer))

    def rva_to_offset(rva: int) -> int | None:
        if rva < section_table and rva < len(data):
            return rva
        for va, span, raw in maps:
            if va <= rva < va + span:
                position = raw + rva - va
                return position if position < len(data) else None
        return None

    imports = []
    directory_offset = optional + (96 if magic == 0x10B else 112)
    num_dirs_offset = optional + (92 if magic == 0x10B else 108)
    directory_count = _u32(data, num_dirs_offset) or 0
    import_rva = _u32(data, directory_offset + 8) if directory_count > 1 else 0
    import_offset = rva_to_offset(import_rva or 0) if import_rva else None
    if import_offset is not None:
        for index in range(512):
            descriptor = import_offset + index * 20
            if descriptor + 20 > len(data):
                break
            original = _u32(data, descriptor) or 0
            name_rva = _u32(data, descriptor + 12) or 0
            first_thunk = _u32(data, descriptor + 16) or 0
            if not (original or name_rva or first_thunk):
                break
            name_offset = rva_to_offset(name_rva)
            if name_offset is None:
                continue
            end = data.find(b"\0", name_offset, min(len(data), name_offset + 260))
            dll = data[name_offset:end if end >= 0 else name_offset + 260].decode("ascii", "replace")
            import_table = rva_to_offset(original or first_thunk)
            symbols = []
            if import_table is not None:
                width = 8 if magic == 0x20B else 4
                ordinal_mask = 1 << (width * 8 - 1)
                for item_index in range(512):
                    entry_offset = import_table + item_index * width
                    value = int.from_bytes(data[entry_offset:entry_offset + width], "little") if entry_offset + width <= len(data) else 0
                    if not value:
                        break
                    if value & ordinal_mask:
                        symbols.append(f"ordinal:{value & 0xffff}")
                    else:
                        hint_name = rva_to_offset(value)
                        if hint_name is not None and hint_name + 2 < len(data):
                            terminator = data.find(b"\0", hint_name + 2, min(len(data), hint_name + 258))
                            if terminator > 0:
                                symbols.append(data[hint_name + 2:terminator].decode("ascii", "replace"))
                    if len(symbols) >= 256:
                        break
            imports.append({"library": dll, "symbols": symbols})
            if len(imports) >= 128:
                break
    return {"format": "PE", "valid_header": True, "architecture": arch, "section_count": len(sections), "sections": sections, "imports": imports}


def analyze_bytes(data: bytes, file_type: str) -> tuple[list[dict], float, str, str]:
    findings: list[dict] = []
    strings = [match.group().decode("ascii", errors="ignore") for match in islice(re.finditer(rb"[\x20-\x7e]{6,}", data[:8_000_000]), 50_000)]
    lowered = "\n".join(strings).lower()
    indicators = {
        "network_api": ("network-related strings", ("http://", "https://", "winsock", "socket")),
        "persistence_hint": ("possible persistence-related strings", ("currentversion\\run", "startup", "schtasks")),
        "process_injection_hint": ("possible process-manipulation strings", ("writeprocessmemory", "createremotethread", "ptrace")),
    }
    for kind, (title, tokens) in indicators.items():
        hits = [token for token in tokens if token in lowered]
        if hits:
            findings.append({"kind": kind, "title": title, "detail": "Matched strings: " + ", ".join(hits) + ". Strings are leads for review, not proof of behavior.", "source": "static_strings", "confidence": None})
    imported_names = {symbol.lower() for library in extract_metadata(data).get("imports", []) for symbol in library.get("symbols", [])}
    dangerous_imports = {"writeprocessmemory": "process manipulation", "createremotethread": "remote thread creation", "virtualallocex": "remote memory allocation", "urldownloadtofilea": "network download", "urldownloadtofilew": "network download", "regsetvalueexw": "registry modification"}
    for symbol, description in dangerous_imports.items():
        if symbol in imported_names and not any(f["kind"] == "process_injection_hint" for f in findings):
            findings.append({"kind": "suspicious_import", "title": f"Import suggests {description}", "detail": f"Imported API: {symbol}. An import indicates availability, not execution or malicious intent.", "source": "static_imports", "confidence": None})
    score = min(0.75, 0.25 * len(findings))
    if not file_type.startswith(("PE", "ELF", "Mach-O")):
        recommendation, completeness = "analyze_further", "partial"
        summary = "The file format is not a supported executable. Static string indicators are limited and no safety conclusion is available."
    elif findings:
        recommendation, completeness = "human_review", "partial"
        summary = "Static strings suggest capabilities that need validation. No code was executed and no behavior is confirmed."
    else:
        recommendation, completeness = "analyze_further", "partial"
        summary = "No configured static string indicators were found. This is incomplete evidence and does not establish that the file is safe."
    return findings, score, recommendation, summary
