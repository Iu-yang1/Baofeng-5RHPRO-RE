#!/usr/bin/env python3
"""Offline, read-only metadata inspection for UV-5RH Pro firmware packages.

This tool does not open a serial port, modify a firmware image, or flash a radio.
Header version fields are reported verbatim and are NOT assumed to be the
radio's software/hardware version strings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

HEADER_SIZE = 0x50
XOR_KEY = 0xC8
MARKER_OFFSET = 0x53


def _header_text(image: bytes, start: int) -> str:
    field = image[start:start + 16]
    field = field.split(b"\xff", 1)[0].split(b"\x00", 1)[0]
    return field.decode("ascii", errors="replace")


def inspect_bytes(image: bytes, name: str = "<memory>") -> dict:
    """Inspect a complete packaged image without modifying it."""
    result = {
        "file": name,
        "file_size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "header": None,
        "payload": None,
        "errors": [],
    }
    errors = result["errors"]
    if len(image) < HEADER_SIZE:
        errors.append("truncated package header (less than 0x50 bytes)")
        return result

    brand = _header_text(image, 0x00)
    model = _header_text(image, 0x10)
    version_20 = _header_text(image, 0x20)
    version_30 = _header_text(image, 0x30)
    declared_length = struct.unpack_from(">I", image, 0x40)[0]
    actual_length = len(image) - HEADER_SIZE
    result["header"] = {
        "brand": brand,
        "model": model,
        "field_0x20": version_20,
        "field_0x30": version_30,
        "declared_payload_length": declared_length,
    }
    if brand != "BaoFeng":
        errors.append("unexpected 0x00 brand signature")
    if model != "BF_5RH":
        errors.append("unexpected 0x10 model signature")
    if declared_length != actual_length:
        errors.append(
            f"payload length mismatch: declared={declared_length}, actual={actual_length}"
        )
    marker = image[MARKER_OFFSET] if len(image) > MARKER_OFFSET else None
    xor_state = {
        0xE8: "xor-obfuscated",
        0x20: "deobfuscated",
    }.get(marker, "unknown")
    payload = {
        "actual_length": actual_length,
        "marker_at_0x53": f"0x{marker:02X}" if marker is not None else None,
        "xor_state_hint": xor_state,
        "vector_hint": None,
    }
    # This is only a Cortex-M vector-table heuristic, not an MCU identification.
    if len(image) >= HEADER_SIZE + 8 and xor_state != "unknown":
        first_eight = image[HEADER_SIZE:HEADER_SIZE + 8]
        if xor_state == "xor-obfuscated":
            first_eight = bytes(value ^ XOR_KEY for value in first_eight)
        initial_sp, reset_vector = struct.unpack("<II", first_eight)
        payload["vector_hint"] = {
            "initial_sp": f"0x{initial_sp:08X}",
            "reset_vector": f"0x{reset_vector:08X}",
            "sram_0x20000000_hint": (initial_sp & 0xFF000000) == 0x20000000,
            "thumb_reset_hint": bool(reset_vector & 1),
        }
    result["payload"] = payload
    return result


def inspect_file(path: Path) -> dict:
    return inspect_bytes(path.read_bytes(), str(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only inspection of Baofeng UV-5RH Pro .dat packages"
    )
    parser.add_argument(
        "files", nargs="*", type=Path,
        help="Packages to inspect (default: firmware/*.dat)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--strict", action="store_true",
        help="Return an error status on missing files or invalid package headers",
    )
    args = parser.parse_args(argv)
    paths = args.files or sorted(Path("firmware").glob("*.dat"))
    if not paths:
        parser.error("no firmware images found; pass one or more .dat paths")
    reports = []
    for path in paths:
        try:
            reports.append(inspect_file(path))
        except OSError as exc:
            reports.append({"file": str(path), "errors": [str(exc)]})
    if args.json:
        print(json.dumps(reports, ensure_ascii=False, indent=2))
    else:
        for report in reports:
            print(f"{report['file']}: {', '.join(report['errors']) or 'header OK'}")
            if report.get("header"):
                header = report["header"]
                payload = report["payload"]
                print(
                    f"  fields: 0x20={header['field_0x20']!r}, "
                    f"0x30={header['field_0x30']!r}; "
                    f"payload={payload['actual_length']} bytes; "
                    f"XOR={payload['xor_state_hint']}"
                )
                if payload["vector_hint"]:
                    print(f"  vector heuristic: {payload['vector_hint']}")
    return 1 if args.strict and any(report["errors"] for report in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
