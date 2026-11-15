#!/usr/bin/env python3
"""Read-only Cortex-M pointer/interrupt vector fingerprint of 5RH Pro images.

An aligned four-byte sequence resembling an address is not proof that it is
used as a pointer. Report raw evidence without guessing the exact MCU.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from firmware_inspect import HEADER_SIZE, XOR_KEY, inspect_bytes

REGIONS = {
    "code_flash": (0x08000000, 0x08200000),
    "sram": (0x20000000, 0x20080000),
    "peripheral": (0x40000000, 0x60000000),
    "system": (0xE0000000, 0xE0100000),
}
VECTOR_ENTRIES = 64


def decoded_payload(package: bytes) -> bytes:
    meta = inspect_bytes(package)
    if meta["errors"]:
        raise ValueError("package integrity check failed: " + "; ".join(meta["errors"]))
    state = meta["payload"]["xor_state_hint"]
    raw = package[HEADER_SIZE:]
    if state == "xor-obfuscated":
        return bytes(byte ^ XOR_KEY for byte in raw)
    if state == "deobfuscated":
        return raw
    raise ValueError("unknown XOR state; cannot decode without a verified marker")


def analyze(package: bytes, filename: str = "<memory>") -> dict:
    payload = decoded_payload(package)
    words = [
        struct.unpack_from("<I", payload, offset)[0]
        for offset in range(0, len(payload) - len(payload) % 4, 4)
    ]
    vector = words[:VECTOR_ENTRIES]
    groups = {name: Counter() for name in REGIONS}
    for value in words:
        for name, (low, high) in REGIONS.items():
            if low <= value < high:
                groups[name][value] += 1
                break
    peripheral = groups["peripheral"]
    # 4 KiB grouping is only a visualization of evidence, NOT a register model.
    banks = Counter()
    for addr, count in peripheral.items():
        banks[addr & ~0xFFF] += count
    # Keep all information needed for independent offline analysis in JSON.
    return {
        "file": filename,
        "payload_bytes": len(payload),
        "initial_sp_candidate": f"0x{vector[0]:08X}" if vector else None,
        "reset_handler_candidate": f"0x{vector[1]:08X}" if len(vector) > 1 else None,
        "vector_first_64": [f"0x{v:08X}" for v in vector],
        "region_counts_aligned_words": {
            name: sum(counter.values()) for name, counter in groups.items()
        },
        "peripheral_top_words": [
            {"address": f"0x{addr:08X}", "count": count}
            for addr, count in peripheral.most_common(60)
        ],
        "peripheral_4k_bank_counts": [
            {"bank": f"0x{addr:08X}", "count": count}
            for addr, count in banks.most_common(35)
        ],
        "interpretation_limits": (
            "The aligned 32-bit word search includes incidental constants and data. "
            "Address frequency cannot identify an MCU without disassembly, "
            "peripheral register cross-references and PCB/debugger confirmation."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true", help="Machine-readable report")
    args = parser.parse_args(argv)
    reports = [analyze(p.read_bytes(), str(p)) for p in args.files]
    if args.json:
        print(json.dumps(reports, indent=2))
        return 0
    for report in reports:
        print(f"== {report['file']} ==")
        print(
            f"Payload {report['payload_bytes']} bytes; "
            f"SP={report['initial_sp_candidate']}; "
            f"Reset={report['reset_handler_candidate']}"
        )
        print("Candidate aligned-address counts:", report["region_counts_aligned_words"])
        print("Peripheral address banks (4 KiB buckets):")
        for item in report["peripheral_4k_bank_counts"][:15]:
            print(f"  {item['bank']}: {item['count']}")
        print("Most common peripheral-address words:")
        for item in report["peripheral_top_words"][:25]:
            print(f"  {item['address']}: {item['count']}")
        print("First 16 vector candidate words:")
        print("  " + " ".join(report["vector_first_64"][:16]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
