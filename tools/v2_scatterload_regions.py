#!/usr/bin/env python3
"""Read-only ARM scatterload region-table inspection in the V2 stock image.

ARM __scatterload descriptors pass source, execution destination, byte count,
and initialization handler to a region callback. No payload bytes are saved.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload
from thumb_window import BASE, inspect_window

REGION_START = 0x08061A34
REGION_END = 0x08061A54
RAM_TABLE_ADDRESSES = (0x20000014, 0x20000018)


def inspect(payload: bytes) -> dict:
    descriptors = []
    for addr in range(REGION_START, REGION_END, 16):
        offset = addr - BASE
        if offset < 0 or offset+16 > len(payload):
            raise ValueError("scatterload descriptor outside image")
        source, dest, size, handler = struct.unpack_from("<IIII", payload, offset)
        func = handler & ~1
        if not BASE <= func < BASE+len(payload):
            raise ValueError("scatterload handler points outside executable image")
        preview = inspect_window(payload, func, min(func+32, BASE+len(payload)))
        descriptors.append({
            "descriptor_pc": f"0x{addr:08X}",
            "load_address": f"0x{source:08X}",
            "run_address": f"0x{dest:08X}",
            "length_bytes": size,
            "handler": f"0x{handler:08X}",
            "handler_disassembly": [
                f"{e['pc']}: {e['mnemonic']} {e['operands']}"
                for e in preview[:10]
            ],
            "target_ram_table_addresses": [
                f"0x{target:08X}" for target in RAM_TABLE_ADDRESSES
                if dest <= target < dest+size
            ],
            "source_in_package": BASE <= source < BASE+len(payload),
        })
    return {
        "table_start": f"0x{REGION_START:08X}",
        "table_end": f"0x{REGION_END:08X}",
        "descriptors": descriptors,
        "note": (
            "ARM scatterload descriptor interpretation is inferred from startup "
            "instructions; inspect callback code before assuming raw copy vs "
            "zero-init or decompression."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    report = inspect(decoded_payload(args.firmware.read_bytes()))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for row in report["descriptors"]:
            print(row["descriptor_pc"], row["load_address"], "=>", row["run_address"],
                  "size", row["length_bytes"], "handler", row["handler"],
                  "contains clock tables", row["target_ram_table_addresses"])
            for ins in row["handler_disassembly"]:
                print(" ", ins)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
