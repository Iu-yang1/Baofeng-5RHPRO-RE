#!/usr/bin/env python3
"""Compare offset-shifted decoded firmware functions without exporting code.

Useful for testing whether UV-5RH Pro V1/V2 share peripheral SDK routines.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload

BASE = 0x08001000


def compare_window(old: bytes, new: bytes, old_pc: int, new_pc: int, size: int) -> dict:
    if size <= 0:
        raise ValueError("window size must be positive")
    old_offset, new_offset = old_pc-BASE, new_pc-BASE
    if old_offset < 0 or new_offset < 0 or old_offset+size > len(old) or new_offset+size > len(new):
        raise ValueError("comparison region must fit within decoded firmware")
    x = old[old_offset:old_offset+size]
    y = new[new_offset:new_offset+size]
    equal_bytes = sum(a == b for a, b in zip(x, y))
    mismatches = [i for i, (a, b) in enumerate(zip(x, y)) if a != b]
    prefix = mismatches[0] if mismatches else size
    old_words = [int.from_bytes(x[i:i+4], "little") for i in range(0, size-size%4, 4)]
    new_words = [int.from_bytes(y[i:i+4], "little") for i in range(0, size-size%4, 4)]
    equal_words = sum(a == b for a, b in zip(old_words, new_words))
    return {
        "old_pc": f"0x{old_pc:08X}",
        "new_pc": f"0x{new_pc:08X}",
        "relocation_delta": f"0x{new_pc-old_pc:X}",
        "size_bytes": size,
        "exact_bytes": x == y,
        "matching_bytes": equal_bytes,
        "matching_percent": round(100 * equal_bytes / size, 2),
        "matching_32bit_words": equal_words,
        "compared_32bit_words": len(old_words),
        "equal_prefix_bytes": prefix,
        "mismatch_offsets_sample": mismatches[:24],
        "old_sha256": hashlib.sha256(x).hexdigest(),
        "new_sha256": hashlib.sha256(y).hexdigest(),
        "limitations": (
            "A high byte similarity is evidence of shared code but does not prove "
            "execution or identify the MCU. Literal pool relocations can create "
            "byte differences without changing instructions."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--pair", action="append", required=True, metavar="OLD:NEW:BYTES")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    old = decoded_payload(args.old.read_bytes())
    new = decoded_payload(args.new.read_bytes())
    output = []
    for item in args.pair:
        parts = item.split(":")
        if len(parts) != 3:
            parser.error("--pair must be OLD:NEW:BYTES, with 0x hex addresses supported")
        a, b, length = (int(p, 0) for p in parts)
        output.append(compare_window(old, new, a, b, length))
    if args.json:
        print(json.dumps(output, indent=2))
    else:
        for entry in output:
            print(entry["old_pc"], "->", entry["new_pc"],
                  "delta", entry["relocation_delta"],
                  "bytes matching", f'{entry["matching_percent"]}%',
                  "exact", entry["exact_bytes"],
                  "sample mismatches", entry["mismatch_offsets_sample"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
