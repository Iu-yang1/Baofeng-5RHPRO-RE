#!/usr/bin/env python3
"""Inspect a bounded Thumb disassembly window with resolved PC-relative literals.

This is a *linear* disassembly aid for selected firmware addresses; it does
not imply every instruction in the window is executed. Read-only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from mcu_fingerprint import decoded_payload

BASE = 0x08001000


def inspect_window(payload: bytes, start: int, end: int) -> list[dict]:
    if not (BASE <= start < end <= BASE + len(payload)):
        raise ValueError("requested disassembly window is outside decoded image")
    if start % 2:
        raise ValueError("Thumb window address must be halfword aligned")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    entries = []
    for ins in decoder.disasm(payload[start-BASE:end-BASE], start):
        entry = {
            "pc": f"0x{ins.address:08X}",
            "size": ins.size,
            "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        }
        if ins.mnemonic.startswith("ldr"):
            for op in ins.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC and not op.mem.index:
                    location = ((ins.address + 4) & ~3) + op.mem.disp
                    if BASE <= location <= BASE + len(payload) - 4 and not location % 4:
                        value = struct.unpack_from("<I", payload, location - BASE)[0]
                        entry["literal_address"] = f"0x{location:08X}"
                        entry["literal_value"] = f"0x{value:08X}"
        entries.append(entry)
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--start", required=True, type=lambda v: int(v, 0))
    parser.add_argument("--end", required=True, type=lambda v: int(v, 0))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    items = inspect_window(decoded_payload(args.firmware.read_bytes()), args.start, args.end)
    if args.json:
        print(json.dumps(items, indent=2))
    else:
        for item in items:
            literal = (
                f"  ; pool[{item['literal_address']}]={item['literal_value']}"
                if "literal_value" in item else ""
            )
            print(f"{item['pc']}  {item['mnemonic']:<9} {item['operands']}{literal}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
