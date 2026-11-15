#!/usr/bin/env python3
"""Find Thumb BL direct callsites in decoded Pro firmware.

A halfword-sweep can also decode aligned data as an instruction. Results are
*callsite candidates* until validated against a control-flow graph/caller entry.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM

from mcu_fingerprint import decoded_payload

BASE = 0x08001000


def find_calls(payload: bytes, targets: list[int]) -> dict[str, list[dict]]:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    target_set = set(t & ~1 for t in targets)
    found = defaultdict(list)
    for offset in range(0, len(payload)-3, 2):
        halfword = struct.unpack_from("<H", payload, offset)[0]
        if halfword & 0xF800 != 0xF000:
            continue
        pc = BASE + offset
        ins = next(md.disasm(payload[offset:offset+4], pc, count=1), None)
        if ins is None or ins.size != 4 or ins.mnemonic not in ("bl", "blx"):
            continue
        operands = [op.imm for op in ins.operands if op.type == ARM_OP_IMM]
        if not operands:
            continue
        target = operands[0] & ~1
        if target not in target_set:
            continue
        found[target].append({
            "call_pc": f"0x{pc:08X}",
            "instruction": f"{ins.mnemonic} {ins.op_str}",
            "callee": f"0x{target:08X}",
        })
    return {f"0x{target:08X}": found.get(target, []) for target in sorted(target_set)}


def scan_nearby_target(payload: bytes, start: int, end: int, cap: int = 200) -> list[dict]:
    """Find plausible actual function-entry targets in an address window."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    result = []
    for offset in range(0, len(payload)-3, 2):
        if struct.unpack_from("<H", payload, offset)[0] & 0xF800 != 0xF000:
            continue
        pc = BASE + offset
        ins = next(md.disasm(payload[offset:offset+4], pc, count=1), None)
        if not ins or ins.size != 4 or ins.mnemonic not in ("bl", "blx"):
            continue
        operands = [op.imm for op in ins.operands if op.type == ARM_OP_IMM]
        if not operands:
            continue
        target = operands[0] & ~1
        if start <= target < end:
            result.append({
                "call_pc": f"0x{pc:08X}",
                "function_candidate": f"0x{target:08X}",
            })
            if len(result) == cap:
                break
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--target", action="append", type=lambda s: int(s, 0), default=[])
    p.add_argument("--near-start", type=lambda s: int(s, 0))
    p.add_argument("--near-end", type=lambda s: int(s, 0))
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not args.target and (args.near_start is None or args.near_end is None):
        p.error("pass --target or --near-start and --near-end")
    payload = decoded_payload(args.image.read_bytes())
    data = {}
    if args.target:
        data["exact_callees"] = find_calls(payload, args.target)
    if args.near_start is not None and args.near_end is not None:
        data["nearby_callees"] = scan_nearby_target(payload, args.near_start, args.near_end)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        for target, rows in data.get("exact_callees", {}).items():
            print(target, "candidate BL callers:", len(rows))
            for row in rows[:65]:
                print(" ", row["call_pc"], row["instruction"])
        if "nearby_callees" in data:
            print("Nearby function-entry candidates:")
            for row in data["nearby_callees"][:80]:
                print(" ", row["call_pc"], "->", row["function_candidate"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
