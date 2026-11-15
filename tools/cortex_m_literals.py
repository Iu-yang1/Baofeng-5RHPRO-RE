#!/usr/bin/env python3
"""Follow Thumb control flow from Cortex-M vectors to collect PC-relative literals.

Unlike raw aligned-word scanning, this requires a decoded LDR instruction
that actually references the word. It is still only a *candidate* hardware
fingerprint: static disassembly cannot prove a literal is reached on device.
Dependencies: capstone >= 5.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_GRP_CALL, CS_GRP_JUMP
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

from mcu_fingerprint import decoded_payload

FLASH_ORIGIN = 0x08001000
MAX_INSTRUCTIONS = 180000
VECTOR_LIMIT = 64


def _peripheral_literal(inst, pc: int, buf: bytes, base: int, end: int):
    """Identify a candidate peripheral address loaded from a Thumb literal pool."""
    if not inst.mnemonic.startswith("ldr"):
        return None
    for op in inst.operands:
        if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
            continue
        location = ((pc + 4) & ~3) + op.mem.disp
        if location % 4 != 0 or not (base <= location <= end - 4):
            continue
        value = struct.unpack_from("<I", buf, location - base)[0]
        if 0x40000000 <= value < 0x60000000:
            return location, value
    return None


def profile(package: bytes, file: str = "<memory>") -> dict:
    buf = decoded_payload(package)
    base = FLASH_ORIGIN
    end = base + len(buf)
    words = struct.unpack_from("<" + "I" * min(VECTOR_LIMIT, len(buf) // 4), buf)
    roots = [
        value & ~1
        for value in words[1:]
        if (value & 1) and base <= (value & ~1) < end
    ]
    roots = list(dict.fromkeys(roots))
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    visited: set[int] = set()
    queued: set[int] = set(roots)
    pending = deque(roots)
    literals = Counter()
    refs = []
    instructions = 0

    def queue_address(addr: int) -> None:
        addr &= ~1
        if base <= addr < end and addr not in queued and addr not in visited:
            pending.append(addr)
            queued.add(addr)

    while pending and instructions < MAX_INSTRUCTIONS:
        addr = pending.popleft()
        for _ in range(30000):
            if not (base <= addr < end - 3) or addr in visited:
                break
            offset = addr - base
            inst = next(md.disasm(buf[offset:offset + 4], addr, count=1), None)
            if inst is None:
                break
            visited.add(addr)
            instructions += 1
            mnemonic = inst.mnemonic
            operands = inst.operands
            found = _peripheral_literal(inst, addr, buf, base, end)
            if found is not None:
                location, word = found
                literals[word] += 1
                refs.append((addr, location, word))
            targets = [op.imm for op in operands if op.type == ARM_OP_IMM]
            if targets and (inst.group(CS_GRP_CALL) or inst.group(CS_GRP_JUMP)):
                for target in targets:
                    queue_address(target)
            # Stop at an unconditional branch or a return; keep traversing
            # after calls and conditional branches.
            if mnemonic in ("b", "b.w", "bx", "bx.w", "bxj", "tbb", "tbh"):
                break
            if mnemonic.startswith(("pop", "ldmia")) and "pc" in inst.op_str:
                break
            if mnemonic in ("svc", "bkpt", "udf"):
                break
            addr += inst.size
            if instructions >= MAX_INSTRUCTIONS:
                break

    buckets = Counter()
    for value, count in literals.items():
        buckets[value & ~0xFFF] += count
    return {
        "file": file,
        "analysis_kind": "PC-relative literal loads from statically reachable Thumb instructions",
        "flash_origin_assumption": f"0x{FLASH_ORIGIN:08X}",
        "vector_roots": len(roots),
        "instructions_examined": instructions,
        "budget_exhausted": instructions >= MAX_INSTRUCTIONS,
        "literal_loads_peripheral": sum(literals.values()),
        "literal_values": [
            {"address": f"0x{value:08X}", "load_sites": count}
            for value, count in literals.most_common(90)
        ],
        "peripheral_4k_banks": [
            {"bank": f"0x{value:08X}", "load_sites": count}
            for value, count in buckets.most_common(45)
        ],
        "sample_cross_references": [
            {"instruction": f"0x{a:08X}", "literal_location": f"0x{b:08X}", "value": f"0x{c:08X}"}
            for a, b, c in refs[:70]
        ],
        "caveats": [
            "Only Cortex-M Thumb decoding is attempted; the exact core generation is not identified.",
            "No runtime paths, register readback, or physical hardware are inspected.",
            "Control-flow traversal may miss indirect calls and can misidentify code in data regions.",
            "Address values and code layout do not by themselves establish an MCU part number.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    reports = [profile(path.read_bytes(), str(path)) for path in args.files]
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        for report in reports:
            print(f"== {report['file']} ==")
            print(
                f"Roots: {report['vector_roots']}; instructions: "
                f"{report['instructions_examined']}; peripheral LDR literals: "
                f"{report['literal_loads_peripheral']}"
            )
            print("Top peripheral address banks:")
            for item in report["peripheral_4k_banks"][:20]:
                print(f"  {item['bank']}: {item['load_sites']}")
            print("Top peripheral literal values:")
            for item in report["literal_values"][:30]:
                print(f"  {item['address']}: {item['load_sites']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
