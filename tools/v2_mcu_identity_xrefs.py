#!/usr/bin/env python3
"""Search the stock V2 firmware for code-referenced MCU identity registers.

Unlike naive raw string/word scanning, an xref here requires a valid Thumb
LDR-literal instruction pointing to the exact word. Still a disassembly
candidate until path reachability is established. Read-only.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from mcu_fingerprint import decoded_payload

BASE = 0x08001000
CANDIDATES = {
    0xE000ED00: "ARM CPUID",
    0xE0042000: "AT32 DEBUG_IDCODE",
    0x1FFFF7E0: "Artery Flash size address, device-dependent",
    0x1FFFF7F3: "Artery project-type byte address",
    0x1FFFF7E8: "Artery UID region (avoid dumping unique identity)",
    0x40022000: "STM32F1-style FLASH controller",
    0x40016C00: "AT32F403A/407-compatible I2S2EXT candidate",
    0x1FFFD000: "System boot ROM pointer table candidate",
    0x40021000: "STM32F1/AT32 CRM/RCC",
    0x40020400: "DMA2 candidate",
}


def scan(payload: bytes) -> dict:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    raw_counts: Counter[int] = Counter()
    refs: dict[int, list[dict]] = {x: [] for x in CANDIDATES}
    for ofs in range(0, len(payload)-3, 4):
        word = struct.unpack_from("<I", payload, ofs)[0]
        if word in CANDIDATES:
            raw_counts[word] += 1
    for ofs in range(0, len(payload)-3, 2):
        halfword = struct.unpack_from("<H", payload, ofs)[0]
        if (halfword & 0xF800) != 0x4800 and (halfword & 0xFFF0) not in (0xF85F, 0xF8DF):
            continue
        pc = BASE+ofs
        inst = next(md.disasm(payload[ofs:ofs+4], pc, count=1), None)
        if not inst or not inst.mnemonic.startswith("ldr"):
            continue
        for op in inst.operands[1:]:
            if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index:
                continue
            pool_addr = ((pc+4)&~3)+op.mem.disp
            if pool_addr % 4 or not (BASE <= pool_addr <= BASE+len(payload)-4):
                continue
            word = struct.unpack_from("<I", payload, pool_addr-BASE)[0]
            if word not in CANDIDATES:
                continue
            refs[word].append({
                "ldr_pc": f"0x{pc:08X}",
                "pool_pc": f"0x{pool_addr:08X}",
                "instruction": f"{inst.mnemonic} {inst.op_str}",
            })
    return {
        "image_load_base_hypothesis": f"0x{BASE:08X}",
        "candidates": [{
            "address": f"0x{addr:08X}", "label": name,
            "aligned_raw_word_occurrences": raw_counts[addr],
            "thumb_literal_load_candidates": refs[addr],
        } for addr,name in CANDIDATES.items()],
        "limitations": [
            "Absence of a reference does not rule out a family; the application may never read its ID.",
            "Thumb halfword sweep may produce false positives; validate candidates by CFG.",
            "This script never reads chip registers, firmware protection state, or unique device IDs.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    result = scan(decoded_payload(args.image.read_bytes()))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for entry in result["candidates"]:
            print(entry["address"],entry["label"],"raw=",entry["aligned_raw_word_occurrences"],
                  "ldr_candidates=",len(entry["thumb_literal_load_candidates"]))
            for x in entry["thumb_literal_load_candidates"][:20]:
                print(" ", x["ldr_pc"],x["instruction"],"pool",x["pool_pc"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
