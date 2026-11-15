#!/usr/bin/env python3
"""Read-only V2.0.09 Cortex-M boot/IRQ/control-flow reconnaissance.

Output is static *evidence*, not proof of MCU identity, hardware layout, or
successful execution on the radio. Requires capstone>=5; never opens a port.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import (
    Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB,
    CS_GRP_CALL, CS_GRP_JUMP,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

from mcu_fingerprint import decoded_payload

FLASH_ORIGIN = 0x08001000  # Hypothesis from all six XOR-decoded reset vectors
MAX_VISITED = 120_000
VECTOR_WORDS = 64
LITERAL_ADDRESS_MIN = 0x40000000
LITERAL_ADDRESS_MAX = 0x60000000
# Thumb-2 forms beyond the ARMv6-M subset are useful architectural clues.
THUMB2_M3_PLUS = frozenset({
    "movw", "movt", "ubfx", "sbfx", "bfi", "bfc",
    "ldrex", "strex", "clz", "udiv", "sdiv",
    "tbb", "tbh", "rbit", "smlal", "smull", "umull",
})
INTERESTING_STRINGS = re.compile(
    rb"(?:AT32|STM32|GD32|Cortex|KDH|FD6818|GPS|APRS|BaoFeng|"
    rb"Firmware|Software|[Vv][12][._][0-9][._][0-9])", re.I,
)
ASCII_RUN = re.compile(rb"[\x20-\x7e]{8,}")


def read_words(data: bytes, count: int = VECTOR_WORDS) -> list[int]:
    take = min(count, len(data) // 4)
    return list(struct.unpack_from("<" + "I" * take, data, 0))


def valid_thumb_target(target: int, end: int) -> bool:
    return (target & 1) == 1 and FLASH_ORIGIN <= (target & ~1) < end


def trace(payload: bytes, instruction_limit: int = MAX_VISITED) -> dict:
    """Trace reachable *candidate* Thumb paths using vector-derived roots."""
    end = FLASH_ORIGIN + len(payload)
    vectors = read_words(payload)
    entries = {
        i: value for i, value in enumerate(vectors[1:], start=1)
        if valid_thumb_target(value, end)
    }
    roots = list(dict.fromkeys(value & ~1 for value in entries.values()))
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    pending = deque(roots)
    queued = set(roots)
    visited: set[int] = set()
    mnemonic_counts: Counter[str] = Counter()
    thumb2_clues: dict[str, list[str]] = {}
    literal_refs: list[dict[str, str]] = []
    peripheral_values: Counter[int] = Counter()
    indirect_targets: Counter[int] = Counter()
    indirect_branch_samples: list[dict[str, str]] = []
    calls: Counter[int] = Counter()
    branches: Counter[int] = Counter()

    while pending and len(visited) < instruction_limit:
        addr = pending.popleft()
        # Trivial intra-basic-block constant propagation for LDR-literal -> BX/BLX reg.
        loaded_literals: dict[int, int] = {}
        for _ in range(25000):
            if addr in visited or not (FLASH_ORIGIN <= addr <= end - 4):
                break
            offset = addr - FLASH_ORIGIN
            inst = next(decoder.disasm(payload[offset:offset + 4], addr, count=1), None)
            if inst is None:
                break
            visited.add(addr)
            mnemonic = inst.mnemonic.split(".")[0]
            mnemonic_counts[mnemonic] += 1
            if mnemonic in THUMB2_M3_PLUS:
                hits = thumb2_clues.setdefault(mnemonic, [])
                if len(hits) < 5:
                    hits.append(f"0x{addr:08X}")
            for operand in inst.operands:
                if mnemonic.startswith("ldr") and operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                    location = ((addr + 4) & ~3) + operand.mem.disp
                    if FLASH_ORIGIN <= location <= end - 4 and location % 4 == 0:
                        value = struct.unpack_from("<I", payload, location - FLASH_ORIGIN)[0]
                        if inst.operands and inst.operands[0].type == ARM_OP_REG:
                            loaded_literals[inst.operands[0].reg] = value
                        if LITERAL_ADDRESS_MIN <= value < LITERAL_ADDRESS_MAX:
                            peripheral_values[value] += 1
                            if len(literal_refs) < 250:
                                literal_refs.append({
                                    "load_pc": f"0x{addr:08X}",
                                    "literal_pc": f"0x{location:08X}",
                                    "peripheral_address": f"0x{value:08X}",
                                })
            is_branch = inst.group(CS_GRP_JUMP)
            is_call = inst.group(CS_GRP_CALL)
            if mnemonic in ("bx", "blx") and inst.operands and inst.operands[0].type == ARM_OP_REG:
                dest = loaded_literals.get(inst.operands[0].reg)
                if dest is not None and valid_thumb_target(dest, end):
                    target = dest & ~1
                    indirect_targets[target] += 1
                    if len(indirect_branch_samples) < 60:
                        indirect_branch_samples.append({
                            "branch_site": f"0x{addr:08X}",
                            "resolved_target": f"0x{dest:08X}",
                        })
                    if target not in visited and target not in queued:
                        pending.append(target)
                        queued.add(target)
            if is_call:
                # CALL clobbers volatile registers. Do not attribute post-call
                # indirect branches to pre-call constants.
                loaded_literals.clear()
            if is_branch or is_call:
                for operand in inst.operands:
                    if operand.type == ARM_OP_IMM:
                        target = operand.imm & ~1
                        if FLASH_ORIGIN <= target < end:
                            counter = calls if is_call else branches
                            counter[target] += 1
                            if target not in visited and target not in queued:
                                pending.append(target)
                                queued.add(target)
            # Do not decode literal-pool/data bytes beyond unconditional control-flow transfer.
            if mnemonic in ("b", "bx", "bxj", "tbb", "tbh", "udf", "bkpt"):
                break
            if mnemonic.startswith(("pop", "ldmia")) and "pc" in inst.op_str:
                break
            if mnemonic == "svc":
                break
            addr += inst.size
            if len(visited) >= instruction_limit:
                break

    reset = vectors[1] & ~1 if len(vectors) > 1 else None
    boot_instructions = []
    if reset is not None and FLASH_ORIGIN <= reset < end:
        # This is linear disassembly for context, NOT a validated execution trace.
        for inst in decoder.disasm(payload[reset-FLASH_ORIGIN:reset-FLASH_ORIGIN+256], reset):
            if len(boot_instructions) >= 32:
                break
            boot_instructions.append(f"0x{inst.address:08X}: {inst.mnemonic} {inst.op_str}".strip())
            if inst.mnemonic in ("b", "b.w", "bx", "bx.w", "bxj", "udf"):
                break

    strings = []
    for match in ASCII_RUN.finditer(payload):
        raw = match.group(0)
        if INTERESTING_STRINGS.search(raw):
            strings.append({
                "image_address": f"0x{FLASH_ORIGIN + match.start():08X}",
                "text": raw[:120].decode("ascii", errors="replace"),
            })
            if len(strings) == 80:
                break

    bank_count: Counter[int] = Counter()
    for addr, hits in peripheral_values.items():
        bank_count[addr & ~0xFFF] += hits
    return {
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_length_bytes": len(payload),
        "flash_origin_hypothesis": f"0x{FLASH_ORIGIN:08X}",
        "initial_stack_pointer_candidate": f"0x{vectors[0]:08X}" if vectors else None,
        "reset_candidate": f"0x{vectors[1]:08X}" if len(vectors)>1 else None,
        "vectors_first_64": [f"0x{x:08X}" for x in vectors],
        "vector_valid_thumb_entries": len(entries),
        "vector_unique_entry_points": len(roots),
        "vector_zero_entries": sum(1 for x in vectors if x == 0),
        "vector_first_32": [
            {"index": i, "value": f"0x{value:08X}"} for i, value in enumerate(vectors[:32])
        ],
        "reset_linear_disassembly": boot_instructions,
        "reachable_instruction_candidates": len(visited),
        "max_instructions_reached": len(visited) >= instruction_limit,
        "thumb2_m3_plus_clues": thumb2_clues,
        "top_mnemonics": mnemonic_counts.most_common(25),
        "direct_call_target_count": len(calls),
        "direct_branch_target_count": len(branches),
        "resolved_indirect_branch_targets": [
            {"target": f"0x{target:08X}", "sites": count}
            for target, count in indirect_targets.most_common(60)
        ],
        "indirect_branch_sample": indirect_branch_samples,
        "peripheral_ldr_sites": sum(peripheral_values.values()),
        "peripheral_addresses": [
            {"address": f"0x{k:08X}", "load_sites": v}
            for k, v in peripheral_values.most_common(90)
        ],
        "peripheral_4k_banks": [
            {"base": f"0x{k:08X}", "load_sites": v}
            for k, v in bank_count.most_common(40)
        ],
        "literal_cross_reference_sample": literal_refs,
        "interesting_ascii_strings": strings,
        "notes": [
            "All results come from a read-only XOR-decoded update-package payload.",
            "The assumed load base 0x08001000 and all vector/call targets require independent validation.",
            "Only simple same-basic-block LDR-literal -> BX/BLX register branches are resolved.",
            "Control-flow traversal still misses general indirect calls and may decode embedded data.",
            "A Thumb-2 clue on a reachable path is evidence about the ISA, not a vendor/part-number ID.",
            "Unmatched ASCII strings may be missing due to encoding, compression or resource packaging.",
        ],
    }


def compare(first: dict, second: dict) -> dict:
    fvec = first["vectors_first_64"]
    svec = second["vectors_first_64"]
    different = [
        {"index": i, "older": a, "newer": b}
        for i, (a, b) in enumerate(zip(fvec, svec))
        if a != b
    ]
    first_regs = {v["address"] for v in first["peripheral_addresses"]}
    second_regs = {v["address"] for v in second["peripheral_addresses"]}
    return {
        "vector_entries_changed": different,
        "old_only_peripheral_addresses": sorted(first_regs - second_regs),
        "new_only_peripheral_addresses": sorted(second_regs - first_regs),
        "identical_reset_candidates": first["reset_candidate"] == second["reset_candidate"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    reports = []
    for path in args.images:
        report = trace(decoded_payload(path.read_bytes()))
        report["file"] = str(path)
        reports.append(report)
    output = {"images": reports}
    if len(reports) == 2:
        output["comparison"] = compare(reports[0], reports[1])
    if args.json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        for report in reports:
            print(f"=== {report['file']} ===")
            print("vectors", report["vector_valid_thumb_entries"], "unique ISRs",
                  report["vector_unique_entry_points"])
            print("reset", report["reset_candidate"], "stack", report["initial_stack_pointer_candidate"])
            print("statically reachable instructions", report["reachable_instruction_candidates"])
            print("Thumb-2 M3+ candidate instructions", report["thumb2_m3_plus_clues"])
            print("Resolved indirect BX/BLX target samples:")
            for item in report["indirect_branch_sample"][:15]:
                print(" ", item)
            print("Reset disassembly:")
            for line in report["reset_linear_disassembly"]:
                print(" ", line)
            print("Peripheral LDR literals:")
            for entry in report["peripheral_addresses"][:28]:
                print(" ", entry)
            print("ASCII signature candidates:")
            for entry in report["interesting_ascii_strings"][:15]:
                print(" ", entry)
        if "comparison" in output:
            print("comparison", json.dumps(output["comparison"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
