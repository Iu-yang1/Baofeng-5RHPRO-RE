#!/usr/bin/env python3
"""Conservative original-firmware Thumb CFG analysis of RCC write candidates.

Source-seeded paths are *may paths*, not proof of runtime execution,
whole-image coverage, or absence of mode-dependent clock switching.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import struct

from capstone import CS_GRP_JUMP
from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC
from mcu_fingerprint import decoded_payload
from v2_mcu_identity_xrefs import scan as scan_literals
from v2_rom_cfgr_mmio_audit import scan_local_rcc_writes
from thumb_rcc_abstract import (
    BASE, LOADS, State, const, meet, valid, hx, new_decoder, decode, transfer,
)

STOP = frozenset(("udf", "svc", "bkpt", "tbb", "tbh", "bxj"))
MAX_VISITS = 1800
MAX_MOVW_TO_MOVT_BYTES = 96


def successors(ins, next_pc: int) -> list[int]:
    m = ins.mnemonic.split(".")[0]
    if m in STOP or m in ("bx", "blx", "bl"):
        return [next_pc] if m in ("bl", "blx") else []
    if m.startswith("pop") and "pc" in ins.op_str:
        return []
    if m in LOADS and ins.operands and ins.operands[0].type == ARM_OP_REG and ins.operands[0].reg == ARM_REG_PC:
        return []
    if m == "b":
        targets = [x.imm & ~1 for x in ins.operands if x.type == ARM_OP_IMM]
        return targets if ins.cc in (0, 15) else targets + [next_pc]
    if ins.group(CS_GRP_JUMP) or m in ("cbz", "cbnz"):
        targets = [x.imm & ~1 for x in ins.operands if x.type == ARM_OP_IMM]
        return targets + [next_pc]
    return [next_pc]


def walk_cfg(payload: bytes, entry: int, limit: int = MAX_VISITS) -> dict:
    """May-CFG from a candidate seed. Join discards disagreements."""
    md = new_decoder()
    end = BASE + len(payload)
    pending = deque([entry])
    incoming: dict[int, State] = {entry: State()}
    events = {}
    indirect = {}
    processed = 0
    while pending and processed < limit:
        pc = pending.popleft()
        state = incoming[pc]
        ins = decode(md, payload, pc)
        if ins is None:
            continue
        processed += 1
        after, stores, branches = transfer(payload, ins, state)
        for row in stores:
            events[(row["pc"], row["address"])] = row
        for row in branches:
            indirect[row["pc"]] = row
        for dest in successors(ins, pc + ins.size):
            if not (BASE <= dest <= end - 4) or dest % 2:
                continue
            if dest not in incoming:
                incoming[dest] = after.clone()
                pending.append(dest)
            else:
                merged = incoming[dest].combined(after)
                if merged != incoming[dest]:
                    incoming[dest] = merged
                    pending.append(dest)
    return {
        "seed": hx(entry), "visited_instruction_evaluations": processed,
        "budget_exhausted": bool(pending),
        "candidate_stores": sorted(events.values(), key=lambda x: x["pc"]),
        "register_indirect_branches": sorted(indirect.values(), key=lambda x: x["pc"]),
    }


def _rcc_movt_starts(pc: int, reg: int,
                     lows: dict[int, list[tuple[int, int]]],
                     all_movw: list[int]) -> set[int]:
    """Select a matched RCC MOVW plus nearby SRAM-provenance candidates."""
    start = next((old for old, _ in reversed(lows.get(reg, []))
                  if 0 < pc - old <= MAX_MOVW_TO_MOVT_BYTES), None)
    if start is None:
        return set()
    roots = {start}
    for earlier in reversed(all_movw):
        delta = start - earlier
        if delta > 32:
            break
        if delta > 0:
            roots.add(earlier)
    return roots


def mov_pair_seeds(data: bytes) -> list[int]:
    """Find adjacent MOVW/MOVT RCC base constructions; verify with disassembler."""
    md = new_decoder()
    lows: dict[int, list[tuple[int, int]]] = {}
    all_movw: list[int] = []
    seeds = set()
    for offset in range(0, len(data) - 3, 2):
        h = struct.unpack_from("<H", data, offset)[0]
        if (h & 0xFBF0) not in (0xF240, 0xF2C0):
            continue
        pc = BASE + offset
        ins = decode(md, data, pc)
        if ins is None or ins.mnemonic not in ("movw", "movt"):
            continue
        op = ins.operands
        if len(op) != 2 or op[0].type != ARM_OP_REG or op[1].type != ARM_OP_IMM:
            continue
        reg, imm = op[0].reg, op[1].imm
        if ins.mnemonic == "movw":
            all_movw.append(pc)
            if 0x1000 <= imm < 0x2000:
                lows.setdefault(reg, []).append((pc, imm))
        elif ins.mnemonic == "movt" and imm == 0x4002:
            seeds.update(_rcc_movt_starts(pc, reg, lows, all_movw))
    return sorted(seeds)


def candidate_seeds(data: bytes) -> dict:
    refs = scan_literals(data)["candidates"]
    literals = sorted({
        int(row["ldr_pc"], 16)
        for item in refs if int(item["address"], 16) in
        (0x40021000, 0x40021004, 0x400210F0)
        for row in item["thumb_literal_load_candidates"]
    })
    return {"pc_relative_literal": literals, "movw_movt_candidate": mov_pair_seeds(data)}


def verified_entry_context(data: bytes) -> dict:
    """Independently inspect original vector root and shared helper entry.

    The vector is a *firmware-specified* entry, not an observed PC. An
    indirect ROM callback remains unknown because system ROM is absent.
    """
    if len(data) < 0x400:
        return {}
    reset_vector = struct.unpack_from("<I", data, 4)[0]
    roots = {"reset_vector_entry": reset_vector & ~1}
    # The shared helper has been independently byte-verified in V1 and V2.
    helper = decode(new_decoder(), data, 0x08001260)
    if helper and helper.mnemonic.startswith("push") and "lr" in helper.op_str:
        roots["shared_rom_helper"] = 0x08001260
    output = {}
    for name, pc in roots.items():
        if (reset_vector & 1) and BASE <= pc <= BASE + len(data) - 4:
            output[name] = walk_cfg(data, pc, 320)
    return output


def scan(data: bytes, per_seed_limit: int = MAX_VISITS) -> dict:
    roots = candidate_seeds(data)
    candidate_stores = {}
    branches = {}
    exhausted = []
    for kind, starts in roots.items():
        for entry in starts:
            result = walk_cfg(data, entry, per_seed_limit)
            if result["budget_exhausted"]:
                exhausted.append(hx(entry))
            for row in result["candidate_stores"]:
                key = (row["pc"], row["address"])
                candidate_stores.setdefault(key, {**row, "source_seed": hx(entry),
                                                   "source_kind": kind})
            for row in result["register_indirect_branches"]:
                branches.setdefault(row["pc"], row)
    previous = scan_local_rcc_writes(data)["straight_line_store_candidates"]
    old_sites = {(row["store_pc"], row["address"]) for row in previous}
    recovered = sorted(candidate_stores.values(), key=lambda row: (row["pc"], row["address"]))
    new_sites = [row for row in recovered
                 if (row["pc"], row["address"]) not in old_sites]
    return {
        "seed_count_by_type": {name: len(rows) for name, rows in roots.items()},
        "all_seeds": {name: [hx(x) for x in rows] for name, rows in roots.items()},
        "old_linear_unique_store_count": len(old_sites),
        "verified_entry_context": verified_entry_context(data),
        "cfg_candidate_store_count": len(recovered),
        "new_vs_linear_candidates": new_sites,
        "cfg_candidate_stores": recovered,
        "known_register_indirect_branch_candidates": sorted(
            branches.values(), key=lambda row: row["pc"]),
        "exhausted_seeds": exhausted,
        "limits": [
            "All CFG paths originate at a candidate source instruction, not a verified function entry.",
            "Conditional paths are treated as may paths; findings do not prove runtime execution.",
            "MOVW/MOVT seeds require the same register and <=96 bytes between instructions; preceding MOVW within 32 bytes is also a candidate SRAM-provenance start.",
            "Only PC-relative RCC literal bases and MOVW/MOVT pairs ending in 0x40021xxx are seeded.",
            "RAM/stack contents are tracked only within one path until unknown stores or calls.",
            "Unknown indirect targets, register offsets, DMA, ROM-internal stores, and other address constructions remain unresolved.",
            "Absence of a candidate is NOT proof of absence of runtime frequency switching.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("v2", type=Path)
    p.add_argument("--v1", type=Path)
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    result = {"v2": scan(decoded_payload(a.v2.read_bytes()))}
    if a.v1:
        result["v1"] = scan(decoded_payload(a.v1.read_bytes()))
    if a.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        for version, item in result.items():
            print(version, "source seeds", item["seed_count_by_type"],
                  "old linear", item["old_linear_unique_store_count"],
                  "CFG candidate stores", item["cfg_candidate_store_count"],
                  "new candidate sites", len(item["new_vs_linear_candidates"]),
                  "budget exhausted", len(item["exhausted_seeds"]))
            for row in item["new_vs_linear_candidates"]:
                print("  new", row["pc"], row["address"], row["source_seed"],
                      row["source_kind"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
