#!/usr/bin/env python3
"""Conservative Thumb CFG evidence for reads of MCU identification registers.

These are candidate *code memory accesses*, not real chip register reads.
No debugger, serial port, hardware connection, or modification of firmware.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import struct

from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

from mcu_fingerprint import decoded_payload
from thumb_rcc_abstract import (
    BASE, State, LOADS, STORES, base_address, decode,
    hx, new_decoder, transfer,
)
from v2_rcc_cfg_dataflow import successors
from v2_bootrom_dispatch import require

# The *width* is the datum's declared access size, not an observed access.
IDENTITY_REGISTERS = {
    0x1FFFF7E0: ("Flash F_SIZE (vendor-dependent units)", 2),
    0x1FFFF7E8: ("UID low 32-bit word, AIR32 pattern field", 4),
    0x1FFFF7EC: ("UID middle 32-bit word", 4),
    0x1FFFF7F0: ("UID high word, AT32 Series ID at byte +3", 4),
    0xE000ED00: ("ARM SCB CPUID", 4),
    0xE0042000: ("MCU DEBUG_IDCODE / PID if implemented", 4),
}
SEARCH_WINDOWS = (
    (0x1FFFF7C0, 0x1FFFF800),
    (0xE000ECC0, 0xE000ED40),
    (0xE0041FC0, 0xE0042040),
)
MAX_PER_ROOT = 1100
MAX_MOV_PAIR_GAP = 96
MEMORY_WIDTHS = {"ldr": 4, "ldrh": 2, "ldrb": 1,
                 "str": 4, "strh": 2, "strb": 1}


def near_identity(value: int) -> bool:
    return any(start <= value < end for start, end in SEARCH_WINDOWS)


def affected_registers(address: int, width: int) -> list[dict]:
    if not width:
        return []
    candidates = []
    for target, (name, size) in IDENTITY_REGISTERS.items():
        if address < target + size and target < address + width:
            candidates.append({
                "register": hx(target),
                "register_name": name,
                "exact_start": address == target,
                "overlaps_bytes": min(address + width, target + size) -
                                  max(address, target),
            })
    return candidates


def _code_literal_sources(data: bytes) -> list[dict]:
    md = new_decoder()
    rows = {}
    for ofs in range(0, len(data) - 3, 2):
        hw = struct.unpack_from("<H", data, ofs)[0]
        if (hw & 0xF800) != 0x4800 and (hw & 0xFFF0) not in (0xF85F, 0xF8DF):
            continue
        pc = BASE + ofs
        ins = decode(md, data, pc)
        if not ins or ins.mnemonic.split(".")[0] != "ldr":
            continue
        if len(ins.operands) < 2 or ins.operands[1].type != ARM_OP_MEM:
            continue
        m = ins.operands[1].mem
        if m.base != ARM_REG_PC or m.index:
            continue
        pool = ((pc + 4) & ~3) + m.disp
        off = pool - BASE
        if pool % 4 or not (0 <= off <= len(data) - 4):
            continue
        value = struct.unpack_from("<I", data, off)[0]
        if near_identity(value):
            rows[pc] = {"seed": pc, "kind": "PC-relative nearby ID literal",
                        "loaded_value": hx(value), "pool": hx(pool)}
    return [rows[k] for k in sorted(rows)]


def _movpair_sources(data: bytes) -> list[dict]:
    md = new_decoder()
    low: dict[int, list[tuple[int, int]]] = {}
    seeds = {}
    for ofs in range(0, len(data) - 3, 2):
        hw = struct.unpack_from("<H", data, ofs)[0]
        if (hw & 0xFBF0) not in (0xF240, 0xF2C0):
            continue
        pc = BASE + ofs
        ins = decode(md, data, pc)
        if not ins or ins.mnemonic not in ("movw", "movt"):
            continue
        if (len(ins.operands) != 2 or ins.operands[0].type != ARM_OP_REG or
                ins.operands[1].type != ARM_OP_IMM):
            continue
        reg, immediate = ins.operands[0].reg, ins.operands[1].imm
        if ins.mnemonic == "movw":
            low.setdefault(reg, []).append((pc, immediate))
        else:
            for start, lsw in reversed(low.get(reg, [])):
                if pc - start > MAX_MOV_PAIR_GAP:
                    break
                if 0 < pc - start and near_identity((immediate << 16) | lsw):
                    seeds[start] = {
                        "seed": start, "kind": "MOVW/MOVT possible ID address",
                        "loaded_value": hx((immediate << 16) | lsw),
                        "movt_pc": hx(pc),
                    }
                    break
    return [seeds[k] for k in sorted(seeds)]


def find_seeds(data: bytes) -> list[dict]:
    seeds = {r["seed"]: r for r in _code_literal_sources(data)}
    for row in _movpair_sources(data):
        seeds.setdefault(row["seed"], row)
    return [seeds[k] for k in sorted(seeds)]


def memory_event(ins, state: State) -> list[dict]:
    name = ins.mnemonic.split(".")[0]
    width = MEMORY_WIDTHS.get(name)
    op = ins.operands
    if width is None or len(op) < 2 or op[1].type != ARM_OP_MEM:
        return []
    destination = base_address(state, op[1].mem, ins.address)
    if destination is None or destination[0] != "abs":
        return []
    addr = destination[1]
    matched = affected_registers(addr, width)
    if not matched:
        return []
    access = "read" if name in LOADS else "write"
    return [{
        "pc": hx(ins.address),
        "address": hx(addr),
        "width_bytes": width,
        "direction": access,
        "instruction": f"{ins.mnemonic} {ins.op_str}",
        "match": entry,
        "certainty": "candidate static path, not physical execution",
    } for entry in matched]


def trace_from(data: bytes, entry: int, budget: int = MAX_PER_ROOT) -> dict:
    """Join dataflow states at CFG merges; keep only concrete effective addresses."""
    md = new_decoder()
    queue = deque([entry])
    inputs = {entry: State()}
    events = {}
    evaluations = 0
    end = BASE + len(data)
    while queue and evaluations < budget:
        pc = queue.popleft()
        ins = decode(md, data, pc)
        if ins is None:
            continue
        evaluations += 1
        before = inputs[pc]
        for ev in memory_event(ins, before):
            key = (ev["pc"], ev["address"], ev["direction"])
            events[key] = ev
        after, _, _ = transfer(data, ins, before)
        for succ in successors(ins, pc + ins.size):
            if succ & 1 or not (BASE <= succ <= end - 4):
                continue
            previous = inputs.get(succ)
            if previous is None:
                inputs[succ] = after.clone()
                queue.append(succ)
            else:
                joined = previous.combined(after)
                if joined != previous:
                    inputs[succ] = joined
                    queue.append(succ)
    return {
        "seed": hx(entry),
        "evaluations": evaluations,
        "budget_exhausted": bool(queue),
        "memory_access_candidates": sorted(events.values(),
                                           key=lambda row: (row["pc"], row["address"])),
    }


def inspect_stock(data: bytes, budget: int = MAX_PER_ROOT) -> dict:
    # Independently check an actual UID0 dereference (not just the pointer).
    checks = (
        require(data, 0x080012A2, "ldr", "r0, [pc, #0x15c]", 0x1FFFF7E8),
        require(data, 0x080012A4, "ldr", "r6, [r0]"),
    )
    candidates = {}
    exhausted = []
    seed_list = find_seeds(data)
    for seed in seed_list:
        result = trace_from(data, seed["seed"], budget)
        if result["budget_exhausted"]:
            exhausted.append(hx(seed["seed"]))
        for event in result["memory_access_candidates"]:
            key = (event["pc"], event["address"], event["direction"])
            candidates.setdefault(key, {**event, "seed": hx(seed["seed"]),
                                        "source_type": seed["kind"]})
    # Distinguish the validated ROM helper entry from arbitrary PC seeds.
    helper = trace_from(data, 0x08001260, budget)
    verified = [
        e for e in helper["memory_access_candidates"]
        if e["pc"] == "0x080012A4" and e["address"] == "0x1FFFF7E8"
    ]
    if not verified:
        raise ValueError("validated ROM helper entry did not reach expected UID0 read")
    items = sorted(candidates.values(), key=lambda x: (x["pc"], x["address"]))
    return {
        "uid0_confirmed_original_instructions": checks,
        "candidate_source_count": len(seed_list),
        "source_types": {
            kind: sum(x["kind"] == kind for x in seed_list)
            for kind in ("PC-relative nearby ID literal", "MOVW/MOVT possible ID address")
        },
        "all_sources": [{**x, "seed": hx(x["seed"])} for x in seed_list],
        "unique_candidate_accesses": len(items),
        "candidate_id_accesses": items,
        "original_helper_uid0_read_reachable_from_entry": bool(verified),
        "helper_bounded_evaluations": helper["evaluations"],
        "helper_budget_exhausted": helper["budget_exhausted"],
        "source_budget_exhausted": exhausted,
        "limits": [
            "Firmware machine-code candidates are not live device readbacks.",
            "Sources are PC-relative nearby ID literals or same-register MOVW/MOVT pairs <=96 bytes apart.",
            "Memory access requires an exact effective address from bounded CFG abstract propagation.",
            "Unmodeled arithmetic/aliases, cross-function pointer arguments, computed branches, ROM-internal code and interrupt dataflow are not searched exhaustively.",
            "No matching store/read candidate cannot exclude any vendor.",
            "The helper entry is byte-validated; conditional UID0 read is statically reachable, but no device UID or branch outcome was observed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("v2", type=Path)
    p.add_argument("--v1", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--show-accesses", action="store_true")
    args = p.parse_args(argv)
    result = {"v2": inspect_stock(decoded_payload(args.v2.read_bytes()))}
    if args.v1:
        result["v1"] = inspect_stock(decoded_payload(args.v1.read_bytes()))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        for version, row in result.items():
            print(version, "seeds", row["source_types"],
                  "ID access candidates", row["unique_candidate_accesses"],
                  "helper UID0 read:", row["original_helper_uid0_read_reachable_from_entry"],
                  "budget exhausted", len(row["source_budget_exhausted"]))
            if args.show_accesses:
                for seed in row["all_sources"]:
                    print("  source", seed["seed"], seed["kind"], seed["loaded_value"])
                for item in row["candidate_id_accesses"]:
                    print(" ", item["pc"], item["direction"], item["address"],
                          item["width_bytes"], item["match"]["register"],
                          "seed", item["seed"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
