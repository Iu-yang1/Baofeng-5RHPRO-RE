#!/usr/bin/env python3
"""Conservative Thumb CFG constant propagation for candidate RCC register writes.

This is a *may-path* static scanner over source seeds, not a proof of
whole-image reachability or of the absence of dynamic RCC configuration.
It never accesses the radio, UID registers, ROM bytes, or hardware.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_GRP_JUMP
from capstone.arm import (
    ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP,
    ARM_REG_LR, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12,
)
from mcu_fingerprint import decoded_payload
from v2_mcu_identity_xrefs import scan as scan_literals
from v2_rom_cfgr_mmio_audit import scan_local_rcc_writes

BASE = 0x08001000
RCC_START, RCC_END = 0x40021000, 0x400210F4
RAM_START, RAM_END = 0x20000000, 0x20080000
ALL = 0xFFFFFFFF
UNKNOWN = (0, 0)
CALLEE_CLOBBER = frozenset(
    (ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12, ARM_REG_LR)
)
STOP = frozenset(("udf", "svc", "bkpt", "tbb", "tbh", "bxj"))
STORES = frozenset(("str", "strb", "strh"))
LOADS = frozenset(("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh"))
MAX_VISITS = 1800
MAX_MOVW_TO_MOVT_BYTES = 96


def hx(value: int) -> str:
    return f"0x{value:08X}"


def const(value: int) -> tuple[int, int]:
    return value & ALL, ALL


def valid(atom: tuple[int, int]) -> bool:
    return atom[1] == ALL


def meet(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    mask = a[1] & b[1] & ~(a[0] ^ b[0]) & ALL
    return a[0] & mask, mask


@dataclass
class State:
    regs: dict[int, tuple[int, int]] = field(default_factory=dict)
    memory: dict[tuple[str, int], tuple[int, int]] = field(default_factory=dict)
    sp: int | None = 0

    def clone(self) -> State:
        return State(self.regs.copy(), self.memory.copy(), self.sp)

    def combined(self, other: State) -> State:
        sp = self.sp if self.sp == other.sp else None
        regs = {}
        for reg in self.regs.keys() & other.regs.keys():
            atom = meet(self.regs[reg], other.regs[reg])
            if atom[1]:
                regs[reg] = atom
        memory = {}
        for key in self.memory.keys() & other.memory.keys():
            if key[0] == "stack" and sp is None:
                continue
            atom = meet(self.memory[key], other.memory[key])
            if atom[1]:
                memory[key] = atom
        return State(regs, memory, sp)


def new_decoder() -> Cs:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def decode(md: Cs, data: bytes, pc: int):
    offset = pc - BASE
    if offset < 0 or offset + 4 > len(data):
        return None
    return next(md.disasm(data[offset:offset+4], pc, count=1), None)


def base_address(state: State, mem, pc: int) -> tuple[str, int] | None:
    if mem.index:
        return None
    if mem.base == ARM_REG_PC:
        return "abs", (((pc + 4) & ~3) + mem.disp) & ALL
    if mem.base == ARM_REG_SP:
        if state.sp is not None:
            return "stack", state.sp + mem.disp
        return None
    base = state.regs.get(mem.base, UNKNOWN)
    if valid(base):
        return "abs", (base[0] + mem.disp) & ALL
    return None


def read_word(data: bytes, pc: int) -> tuple[int, int]:
    offset = pc - BASE
    if pc % 4 or not (0 <= offset <= len(data)-4):
        return UNKNOWN
    return const(struct.unpack_from("<I", data, offset)[0])


def _imm(op) -> int | None:
    return op.imm if op.type == ARM_OP_IMM else None


def _operand_value(state: State, op) -> tuple[int, int]:
    if op.type == ARM_OP_IMM:
        return const(op.imm)
    if op.type == ARM_OP_REG and not op.shift.value:
        return state.regs.get(op.reg, UNKNOWN)
    return UNKNOWN


def transfer(data: bytes, ins, before: State) -> tuple[State, list[dict], list[dict]]:
    """Abstractly interpret one instruction; unknown writes drop known facts."""
    after = before.clone()
    m = ins.mnemonic.split(".")[0]
    op = ins.operands
    writes: dict[int, tuple[int, int]] = {}
    events = []
    indirect = []
    pc = ins.address
    conditional = ins.cc not in (0, 15)  # Capstone invalid / ARM_CC_AL.
    if m in STORES and len(op) >= 2 and op[1].type == ARM_OP_MEM:
        dest = base_address(before, op[1].mem, pc)
        value = _operand_value(before, op[0])
        if dest is not None:
            kind, address = dest
            if kind == "abs" and RCC_START <= address < RCC_END:
                events.append({
                    "pc": hx(pc), "address": hx(address),
                    "opcode": ins.mnemonic, "operands": ins.op_str,
                    "value": hx(value[0]) if valid(value) and m == "str" else None,
                    "certainty": "candidate conditional or entry-unverified",
                })
            if (kind == "stack" or (kind == "abs" and RAM_START <= address < RAM_END)):
                if m == "str" and valid(value) and not conditional:
                    after.memory[dest] = value
                else:
                    after.memory.pop(dest, None)
        else:
            # An unknown store can alias local SRAM scratch bytes.
            after.memory.clear()
    if m in LOADS and len(op) >= 2 and op[0].type == ARM_OP_REG:
        result = UNKNOWN
        if op[1].type == ARM_OP_MEM:
            address = base_address(before, op[1].mem, pc)
            if address is not None and m == "ldr":
                if address[0] == "abs" and BASE <= address[1] < BASE + len(data):
                    result = read_word(data, address[1])
                elif address[0] == "stack" or (
                    address[0] == "abs" and RAM_START <= address[1] < RAM_END
                ):
                    result = before.memory.get(address, UNKNOWN)
        writes[op[0].reg] = result
    elif m in ("movw", "movt") and len(op) >= 2 and op[0].type == ARM_OP_REG:
        dest = op[0].reg
        imm = _imm(op[1])
        if imm is not None:
            if m == "movw":
                writes[dest] = const(imm & 0xFFFF)
            else:
                old = before.regs.get(dest, UNKNOWN)
                writes[dest] = ((old[0] & 0xFFFF) | ((imm & 0xFFFF) << 16),
                                (old[1] & 0xFFFF) | 0xFFFF0000)
    elif m in ("mov", "movs") and len(op) == 2 and op[0].type == ARM_OP_REG:
        writes[op[0].reg] = _operand_value(before, op[1])
    elif m in ("add", "adds", "addw", "sub", "subs", "subw") and len(op) in (2, 3):
        dst = op[0].reg if op[0].type == ARM_OP_REG else None
        src = op[0] if len(op) == 2 else op[1]
        rhs = op[-1]
        sign = 1 if m.startswith("add") else -1
        # Full-known operands only: adding a constant to a partial bitmask
        # cannot be computed safely due to carry between unknown bits.
        if dst is not None and rhs.type == ARM_OP_IMM:
            if dst == ARM_REG_SP and src.type == ARM_OP_REG and src.reg == ARM_REG_SP:
                if after.sp is not None:
                    after.sp += sign * rhs.imm
            else:
                value = _operand_value(before, src)
                if valid(value):
                    writes[dst] = const(value[0] + sign * rhs.imm)
                else:
                    writes[dst] = UNKNOWN
    elif m == "push":
        if after.sp is not None:
            after.sp -= 4 * sum(1 for x in op if x.type == ARM_OP_REG)
    elif m == "pop":
        if after.sp is not None:
            after.sp += 4 * sum(1 for x in op if x.type == ARM_OP_REG)
    elif m in ("bl", "blx", "bx") and op:
        if op[0].type == ARM_OP_REG:
            target = before.regs.get(op[0].reg, UNKNOWN)
            indirect.append({
                "pc": hx(pc),
                "target": hx(target[0]) if valid(target) else None,
                "mnemonic": m,
                "target_provenance": "register constant, not runtime execution"
                                  if valid(target) else "unresolved",
            })

    # A conditional non-branch write need not happen; do not propagate
    # its result as an unconditional fact.
    try:
        _, changed = ins.regs_access()
    except Cs.CsError:
        changed = []
    for reg in changed:
        if reg == ARM_REG_SP and after.sp is not None and m not in ("push", "pop", "add", "adds", "addw", "sub", "subs", "subw"):
            after.sp = None
        if reg in writes and not conditional:
            atom = writes[reg]
            if atom[1]:
                after.regs[reg] = atom
            else:
                after.regs.pop(reg, None)
        else:
            after.regs.pop(reg, None)
    if m in ("bl", "blx"):
        for reg in CALLEE_CLOBBER:
            after.regs.pop(reg, None)
        after.memory.clear()
    return after, events, indirect


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


def mov_pair_seeds(data: bytes) -> list[int]:
    """Find adjacent MOVW/MOVT RCC base constructions; verify with disassembler."""
    md = new_decoder()
    lows: dict[int, list[tuple[int, int]]] = {}
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
        if ins.mnemonic == "movw" and 0x1000 <= imm < 0x2000:
            lows.setdefault(reg, []).append((pc, imm))
        elif ins.mnemonic == "movt" and imm == 0x4002:
            for start, _ in reversed(lows.get(reg, [])):
                if 0 < pc - start <= MAX_MOVW_TO_MOVT_BYTES:
                    seeds.add(start)
                    break
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
        "cfg_candidate_store_count": len(recovered),
        "new_vs_linear_candidates": new_sites,
        "cfg_candidate_stores": recovered,
        "known_register_indirect_branch_candidates": sorted(
            branches.values(), key=lambda row: row["pc"]),
        "exhausted_seeds": exhausted,
        "limits": [
            "All CFG paths originate at a candidate source instruction, not a verified function entry.",
            "Conditional paths are treated as may paths; findings do not prove runtime execution.",
            "MOVW/MOVT seeds require the same register and <=96 bytes between instructions.",
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
