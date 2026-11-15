#!/usr/bin/env python3
"""Thumb abstract register, stack and SRAM transfer operations (offline only).

Shared by RCC candidate CFG analysis; this module has no hardware I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct

from capstone import Cs, CsError, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import (
    ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP,
    ARM_REG_LR, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12,
)

BASE = 0x08001000
RCC_START, RCC_END = 0x40021000, 0x400210F4
RAM_START, RAM_END = 0x20000000, 0x20080000
ALL = 0xFFFFFFFF
UNKNOWN = (0, 0)
CALLEE_CLOBBER = frozenset(
    (ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ARM_REG_R12, ARM_REG_LR)
)
STORES = frozenset(("str", "strb", "strh"))
LOADS = frozenset(("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh"))

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


def _memory_effect(data: bytes, ins, before: State, after: State,
                   conditional: bool) -> tuple[dict, list[dict]]:
    """Track an exact memory operand, preserving only proven local aliases."""
    m = ins.mnemonic.split(".")[0]
    op = ins.operands
    pc = ins.address
    writes: dict[int, tuple[int, int]] = {}
    events: list[dict] = []
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
    return writes, events


def transfer(data: bytes, ins, before: State) -> tuple[State, list[dict], list[dict]]:
    """Abstractly interpret one instruction; unknown writes drop known facts."""
    after = before.clone()
    m = ins.mnemonic.split(".")[0]
    op = ins.operands
    indirect = []
    pc = ins.address
    conditional = ins.cc not in (0, 15)  # Capstone invalid / ARM_CC_AL.
    writes, events = _memory_effect(data, ins, before, after, conditional)
    if m in ("movw", "movt") and len(op) >= 2 and op[0].type == ARM_OP_REG:
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
    except CsError:
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


