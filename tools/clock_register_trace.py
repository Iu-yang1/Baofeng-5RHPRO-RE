#!/usr/bin/env python3
"""Read-only Pro .dat firmware clock-control access tracing.

This analyzes decoded Thumb instructions, NOT physical register activity.
The load base, MCU register names, and conditional paths remain hypotheses.
Capstone 5 is required. No serial/hardware access, flash programming, or output
of decoded firmware bytes.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
import json
from pathlib import Path
import struct

from capstone import (
    Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB,
    CS_GRP_CALL, CS_GRP_JUMP,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

from mcu_fingerprint import decoded_payload

BASE = 0x08001000  # supported by reset veneer disassembly; not confirmed on a board
MAX_INSTRUCTIONS = 120_000
REGISTER_BANKS = (
    ("CRM/RCC", 0x40021000, 0x40021100),
    ("FLASH", 0x40022000, 0x40022100),
    ("PWR", 0x40007000, 0x40007100),
    ("SysTick", 0xE000E010, 0xE000E020),
)
# Names are AT32F403A/STM32F1-style interpretations, not a part-number claim.
CRM_OFFSETS = {
    0x00: "CTRL/CR", 0x04: "CFG/CFGR", 0x08: "CLKINT/CIR",
    0x0C: "APB2RST", 0x10: "APB1RST", 0x14: "AHBEN",
    0x18: "APB2EN", 0x1C: "APB1EN", 0x20: "BPDC",
    0x24: "CTRLSTS", 0x28: "AHBRST",
}
MAX_SITES = 2500


def _region(address: int) -> tuple[str, str] | None:
    for name, start, end in REGISTER_BANKS:
        if start <= address < end:
            suffix = CRM_OFFSETS.get(address-start) if name == "CRM/RCC" else None
            return name, suffix or f"+0x{address-start:02X}"
    return None


def _literal(payload: bytes, pc: int, ins) -> tuple[int, int] | None:
    if not ins.mnemonic.startswith("ldr"):
        return None
    for op in ins.operands[1:]:
        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC and not op.mem.index:
            location = ((pc+4) & ~3) + op.mem.disp
            if BASE <= location <= BASE+len(payload)-4 and location % 4 == 0:
                return struct.unpack_from("<I", payload, location-BASE)[0], location
    return None


def _target(value: int, end: int) -> int | None:
    target = value & ~1
    return target if value & 1 and BASE <= target < end else None


def _decode_one(md, payload: bytes, pc: int):
    return next(md.disasm(payload[pc-BASE:pc-BASE+4], pc, count=1), None)


def _instruction_text(ins) -> str:
    return f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}".rstrip()


def _access(ins, known: dict[int, int]) -> tuple[str, int] | None:
    mnemonic = ins.mnemonic.split(".")[0]
    if not mnemonic.startswith(("ldr", "str")):
        return None
    for operand in ins.operands:
        if operand.type != ARM_OP_MEM or operand.mem.base == ARM_REG_PC:
            continue
        # Require constant base, no register-indexed dynamic offset.
        if operand.mem.base not in known or operand.mem.index:
            continue
        address = (known[operand.mem.base] + operand.mem.disp) & 0xFFFFFFFF
        if _region(address):
            return ("write" if mnemonic.startswith("str") else "read"), address
    return None


def _update_known(ins, known: dict[int, int], payload: bytes) -> None:
    """Only preserve constants across instructions whose semantics we model."""
    ops = ins.operands
    mnemonic = ins.mnemonic.split(".")[0]
    if not ops or ops[0].type != ARM_OP_REG:
        return
    dest = ops[0].reg
    lit = _literal(payload, ins.address, ins)
    if lit is not None:
        known[dest] = lit[0]
    elif mnemonic in ("mov", "movs", "movw") and len(ops) >= 2:
        if ops[1].type == ARM_OP_IMM:
            known[dest] = ops[1].imm
        elif ops[1].type == ARM_OP_REG and ops[1].reg in known:
            known[dest] = known[ops[1].reg]
        else:
            known.pop(dest, None)
    elif mnemonic == "movt" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
        if dest in known:
            known[dest] = (known[dest] & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
        else:
            known.pop(dest, None)
    elif mnemonic in ("add", "adds", "sub", "subs") and len(ops) == 3:
        if ops[1].type == ARM_OP_REG and ops[1].reg in known and ops[2].type == ARM_OP_IMM:
            delta = ops[2].imm if mnemonic.startswith("add") else -ops[2].imm
            known[dest] = (known[ops[1].reg] + delta) & 0xFFFFFFFF
        else:
            known.pop(dest, None)
    elif mnemonic in ("adds", "subs") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
        if dest in known:
            delta = ops[1].imm if mnemonic == "adds" else -ops[1].imm
            known[dest] = (known[dest] + delta) & 0xFFFFFFFF
    elif mnemonic.startswith("str") or mnemonic in ("cmp", "cmn", "tst", "teq"):
        pass  # Stores and comparisons do not write their first source operand.
    elif mnemonic in ("bx", "blx", "b", "bl", "cbz", "cbnz"):
        pass  # Branch operands are not register destinations.
    else:
        known.pop(dest, None)


def _branch_target(ins, known: dict[int, int], end: int) -> int | None:
    if not (ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP)):
        return None
    for op in ins.operands:
        if op.type == ARM_OP_IMM:
            value = op.imm & ~1
            if BASE <= value < end:
                return value
    mnemonic = ins.mnemonic.split(".")[0]
    if mnemonic in ("bx", "blx") and ins.operands[0].type == ARM_OP_REG:
        return _target(known.get(ins.operands[0].reg, 0), end)
    return None


def _walk(payload: bytes, roots: list[int], cap: int) -> dict:
    end = BASE + len(payload)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    queue = deque((pc, {}, "vector") for pc in roots)
    seen: set[int] = set()
    queued: set[int] = set(roots)
    access: list[dict] = []
    literals: list[dict] = []
    branches: list[dict] = []
    counts: Counter[str] = Counter()
    while queue and len(seen) < cap:
        start, inherited, provenance = queue.popleft()
        known = dict(inherited)
        recent: deque[str] = deque(maxlen=6)
        pc = start
        for _ in range(20_000):
            if pc in seen or not BASE <= pc <= end-4:
                break
            ins = _decode_one(md, payload, pc)
            if ins is None:
                break
            seen.add(pc)
            ops = ins.operands
            mnemonic = ins.mnemonic.split(".")[0]
            found = _access(ins, known)
            if found is not None:
                kind, addr = found
                region, name = _region(addr)
                counts[f"{region}:{kind}"] += 1
                if len(access) < MAX_SITES:
                    source = ops[0] if ops and kind == "write" else None
                    value = known.get(source.reg) if source is not None and source.type == ARM_OP_REG else None
                    access.append({
                        "pc": f"0x{pc:08X}", "type": kind,
                        "address": f"0x{addr:08X}", "bank": region, "register": name,
                        "write_constant": f"0x{value:08X}" if value is not None else None,
                        "instruction": _instruction_text(ins), "context": list(recent),
                    })
            literal = _literal(payload, pc, ins)
            if literal is not None and _region(literal[0]) and len(literals) < MAX_SITES:
                region, reg = _region(literal[0])
                literals.append({
                    "load_pc": f"0x{pc:08X}",
                    "literal_location": f"0x{literal[1]:08X}",
                    "value": f"0x{literal[0]:08X}",
                    "bank": region, "register": reg,
                })
            # Resolve direct and literal-fed indirect calls; preserve only
            # known input registers at the called function's entry.
            call = ins.group(CS_GRP_CALL)
            jump = ins.group(CS_GRP_JUMP)
            target = _branch_target(ins, known, end)
            if (target is not None and mnemonic in ("bx", "blx")
                    and ops and ops[0].type == ARM_OP_REG and len(branches) < 200):
                branches.append({
                    "pc": f"0x{pc:08X}",
                    "kind": mnemonic, "target": f"0x{target:08X}",
                })
            if target is not None and target not in queued and target not in seen:
                queue.append((target, dict(known), "call" if call else "branch"))
                queued.add(target)
            _update_known(ins, known, payload)
            recent.append(_instruction_text(ins))
            if call:
                # ARM AAPCS: volatile r0-r3/r12 are not guaranteed after BL/BLX.
                # Different Thumb instruction forms may also mutate flags.
                for reg in list(known):
                    if md.reg_name(reg) in ("r0", "r1", "r2", "r3", "r12", "lr"):
                        known.pop(reg, None)
            if mnemonic in ("bx", "b", "bxj", "tbb", "tbh", "udf", "bkpt", "svc"):
                break
            if mnemonic.startswith(("pop", "ldmia")) and "pc" in ins.op_str:
                break
            pc += ins.size
            if len(seen) >= cap:
                break
    return {
        "unique_instruction_candidates": len(seen),
        "budget_exhausted": len(seen) >= cap,
        "crm_related_access_counts": dict(counts),
        "register_accesses": access,
        "register_literals": literals,
        "resolved_indirect_control_transfers": branches,
    }


def analyze(payload: bytes, scope: str = "reset", cap: int = MAX_INSTRUCTIONS) -> dict:
    if len(payload) < 64*4:
        raise ValueError("Cortex-M candidate vector window is incomplete")
    end = BASE + len(payload)
    vectors = struct.unpack_from("<64I", payload, 0)
    roots = ([vectors[1]] if scope == "reset" else vectors[1:])
    roots = list(dict.fromkeys(
        addr for word in roots
        if (addr := _target(word, end)) is not None
    ))
    result = {
        "origin_hypothesis": f"0x{BASE:08X}",
        "scope": scope,
        "initial_sp": f"0x{vectors[0]:08X}",
        "reset_vector": f"0x{vectors[1]:08X}",
        "root_count": len(roots),
        "limitations": [
            "Static candidates, not evidence that a register was written on physical hardware.",
            "CRM/FLASH labels follow a STM32F1/AT32F403A-style candidate map.",
            "No hardware clock frequency, HSE frequency, PLL multiplier, or exact MCU model is assumed.",
            "Unknown register arithmetic, branch predicates, and indirect targets may be missed.",
            "Register constants propagate within blocks and into candidate callees; joins are not a full dataflow solution.",
        ],
    }
    result.update(_walk(payload, roots, cap))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--scope", choices=("reset", "vectors"), default="reset")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--show-context", action="store_true", help="Print instructions preceding matching access sites")
    parser.add_argument("--pc-from", type=lambda s: int(s, 0), help="Inclusive start of PC range for text output")
    parser.add_argument("--pc-to", type=lambda s: int(s, 0), help="Exclusive end of PC range for text output")
    args = parser.parse_args(argv)
    reports = []
    for path in args.images:
        result = analyze(decoded_payload(path.read_bytes()), scope=args.scope)
        result["file"] = str(path)
        reports.append(result)
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        for r in reports:
            print(f"== {r['file']} [{r['scope']}] ==")
            print("instructions", r["unique_instruction_candidates"], "access counts", r["crm_related_access_counts"])
            print("Resolved startup register branches:", r["resolved_indirect_control_transfers"][:10])
            print("Clock/bus/Flash register accesses:")
            for item in r["register_accesses"]:
                pc = int(item["pc"], 16)
                if args.pc_from is not None and pc < args.pc_from:
                    continue
                if args.pc_to is not None and pc >= args.pc_to:
                    continue
                print(item["instruction"], "->", item["bank"], item["register"], item["type"],
                      "value", item["write_constant"] or "unknown")
                if args.show_context:
                    for previous in item["context"]:
                        print("   ", previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
