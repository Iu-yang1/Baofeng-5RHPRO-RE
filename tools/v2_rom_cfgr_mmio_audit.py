#!/usr/bin/env python3
"""Evidence-only audit of AIR32-style ROM clock dispatch and RCC MMIO.

No physical UID, ROM contents, debugger, peripherals, or flashing is accessed.
The local MMIO xref scan is explicitly bounded to straight-line instruction
sequences following a PC-relative RCC-base literal; it is NOT a complete proof
that no other register writer exists.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
from mcu_fingerprint import decoded_payload
from v2_bootrom_dispatch import analyze as verify_dispatch, require
from v2_mcu_identity_xrefs import scan as scan_xrefs
from v2_pll_runtime_order import clock_helper_direct_xrefs

BASE = 0x08001000
RCC_BASE = 0x40021000
RCC_CFGR = RCC_BASE + 4
RCC_GATE = RCC_BASE + 0xF0
UID_BRANCH_MASK_LITERAL = 0x08001408
BRANCH_MASK = 0xEFC3FFFF
PLLMUL_16 = 0x00380000
PLL_SOURCE_HSE = 0x00010000
SOURCE_CLEAR_MASK = 0x00030000
CHECKS = [
    (0x080012AC, "bne", "#0x80012c0", None),
    (0x080012BE, "b", "#0x8001306", None),
    (0x080012C6, "bne", "#0x80012da", None),
    (0x080012D8, "b", "#0x8001306", None),
    (0x080012E0, "bne", "#0x8001306", None),
    (0x080012E2, "ldr", "r0, [pc, #0x100]", RCC_GATE),
    (0x080012E4, "subs", "r0, #0xf0", None),
    (0x080012E6, "ldr", "r0, [r0, #4]", None),
    (0x080012E8, "ldr", "r1, [pc, #0x11c]", BRANCH_MASK),
    (0x080012EA, "ands", "r0, r1", None),
    (0x080012EC, "ldr", "r1, [pc, #0xf4]", RCC_GATE),
    (0x080012EE, "subs", "r1, #0xf0", None),
    (0x080012F0, "str", "r0, [r1, #4]", None),
    (0x080012F2, "mov", "r0, r1", None),
    (0x080012F4, "ldr", "r0, [r0, #4]", None),
    (0x080012F6, "orrs", "r0, r4", None),
    (0x080012F8, "str", "r0, [r1, #4]", None),
    (0x080012FC, "movs", "r2, #1", None),
    (0x080012FE, "movs", "r1, #0", None),
    (0x08001300, "ldr", "r3, [r0, #0xc]", None),
    (0x08001302, "mov", "r0, r5", None),
    (0x08001304, "blx", "r3", None),
    (0x08001306, "ldr", "r0, [pc, #0xdc]", RCC_GATE),
    (0x08001308, "subs", "r0, #0xf0", None),
    (0x0800130A, "ldr", "r0, [r0, #4]", None),
    (0x0800130C, "bic", "r0, r0, #0x30000", None),
    (0x08001310, "orrs", "r0, r7", None),
    (0x08001312, "ldr", "r1, [pc, #0xd0]", RCC_GATE),
    (0x08001314, "subs", "r1, #0xf0", None),
    (0x08001316, "str", "r0, [r1, #4]", None),
    (0x0800133C, "movs", "r0, #0", None),
    (0x0800133E, "ldr", "r1, [pc, #0xa4]", RCC_GATE),
    (0x08001340, "subs", "r1, #0xf0", None),
    (0x08001342, "str.w", "r0, [r1, #0xf0]", None),
]


def checked_word(data: bytes, pc: int) -> int:
    offset = pc - BASE
    if not (0 <= offset <= len(data) - 4):
        raise ValueError(f"literal out of image at 0x{pc:08X}")
    return struct.unpack_from("<I", data, offset)[0]


def branch_cfgr_effect(data: bytes, older: bytes | None = None) -> dict:
    base = verify_dispatch(data, older)
    evidence = [require(data, pc, name, operands, literal)
                for pc, name, operands, literal in CHECKS]
    if checked_word(data, UID_BRANCH_MASK_LITERAL) != BRANCH_MASK:
        raise ValueError("0x1C CFGR mask changed")
    clear = ~BRANCH_MASK & 0xFFFFFFFF
    if clear != 0x103C0000:
        raise ValueError("PLL mask decomposition no longer valid")
    # Pure symbolic transforms, not a hardware or ROM execution.
    def before_rom(cfgr: int) -> int:
        return ((cfgr & BRANCH_MASK) | PLLMUL_16) & 0xFFFFFFFF

    def after_rom(cfgr: int) -> int:
        return ((cfgr & ~SOURCE_CLEAR_MASK) | PLL_SOURCE_HSE) & 0xFFFFFFFF

    scenarios = []
    for byte in (0x1A, 0x1B, 0x1C, 0x55):
        if byte in (0x1A, 0x1B):
            callback_args = {"r0": "0x00380000", "r1": "0x00000001",
                             "r2": "0x00000000", "r3": "0x00000001"}
            before = "no explicit local CFGR pre-write; ROM controls unknown"
        elif byte == 0x1C:
            callback_args = {"r0": "0x00000001", "r1": "0x00000000",
                             "r2": "0x00000001", "r3": "ROM callback pointer"}
            before = "CFGR = (CFGR & 0xEFC3FFFF) | 0x00380000"
        else:
            callback_args = None
            before = "skip ROM callback"
        scenarios.append({
            "uid_lowword_high_byte": f"0x{byte:02X}",
            "before_rom": before,
            "callback_abi": callback_args,
            "common_after_rom": "CFGR = (CFGR & ~0x00030000) | 0x00010000",
            "gate_restoration": "0x400210F0 = 0",
        })
    return {
        "instruction_checks": evidence,
        "uid_comparisons": base["recognized_decision_bytes"],
        "cfgr_address": f"0x{RCC_CFGR:08X}",
        "uid_1c_pre_mask": f"0x{BRANCH_MASK:08X}",
        "uid_1c_cleared_bits_mask": f"0x{clear:08X}",
        "uid_1c_pre_write_sites": ["0x080012F0", "0x080012F8"],
        "common_cfgr_write_pc": "0x08001316",
        "uid_1c_example_input_cfgr_0": f"0x{before_rom(0):08X}",
        "common_example_input_cfgr_0": f"0x{after_rom(0):08X}",
        "branches": scenarios,
        "interpretation": (
            "Only the host-side registers R0-R3 and local CFGR writes are "
            "established. The referenced ROM function's body, runtime UID "
            "branch, PLL lock, Flash latency and output frequency are unknown."
        ),
        "v1_v2_shared_window": base.get("v1_v2_window_comparison"),
    }


def _decode_one(md: Cs, data: bytes, pc: int):
    offset = pc - BASE
    return next(md.disasm(data[offset:offset+4], pc, count=1), None)


def _local_writes(data: bytes, load_pc: int, limit_instructions: int = 32) -> list[dict]:
    """Conservatively propagate *known address constants* until a branch/call.

    This deliberately does not cross any branch, call, or a register write
    whose semantics are not handled. An output is a local store candidate,
    not proof of dynamic execution or globally complete alias analysis.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    known: dict[int, int] = {}
    stores: list[dict] = []
    pc = load_pc
    for _ in range(limit_instructions):
        if not (BASE <= pc <= BASE + len(data) - 4):
            break
        ins = _decode_one(md, data, pc)
        if ins is None:
            break
        name, ops = ins.mnemonic, ins.operands
        if name in ("bl", "blx", "b", "b.w", "bx", "bxj", "udf", "svc", "bkpt",
                    "cbz", "cbnz", "tbb", "tbh") or name.startswith(("bne", "beq", "bhi", "blo", "bpl", "bmi", "bge", "blt", "bgt", "ble", "bcs", "bcc", "bvs", "bvc")):
            break
        if name.startswith("pop") and "pc" in ins.op_str:
            break
        if name.startswith(("str", "stm")) and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            if mem.base in known and not mem.index:
                addr = (known[mem.base] + mem.disp) & 0xFFFFFFFF
                if RCC_BASE <= addr <= RCC_GATE:
                    stores.append({
                        "load_pc": f"0x{load_pc:08X}",
                        "store_pc": f"0x{pc:08X}",
                        "address": f"0x{addr:08X}",
                        "mnemonic": name,
                        "operands": ins.op_str,
                        "confidence": "straight-line constant base tracked; candidate",
                    })
        # Single-reg destination tracking for only safely modeled instructions.
        if ops and ops[0].type == ARM_OP_REG:
            target = ops[0].reg
            if name.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
                mem = ops[1].mem
                if mem.base == ARM_REG_PC and not mem.index:
                    pool = ((pc + 4) & ~3) + mem.disp
                    if BASE <= pool <= BASE + len(data) - 4 and pool % 4 == 0:
                        known[target] = checked_word(data, pool)
                    else:
                        known.pop(target, None)
                else:
                    known.pop(target, None)
            elif name.startswith("mov") and len(ops) >= 2:
                src = ops[1]
                if src.type == ARM_OP_REG:
                    if src.reg in known:
                        known[target] = known[src.reg]
                    else:
                        known.pop(target, None)
                elif src.type == ARM_OP_IMM:
                    known[target] = src.imm & 0xFFFFFFFF
                else:
                    known.pop(target, None)
            elif name.startswith(("add", "sub")) and len(ops) in (2, 3):
                if len(ops) == 2:
                    source = target
                    imm = ops[1]
                else:
                    source = ops[1].reg if ops[1].type == ARM_OP_REG else None
                    imm = ops[2]
                if source in known and imm.type == ARM_OP_IMM:
                    delta = imm.imm if name.startswith("add") else -imm.imm
                    known[target] = (known[source] + delta) & 0xFFFFFFFF
                else:
                    known.pop(target, None)
            elif not name.startswith(("cmp", "cmn", "tst", "teq", "str", "stm", "push")):
                known.pop(target, None)
        pc += ins.size
    return stores


def scan_local_rcc_writes(payload: bytes) -> dict:
    """Find bounded candidate stores from literal loads of RCC/RCC_GATE."""
    items = scan_xrefs(payload)["candidates"]
    refs = []
    for item in items:
        if int(item["address"], 16) in (RCC_BASE, RCC_GATE):
            refs.extend(int(e["ldr_pc"], 16)
                        for e in item["thumb_literal_load_candidates"])
    findings = {}
    for pc in sorted(set(refs)):
        for row in _local_writes(payload, pc):
            findings[(row["load_pc"], row["store_pc"], row["address"])] = row
    return {
        "literal_load_candidate_sites": [f"0x{pc:08X}" for pc in sorted(set(refs))],
        "straight_line_store_candidates": sorted(
            findings.values(), key=lambda x: (x["store_pc"], x["address"])
        ),
        "scope": (
            "PC-relative exact base literals 0x40021000/0x400210F0; "
            "max 32 straight-line instructions; stop at call/branch; "
            "no alias, stack, or indirect pointer propagation"
        ),
        "not_proven": (
            "Neither completeness of all MMIO writes nor absence of "
            "runtime clock switching can be inferred from this scan"
        ),
    }


def analyze(v2: bytes, v1: bytes | None = None) -> dict:
    return {
        "rom_dispatch": branch_cfgr_effect(v2, v1),
        "v2_rcc_literal_local_scan": scan_local_rcc_writes(v2),
        "v2_rcc_helper_direct_calls": clock_helper_direct_xrefs(v2),
        "v1_rcc_literal_local_scan": scan_local_rcc_writes(v1) if v1 else None,
        "physical_mcu_confirmed": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("v2", type=Path)
    p.add_argument("--v1", type=Path)
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    result = analyze(decoded_payload(a.v2.read_bytes()),
                     decoded_payload(a.v1.read_bytes()) if a.v1 else None)
    if a.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        r = result["rom_dispatch"]
        print("ROM branch CFGR pre-mask:", r["uid_1c_pre_mask"])
        print("Pre-clear mask:", r["uid_1c_cleared_bits_mask"])
        for b in r["branches"]:
            print(b["uid_lowword_high_byte"], b["before_rom"], b["callback_abi"])
        for image in ("v2_rcc_literal_local_scan", "v1_rcc_literal_local_scan"):
            item = result[image]
            if item:
                print(image, "literal references", len(item["literal_load_candidate_sites"]),
                      "local write candidates", len(item["straight_line_store_candidates"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
