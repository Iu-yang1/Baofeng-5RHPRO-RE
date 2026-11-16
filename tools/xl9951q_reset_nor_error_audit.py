#!/usr/bin/env python3
"""Read-only Reset-to-recovery and NOR return/error-path audit of OEM images.

Records observed machine code, not physical hardware operations or proven
execution of all branches. Never opens ports or runs the vendor upgrader.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from v2_pll_runtime_order import V1, V2, verify_reset_to_main, reachable_calls
from xl9951q_journal_recovery_audit import STOCK, verify_recovery

IMAGE_BASE = 0x08001000

EVIDENCE = {
    "v1": {
        "spec": V1,
        "main_early": (0x08027BE8, 0x08027C04),
        "main_calls": ((0x08027BEE, 0x08024978), (0x08027BF2, 0x080111F0),
                       (0x08027BF8, 0x08002CF0), (0x08027BFC, 0x0800AB74),
                       (0x08027C00, 0x080111B4)),
        "nor_status": (0x080030C8, 0x080030F0),
        "nor_status_sites": {
            0x080030D6: ("movs", "r0, #5"),
            0x080030EA: ("lsls", "r0, r0, #0x1f"),
            0x080030EC: ("bne", "#0x80030ce"),
            0x080030EE: ("pop", "{r4, r5, r6, pc}"),
        },
        "nor_erase": (0x08007C94, 0x08007CDA),
        "nor_erase_sites": {
            0x08007C98: ("bl", "#0x80030f4"),
            0x08007C9C: ("bl", "#0x80030c8"),
            0x08007CAA: ("movs", "r0, #0x20"),
            0x08007CD6: ("b.w", "#0x80030c8"),
        },
        "nor_program": (0x08003118, 0x080031A0),
        "nor_program_sites": {
            0x08003136: ("bl", "#0x80030f4"),
            0x08003146: ("movs", "r0, #2"),
            0x08003182: ("bl", "#0x80030c8"),
            0x08003186: ("cmp", "r6, r4"),
            0x0800319C: ("pop.w", "{r4, r5, r6, r7, r8, sb, sl, pc}"),
        },
        "nor_replay": (0x0800ED50, 0x0800ED6A),
        "nor_replay_sites": {
            0x0800ED56: ("bl", "#0x8007c94"),
            0x0800ED5E: ("pop.w", "{r4, r5, r6, lr}"),
            0x0800ED62: ("mov.w", "r1, #0x1000"),
            0x0800ED66: ("b.w", "#0x8003118"),
        },
        "recovery_sites": {
            0x0800AC08: ("bl", "#0x800ed50"),
            0x0800AC0C: ("bl", "#0x8007c68"),
        },
        "flash_erase": (0x08002E70, 0x08002EA8),
        "flash_erase_sites": {
            0x08002E7E: ("cmp", "r0, #4"),
            0x08002E80: ("bne", "#0x8002ea6"),
            0x08002EA6: ("pop", "{r4, r5, r6, pc}"),
        },
    },
    "v2": {
        "spec": V2,
        "main_early": (0x080340E0, 0x080340FC),
        "main_calls": ((0x080340E6, 0x080309BC), (0x080340EA, 0x080173DC),
                       (0x080340F0, 0x08006800), (0x080340F4, 0x08010400),
                       (0x080340F8, 0x080173A0)),
        "nor_status": (0x08006BD8, 0x08006C00),
        "nor_status_sites": {
            0x08006BE6: ("movs", "r0, #5"),
            0x08006BFA: ("lsls", "r0, r0, #0x1f"),
            0x08006BFC: ("bne", "#0x8006bde"),
            0x08006BFE: ("pop", "{r4, r5, r6, pc}"),
        },
        "nor_erase": (0x0800D334, 0x0800D37A),
        "nor_erase_sites": {
            0x0800D338: ("bl", "#0x8006c04"),
            0x0800D33C: ("bl", "#0x8006bd8"),
            0x0800D34A: ("movs", "r0, #0x20"),
            0x0800D376: ("b.w", "#0x8006bd8"),
        },
        "nor_program": (0x08006C28, 0x08006CB0),
        "nor_program_sites": {
            0x08006C46: ("bl", "#0x8006c04"),
            0x08006C56: ("movs", "r0, #2"),
            0x08006C92: ("bl", "#0x8006bd8"),
            0x08006C96: ("cmp", "r6, r4"),
            0x08006CAC: ("pop.w", "{r4, r5, r6, r7, r8, sb, sl, pc}"),
        },
        "nor_replay": (0x08014A28, 0x08014A42),
        "nor_replay_sites": {
            0x08014A2E: ("bl", "#0x800d334"),
            0x08014A36: ("pop.w", "{r4, r5, r6, lr}"),
            0x08014A3A: ("mov.w", "r1, #0x1000"),
            0x08014A3E: ("b.w", "#0x8006c28"),
        },
        "recovery_sites": {
            0x08010494: ("bl", "#0x8014a28"),
            0x08010498: ("bl", "#0x800d308"),
        },
        "flash_erase": (0x08006980, 0x080069B8),
        "flash_erase_sites": {
            0x0800698E: ("cmp", "r0, #4"),
            0x08006990: ("bne", "#0x80069b6"),
            0x080069B6: ("pop", "{r4, r5, r6, pc}"),
        },
    }
}


def _require(index: dict[int, dict], pc: int, name: str, operand: str) -> None:
    row = index.get(pc)
    if row is None or row["mnemonic"] != name or operand not in row["operands"]:
        raise ValueError(f"unexpected source instruction at {pc:#010x}: {row}")


def _check_peripheral_paths(payload: bytes, info: dict, edition: str) -> dict:
    checks = {}
    for label in ("nor_status", "nor_program", "nor_erase", "nor_replay", "flash_erase"):
        start, end = info[label]
        index = {int(r["pc"], 16): r for r in inspect_window(payload, start, end)}
        assertions = info[label + "_sites"]
        for pc, (opcode, operand) in assertions.items():
            _require(index, pc, opcode, operand)
        checks[label] = len(assertions)

    # RDSR checks WIP bit0 only; no other conditional exit in this span.
    status = inspect_window(payload, *info["nor_status"])
    if any(r["mnemonic"] in ("cbz", "cbnz", "bhi", "bhs", "blo", "bls")
           for r in status):
        raise ValueError(f"{edition}: unexpected NOR status exit condition")
    return checks


def audit_one(payload: bytes, edition: str) -> dict:
    info = EVIDENCE[edition]
    stock = STOCK[edition]
    reset = verify_reset_to_main(payload, info["spec"], edition == "v2")
    recovery = verify_recovery(payload, edition)
    checks = _check_peripheral_paths(payload, info, edition)

    # Decode a single, continuous main prologue and assert that these BLs
    # occur in order before the next initialization block; no conditional branch.
    start, end = info["main_early"]
    main_ins = inspect_window(payload, start, end)
    index = {int(r["pc"], 16): r for r in main_ins}
    for pc, target in info["main_calls"]:
        _require(index, pc, "bl", f"#{target:#x}")
    before_recovery = [r for r in main_ins
                       if int(r["pc"], 16) < stock["boot_call"]]
    if any(r["mnemonic"] in ("b", "b.w", "beq", "bne", "cbz", "cbnz",
                           "bx", "blx") for r in before_recovery):
        raise ValueError(f"{edition}: conditional branch in main prologue")
    actual_calls = reachable_calls(payload, info["spec"]["main"])
    if (stock["boot_call"], stock["recovery"]) not in actual_calls:
        raise ValueError(f"{edition}: main CFG does not include direct recovery BL")

    record_start = min(info["recovery_sites"])
    recovery_index = {
        int(r["pc"], 16): r
        for r in inspect_window(payload, record_start, record_start + 8)
    }
    for pc, (mnemonic, operand) in info["recovery_sites"].items():
        _require(recovery_index, pc, mnemonic, operand)
    keys = sorted(info["recovery_sites"])
    if keys[1] != keys[0] + 4:
        raise ValueError(f"{edition}: changed recovery cleanup sequencing")

    return {
        "reset": reset["reset_vector"],
        "reset_veneer": reset["reset_software_path"],
        "scatterload_handoff": "0x08001220",
        "main_entry": reset["main_entry"],
        "main_direct_recovery_call": f"0x{stock['boot_call']:08X}",
        "recovery_entry": f"0x{stock['recovery']:08X}",
        "main_first_five_calls": [
            {"pc": f"0x{pc:08X}", "target": f"0x{callee:08X}"}
            for pc, callee in info["main_calls"]
        ],
        "nor_status_poll": {
            "entry": f"0x{info['nor_status'][0]:08X}",
            "opcode": "0x05",
            "observed_bit": "WIP bit0",
            "loop_until_zero": True,
            "retry_timeout_observed": False,
            "separate_program_verify_observed": False,
        },
        "nor_program": {
            "entry": f"0x{info['nor_program'][0]:08X}",
            "opcode": "0x02",
            "page_unit": 256,
            "calls_status_poll": True,
            "final_path": "POP {...,PC} after comparing remaining block length",
        },
        "nor_erase": {
            "entry": f"0x{info['nor_erase'][0]:08X}",
            "opcode": "0x20",
            "final_path": "tail B.W to RDSR WIP polling",
        },
        "restore_then_clear": {
            "restore_call": f"0x{keys[0]:08X}",
            "journal_clear_call": f"0x{keys[1]:08X}",
            "conditional_status_branch_between": False,
        },
        "flash_erase": {
            "entry": f"0x{info['flash_erase'][0]:08X}",
            "does_poll_controller_status": True,
            "does_conditionally_skip_erase_on_status_not_four": True,
            "restore_caller_checks_success": False,
        },
        "verified_checks": checks,
        "caveats": [
            "The Reset->scatterload->main path assumes normal return from earlier functions.",
            "This is a static graph of direct instructions, not a device execution trace.",
            "A successful WIP=0 read only indicates end of busy status, not CRC-verified data.",
            "Unobserved hardware faults, system resets or alternate code paths are not ruled out.",
        ],
    }


def analyze(v1: bytes, v2: bytes) -> dict:
    return {
        "method": "read-only decoded stock firmware, bounded instruction and CFG checks",
        "v1": audit_one(v1, "v1"),
        "v2": audit_one(v2, "v2"),
        "conclusion": (
            "Both versions have a verified static Reset/scatterload/main "
            "handoff to journal recovery, plus unbounded RDSR WIP polling "
            "and no separate restore-success check before journal clearance"
        ),
        "hardware_verified": False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    payloads = {version: decoded_payload(Path(STOCK[version]["file"]).read_bytes())
                for version in ("v1", "v2")}
    report = analyze(payloads["v1"], payloads["v2"])
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for version in ("v1", "v2"):
            row = report[version]
            print(version, row["reset"], row["main_direct_recovery_call"],
                  row["nor_status_poll"]["entry"],
                  row["restore_then_clear"]["journal_clear_call"])


if __name__ == "__main__":
    main()
