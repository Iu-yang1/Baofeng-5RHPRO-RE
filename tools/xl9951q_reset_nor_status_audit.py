#!/usr/bin/env python3
"""Read-only V1/V2 Reset-to-recovery and NOR error propagation audit.

Evidence is confined to original archived Thumb instructions and their direct
control flow. This does not execute the firmware or connect any hardware.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window
from v2_pll_runtime_order import V1, V2, verify_reset_to_main, reachable_calls
from xl9951q_journal_recovery_audit import verify_recovery, STOCK as JOURNAL

VERSIONS = {
    "v1": {
        "package": "firmware/BF_5RH_501_v1_1_04.dat",
        "reset": V1,
        "main": 0x08027BE8,
        "main_recovery_bl": 0x08027BFC,
        "spi_byte": 0x080257A0,
        "spi_status": 0x080030C8,
        "nor_program": 0x08003118,
        "nor_erase": 0x08007C94,
        "restore": 0x0800ED50,
        "journal_clear": 0x08007C68,
        "windows": [
            (0x080257A0, 0x080257EC),
            (0x080030C8, 0x080030F0),
            (0x08003118, 0x080031A0),
            (0x08007C94, 0x08007CDA),
            (0x0800ED50, 0x0800ED6A),
            (0x0800AB74, 0x0800AC10),
            (0x08027BE8, 0x08027C08),
        ],
        "ins": {
            "spi_tx_budget": (0x080257AE, "cmp", "r4, #0xc8"),
            "spi_tx_timeout_branch": (0x080257B0, "bhi", "#0x80257d2"),
            "spi_tx_pending": (0x080257BC, "beq", "#0x80257aa"),
            "spi_rx_budget": (0x080257CE, "cmp", "r4, #0xc8"),
            "spi_rx_timeout_branch": (0x080257D0, "bls", "#0x80257d6"),
            "spi_timeout_return_zero": (0x080257D2, "movs", "r0, #0"),
            "spi_timeout_return": (0x080257D4, "pop", "pc"),
            "spi_rx_pending": (0x080257E0, "beq", "#0x80257ca"),
            "spi_received_byte": (0x080257E8, "uxtb", "r0, r0"),
            "status_opcode": (0x080030D6, "movs", "r0, #5"),
            "status_spi_call": (0x080030DE, "bl", "#0x80257a0"),
            "status_wip_test": (0x080030EA, "lsls", "r0, r0, #0x1f"),
            "status_retry": (0x080030EC, "bne", "#0x80030ce"),
            "status_return": (0x080030EE, "pop", "pc"),
            "program_status_wait": (0x08003182, "bl", "#0x80030c8"),
            "program_following_cmp": (0x08003186, "cmp", "r6, r4"),
            "program_return": (0x0800319C, "pop", "pc"),
            "erase_status_tail": (0x08007CD6, "b", "#0x80030c8"),
            "restore_erase_call": (0x0800ED56, "bl", "#0x8007c94"),
            "restore_program_tail": (0x0800ED66, "b", "#0x8003118"),
            "replay_restore_call": (0x0800AC08, "bl", "#0x800ed50"),
            "replay_clear_call": (0x0800AC0C, "bl", "#0x8007c68"),
            "main_recovery_call": (0x08027BFC, "bl", "#0x800ab74"),
        },
        "branches": (0x080030EC,),
    },
    "v2": {
        "package": "firmware/BF_5RH_501_v2_0_9.dat",
        "reset": V2,
        "main": 0x080340E0,
        "main_recovery_bl": 0x080340F4,
        "spi_byte": 0x08031814,
        "spi_status": 0x08006BD8,
        "nor_program": 0x08006C28,
        "nor_erase": 0x0800D334,
        "restore": 0x08014A28,
        "journal_clear": 0x0800D308,
        "windows": [
            (0x08031814, 0x08031860),
            (0x08006BD8, 0x08006C00),
            (0x08006C28, 0x08006CB0),
            (0x0800D334, 0x0800D37A),
            (0x08014A28, 0x08014A42),
            (0x08010400, 0x0801049C),
            (0x080340E0, 0x08034100),
        ],
        "ins": {
            "spi_tx_budget": (0x08031822, "cmp", "r4, #0xc8"),
            "spi_tx_timeout_branch": (0x08031824, "bhi", "#0x8031846"),
            "spi_tx_pending": (0x08031830, "beq", "#0x803181e"),
            "spi_rx_budget": (0x08031842, "cmp", "r4, #0xc8"),
            "spi_rx_timeout_branch": (0x08031844, "bls", "#0x803184a"),
            "spi_timeout_return_zero": (0x08031846, "movs", "r0, #0"),
            "spi_timeout_return": (0x08031848, "pop", "pc"),
            "spi_rx_pending": (0x08031854, "beq", "#0x803183e"),
            "spi_received_byte": (0x0803185C, "uxtb", "r0, r0"),
            "status_opcode": (0x08006BE6, "movs", "r0, #5"),
            "status_spi_call": (0x08006BEE, "bl", "#0x8031814"),
            "status_wip_test": (0x08006BFA, "lsls", "r0, r0, #0x1f"),
            "status_retry": (0x08006BFC, "bne", "#0x8006bde"),
            "status_return": (0x08006BFE, "pop", "pc"),
            "program_status_wait": (0x08006C92, "bl", "#0x8006bd8"),
            "program_following_cmp": (0x08006C96, "cmp", "r6, r4"),
            "program_return": (0x08006CAC, "pop", "pc"),
            "erase_status_tail": (0x0800D376, "b", "#0x8006bd8"),
            "restore_erase_call": (0x08014A2E, "bl", "#0x800d334"),
            "restore_program_tail": (0x08014A3E, "b", "#0x8006c28"),
            "replay_restore_call": (0x08010494, "bl", "#0x8014a28"),
            "replay_clear_call": (0x08010498, "bl", "#0x800d308"),
            "main_recovery_call": (0x080340F4, "bl", "#0x8010400"),
        },
        "branches": (0x08006BFC,),
    },
}


def _require_instruction(index: dict[str, dict], label: str, expected: tuple) -> dict:
    pc, op, operand = expected
    found = index.get(f"0x{pc:08X}")
    if (found is None or found["mnemonic"].split(".")[0] != op
            or operand not in found["operands"]):
        raise ValueError(f"{label}: mismatch at 0x{pc:08X}: {found}")
    return found


def classify_status_result(spi_timed_out: bool, actual_status: int = 0) -> dict:
    """Express the observed ambiguity; a model, not hardware simulation."""
    if not 0 <= actual_status <= 0xFF:
        raise ValueError("status byte out of range")
    returned_byte = 0 if spi_timed_out else actual_status
    return {
        "spi_timed_out": spi_timed_out,
        "byte_returned_by_spi_exchange": returned_byte,
        "journal_driver_interpretation": (
            "busy" if returned_byte & 1 else "ready"
        ),
        "timeout_is_distinguishable_from_valid_zero_status": False,
    }


def verify_version(payload: bytes, edition: str) -> dict:
    spec = VERSIONS[edition]
    reset = verify_reset_to_main(payload, spec["reset"], edition == "v2")
    if reset["reset_vector"] != "0x0800123D":
        raise ValueError(f"{edition}: reset vector no longer points to tested Thumb veneer")
    journal = verify_recovery(payload, edition)
    index = {}
    for start, end in spec["windows"]:
        for row in inspect_window(payload, start, end):
            index[row["pc"]] = row
    checks = {
        name: _require_instruction(index, f"{edition}/{name}", exp)
        for name, exp in spec["ins"].items()
    }
    main_path = reachable_calls(payload, spec["main"])
    recovery_edge = (spec["main_recovery_bl"], JOURNAL[edition]["recovery"])
    if recovery_edge not in main_path:
        raise ValueError(f"{edition}: main-to-journal call no longer reachable by direct CFG")
    main_prefix = inspect_window(
        payload, spec["main"], spec["main_recovery_bl"] + 4
    )
    unexpected_jumps = [
        r for r in main_prefix
        if r["mnemonic"].split(".")[0] in
        ("b", "beq", "bne", "bcs", "bcc", "bhi", "bls", "cbz", "cbnz", "bx")
    ]
    if unexpected_jumps:
        raise ValueError(f"{edition}: early main path now has a branch: {unexpected_jumps}")
    status_start = spec["spi_status"]
    status_end = spec["ins"]["status_return"][0] + 2
    status_code = inspect_window(payload, status_start, status_end)
    local_branches = [
        r["pc"] for r in status_code
        if r["mnemonic"].split(".")[0].startswith(("bne", "beq", "bhi", "bls", "bcc", "bcs", "cb"))
    ]
    expected_branches = [f"0x{x:08X}" for x in spec["branches"]]
    if local_branches != expected_branches:
        raise ValueError(f"{edition}: status polling control flow changed: {local_branches}")
    if (spec["ins"]["status_spi_call"][2].split("#")[1] !=
            f"{spec['spi_byte']:#x}"):
        raise ValueError(f"{edition}: status read does not call expected SPI helper")
    # The SPI routine has two bounded hardware-ready loops, both joining
    # a single zero-return failure exit. NOR WIP polling has its own unbounded
    # back-edge and tests only the received byte's least significant bit.
    if (spec["ins"]["program_status_wait"][0] + 4 !=
            spec["ins"]["program_following_cmp"][0]):
        raise ValueError(f"{edition}: program branch no longer immediately ignores WIP result")
    if (spec["ins"]["replay_restore_call"][0] + 4 !=
            spec["ins"]["replay_clear_call"][0]):
        raise ValueError(f"{edition}: recovery no longer clears immediately after replay call")
    targets = [spec["spi_byte"], spec["spi_status"], spec["nor_program"],
               spec["nor_erase"], spec["restore"], spec["journal_clear"]]
    calls = find_calls(payload, targets)
    for name, callee in (
        ("status_spi_call", "spi_byte"),
        ("program_status_wait", "spi_status"),
        ("restore_erase_call", "nor_erase"),
        ("replay_restore_call", "restore"),
        ("replay_clear_call", "journal_clear"),
    ):
        target = f"0x{spec[callee]:08X}"
        caller = f"0x{spec['ins'][name][0]:08X}"
        if caller not in {c["call_pc"] for c in calls[target]}:
            raise ValueError(f"{edition}: direct BL missing: {name}")
    return {
        "reset_vector": reset["reset_vector"],
        "reset_entry": reset["reset_software_path"],
        "main_entry": reset["main_entry"],
        "main_recovery_call": f"0x{spec['main_recovery_bl']:08X}",
        "recovery_entry": journal["recovery_entry"],
        "reset_to_recovery": (
            "verified reset veneer and scatterload main pointer; "
            "main CFG has direct recovery BL without local branch; "
            "all calls require successful preceding returns"
        ),
        "spi_byte_exchange": {
            "function": f"0x{spec['spi_byte']:08X}",
            "tx_poll_limit_immediate": "0xC8",
            "rx_poll_limit_immediate": "0xC8",
            "timeout_return": "0x00",
            "successful_receive_return_type": "uint8",
            "failure_indistinguishable_from_valid_0x00": True,
        },
        "nor_status_poll": {
            "function": f"0x{spec['spi_status']:08X}",
            "read_status_opcode": "0x05",
            "tests_bit": 0,
            "total_timeout_present_in_bounded_function": False,
            "busy_back_edge": checks["status_retry"]["operands"],
            "spi_timeout_zero_treated_as_ready": True,
        },
        "nor_write_and_replay": {
            "page_program": f"0x{spec['nor_program']:08X}",
            "wait_after_program": checks["program_status_wait"]["pc"],
            "compares_remaining_length_not_spi_result": True,
            "nor_erase": f"0x{spec['nor_erase']:08X}",
            "erase_tail_wait": checks["erase_status_tail"]["operands"],
            "recovery_erase_and_program": True,
            "restore_result_checked_before_journal_clear": False,
        },
        "validated_thumb_sites": len(checks),
        "exact_code_pcs": {k: row["pc"] for k, row in checks.items()},
        "limitations": [
            "Static control-flow graph, not a physical execution trace.",
            "Unobserved ROM/bootloader, clock/peripheral failures can prevent reaching main.",
            "The 0xC8 comparisons are polling iteration bounds, not measured milliseconds.",
            "Status function has no overall timeout in the audited bounded routine; watchdog behavior is not modeled.",
            "No real SPI bus capture or brownout fault injection.",
        ],
    }


def analyze(v1: bytes, v2: bytes) -> dict:
    return {
        "mode": "original OEM firmware only; offline Thumb validation",
        "versions": {
            "v1": verify_version(v1, "v1"),
            "v2": verify_version(v2, "v2"),
        },
        "cross_version": {
            "reset_to_main_and_recovery_direct_bl_both": True,
            "single_spi_exchange_has_bounded_polling": True,
            "nor_wip_wait_has_no_own_deadline": True,
            "spi_timeout_can_masquerade_as_nor_ready": True,
            "restore_is_followed_by_unconditional_journal_erase": True,
            "actual_board_behavior_verified": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    images = {
        k: decoded_payload(Path(item["package"]).read_bytes())
        for k, item in VERSIONS.items()
    }
    report = analyze(images["v1"], images["v2"])
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for edition, item in report["versions"].items():
            print(edition, item["reset_vector"], "→", item["main_entry"],
                  "→", item["recovery_entry"], "NOR WIP:", item["nor_status_poll"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
