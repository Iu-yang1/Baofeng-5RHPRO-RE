#!/usr/bin/env python3
"""Verify the cold-start NOR journal recovery path in original V1/V2 images.

Read-only static Thumb evidence. No firmware execution or real-device access.
This audits bounded instruction/call-site flow, not all possible C paths.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window

SCRATCH = 0x0807F800
BACKUP = 0x001FE000
SECTOR_BYTES = 4096
BLOCK_BYTES = 64

STOCK = {
    "v1": {
        "file": "firmware/BF_5RH_501_v1_1_04.dat",
        "init": 0x08027BE8, "boot_call": 0x08027BFC,
        "recovery": 0x0800AB74, "recovery_end": 0x0800AC10,
        "header_reader": 0x08007C80,
        "backup_reader": 0x0800E5CC,
        "restore_writer": 0x0800ED50,
        "journal_clear": 0x08007C68,
        "flash_erase": 0x08002E70,
        "nor_erase": 0x08007C94,
        "nor_program": 0x08003118,
        "writer": 0x08012D98, "writer_end": 0x08012E7E,
        "sram_backup": 0x20001CA8,
        "checks": {
            "boot_set_vtor": (0x08027BE8, "mov", "r1, #0x1000"),
            "boot_recovery_call": (0x08027BFC, "bl", "#0x800ab74"),
            "header_length": (0x0800AB86, "movs", "r1, #8"),
            "header_literal": (0x0800AB88, "ldr", "r0, [pc"),
            "header_read_call": (0x0800AB8A, "bl", "#0x8007c80"),
            "address_little_endian_lsb": (0x0800AB92, "ldrb", "r6, [sp, #0xc]"),
            "address_little_endian_msb": (0x0800AB8E, "ldrb", "r0, [sp, #0xf]"),
            "address_assembled": (0x0800ABA8, "orr", "r6, r6, r0, lsl #8"),
            "empty_sentinel_test": (0x0800ABAC, "adds", "r0, r6, #1"),
            "empty_sentinel_branch": (0x0800ABAE, "beq", "#0x800ac10"),
            "completion_byte": (0x0800ABB0, "ldrb", "[sp, #0x10]"),
            "completion_compare": (0x0800ABB4, "cmp", "r0, #1"),
            "completion_branch": (0x0800ABB6, "beq", "#0x800ac0c"),
            "backup_length": (0x0800ABB8, "mov", "sb, #0x1000"),
            "backup_address": (0x0800ABC0, "mov", "r0, #0x1fe000"),
            "backup_read": (0x0800ABC4, "bl", "#0x800e5cc"),
            "target_chunk_size": (0x0800ABD4, "movs", "r1, #0x40"),
            "target_chunk_read": (0x0800ABD6, "bl", "#0x800e5cc"),
            "byte_compare": (0x0800ABE2, "cmp", "r2, r3"),
            "mismatch_branch": (0x0800ABE4, "bne", "#0x800abf2"),
            "chunk_count": (0x0800ABFA, "cmp", "r4, #0x40"),
            "all_equal_branch": (0x0800AC00, "beq", "#0x800ac0c"),
            "restore_call": (0x0800AC08, "bl", "#0x800ed50"),
            "clear_call": (0x0800AC0C, "bl", "#0x8007c68"),
            "nor_erase_restore": (0x0800ED56, "bl", "#0x8007c94"),
            "nor_restore_size": (0x0800ED62, "mov", "r1, #0x1000"),
            "nor_program_restore": (0x0800ED66, "b", "#0x8003118"),
            "clear_unlock": (0x08007C6A, "bl", "#0x8002f34"),
            "clear_scratch_address": (0x08007C6E, "ldr", "r0, [pc"),
            "clear_internal_flash": (0x08007C70, "bl", "#0x8002e70"),
            "writer_erase_metadata": (0x08012DB6, "bl", "#0x8002e70"),
            "writer_backup_save": (0x08012DDC, "bl", "#0x8003118"),
            "writer_journal_address": (0x08012DE2, "ldr", "r0, [pc"),
            "writer_journal_program": (0x08012DE4, "bl", "#0x8002ee4"),
            "writer_commit_address": (0x08012E6C, "ldr", "r0, [pc"),
            "writer_commit_value": (0x08012E6E, "movs", "r1, #1"),
            "writer_commit_offset": (0x08012E70, "adds", "r0, r0, #4"),
            "writer_commit_program": (0x08012E72, "bl", "#0x8002ee4"),
        },
        "ranges": [(0x08027BE8,0x08027C08),(0x0800AB74,0x0800AC10),
                   (0x0800ED50,0x0800ED6A),(0x08007C68,0x08007C7C),
                   (0x08012D98,0x08012E7E)],
        "literal_sites": ("header_literal", "clear_scratch_address",
                          "writer_journal_address", "writer_commit_address"),
    },
    "v2": {
        "file": "firmware/BF_5RH_501_v2_0_9.dat",
        "init": 0x080340E0, "boot_call": 0x080340F4,
        "recovery": 0x08010400, "recovery_end": 0x0801049C,
        "header_reader": 0x0800D320,
        "backup_reader": 0x080141DC,
        "restore_writer": 0x08014A28,
        "journal_clear": 0x0800D308,
        "flash_erase": 0x08006980,
        "nor_erase": 0x0800D334,
        "nor_program": 0x08006C28,
        "writer": 0x080190E0, "writer_end": 0x080191C6,
        "sram_backup": 0x20002580,
        "checks": {
            "boot_set_vtor": (0x080340E0, "mov", "r1, #0x1000"),
            "boot_recovery_call": (0x080340F4, "bl", "#0x8010400"),
            "header_length": (0x08010412, "movs", "r1, #8"),
            "header_literal": (0x08010414, "ldr", "r0, [pc"),
            "header_read_call": (0x08010416, "bl", "#0x800d320"),
            "address_little_endian_lsb": (0x0801041E, "ldrb", "r6, [sp, #0xc]"),
            "address_little_endian_msb": (0x0801041A, "ldrb", "r0, [sp, #0xf]"),
            "address_assembled": (0x08010434, "orr", "r6, r6, r0, lsl #8"),
            "empty_sentinel_test": (0x08010438, "adds", "r0, r6, #1"),
            "empty_sentinel_branch": (0x0801043A, "beq", "#0x801049c"),
            "completion_byte": (0x0801043C, "ldrb", "[sp, #0x10]"),
            "completion_compare": (0x08010440, "cmp", "r0, #1"),
            "completion_branch": (0x08010442, "beq", "#0x8010498"),
            "backup_length": (0x08010444, "mov", "sb, #0x1000"),
            "backup_address": (0x0801044C, "mov", "r0, #0x1fe000"),
            "backup_read": (0x08010450, "bl", "#0x80141dc"),
            "target_chunk_size": (0x08010460, "movs", "r1, #0x40"),
            "target_chunk_read": (0x08010462, "bl", "#0x80141dc"),
            "byte_compare": (0x0801046E, "cmp", "r2, r3"),
            "mismatch_branch": (0x08010470, "bne", "#0x801047e"),
            "chunk_count": (0x08010486, "cmp", "r4, #0x40"),
            "all_equal_branch": (0x0801048C, "beq", "#0x8010498"),
            "restore_call": (0x08010494, "bl", "#0x8014a28"),
            "clear_call": (0x08010498, "bl", "#0x800d308"),
            "nor_erase_restore": (0x08014A2E, "bl", "#0x800d334"),
            "nor_restore_size": (0x08014A3A, "mov", "r1, #0x1000"),
            "nor_program_restore": (0x08014A3E, "b", "#0x8006c28"),
            "clear_unlock": (0x0800D30A, "bl", "#0x8006a44"),
            "clear_scratch_address": (0x0800D30E, "ldr", "r0, [pc"),
            "clear_internal_flash": (0x0800D310, "bl", "#0x8006980"),
            "writer_erase_metadata": (0x080190FE, "bl", "#0x8006980"),
            "writer_backup_save": (0x08019124, "bl", "#0x8006c28"),
            "writer_journal_address": (0x0801912A, "ldr", "r0, [pc"),
            "writer_journal_program": (0x0801912C, "bl", "#0x80069f4"),
            "writer_commit_address": (0x080191B4, "ldr", "r0, [pc"),
            "writer_commit_value": (0x080191B6, "movs", "r1, #1"),
            "writer_commit_offset": (0x080191B8, "adds", "r0, r0, #4"),
            "writer_commit_program": (0x080191BA, "bl", "#0x80069f4"),
        },
        "ranges": [(0x080340E0,0x08034100),(0x08010400,0x0801049C),
                   (0x08014A28,0x08014A42),(0x0800D308,0x0800D31C),
                   (0x080190E0,0x080191C6)],
        "literal_sites": ("header_literal", "clear_scratch_address",
                          "writer_journal_address", "writer_commit_address"),
    },
}


def classify_recovery(header: bytes, backup: bytes | None = None,
                      target: bytes | None = None) -> dict:
    """A pure logical model of the *observed branches*, not an emulator."""
    if len(header) != 8:
        raise ValueError("eight-byte journal record required")
    offset = int.from_bytes(header[:4], "little")
    completed = header[4] == 1
    if offset == 0xFFFFFFFF:
        action = "skip_empty"
    elif completed:
        action = "skip_committed_then_clear"
    elif backup is None or target is None:
        action = "pending_compare"
    elif len(backup) != SECTOR_BYTES or len(target) != SECTOR_BYTES:
        raise ValueError("4KiB source and destination required")
    else:
        action = ("restore_then_clear" if backup != target
                  else "equal_then_clear")
    return {
        "target_nor_offset": offset,
        "completion_byte": header[4],
        "action": action,
        "recovery_entry_replays_only_if_mismatch": True,
    }


def _require(index: dict[str, dict], name: str, site: tuple) -> dict:
    pc, mnemonic, operand = site
    row = index.get(f"0x{pc:08X}")
    if (row is None or row["mnemonic"].split(".")[0] != mnemonic
            or operand not in row["operands"]):
        raise ValueError(f"{name}: unexpected Thumb instruction at 0x{pc:08X}: {row}")
    return row


def verify_recovery(payload: bytes, edition: str) -> dict:
    spec = STOCK[edition]
    index: dict[str, dict] = {}
    for start, end in spec["ranges"]:
        for ins in inspect_window(payload, start, end):
            index[ins["pc"]] = ins
    checks = spec["checks"]
    checked = {name: _require(index, f"{edition}/{name}", pattern)
               for name, pattern in checks.items()}
    for name in spec["literal_sites"]:
        if checked[name].get("literal_value") != f"0x{SCRATCH:08X}":
            raise ValueError(f"{edition}: literal at {name} is not the internal Flash journal")
    calls = find_calls(
        payload,
        [spec[k] for k in ("recovery", "header_reader", "backup_reader",
                          "restore_writer", "journal_clear", "flash_erase")]
    )
    for caller_name, callee_name in (
        ("boot_recovery_call", "recovery"),
        ("header_read_call", "header_reader"),
        ("backup_read", "backup_reader"),
        ("target_chunk_read", "backup_reader"),
        ("restore_call", "restore_writer"),
        ("clear_call", "journal_clear"),
        ("clear_internal_flash", "flash_erase"),
        ("writer_erase_metadata", "flash_erase"),
    ):
        pc = f"0x{checks[caller_name][0]:08X}"
        target = f"0x{spec[callee_name]:08X}"
        if pc not in {c["call_pc"] for c in calls[target]}:
            raise ValueError(f"{edition}: no genuine BL from {pc} to {target}")
    backup_literal = checked["backup_address"]
    if "#0x1fe000" not in backup_literal["operands"]:
        raise ValueError(f"{edition}: expected NOR backup offset absent")
    return {
        "early_init_callsite": f"0x{spec['boot_call']:08X}",
        "recovery_entry": f"0x{spec['recovery']:08X}",
        "journal_metadata_read": {
            "address": f"0x{SCRATCH:08X}",
            "bytes": 8,
            "target_offset_endian": "little",
            "empty_offset": "0xFFFFFFFF",
            "complete_byte_offset": 4,
            "complete_byte_value": 1,
        },
        "recovery_backup": {
            "nor_offset": f"0x{BACKUP:08X}",
            "bytes": SECTOR_BYTES,
            "staging_sram_address": f"0x{spec['sram_backup']:08X}",
        },
        "mismatch_scan": {"chunk_bytes": BLOCK_BYTES,
                          "total_bytes": SECTOR_BYTES,
                          "byte_comparison": True,
                          "restores_full_sector_only_if_different": True},
        "restore": {
            "wrapper": f"0x{spec['restore_writer']:08X}",
            "nor_erase_helper": f"0x{spec['nor_erase']:08X}",
            "nor_program_helper": f"0x{spec['nor_program']:08X}",
            "bytes": SECTOR_BYTES,
        },
        "journal_cleanup": {
            "helper": f"0x{spec['journal_clear']:08X}",
            "mcuflash_erase_helper": f"0x{spec['flash_erase']:08X}",
            "performed_after_equal_or_recovery": True,
            "not_performed_for_erased_sentinel": True,
        },
        "writer_markers": {
            "start": f"0x{spec['writer']:08X}",
            "first_metadata_address": f"0x{SCRATCH:08X}",
            "final_commit_address": f"0x{SCRATCH+4:08X}",
            "final_commit_value": 1,
        },
        "verified_instruction_count": len(checks),
        "validated_sites": {name: f"0x{t[0]:08X}" for name, t in checks.items()},
        "limits": [
            "This proves an application recovery subroutine and an early-init BL, not a bootloader image.",
            "Reset-to-init reachability and every failure branch are not fully exhaustively proven.",
            "No checksum protecting the 4KiB backup is shown in this recovery subroutine.",
            "No physical flash I/O, brownout injection, or hardware crash recovery test.",
        ],
    }


def analyze(v1: bytes, v2: bytes) -> dict:
    return {
        "analysis": "offline original firmware instruction and direct BL validation",
        "versions": {"v1": verify_recovery(v1, "v1"),
                     "v2": verify_recovery(v2, "v2")},
        "main_result": (
            "Both stock applications implement an early-init NOR sector "
            "comparison/replay path controlled by MCU Flash metadata"
        ),
        "proven": {
            "cross_version_recovery_logic_exists": True,
            "direct_early_init_bl": True,
            "on_mismatch_full_4k_restore": True,
            "physical_powerloss_atomicity": False,
            "backup_integrity_verified": False,
            "complete_partition_map": False,
            "full_reset_to_init_callgraph": False,
            "chip_identity_verified": False,
        },
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    images = {k: decoded_payload(Path(s["file"]).read_bytes())
              for k, s in STOCK.items()}
    output = analyze(images["v1"], images["v2"])
    if args.json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        for version, r in output["versions"].items():
            print(version, r["recovery_entry"],
                  r["early_init_callsite"],
                  r["journal_cleanup"]["helper"],
                  r["verified_instruction_count"], "verified sites")
        print("Physical brownout resilience and MCU identity: NOT VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
