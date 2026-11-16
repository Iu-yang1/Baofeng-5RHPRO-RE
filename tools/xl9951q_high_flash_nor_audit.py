#!/usr/bin/env python3
"""Offline cross-version evidence of external NOR and internal Flash journal paths.

All inputs are archived OEM .dat payloads; no UART, updater or radio accesses.
Thumb instructions are verified at their actual program counters, not searched
as uncorrelated literals. Hardware operation and physical vendor are unknown.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls

ORIGIN = 0x08001000
SCRATCH_FLASH = 0x0807F800
NOR_BACKUP_OFFSET = 0x001FE000
NOR_UNIT = 0x1000

MAP = {
    "v1": {
        "path": "firmware/BF_5RH_501_v1_1_04.dat",
        "journal": 0x08012D98, "erase_journal": 0x08007C64,
        "spi_read": 0x08002FE4, "spi_write": 0x08003118,
        "spi_erase": 0x08002F98, "spi_erase_absolute": 0x08007C94,
        "nor_status": 0x080030C8, "nor_wren": 0x080030F4,
        "flash_erase": 0x08002E70, "flash_write": 0x08002EE4,
        "code_sites": {
            "nor_read_opcode": (0x08002FF6, "movs", "r0, #3"),
            "nor_write_opcode": (0x08003146, "movs", "r0, #2"),
            "nor_erase_opcode": (0x08002FAE, "movs", "r0, #0x20"),
            "nor_erase_backup_opcode": (0x08007CAA, "movs", "r0, #0x20"),
            "nor_status_opcode": (0x080030D6, "movs", "r0, #5"),
            "nor_wren_opcode": (0x08003100, "movs", "r0, #6"),
            "flash_erase_call": (0x08012DB6, "bl", "#0x8002e70"),
            "nor_read_call": (0x08012DC8, "bl", "#0x8002fe4"),
            "nor_erase_backup_call": (0x08012DD2, "bl", "#0x8007c94"),
            "nor_backup_write_call": (0x08012DDC, "bl", "#0x8003118"),
            "flash_mark_call": (0x08012DE4, "bl", "#0x8002ee4"),
            "nor_erase_target_call": (0x08012E24, "bl", "#0x8002f98"),
            "nor_target_write_call": (0x08012E46, "bl", "#0x8003118"),
            "flash_commit_call": (0x08012E72, "bl", "#0x8002ee4"),
        },
        "journal_ldr": 0x08012DB4, "nor_backup_mov": 0x08012DCC,
        "journal_commit_ldr": 0x08012E6C, "unit_mov": 0x08012DBA,
        "sram_pool": 0x08012E84, "sram_addr": 0x20002CA8,
    },
    "v2": {
        "path": "firmware/BF_5RH_501_v2_0_9.dat",
        "journal": 0x080190E0, "erase_journal": 0x0800D304,
        "spi_read": 0x08006AF4, "spi_write": 0x08006C28,
        "spi_erase": 0x08006AA8, "spi_erase_absolute": 0x0800D334,
        "nor_status": 0x08006BD8, "nor_wren": 0x08006C04,
        "flash_erase": 0x08006980, "flash_write": 0x080069F4,
        "code_sites": {
            "nor_read_opcode": (0x08006B06, "movs", "r0, #3"),
            "nor_write_opcode": (0x08006C56, "movs", "r0, #2"),
            "nor_erase_opcode": (0x08006ABE, "movs", "r0, #0x20"),
            "nor_erase_backup_opcode": (0x0800D34A, "movs", "r0, #0x20"),
            "nor_status_opcode": (0x08006BE6, "movs", "r0, #5"),
            "nor_wren_opcode": (0x08006C10, "movs", "r0, #6"),
            "flash_erase_call": (0x080190FE, "bl", "#0x8006980"),
            "nor_read_call": (0x08019110, "bl", "#0x8006af4"),
            "nor_erase_backup_call": (0x0801911A, "bl", "#0x800d334"),
            "nor_backup_write_call": (0x08019124, "bl", "#0x8006c28"),
            "flash_mark_call": (0x0801912C, "bl", "#0x80069f4"),
            "nor_erase_target_call": (0x0801916C, "bl", "#0x8006aa8"),
            "nor_target_write_call": (0x0801918E, "bl", "#0x8006c28"),
            "flash_commit_call": (0x080191BA, "bl", "#0x80069f4"),
        },
        "journal_ldr": 0x080190FC, "nor_backup_mov": 0x08019114,
        "journal_commit_ldr": 0x080191B4, "unit_mov": 0x08019102,
        "sram_pool": 0x080191CC, "sram_addr": 0x20003580,
    },
}


def verify_one(payload: bytes, version: str) -> dict:
    spec = MAP[version]
    checks = spec["code_sites"]
    windows = [
        (spec["journal"], spec["journal"] + 0xE0),
        (spec["spi_read"], spec["spi_read"] + 0x50),
        (spec["spi_write"], spec["spi_write"] + 0x70),
        (spec["spi_erase"], spec["spi_erase"] + 0x40),
        (spec["spi_erase_absolute"], spec["spi_erase_absolute"] + 0x48),
        (spec["nor_status"], spec["nor_status"] + 0x2C),
        (spec["nor_wren"], spec["nor_wren"] + 0x22),
    ]
    instruction_index = {}
    for start, end in windows:
        for row in inspect_window(payload, start, end):
            instruction_index[row["pc"]] = row
    for name, (pc, mnemonic, operand) in checks.items():
        row = instruction_index.get(f"0x{pc:08X}")
        if row is None or row["mnemonic"].split(".")[0] != mnemonic or operand not in row["operands"]:
            raise ValueError(f"{version}: {name} changed at 0x{pc:08X}: {row}")
    journal = instruction_index[f"0x{spec['journal_ldr']:08X}"]
    if journal.get("literal_value") != f"0x{SCRATCH_FLASH:08X}":
        raise ValueError(f"{version}: internal journal literal mismatch")
    commit = instruction_index[f"0x{spec['journal_commit_ldr']:08X}"]
    if commit.get("literal_value") != f"0x{SCRATCH_FLASH:08X}":
        raise ValueError(f"{version}: commit scratch literal mismatch")
    backup = instruction_index[f"0x{spec['nor_backup_mov']:08X}"]
    if backup["mnemonic"] != "mov.w" or "0x1fe000" not in backup["operands"]:
        raise ValueError(f"{version}: NOR backup offset changed")
    unit = instruction_index[f"0x{spec['unit_mov']:08X}"]
    if unit["mnemonic"] != "mov.w" or "#0x1000" not in unit["operands"]:
        raise ValueError(f"{version}: 4KiB data unit changed")
    targets = [spec[k] for k in ("spi_read", "spi_write", "spi_erase", "spi_erase_absolute",
                                "flash_erase", "flash_write")]
    calls = find_calls(payload, targets)
    for name in ("flash_erase_call", "nor_read_call", "nor_erase_backup_call",
                 "nor_backup_write_call", "flash_mark_call", "nor_erase_target_call",
                 "nor_target_write_call", "flash_commit_call"):
        pc, _, operand = checks[name]
        target = int(operand.lstrip("#"), 16)
        if f"0x{pc:08X}" not in {r["call_pc"] for r in calls[f"0x{target:08X}"]}:
            raise ValueError(f"{version}: missing actual BL instruction {name}")
    # Cross-check the SPI3-compatible base in bounded hardware setup.
    spi_base_windows = {
        "v1": (0x08003088, 0x080030B8),
        "v2": (0x08006B94, 0x08006BC4),
    }
    start, end = spi_base_windows[version]
    setup = inspect_window(payload, start, end)
    if not any(r.get("literal_value") == "0x40003C00" for r in setup):
        raise ValueError(f"{version}: SPI3-compatible peripheral literal changed")
    return {
        "journal_entry": f"0x{spec['journal']:08X}",
        "programming_unit_bytes": NOR_UNIT,
        "internal_flash_journal_candidate": f"0x{SCRATCH_FLASH:08X}",
        "external_nor_backup_offset": f"0x{NOR_BACKUP_OFFSET:08X}",
        "staging_sram": f"0x{spec['sram_addr']:08X}",
        "verified_sites": {k: f"0x{v[0]:08X}" for k, v in checks.items()},
        "spi_register_base_compatible_with_spi3": "0x40003C00",
        "nor_opcodes": {
            "read": "0x03", "page_program": "0x02",
            "erase_4k": "0x20", "read_status": "0x05", "write_enable": "0x06",
        },
        "notes": "Static application code shows 24-bit SPI NOR commands and address arguments; not physical bus capture",
    }


def analyze(v1: bytes, v2: bytes) -> dict:
    versions = {v: verify_one(p, v) for v, p in (("v1", v1), ("v2", v2))}
    return {
        "mode": "offline stock firmware machine code",
        "versions": versions,
        "cross_version": {
            "both_access_0x0807F800_flash_journal": True,
            "both_use_external_nor_offset_0x001FE000": True,
            "both_use_4096_byte_transfer_unit": True,
            "different_staging_sram": True,
        },
        "physical_storage_inference": {
            "external_nor_spi_access": "Strong: explicit 0x03/0x02/0x20/0x05/0x06 opcodes plus SPI peripheral",
            "nor_backup_offset_near_end_of_2MiB": True,
            "actual_silicon_flash_capacity_verified": False,
            "external_nor_xip_verified": False,
            "erase_sector_geometry_on_real_chip_verified": False,
            "crash_recovery_behavior_verified": False,
        },
        "limits": [
            "These are application data persistence paths, not a recovered Bootloader.",
            "NOR backup sector is referenced but its full allocation and recovery mechanism are not proven.",
            "SPI3 is an STM32F1-compatible peripheral label, not XL9951Q vendor proof.",
            "No radio, serial connection, SWD, erase or Flash write was used.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    images = {name: decoded_payload(Path(spec["path"]).read_bytes())
              for name, spec in MAP.items()}
    result = analyze(images["v1"], images["v2"])
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        for version, info in result["versions"].items():
            print(version, info["journal_entry"], info["nor_opcodes"],
                  info["external_nor_backup_offset"])
        print("Silicon Flash capacity/bootloader details: UNCONFIRMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
