#!/usr/bin/env python3
"""Instruction-verified UV-5RH Pro boot ROM dispatch, without reading device UID.

A named I2S2EXT address may be used for undocumented silicon control here:
do not transplant the original register writes into any new HAL.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from compare_sdk_windows import compare_window
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window

UID_LSW_ADDRESS = 0x1FFFF7E8
BOOTROM_TABLE = 0x1FFFD000
ROM_ENTRY_OFFSET = 0x0C
SPECIAL_MMIO_BASE = 0x40016C00
UNDOCUMENTED_FLASH_MMIO = 0x4002228C
COMPARISONS = {0x1A: 0x080012A8, 0x1B: 0x080012C2, 0x1C: 0x080012DC}
CALLS = {0x1A: 0x080012BC, 0x1B: 0x080012D6, 0x1C: 0x08001304}


def instruction(payload: bytes, pc: int) -> dict:
    row = inspect_window(payload, pc, pc + 4)
    if not row or row[0]["pc"] != f"0x{pc:08X}":
        raise ValueError(f"missing Thumb instruction at {pc:#x}")
    return row[0]


def require(payload: bytes, pc: int, mnemonic: str, operands: str,
            literal: int | None = None) -> dict:
    x = instruction(payload, pc)
    if x["mnemonic"] != mnemonic or x["operands"] != operands:
        raise ValueError(f"stock startup instruction mismatch at 0x{pc:08X}: {x}")
    if literal is not None and x.get("literal_value") != f"0x{literal:08X}":
        raise ValueError(f"stock startup literal mismatch at 0x{pc:08X}: {x}")
    return {"pc": x["pc"], "mnemonic": mnemonic, "operands": operands, **(
        {"literal": f"0x{literal:08X}"} if literal is not None else {}
    )}


def choose_path(uid_low_word_msb: int) -> dict:
    """Model the _decision_ only; no hardware read or instructions executed."""
    if not 0 <= uid_low_word_msb <= 255:
        raise ValueError("UID low-word most-significant byte must be 0..255")
    if uid_low_word_msb in (0x1A, 0x1B):
        behavior = "ROM offset 0x0C call; (r0,r1,r2,r3)=(r4,r5,0,1)"
    elif uid_low_word_msb == 0x1C:
        behavior = "temporarily adjust CRM_CFG then ROM offset 0x0C call; (r0,r1,r2)=(r5,0,1)"
    else:
        behavior = "skip the ROM call and continue with shared register restoration"
    return {
        "uid_low_word_msb": f"0x{uid_low_word_msb:02X}",
        "dispatch": behavior,
        "series_id_assessment": (
            "This is UID0[31:24], not AT32 F403A/407 Series ID UID[95:88]. "
            "LuatOS AIR32F103 documents some UID0 patterns with high byte 0x1A; "
            "neither the actual device UID nor 0x1B/0x1C models is established."
        ),
    }


def analyze(v2: bytes, v1: bytes | None = None) -> dict:
    verified = [
        require(v2, 0x080012A2, "ldr", "r0, [pc, #0x15c]", UID_LSW_ADDRESS),
        require(v2, 0x080012A4, "ldr", "r6, [r0]"),
        require(v2, 0x080012A6, "movs", "r0, #0x1a"),
        require(v2, 0x080012A8, "cmp.w", "r0, r6, lsr #24"),
        require(v2, 0x080012C0, "movs", "r0, #0x1b"),
        require(v2, 0x080012C2, "cmp.w", "r0, r6, lsr #24"),
        require(v2, 0x080012DA, "movs", "r0, #0x1c"),
        require(v2, 0x080012DC, "cmp.w", "r0, r6, lsr #24"),
        require(v2, 0x080012AE, "ldr", "r0, [pc, #0x154]", BOOTROM_TABLE),
        require(v2, 0x080012B6, "ldr.w", "ip, [r0, #0xc]"),
        require(v2, 0x080012BC, "blx", "ip"),
        require(v2, 0x080012D0, "ldr.w", "ip, [r0, #0xc]"),
        require(v2, 0x080012D6, "blx", "ip"),
        require(v2, 0x080012FA, "ldr", "r0, [pc, #0x108]", BOOTROM_TABLE),
        require(v2, 0x08001300, "ldr", "r3, [r0, #0xc]"),
        require(v2, 0x08001304, "blx", "r3"),
        require(v2, 0x08001288, "ldr", "r0, [pc, #0x160]", SPECIAL_MMIO_BASE),
        require(v2, 0x0800128C, "ldr.w", "r8, [r0]"),
        require(v2, 0x08001296, "str", "r0, [r1]"),
        require(v2, 0x08001298, "mov.w", "r0, #-0x5a5a5a5b"),
        require(v2, 0x0800129E, "str.w", "r0, [r1, #0x28c]"),
        require(v2, 0x08001318, "ldr", "r0, [pc, #0xd0]", SPECIAL_MMIO_BASE),
        require(v2, 0x0800131C, "str.w", "r8, [r0]"),
        require(v2, 0x08001334, "mov.w", "r0, #0x5a5a5a5a"),
        require(v2, 0x08001338, "ldr", "r1, [pc, #0xd0]", UNDOCUMENTED_FLASH_MMIO),
        require(v2, 0x0800133A, "str", "r0, [r1]"),
        require(v2, 0x08032364, "mov.w", "r4, #0x10000"),
        require(v2, 0x0803237E, "movs", "r2, #1"),
        require(v2, 0x08032380, "mov.w", "r1, #0x380000"),
        require(v2, 0x08032386, "bl", "#0x8001260"),
    ]
    report = {
        "image": "UV-5RH Pro V2.0.09 original decoded Thumb",
        "uid_register_read": f"0x{UID_LSW_ADDRESS:08X}",
        "read_field": "UID0[31:24] at 0x1FFFF7E8; distinct from AT32 UID[95:88] Series ID",
        "rom_vector_table": f"0x{BOOTROM_TABLE:08X}",
        "rom_callback_offset": ROM_ENTRY_OFFSET,
        "direct_caller_pc": "0x08032386",
        "caller_argument_register_values": {
            "r0": "0x00010000", "r1": "0x00380000", "r2": "0x00000001"
        },
        "special_flash_write_pattern": {
            "address": "0x4002228C",
            "before_uid_dispatch": "0xA5A5A5A5",
            "after_uid_dispatch": "0x5A5A5A5A",
            "meaning": "unknown; not listed as a standard register in examined AT32F403A/407 FLASH table",
        },
        "recognized_decision_bytes": [f"0x{v:02X}" for v in COMPARISONS],
        "branch_models": [choose_path(v) for v in (0x1A, 0x1B, 0x1C, 0x55)],
        "magic_register_addresses": [
            f"0x{SPECIAL_MMIO_BASE:08X}",
            f"0x{SPECIAL_MMIO_BASE+0x18:08X}",
            f"0x{UNDOCUMENTED_FLASH_MMIO:08X}",
        ],
        "verified_instructions": verified,
        "physical_mcu_identity": "unconfirmed",
        "limits": [
            "Decoding proves only static firmware behavior, not which branch the user's MCU executes.",
            "No physical UID bits, unique identifiers or ROM memory were read.",
            "0x40016C00 is documented as I2S2EXT on AT32F403A/407, yet the "
            "observed repeated magic writes suggest an undocumented mode/alias; "
            "do not assign ordinary I2S semantics to this boot sequence.",
            "0x4002228C is outside published AT32F403A/407 FLASH named offsets "
            "in the consulted manual; vendor and actual register meaning are unknown.",
        ],
    }
    if v1 is not None:
        delta = compare_window(v1, v2, 0x08001280, 0x08001280, 0xD8)
        report["v1_v2_window_comparison"] = {
            "start_pc": "0x08001280",
            "length": delta["size_bytes"],
            "byte_for_byte_identical": delta["exact_bytes"],
            "matching_bytes": delta["matching_bytes"],
        }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("v2", type=Path)
    parser.add_argument("--v1", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    payload = decoded_payload(args.v2.read_bytes())
    other = decoded_payload(args.v1.read_bytes()) if args.v1 else None
    report = analyze(payload, other)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("UID low-word byte comparisons:", report["recognized_decision_bytes"])
        print("Boot ROM callback: 0x1FFFD000 + 0x0C")
        print("Special MMIO:", report["magic_register_addresses"])
        print("Verified source instructions:", len(report["verified_instructions"]))
        if other is not None:
            print("V1/V2 216-byte identity:", report["v1_v2_window_comparison"])
        for item in report["branch_models"]:
            print(item["uid_low_word_msb"], item["dispatch"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
