#!/usr/bin/env python3
"""Verify stock UV-5RH Pro keypad, FD6818 and RDA5807M GPIO bus evidence.

Read-only original Thumb instruction/literal cross-version checks and actual
ARM scatterload keymap bytes. No actual hardware or physical-pad verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window, BASE
from v2_scatterload_decode import decompress_region
from v2_scatterload_regions import REGION_START

SRAM_BASE = 0x20000000
KEY_ARRAY_ADDRESS = 0x200000A6
KEY_COUNT = 22
KEY_STRIDE = 4
EXPECTED_KEYMAP = (
    0x01A8, 0x00E1, 0x0170, 0x0168, 0x0162, 0x0161,
    0x01B0, 0x01A4, 0x01A2, 0x01A1, 0x00F0, 0x00E8,
    0x00E4, 0x00E2, 0x0164, 0x01D0, 0x01C2, 0x01C8,
    0x01C4, 0x0160, 0x01A0, 0x00F1,
)
V1_RELOCATIONS = {"keypad": 0x5894, "rda5807m": 0xC074, "fd6818": 0x3B14}

# V2 original Thumb PC, exact mnemonic, significant operand fragment, literal.
# For all records in this table, corresponding V1 instructions are verified
# at (pc - the group-specific relocation), not inferred from addresses alone.
STOCK_SITES = {
    "keypad": (
        (0x080109AE, "ldr", "r4, [pc", 0x40011000),
        (0x080109BA, "ldr", "r1, [pc", 0x88333330),
        (0x080109C2, "orr", "r0, r0, #0x3e", None),
        (0x080109E0, "and", "r5, r0, #0x3c0", None),
        (0x080109EE, "ldr", "r1, [pc", 0x33888880),
        (0x080109F6, "orr", "r0, r0, #0xc0", None),
        (0x08010A06, "orr", "r0, r0, #0x33", None),
        (0x08010A0E, "orr", "r0, r0, #0x300", None),
        (0x08010A1C, "and", "r0, r0, #0x3e", None),
        (0x08010A22, "lsrs", "r1, r5, #1", None),
        (0x08010A24, "ldr", "r0, [pc", 0x20000096),
        (0x08010A2A, "ldrh.w", "r2, [r0, r5, lsl #2]", None),
        (0x08010A3A, "cmp", "r5, #0x16", None),
        (0x08010A42, "movs", "r6, #0xff", None),
    ),
    "rda5807m": (
        (0x08030DF8, "movs", "r0, #0x22", None),
        (0x08030DFA, "bl", "0x8030f34", None),
        (0x08030E18, "movs", "r0, #0x23", None),
        (0x08030E26, "bl", "0x8030eb8", None),
        (0x08030E32, "bl", "0x8030eb8", None),
        (0x08030E4E, "movs", "r0, #0x22", None),
        (0x08030E6A, "lsrs", "r0, r4, #8", None),
        (0x08030E78, "uxtb", "r0, r4", None),
        (0x08030F38, "ldr", "r6, [pc", 0x40011000),
        (0x08030F4A, "ldr", "r0, [pc", 0x40010804),
        (0x08030F62, "ldr", "r7, [pc", 0x40010804),
        (0x08030F90, "ldr", "r0, [r6, #0x10]", None),
        (0x08030F92, "orr", "r0, r0, #0x4000", None),
        (0x08030F0C, "ldr", "r0, [r7]", None),
    ),
    "fd6818": (
        (0x08005E4C, "movs", "r0, #0xe2", None),
        (0x08005E64, "movs", "r0, #0xe3", None),
        (0x08005E96, "movs", "r0, #0xe2", None),
        (0x08005ECC, "movs", "r0, #0x39", None),
        (0x08005ED8, "movs", "r0, #0x38", None),
        (0x08005F04, "movw", "r1, #0xc3fa", None),
        (0x08005F08, "movs", "r0, #0x30", None),
        (0x08005F18, "ldr", "r6, [pc", 0x40010814),
        (0x08005F2A, "ldr", "r7, [pc", 0x40011000),
        (0x08005F94, "ldr", "r6, [pc", 0x40011000),
        (0x08005FA2, "orr", "r0, r0, #0x30000000", None),
        (0x08005FAE, "ldr", "r7, [pc", 0x40010814),
        (0x08005FB2, "orr", "r0, r0, #0x4000", None),
        (0x08005FCA, "orr", "r0, r0, #0x8000", None),
        (0x08005FD4, "orr", "r0, r0, #0x8000", None),
    ),
}


def original_v2_key_table(payload: bytes) -> dict:
    addr = REGION_START - BASE
    source, destination, length, handler = struct.unpack_from("<IIII", payload, addr)
    following_source = struct.unpack_from("<I", payload, addr + 16)[0]
    if destination != SRAM_BASE or length != 7084 or (handler & ~1) != 0x08001F06:
        raise ValueError("original V2 scatterload descriptor changed")
    if not (BASE <= source < following_source <= BASE + len(payload)):
        raise ValueError("V2 compressed SRAM source outside package")
    image, consumed = decompress_region(payload[source-BASE:following_source-BASE], length)
    begin = KEY_ARRAY_ADDRESS - SRAM_BASE
    entries = [struct.unpack_from("<I", image, begin + index * KEY_STRIDE)[0]
               for index in range(KEY_COUNT)]
    values = tuple(x & 0xFFFF for x in entries)
    if values != EXPECTED_KEYMAP or any((x >> 16) != 3 for x in entries):
        raise ValueError("original 22-entry keypad mapping changed")
    return {
        "sram_address": f"0x{KEY_ARRAY_ADDRESS:08X}",
        "entry_count": len(entries),
        "entry_stride_bytes": KEY_STRIDE,
        "raw_words": [f"0x{x:08X}" for x in entries],
        "normalized_codes": [f"0x{x:04X}" for x in values],
        "compressed_image_sha256": hashlib.sha256(image).hexdigest(),
        "compressed_bytes_consumed": consumed,
        "physical_key_labels_known": False,
    }


def check_site(payload: bytes, address: int, mnemonic: str, operand: str,
               literal: int | None = None) -> None:
    rows = inspect_window(payload, address, address + 4)
    row = rows[0] if rows else None
    if (row is None or row["pc"] != f"0x{address:08X}"
            or row["mnemonic"] != mnemonic or operand not in row["operands"]):
        raise ValueError(f"stock instruction mismatch 0x{address:08X}: {row}")
    if literal is not None and row.get("literal_value") != f"0x{literal:08X}":
        raise ValueError(f"stock literal mismatch 0x{address:08X}: {row}")


def verify_version(payload: bytes, version: str) -> dict:
    counts = {}
    for subsystem, entries in STOCK_SITES.items():
        relocation = V1_RELOCATIONS[subsystem] if version == "v1" else 0
        for pc, mnemonic, operand, literal in entries:
            # Direct BL target addresses differ after firmware relocation,
            # and are independently pinned by a V1-specific control graph.
            if version == "v1" and mnemonic == "bl":
                continue
            check_site(payload, pc - relocation, mnemonic, operand, literal)
        counts[subsystem] = len(entries) - (
            sum(1 for _, name, _, _ in entries if name == "bl")
            if version == "v1" else 0
        )
    return {"matched_sites": counts, "total": sum(counts.values())}


def analyze(v1: bytes, v2: bytes) -> dict:
    return {
        "source": "stock original decrypted application images",
        "v1_instruction_check": verify_version(v1, "v1"),
        "v2_instruction_check": verify_version(v2, "v2"),
        "keypad": original_v2_key_table(v2),
        "interface_candidates": {
            "fd6818": {
                "transport": "bit-banged 2-wire indexed register access",
                "i2c_7bit": "0x71", "write_byte": "0xE2", "read_byte": "0xE3",
                "gpio_software_scl": "PA14", "gpio_software_sda": "PC15",
                "frequency_raw_upper_reg": "0x39", "frequency_raw_lower_reg": "0x38",
                "physical_qfn64_pad_mapping_proved": False,
            },
            "rda5807m": {
                "transport": "bit-banged 2-wire indexed register access",
                "i2c_7bit": "0x11", "write_byte": "0x22", "read_byte": "0x23",
                "gpio_software_scl": "PC14", "gpio_software_sda": "PA11",
                "physical_qfn64_pad_mapping_proved": False,
            },
            "keypad": {
                "input_port": "GPIOC",
                "phase_one_idr_mask": "0x03C0",
                "phase_two_idr_mask": "0x003E",
                "normalized_expression": "((phase_one & 0x03C0) | (phase_two & 0x003E)) >> 1",
                "key_index_range": "0..21",
                "unknown_key_code": "0xFF",
                "actual_button_labels_proved": False,
            },
        },
        "limits": [
            "MCU silicon vendor and physical QFN64 pin numbers not verified.",
            "The FD6818/RDA5807 device association combines OEM code with chip markings and public guides, not direct I2C bus captures.",
            "No FD6818 frequency-in-Hz scaling or full RX/TX/PA calibration table is asserted.",
            "No LCD controller identity, complete UI screen protocol or full physical board schematic is established.",
            "The executable independent no_std modules are transport contracts, not a board-clock-accurate flashable firmware.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    images = {
        version: decoded_payload(Path(f"firmware/BF_5RH_501_{edition}.dat").read_bytes())
        for version, edition in (("v1", "v1_1_04"), ("v2", "v2_0_9"))
    }
    report = analyze(images["v1"], images["v2"])
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("V1", report["v1_instruction_check"])
        print("V2", report["v2_instruction_check"])
        print("KEY_TABLE", report["keypad"]["normalized_codes"])
        print("INTERFACES", report["interface_candidates"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
