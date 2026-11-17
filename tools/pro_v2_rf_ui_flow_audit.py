#!/usr/bin/env python3
"""Read-only OEM Pro V2 RF tuning and keyboard event flow verification.

Checks exact original Thumb instructions from the archived V2.0.09 package.
Does not infer an Hz-to-PLL conversion or assign real panel legends.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls
from pro_v2_board_io_audit import verify_version

V2_FILE = Path("firmware/BF_5RH_501_v2_0_9.dat")
V1_FILE = Path("firmware/BF_5RH_501_v1_1_04.dat")
BASE = 0x08001000

# V2.0.09 machine-code address, mnemonic, distinguishing operand and optional
# literal-pool value. No part of this table is a GPIO physical pad inference.
SITES = {
    "tuning_table": (
        (0x0800DDB8, "ldr", "r0, [pc", 0x20000072),
        (0x0800DDBE, "ldrb", "r1, [r1, #1]", None),
        (0x0800DDC0, "ldrb", "r0, [r0, r1]", None),
        (0x0800DDC2, "ldr", "r1, [pc", 0x2000246C),
        (0x0800DDC4, "ldr.w", "r0, [r1, r0, lsl #2]", None),
        (0x0800DDC8, "bx", "lr", None),
    ),
    "runtime_tune": (
        (0x0800AFE4, "push", "{r3, r4, r5, r6, r7, lr}", None),
        (0x0800AFEA, "mov", "r4, r0", None),
        (0x0800AFEC, "bl", "#0x800ddb8", None),
        (0x0800AFF0, "add", "r0, r4", None),
        (0x0800AFF2, "bl", "#0x8005ec6", None),
        (0x0800AFF6, "ldr", "r4, [pc", 0x20001B84),
        (0x0800B000, "ldrh", "r0, [r4, #0xa]", None),
        (0x0800B006, "cbz", "r7, #0x800b020", None),
    ),
    "tuning_registers": (
        (0x08005EC6, "push", "{r4, lr}", None),
        (0x08005ECA, "lsrs", "r1, r0, #0x10", None),
        (0x08005ECC, "movs", "r0, #0x39", None),
        (0x08005ECE, "bl", "#0x8005e8c", None),
        (0x08005ED2, "uxth", "r1, r4", None),
        (0x08005ED8, "movs", "r0, #0x38", None),
        (0x08005EDA, "b.w", "#0x8005e8c", None),
    ),
    "rf_setup": (
        (0x0800A428, "push.w", "{r3, r4, r5, r6, r7, r8, sb, sl, fp, lr}", None),
        (0x0800A432, "mov.w", "r1, #0x300", None),
        (0x0800A436, "movs", "r0, #0x51", None),
        (0x0800A438, "bl", "#0x8005e8c", None),
        (0x0800A43E, "bl", "#0x8005ec6", None),
        (0x0800A442, "ldr.w", "sl, [pc", 0x20001B84),
        (0x0800A446, "movw", "r0, #0xfdf0", None),
        (0x0800A44C, "ldrh.w", "r1, [sl, #0xa]", None),
        (0x0800A450, "ands", "r1, r0", None),
        (0x0800A452, "movw", "r0, #0x20f", None),
        (0x0800A456, "orrs", "r1, r0", None),
        (0x0800A45C, "movs", "r0, #0x37", None),
        (0x0800A45E, "bl", "#0x8005e8c", None),
        (0x0800A462, "movs", "r1, #0", None),
        (0x0800A464, "movs", "r0, #0x30", None),
        (0x0800A466, "bl", "#0x8005e8c", None),
        (0x0800A46A, "movw", "r1, #0xbff1", None),
        (0x0800A46E, "movs", "r0, #0x30", None),
        (0x0800A470, "bl", "#0x8005e8c", None),
        (0x0800A474, "mov.w", "r0, #0x190", None),
        (0x0800A478, "bl", "#0x8006800", None),
    ),
    "keypad_events": (
        (0x08010AB6, "bl", "#0x8010998", None),
        (0x08010ABA, "mov", "r4, r0", None),
        (0x08010AD4, "cmp", "r4, #0x13", None),
        (0x08010AD8, "cmp", "r4, #0x14", None),
        (0x08010AF6, "cmp", "r4, #0xf", None),
        (0x08010AEC, "cmp", "r4, #0xff", None),
        (0x08010B3A, "cmp", "r4, #0xa", None),
        (0x08010B46, "cmp", "r4, #0x13", None),
        (0x08010B4A, "cmp", "r4, #0x14", None),
    ),
    "rf_key_scan": (
        (0x0800B0D8, "bl", "#0x8010998", None),
        (0x0800B0DC, "cmp", "r0, #0xd", None),
        (0x0800B0F0, "bl", "#0x8010998", None),
        (0x0800B0F4, "cmp", "r0, #0xd", None),
    ),
}


def verify_sites(payload: bytes) -> dict:
    result = {}
    for label, checks in SITES.items():
        for pc, mnemonic, operand, literal in checks:
            rows = inspect_window(payload, pc, pc + 4)
            row = rows[0] if rows else None
            if (row is None or row["pc"] != f"0x{pc:08X}"
                    or row["mnemonic"] != mnemonic
                    or operand not in row["operands"]):
                raise ValueError(f"mismatched OEM Thumb at 0x{pc:08X}: {row}")
            if literal is not None and row.get("literal_value") != f"0x{literal:08X}":
                raise ValueError(f"mismatched OEM literal at 0x{pc:08X}")
        result[label] = len(checks)
    return result


def original_r37_setup_word(cached_value: int) -> int:
    """Copy only the two directly verified OEM bitfield instructions."""
    if not 0 <= cached_value <= 0xFFFF:
        raise ValueError("cached reg37 must fit a 16-bit word")
    return ((cached_value & 0xFDF0) | 0x020F) & 0xFFFF


def original_tuning_word(table_value: int, correction_word: int) -> int:
    """The OEM runtime path performs 32-bit ADD, not a verified Hz formula."""
    if not (0 <= table_value <= 0xFFFFFFFF and
            0 <= correction_word <= 0xFFFFFFFF):
        raise ValueError("OEM raw tuning words must be 32 bits")
    return (table_value + correction_word) & 0xFFFFFFFF


def analyze(v2: bytes, v1: bytes) -> dict:
    sites = verify_sites(v2)
    # Existing independent V1/V2 audit verifies the relocated FD6818
    # frequency-register pair. New tuning-table/control sites are V2 only.
    v1_verified = verify_version(v1, "v1")
    targets = [0x0800DDB8, 0x08005EC6, 0x08010998]
    refs = find_calls(v2, targets)
    expected = {
        "0x0800DDB8": "0x0800AFEC",
        "0x08005EC6": "0x0800AFF2",
        "0x08010998": "0x08010AB6",
    }
    for key, pc in expected.items():
        if pc not in {r["call_pc"] for r in refs[key]}:
            raise ValueError(f"direct stock call changed: {pc} -> {key}")
    return {
        "scope": "V2 original code backed; V1 crosscheck limited to validated FD6818 driver",
        "verified_v2_thumb_sites": sites,
        "verified_v1_existing_board_sites": v1_verified["matched_sites"],
        "tuning_table": {
            "base_sram": "0x2000246C",
            "lookup_entry": "0x0800DDB8",
            "selection": "indexed 32-bit raw word, index from SRAM mode bytes",
            "raw_word_correction": "32-bit wraparound ADD at 0x0800AFF0",
            "frequency_hz_to_pll_formula_known": False,
        },
        "fd6818": {
            "tune_entry": "0x08005EC6",
            "frequency_register_high": "0x39",
            "frequency_register_low": "0x38",
            "setup_prefix": [
                "reg 0x51 <- 0x0300",
                "reg 0x39 <- raw_tune[31:16]",
                "reg 0x38 <- raw_tune[15:0]",
                "reg 0x37 <- (cached_reg37 & 0xFDF0) | 0x020F",
                "reg 0x30 <- 0x0000",
                "reg 0x30 <- 0xBFF1",
                "delay helper called with raw 0x0190 (unit unknown)",
            ],
            "ptt_pa_complete_hardware_sequence_proved": False,
        },
        "keypad": {
            "scanned_index_0x13_and_0x14_in_ui_event": True,
            "scanned_index_0x0d_in_rf_subroutine": True,
            "physical_legends": "unknown; no key identity asserted",
            "full_menu_rendering_proved": False,
        },
        "limits": [
            "No physical pin/pad, RF TX status, frequency calibration or live chip ID verified.",
            "Only the confirmed setup prefix is reconstructed; later branches remain unverified.",
            "Function addresses, xrefs and initialization sequence are software static evidence.",
        ],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    v2 = decoded_payload(V2_FILE.read_bytes())
    v1 = decoded_payload(V1_FILE.read_bytes())
    report = analyze(v2, v1)
    if a.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("OEM V2 RF/UI:", report["verified_v2_thumb_sites"])
        print("tune:", report["tuning_table"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
