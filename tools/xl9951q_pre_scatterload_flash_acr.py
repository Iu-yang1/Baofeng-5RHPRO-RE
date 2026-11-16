#!/usr/bin/env python3
"""Audit the application-visible Flash/RCC operations BEFORE ARM scatterload.

V1/V2 reset veneers call RCC/Flash-clock setup, then ARM scatterload.
This script validates original Thumb instructions and literal-pool targets.
It does NOT read silicon, assert exhaustive ROM behavior, or infer external XIP.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from compare_sdk_windows import compare_window
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from v2_pll_runtime_order import V1, V2, verify_reset_to_main

FLASH_BASE = 0x40022000
RCC_BASE = 0x40021000
VTOR = 0xE000ED08
ROM_PLL_UNLOCK = 0x4002228C
CLOCK_HELPER_BYTES = 0xA8
CLOCK_CODE_BYTES = 0xA0

VERSIONS = {
    "v1": {"clock": 0x08025B80, "reset_clock_wrapper": 0x080262A8,
           "clock_bl": 0x080262DA, "reset": V1},
    "v2": {"clock": 0x08031BF4, "reset_clock_wrapper": 0x080323DC,
           "clock_bl": 0x0803240E, "reset": V2},
}


def _row(rows: list[dict], pc: int, mnemonic: str,
         operands: str | None = None, literal: int | None = None) -> dict:
    match = next((x for x in rows if x["pc"] == f"0x{pc:08X}"), None)
    if match is None or match["mnemonic"].split(".")[0] != mnemonic:
        raise ValueError(f"original instruction changed: 0x{pc:08X} {mnemonic}")
    if operands is not None and match["operands"] != operands:
        raise ValueError(f"original operands changed at 0x{pc:08X}: {match}")
    if literal is not None and match.get("literal_value") != f"0x{literal:08X}":
        raise ValueError(f"original target literal changed at 0x{pc:08X}: {match}")
    return match


def inspect_clock_init(payload: bytes, base: int) -> dict:
    """V1/V2 share exactly 160 Thumb bytes + two 32-bit peripheral literals."""
    rows = inspect_window(payload, base, base + CLOCK_CODE_BYTES)
    _row(rows, base + 0x04, "ldr", "r0, [pc, #0x98]", RCC_BASE)
    flash_load = _row(rows, base + 0x38, "ldr", "r1, [pc, #0x68]", FLASH_BASE)
    effects = []
    for offset, mnemonic, operands in (
        (0x3C, "orr", "r2, r2, #0x10"),
        (0x40, "str", "r2, [r1]"),
        (0x44, "bic", "r2, r2, #3"),
        (0x48, "str", "r2, [r1]"),
        (0x4C, "orr", "r2, r2, #2"),
        (0x50, "str", "r2, [r1]"),
    ):
        ins = _row(rows, base + offset, mnemonic, operands)
        effects.append({"pc": ins["pc"], "operation": f"{mnemonic} {operands}"})
    # In this bounded function, the only memory-based peripheral pointers
    # are 0x40021000 and 0x40022000. Check the complete two-word pool.
    literals = [int.from_bytes(payload[base - 0x08001000 + off:
                                       base - 0x08001000 + off + 4], "little")
                for off in (0xA0, 0xA4)]
    if literals != [RCC_BASE, FLASH_BASE]:
        raise ValueError(f"early clock-function literal pool changed: {literals}")
    if any(x["mnemonic"].split(".")[0] in ("bl", "blx") for x in rows):
        raise ValueError("new direct call in bounded early clock function")
    return {
        "function_pc": f"0x{base:08X}",
        "size_code_and_literals_bytes": CLOCK_HELPER_BYTES,
        "peripheral_literal_targets": [f"0x{x:08X}" for x in literals],
        "flash_acr_pc_relative_load": flash_load,
        "flash_acr_change_sequence": effects,
        "flash_acr_compatible_meaning": {
            "0x10": "enable prefetch bit (STM32F1/AIR32-compatible map)",
            "0x03": "clear latency field before setting 0x02",
            "0x02": "FLASH_ACR latency field becomes 2 wait states",
        },
        "does_not_reference_unlock_register_as_literal": ROM_PLL_UNLOCK not in literals,
        "scope": "exact 160-byte Thumb function and its two literal words only",
    }


def inspect_reset_wrapper(payload: bytes, version: str) -> dict:
    spec = VERSIONS[version]
    base = spec["reset_clock_wrapper"]
    clock = spec["clock"]
    verify_reset_to_main(payload, spec["reset"], version == "v2")
    rows = inspect_window(payload, base, base + 0x40)
    _row(rows, base, "ldr", "r0, [pc, #0x3c]", RCC_BASE)
    _row(rows, base + 0x32, "bl", f"#{clock:#x}")
    _row(rows, base + 0x36, "ldr", "r1, [pc, #0x14]", VTOR)
    _row(rows, base + 0x38, "mov", "r0, #0x8000000")
    _row(rows, base + 0x3C, "str", "r0, [r1]")
    calls = [x for x in rows if x["mnemonic"].split(".")[0] in ("bl", "blx")]
    if len(calls) != 1 or calls[0]["pc"] != f"0x{spec['clock_bl']:08X}":
        raise ValueError("unexpected additional call before startup scatterload")
    return {
        "reset_wrapper_pc": f"0x{base:08X}",
        "clock_helper_bl_site": f"0x{spec['clock_bl']:08X}",
        "calls_in_bounded_reset_wrapper": calls,
        "rcc_base": f"0x{RCC_BASE:08X}",
        "vtor_register": f"0x{VTOR:08X}",
        "vtor_software_write_value": "0x08000000",
        "vtor_observation": "reset wrapper writes VTOR but does not prove vector remap or boot ROM state",
    }


def analyze(v1: bytes, v2: bytes) -> dict:
    compare = compare_window(v1, v2, VERSIONS["v1"]["clock"],
                             VERSIONS["v2"]["clock"], CLOCK_HELPER_BYTES)
    if not compare["exact_bytes"]:
        raise ValueError("original V1/V2 pre-scatterload clock functions differ")
    versions = {}
    for name, payload in (("v1", v1), ("v2", v2)):
        versions[name] = {
            "reset_wrapper": inspect_reset_wrapper(payload, name),
            "early_clock_function": inspect_clock_init(payload, VERSIONS[name]["clock"]),
        }
    return {
        "mode": "offline original firmware instructions, no physical device access",
        "shared_early_clock_function": compare,
        "versions": versions,
        "verified_before_scatterload": [
            "Reset enters original RCC reset/clock wrapper",
            "Clock helper writes 0x40021000 RCC and 0x40022000 FLASH_ACR",
            "FLASH_ACR prefetch and latency configured before scatterload",
            "Reset wrapper writes VTOR 0xE000ED08 with value 0x08000000",
            "Wrapper returns to Reset veneer, then ARM scatterload at 0x08001220",
        ],
        "xip_assessment": {
            "known_early_flash_controller_access": True,
            "confirmed_external_nor_xip_mapper": False,
            "early_acr_is_not_qspi_unlock": True,
            "separate_application_rom_unlock": "0x4002228C (post-scatterload)",
            "assessment": (
                "V1/V2 pre-scatterload code visibly sets FLASH_ACR timing. "
                "No external NOR memory-mapping operation was identified inside "
                "the audited wrapper and clock function; those bounded functions "
                "are not the complete OEM bootloader or mask ROM."
            ),
        },
        "limits": [
            "This audits the specific Reset wrapper and direct clock-helper path, "
            "not all possible interrupts, CPU memory aliases or mask-ROM initialization.",
            "The 0x40022000 Flash access register name and bit meanings assume an "
            "AIR32/STM32F1-compatible register layout; no XL9951Q datasheet exists.",
            "Static code proves writes are encoded, not that hardware accepted them.",
            "Other pre-application code in a bootloader may establish memory mapping.",
            "XL9951Q silicon vendor, die type, Flash capacity, and GT25Q16A role remain unknown.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v1", type=Path, default=Path("firmware/BF_5RH_501_v1_1_04.dat"))
    ap.add_argument("--v2", type=Path, default=Path("firmware/BF_5RH_501_v2_0_9.dat"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    report = analyze(decoded_payload(args.v1.read_bytes()),
                     decoded_payload(args.v2.read_bytes()))
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("Identical 168-byte V1/V2 early clock routine:",
              report["shared_early_clock_function"]["exact_bytes"])
        for name, info in report["versions"].items():
            print(name, info["reset_wrapper"]["clock_helper_bl_site"],
                  info["early_clock_function"]["peripheral_literal_targets"],
                  len(info["early_clock_function"]["flash_acr_change_sequence"]),
                  "Flash ACR sequence instructions")
        print("XIP:", report["xip_assessment"]["assessment"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
