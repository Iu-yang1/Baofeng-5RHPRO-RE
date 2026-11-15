#!/usr/bin/env python3
"""Compare stock Pro V2 instructions with published AIR32F103 SDK fingerprints.

This is an offline *SDK lineage* check, not a silicon identity or ROM execution
test. No hardware access, UID extraction, FLASH writes, or flashable outputs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from mcu_fingerprint import decoded_payload
from v2_bootrom_dispatch import analyze as analyze_dispatch
from v2_clock_tree_model import extract_config, simulate_configuration

FLASH_BASE = 0x08001000

# Literal pool belonging to the original 0x08001260 helper. Evidence is checked
# against original decoded bytes, never inferred from an arbitrary raw search.
ROM_HELPER_LITERALS = {
    0x080013E4: 0x400210F0,  # gate SYSCFG
    0x080013E8: 0xA7D93A86,  # unlock 1
    0x080013EC: 0x40016C00,  # special register key port
    0x080013F0: 0xAB12DFCD,  # unlock 2
    0x080013F4: 0xCDED3526,  # unlock 3
    0x080013F8: 0x200183FF,  # temporary SRAM window setting
    0x080013FC: 0x40022000,  # flash peripheral base
    0x08001400: 0x1FFFF7E8,  # UID low word used as dispatch input
    0x08001404: 0x1FFFD000,  # indirect ROM callback table
    0x0800140C: 0x4002228C,  # QSPI unlock/restore in AIR32 SDK
}

# Values from openLuat's AIR32F10xLib (source links in report below).
SDK_MULTIPLIER_16 = 0x00380000
SDK_PLL_SOURCE_HSE_DIV1 = 0x00010000
SDK_FLASH_DIV_2 = 1
SDK_AHB_APB_PRESCALER = [0, 0, 0, 0, 1, 2, 3, 4, 1, 2, 3, 4, 6, 7, 8, 9]
SDK_ADC_PRESCALER = [2, 4, 6, 8]
SDK_SOURCE = (
    "https://github.com/openLuat/luatos-soc-air32f103/"
    "blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/"
    "Libraries/AIR32F10xLib/src/air32f10x_rcc_ex.c"
)


def literal(payload: bytes, pc: int) -> int:
    offset = pc - FLASH_BASE
    if offset < 0 or offset + 4 > len(payload):
        raise ValueError(f"outside decoded image: 0x{pc:08X}")
    return struct.unpack_from("<I", payload, offset)[0]


def analyze(payload: bytes, v1: bytes | None = None) -> dict:
    dispatch = analyze_dispatch(payload, v1)
    observed = {}
    for pc, expected in ROM_HELPER_LITERALS.items():
        actual = literal(payload, pc)
        if actual != expected:
            raise ValueError(
                f"AIR32 SDK literal mismatch at 0x{pc:08X}: "
                f"got 0x{actual:08X}, expected 0x{expected:08X}"
            )
        observed[f"0x{pc:08X}"] = f"0x{actual:08X}"

    clock = extract_config(payload)
    tables = clock["sram_tables"]
    if tables["clock_prescaler_table_first16"] != SDK_AHB_APB_PRESCALER:
        raise ValueError("AIR32 SDK AHB/APB prescaler table mismatch")
    if tables["adc_prescaler_table_4"] != SDK_ADC_PRESCALER:
        raise ValueError("AIR32 SDK ADC prescaler table mismatch")
    args = dispatch["caller_argument_register_values"]
    if args != {
        "r0": f"0x{SDK_PLL_SOURCE_HSE_DIV1:08X}",
        "r1": f"0x{SDK_MULTIPLIER_16:08X}",
        "r2": f"0x{SDK_FLASH_DIV_2:08X}",
    }:
        raise ValueError("AIR32 SDK PLL call-site parameter mismatch")

    base = simulate_configuration(clock, 0)
    if base["pll_multiplier"] != 6 or base["sysclk_hz"] != 48_000_000:
        raise ValueError("48 MHz reset-clock hypothesis changed")

    return {
        "lineage": "strong match to AIR32F103 SDK implementation, not a chip ID",
        "vendor_sdk_source": SDK_SOURCE,
        "rom_helper_start": "0x08001260",
        "verified_helper_literal_pool": observed,
        "uid_decision_bits": "UID[31:24], not a manufacturer or model ID",
        "rom_callback": "[0x1FFFD000 + 0x0C]",
        "air32_sdk_rom_callback_name": "SysFreq_Set",
        "rom_branch_1a_1b_abi": "(PLL multiplier, Flash divider, 0, 1)",
        "rom_branch_1c_abi": "different argument layout; ROM internals unknown",
        "sdk_prescaler_table_16": tables["clock_prescaler_table_first16"],
        "sdk_adc_prescaler_table_4": tables["adc_prescaler_table_4"],
        "callsite": {
            "rcc_source": "AIR32 RCC_PLLSource_HSE_Div1 (0x00010000)",
            "multiplier": "AIR32 RCC_PLLMul_16 (0x00380000)",
            "flash_divider": "AIR32 FLASH_Div_2 (1)",
            "conditional_target_frequency_hz": 8_000_000 * 16,
            "note": "Compiled-in 8 MHz source; this is a call-site request, "
                    "not proof of actual execution, clock, or crystal.",
        },
        "reset_clock_software_hypothesis_hz": base["sysclk_hz"],
        "flash_size_conflict": (
            "Documented AIR32F103RPT6 has 256 KiB Flash in LQFP64, whereas "
            "the stock V2 scatterload source at 0x08061A54 requires an address "
            "beyond the documented 256 KiB. Do not select this commercial part."
        ),
        "physical_mcu_id": "unconfirmed",
        "limitations": [
            "The exact SDK source may have been reused by compatible or custom-marked silicon.",
            "Flash storage and address aliases require separate evidence.",
            "Neither the masked UID comparison nor helper ROM call determines the package part.",
            "No physical chip, ROM body, Flash size, or clock frequency was read.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("v2", type=Path)
    p.add_argument("--v1", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    result = analyze(
        decoded_payload(args.v2.read_bytes()),
        decoded_payload(args.v1.read_bytes()) if args.v1 else None,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("SDK lineage:", result["lineage"])
        print("ROM callback:", result["rom_callback"])
        print("Matched helper literal words:", len(result["verified_helper_literal_pool"]))
        print("PLL call-site:", result["callsite"])
        print("Documented Flash conflict:", result["flash_size_conflict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
