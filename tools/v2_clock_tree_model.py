#!/usr/bin/env python3
"""Reconstruct the UV-5RH Pro V2 clock tree from verified instruction operands.

Read-only, image-specific reconstruction, NOT measurement of a real oscillator.
The model assumes STM32F1-compatible CRM bit semantics and reset defaults.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM

from mcu_fingerprint import decoded_payload
from v2_scatterload_decode import inspect_tables

BASE = 0x08001000
# Verified V2 addresses. Identical content in another firmware is not assumed.
INSTRUCTIONS = {
    "reset_pll_bits": (0x08032402, "bic"),
    "apb1_div2": (0x08031C50, "orr"),
    "clear_pll_low": (0x08031C58, "bic"),
    "set_pll_source_multiplier": (0x08031C60, "orr"),
    "select_sysclk_clear": (0x08031C76, "bic"),
    "select_sysclk_pll": (0x08031C7E, "orr"),
}
CLOCK_CONSTANTS = {
    "crm_base": 0x08030CC4,
    "hick_hz": 0x08030CC8,
    "half_clock_hz": 0x08030CCC,
    "prescaler_table_in_sram": 0x08030CD0,
    "reset_cfg_mask": 0x08032420,
}
def image_u32(payload: bytes, address: int) -> int:
    offset = address - BASE
    if offset < 0 or offset + 4 > len(payload):
        raise ValueError(f"word outside decoded image: 0x{address:08X}")
    return struct.unpack_from("<I", payload, offset)[0]


def immediate_at(payload: bytes, pc: int, mnemonic_prefix: str) -> int:
    offset = pc - BASE
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    ins = next(decoder.disasm(payload[offset:offset+4], pc, count=1), None)
    if ins is None or not ins.mnemonic.startswith(mnemonic_prefix):
        raise ValueError(f"V2 Thumb instruction mismatch at 0x{pc:08X}")
    operands = [op.imm for op in ins.operands if op.type == ARM_OP_IMM]
    if len(operands) != 1:
        raise ValueError(f"expected one encoded immediate at 0x{pc:08X}")
    return operands[0]


def extract_config(payload: bytes) -> dict:
    actual = {
        name: immediate_at(payload, pc, mnemonic)
        for name, (pc, mnemonic) in INSTRUCTIONS.items()
    }
    const = {name: image_u32(payload, addr) for name, addr in CLOCK_CONSTANTS.items()}
    if const["crm_base"] != 0x40021000:
        raise ValueError("unexpected CRM base; firmware clock model no longer applies")
    if const["half_clock_hz"] * 2 != const["hick_hz"]:
        raise ValueError("clock source constants no longer form an 8/4 MHz pair")
    return {
        "instructions": actual,
        "constants": const,
        "sram_tables": inspect_tables(payload),
    }


def simulate_configuration(config: dict, original_cfg: int = 0) -> dict:
    """Simulate only the CFGR operations seen in reset+clock routines.

    The RCC SWS (bits 3:2) is hardware-updated; the resulting model assumes
    the firmware's wait-for-switch loop actually completed successfully.
    """
    ins = config["instructions"]
    cfg = original_cfg & config["constants"]["reset_cfg_mask"]
    cfg &= ~ins["reset_pll_bits"]
    cfg |= ins["apb1_div2"]
    cfg &= ~ins["clear_pll_low"]
    cfg |= ins["set_pll_source_multiplier"]
    cfg &= ~ins["select_sysclk_clear"]
    cfg |= ins["select_sysclk_pll"]
    pll_source_hext = bool(cfg & (1 << 16))
    pll_input_div2 = bool(cfg & (1 << 17))
    extended_multiplier = bool(cfg & (1 << 28))
    low_multiplier = (cfg & 0x003C0000) >> 18
    multiplier = (low_multiplier | 0x10) + 1 if extended_multiplier else low_multiplier + 2
    source = config["constants"]["hick_hz"]
    if not pll_source_hext:
        source = config["constants"]["half_clock_hz"]
    elif pll_input_div2:
        source //= 2
    sysclk = source * multiplier
    ahb_field = (cfg >> 4) & 0xF
    apb1_field = (cfg >> 8) & 7
    apb2_field = (cfg >> 11) & 7
    lookup = config["sram_tables"]["clock_prescaler_table_first16"]
    adc_divisors = config["sram_tables"]["adc_prescaler_table_4"]
    hclk = sysclk >> lookup[ahb_field]
    pclk1 = hclk >> lookup[apb1_field]
    pclk2 = hclk >> lookup[apb2_field]
    adc_div = adc_divisors[(cfg >> 14) & 3]
    adcclk = pclk2 // adc_div
    return {
        "cfg_register_model": f"0x{cfg:08X}",
        "cfg_initial": f"0x{original_cfg:08X}",
        "pll_input_hz": source,
        "pll_low_multiplier_code": low_multiplier,
        "pll_extended_bit28": extended_multiplier,
        "pll_multiplier": multiplier,
        "pll_input_from_hext": pll_source_hext,
        "hext_div2": pll_input_div2,
        "sclk_select_write": cfg & 3,
        "sysclk_hz": sysclk,
        "hclk_hz": hclk,
        "pclk1_hz": pclk1,
        "pclk2_hz": pclk2,
        "adcclk_hz": adcclk,
        "adc_divisor": adc_div,
        "apb1_field": apb1_field,
        "apb2_field": apb2_field,
        "apb1_timer_clock_hz": pclk1 * (2 if apb1_field >= 4 else 1),
        "apb2_timer_clock_hz": pclk2 * (2 if apb2_field >= 4 else 1),
    }


def analyze(payload: bytes) -> dict:
    config = extract_config(payload)
    normal = simulate_configuration(config, 0)
    bit28_preexisting = simulate_configuration(config, 1 << 28)
    return {
        "source": "UV-5RH Pro stock firmware, XOR-decoded, not executed",
        "firmware_load_base_assumption": f"0x{BASE:08X}",
        "actual_immediates": {
            key: f"0x{value:08X}" for key, value in config["instructions"].items()
        },
        "original_literal_words": {
            key: f"0x{value:08X}" for key, value in config["constants"].items()
        },
        "reset_default_software_profile": normal,
        "restored_sram_table_evidence": config["sram_tables"],
        "bit28_preexisting_alternative": bit28_preexisting,
        "confidence": {
            "literal_constants": "decoded image evidence",
            "clock_tree": "conditional on STM32F1-compatible field layout and reset state",
            "physical_crystal": "unmeasured; 8 MHz is compiled-in expectation",
            "bus_prescaler_table": "recovered from the original 7084-byte ARM scatterload SRAM initialization data",
        },
        "limits": [
            "The code preserves part of the original CFGR, including bit28.",
            "A preceding bootloader could in principle leave non-reset bit28 state.",
            "Clock-ready and clock-switch wait loops must complete for this tree.",
            "Register family compatibility does not prove MCU vendor/part number.",
            "Recovered RAM table initial values are not proof they remain unchanged at runtime.",
            "Timer clock doubling is a conditional STM32F1-compatible rule.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = analyze(decoded_payload(args.firmware.read_bytes()))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Original firmware instruction immediates:", report["actual_immediates"])
        print("Original literal constants:", report["original_literal_words"])
        print("Default register-state hypothesis:", report["reset_default_software_profile"])
        print("Alternative preexisting bit28 high:", report["bit28_preexisting_alternative"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
