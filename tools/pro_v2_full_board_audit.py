#!/usr/bin/env python3
"""Read-only V2 OEM RF trim, GPIO, AF and LCD init instruction audit.

Physical XL9951Q pads, analog PA circuitry and menu legends are NOT inferred
from STM32-style port numbers. Evidence uses archived original image only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from pro_v2_board_io_audit import check_site, verify_version
from pro_v2_rf_ui_flow_audit import verify_sites as verify_rf_ui

V2 = Path("firmware/BF_5RH_501_v2_0_9.dat")
V1 = Path("firmware/BF_5RH_501_v1_1_04.dat")

# (original Thumb PC, exact mnemonic, significant operands, optional literal)
FIXED = {
    "frequency_trim": (
        (0x08012BB4, "ldr", "r2, [pc", 0x20000082),
        (0x08012BB6, "movs", "r1, #4", None),
        (0x08012BB8, "movw", "r0, #0xc5c0", None),
        (0x08012BBC, "bl", "#0x80141dc", None),
        (0x08012BC4, "ldr", "r2, [pc", 0x2000246C),
        (0x08012BD2, "cmp", "r1, #0x60", None),
        (0x08012BD6, "strb", "r6, [r3, r0]", None),
        (0x08012BDA, "cmp", "r1, #0x28", None),
        (0x08012BDE, "add.w", "r1, r1, r1, lsl #2", None),
        (0x08012BE2, "subs", "r1, #0xc8", None),
        (0x08012BE8, "subs", "r1, #0x28", None),
        (0x08012BEA, "add.w", "r1, r1, r1, lsl #2", None),
        (0x08012BEE, "str.w", "r1, [r2, r0, lsl #2]", None),
        (0x08012BFA, "cmp", "r0, #4", None),
        (0x08012C08, "movw", "r0, #0x7982", None),
        (0x08012CBE, "ldr", "r7, [pc", 0x2000246C),
        (0x08012CC4, "adds", "r7, #0x10", None),
        (0x08012CC8, "strb", "r2, [r7]", None),
        (0x08012CE4, "rev16", "r3, r3", None),
        (0x08012CEA, "strh.w", "r3, [ip, #2]", None),
        (0x08012CF4, "cmp", "r1, r2", None),
        (0x08012D10, "mov", "r2, sp", None),
        (0x08012D12, "movs", "r1, #0x82", None),
        (0x08012D14, "bl", "#0x80141dc", None),
        (0x08012D28, "strb.w", "sb, [r7, #0x82]", None),
        (0x08012D44, "rev16", "r3, r3", None),
        (0x08012D4A, "strh.w", "r3, [ip, #0x84]", None),
        (0x08012D54, "cmp", "r1, r2", None),
    ),
    "audio_route": (
        (0x0800A312, "ldr", "r5, [pc", 0x20001B84),
        (0x0800A316, "cmp", "r0, #9", None),
        (0x0800A31C, "bic", "r0, r0, #0xf00", None),
        (0x0800A320, "orr.w", "r1, r0, r4, lsl #8", None),
        (0x0800A324, "strh", "r1, [r5, #0xe]", None),
        (0x0800A326, "movs", "r0, #0x47", None),
        (0x0800A32C, "cmp", "r4, #3", None),
        (0x0800A330, "ldrh", "r1, [r5, #0x10]", None),
        (0x0800A336, "movs", "r0, #0x48", None),
        (0x0800A33C, "movw", "r1, #0x6740", None),
        (0x0800A348, "movw", "r1, #0xb3aa", None),
        (0x0800A39A, "movw", "r1, #0x3028", None),
        (0x0800A3A4, "movw", "r1, #0x4048", None),
    ),
    "lcd_gpio_reset": (
        (0x0801501E, "ldr", "r4, [pc", 0x40010810),
        (0x08015022, "orr", "r0, r0, #0x100", None),
        (0x08015028, "movs", "r0, #0x14", None),
        (0x08015030, "ldr", "r1, [r0]", None),
        (0x08015032, "orr", "r1, r1, #0x100", None),
        (0x08015038, "movs", "r0, #0xc8", None),
        (0x08015040, "orr", "r0, r0, #0x100", None),
        (0x08015046, "movs", "r0, #0x14", None),
        (0x0801504C, "movs", "r0, #0x11", None),
        (0x08015052, "movs", "r0, #0x64", None),
        (0x0801512A, "movs", "r0, #0x31", None),
        (0x08015132, "beq", "#0x8015230", None),
        (0x08015134, "movs", "r0, #0xa0", None),
        (0x0801524C, "movs", "r0, #0x60", None),
        (0x0801524E, "b", "#0x8015136", None),
        (0x08015212, "movs", "r0, #0x3a", None),
        (0x08015218, "movs", "r0, #5", None),
        (0x08015394, "ldr", "r0, [pc", 0x20000FD8),
        (0x0801539A, "bne", "#0x80153aa", None),
        (0x080153A4, "movs", "r0, #0x29", None),
        (0x080153A6, "b.w", "#0x800752c", None),
    ),
    "board_io_events": (
        (0x0800DA34, "ldr", "r0, [pc", 0x40010C10),
        (0x0800DA38, "orr", "r1, r1, #0x40", None),
        (0x0800DA46, "ldr", "r0, [pc", 0x40010C10),
        (0x0800DA48, "adds", "r0, r0, #4", None),
        (0x08011EC2, "ldr", "r0, [pc", 0x40010C10),
        (0x08011EC6, "orr", "r1, r1, #0x100", None),
        (0x08011F5C, "ldr", "r0, [pc", 0x40010C10),
        (0x08011F5E, "adds", "r0, r0, #4", None),
        (0x080138CE, "ldr", "r0, [pc", 0x40010C10),
        (0x080138D2, "orr", "r1, r1, #0x4000", None),
        (0x08017206, "ldr", "r1, [pc", 0x40011410),
        (0x0801720A, "orr", "r0, r0, #4", None),
        (0x080328FE, "ldr", "r0, [pc", 0x40010810),
        (0x08032902, "orr", "r1, r1, #2", None),
        (0x08032944, "ldr", "r0, [pc", 0x40010810),
        (0x08032946, "adds", "r0, r0, #4", None),
        (0x080109A2, "ldr", "r1, [pc", 0x40010808),
        (0x080109A6, "lsls", "r1, r1, #0x16", None),
        (0x080109AC, "strb", "r1, [r0, #7]", None),
    ),
}
GAMMA_POS_SITES = (
    (0x08015140,0x0B),(0x08015146,0x21),(0x0801514C,0x0C),
    (0x08015152,0x16),(0x08015158,0x2E),(0x0801515E,0x27),
    (0x08015164,0x1F),(0x0801516A,0x25),(0x08015170,0x25),
    (0x08015176,0x24),(0x0801517C,0x2C),(0x08015182,0x38),
    (0x08015188,0x00),(0x0801518E,0x03),(0x08015194,0x00),
    (0x0801519A,0x10),
)
GAMMA_NEG_SITES = (
    (0x080151A6,0x0E),(0x080151AC,0x1E),(0x080151B2,0x0E),
    (0x080151B8,0x18),(0x080151BE,0x33),(0x080151C4,0x2D),
    (0x080151CA,0x28),(0x080151D0,0x2A),(0x080151D6,0x28),
    (0x080151DC,0x26),(0x080151E2,0x2F),(0x080151E8,0x3C),
    (0x080151EE,0x00),(0x080151F4,0x05),(0x080151FA,0x05),
    (0x08015200,0x10),
)
LCD_COMMAND_SITES = (
    (0x08015058,0xB1),(0x08015070,0xB2),(0x08015088,0xB3),
    (0x080150B2,0xB4),(0x080150BE,0xC0),(0x080150D6,0xC1),
    (0x080150E2,0xC2),(0x080150F4,0xC3),(0x08015106,0xC4),
    (0x08015118,0xC5),(0x08015124,0x36),(0x0801513A,0xE0),
    (0x080151A0,0xE1),(0x08015206,0x35),(0x08015212,0x3A),
)


def verify_original(payload: bytes) -> dict:
    counts = {}
    for group, rows in FIXED.items():
        for pc, name, operands, literal in rows:
            check_site(payload, pc, name, operands, literal)
        counts[group] = len(rows)
    for name, rows in (("gamma_positive",GAMMA_POS_SITES),
                       ("gamma_negative",GAMMA_NEG_SITES)):
        for pc, value in rows:
            immediate = str(value) if value < 10 else f"0x{value:x}"
            check_site(payload, pc, "movs", f"r0, #{immediate}")
            check_site(payload, pc + 2, "bl", "#0x800755c")
        counts[name] = len(rows)*2
    for pc, command in LCD_COMMAND_SITES:
        immediate = str(command) if command < 10 else f"0x{command:x}"
        check_site(payload, pc, "movs", f"r0, #{immediate}")
        check_site(payload, pc+2, "bl", "#0x800752c")
    counts["lcd_setup_commands"] = len(LCD_COMMAND_SITES)*2
    return counts


def original_trim_word(raw: int) -> int:
    if not 0 <= raw <= 255:
        raise ValueError("OEM trim source byte must be unsigned 8 bit")
    normalized = 0x28 if raw > 0x60 else raw
    return ((normalized - 0x28) * 5) & 0xFFFFFFFF


def analyze(v2: bytes, v1: bytes) -> dict:
    checks = verify_original(v2)
    old = verify_rf_ui(v2)
    cross_version = verify_version(v1,"v1")
    return {
        "firmware_version":"BF_5RH_501_v2_0_9.dat",
        "verified_thumb":checks,
        "existing_rf_ui_sites":old,
        "existing_v1_board_sites":cross_version["total"],
        "frequency_trim": {
            "storage_logical_offset":"0xC5C0",
            "number_of_source_bytes":4,
            "normalized_max_raw":"0x60",
            "invalid_high_replacement":"0x28",
            "signed_word_formula":"5 * (normalized_byte - 40)",
            "fd6818_guide_hz_per_word":10,
            "effective_hz_step":50,
            "per_device_trim_bytes_available":False,
            "destination":"0x2000246C",
            "sample_0x27":original_trim_word(0x27),
            "sample_0x28":original_trim_word(0x28),
            "sample_0x60":original_trim_word(0x60),
            "sample_0x61":original_trim_word(0x61),
        },
        "nv_record": {
            "header_logical_offset":"0x7982",
            "record_length_bytes":130,
            "record_base":"0x7A90",
            "index_stride_bytes":152,
            "halfword_values_per_bank":64,
            "second_bank_present":True,
            "physical_coefficients_unavailable":True,
        },
        "lcd": {
            "gpio_port_bit_reset":"PA8",
            "reset_raw_delay_arguments":[0x14,0xC8,0x14],
            "sleep_out_command":"0x11",
            "sleep_out_delay_raw":0x64,
            "orientation_option_a":"0xA0",
            "orientation_option_b":"0x60",
            "gamma_positive":[v for _,v in GAMMA_POS_SITES],
            "gamma_negative":[v for _,v in GAMMA_NEG_SITES],
            "pixel_format":"RGB565: command 0x3A, data 0x05",
            "display_on_only_after_first_frame":True,
            "display_on_command":"0x29",
            "controller_physical_variant_verified":False,
        },
        "audio": {
            "oem_rfic_registers":["0x47","0x48","0x43"],
            "special_mode9_words":["0x6740","0xB3AA"],
            "reg43_variants":["0x3028","0x4048"],
            "external_amp_gpio_identity_proven":False,
        },
        "board_gpio_software_only": {
            "standalone_active_low_gpio":"PA9",
            "lcd_reset":"PA8",
            "gpio_toggles":["PB6","PB8","PB14","PA1","PD2"],
            "ptt_physical_button_proven":False,
            "rf_pa_external_gpio_proven":False,
            "mcu_pinout_manufacturer_proven":False,
        },
        "mcu": {
            "candidate_core_arch":"ARMv7-M Thumb; exact silicon and peripheral compatibility unknown",
            "initial_msp":"0x20011308",
            "oem_reset_vector_thumb":"0x0800123D",
            "application_image_base":"0x08001000",
            "original_mcu_flash_journal":"0x0807F800",
            "gpio_register_layout":"STM32F1-compatible MMIO, not confirmed pinout",
            "qfn64_physical_pad_number_confirmed":False,
            "silicon_vendor_confirmed":False,
            "bootloader_recovery_verified":False,
        },
        "method":"archived V2 Thumb instruction sites and V1 existing crosscheck; host-only",
    }


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json",action="store_true")
    args=parser.parse_args()
    report=analyze(decoded_payload(V2.read_bytes()),decoded_payload(V1.read_bytes()))
    if args.json:print(json.dumps(report,indent=2,ensure_ascii=False))
    else:print("verified V2 instruction sites:",report["verified_thumb"])
    return 0


if __name__=="__main__":
    raise SystemExit(main())
