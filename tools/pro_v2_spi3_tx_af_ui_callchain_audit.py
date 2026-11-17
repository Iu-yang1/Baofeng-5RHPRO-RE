#!/usr/bin/env python3
"""OEM V2 SPI3 setup and RFIC-TX/audio / PTT-UI software callsite audit.

Only original Thumb callsites and SOFTWARE-MMIO are verified. The
XL9951Q QFN64 physical GPIO pad mapping, PA bias, analogue speaker
amplifier wiring and physical PTT key identification remain unknown.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from pro_v2_board_io_audit import check_site

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")

# PC, original instruction, significant operands, optional PC-relative pool
SITES={
    "spi3_gpio_and_controller_setup":(
        (0x08006B4E,"ldr","r0, [pc",0x00201100),
        (0x08006B50,"bl","#0x8007054",None),
        (0x08006B56,"lsls","r0, r1, #0xf",None),
        (0x08006B58,"bl","#0x8030b9c",None),
        (0x08006B5C,"movs","r0, #0x38",None),
        (0x08006B6A,"ldr","r4, [pc",0x40010C00),
        (0x08006B74,"bl","#0x8006fb8",None),
        (0x08006B78,"movs","r1, #0x38",None),
        (0x08006B7C,"bl","#0x80070b0",None),
        (0x08006B86,"mov.w","r1, #0x104",None),
        (0x08006B9E,"lsls","r1, r1, #9",None),
        (0x08006BAE,"movs","r0, #7",None),
        (0x08006BB0,"ldr","r4, [pc",0x40003C00),
        (0x08006BBA,"bl","#0x80317dc",None),
        (0x08006BC2,"bl","#0x80317b2",None),
        (0x080317B8,"orr","r1, r1, #0x40",None),
        (0x080317E2,"and","r3, r2, #0x3040",None),
        (0x08031804,"strh","r2, [r0]",None),
        (0x08031808,"bic","r2, r2, #0x800",None),
        (0x08031810,"strh","r1, [r0, #0x10]",None),
    ),
    "transmit_rfic_and_audio_control_prefix":(
        (0x0800A8E0,"movs","r0, #1",None),
        (0x0800A8E2,"bl","#0x800a310",None),
        (0x0800A8E8,"ubfx","r1, r0, #0, #0xf",None),
        (0x0800A8EC,"strh","r1, [r5, #0x12]",None),
        (0x0800A8EE,"movs","r0, #0x50",None),
        (0x0800A8F0,"bl","#0x8005e8c",None),
        (0x0800A8F4,"movs","r1, #0",None),
        (0x0800A8F6,"movs","r0, #0x70",None),
        (0x0800A8F8,"bl","#0x8005e8c",None),
        (0x0800A8FC,"movw","r1, #0xc1fe",None),
        (0x0800A900,"movs","r0, #0x30",None),
        (0x0800A902,"bl","#0x8005e8c",None),
        (0x0800A908,"bl","#0x80184d4",None),
    ),
    "keypad_logic_not_physical_ptt":(
        (0x0800B0D8,"bl","#0x8010998",None),
        (0x0800B0DC,"cmp","r0, #0xd",None),
        (0x0800B0F0,"bl","#0x8010998",None),
        (0x0800B0F4,"cmp","r0, #0xd",None),
        (0x0801071E,"bl","#0x8010998",None),
        (0x08010722,"ldr.w","r8, [pc",0x40010808),
        (0x0801072E,"lsls","r1, r1, #0x15",None),
        (0x0801075E,"bl","#0x800da10",None),
        (0x0800DA34,"ldr","r0, [pc",0x40010C10),
        (0x0800DA38,"orr","r1, r1, #0x40",None),
        (0x0800DA46,"ldr","r0, [pc",0x40010C10),
        (0x0800DA50,"str","r1, [r0]",None),
    ),
    "separate_gpio_control_with_opaque_load":(
        (0x08009A8A,"bl","#0x800b630",None),
        (0x08009A8E,"ldr","r0, [pc",0x40010C14),
        (0x08009A92,"orr","r1, r1, #2",None),
        (0x08009BB0,"ldr","r0, [pc",0x40010C10),
        (0x08009BB4,"orr","r1, r1, #2",None),
        (0x0800A310,"push","{r4, r5, r6, lr}",None),
        (0x0800A326,"movs","r0, #0x47",None),
        (0x0800A336,"movs","r0, #0x48",None),
        (0x0800A39A,"movw","r1, #0x3028",None),
        (0x0800A3A4,"movw","r1, #0x4048",None),
    ),
}


def verify_original(payload: bytes) -> dict:
    counts={}
    for name,sites in SITES.items():
        for pc,mnemonic,operand,literal in sites:
            check_site(payload,pc,mnemonic,operand,literal)
        counts[name]=len(sites)
    return {
        "verified_software_sites":counts,
        "spi3":{
            "source_function":"0x08006B48",
            "port_b_mode_mask":"0x0038",
            "software_gpio_b_bits":[3,4,5],
            "spi3_mmio_base":"0x40003C00",
            "initial_cr1_config_fields_or":"0x0317",
            "preserve_initial_cr1_bits":"0x3040",
            "spi_enable_spe":"0x0040",
            "clear_cr2_bit11":"0x0800",
            "crc_polynomial":"0x0007",
            "verified_clock_hz":False,
            "physical_qfn_pad_mapping_verified":False,
        },
        "rf_audio":{
            "oem_tx_related_subpath":"0x0800A8E0 audio mode 1, REG50 masked low15, REG70 0, REG30 0xC1FE",
            "additional_rfic_regs":["0x50","0x70"],
            "physical_tx_pa_and_mic_path_verified":False,
            "speaker_tda2822_lm2904b_wiring_verified":False,
        },
        "gpio_ptt":{
            "scan_index_0d_checked_in_rfic_helper":True,
            "gpioa10_is_separate_input":True,
            "pb6_software_bit_changed_after_ui_state_test":True,
            "pb1_low_high_surrounds_complex_control_sequence":True,
            "physical_ptt_input_verified":False,
            "physical_pa_bias_enable_verified":False,
        },
        "method":"verified V2 Thumb instruction/literal and direct BL sites, read-only archive",
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json",action="store_true")
    args=p.parse_args()
    result=verify_original(decoded_payload(IMAGE.read_bytes()))
    print(json.dumps(result,indent=2,ensure_ascii=False) if args.json else result)

if __name__=="__main__":
    main()
