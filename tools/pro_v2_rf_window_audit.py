#!/usr/bin/env python3
"""Cross-version OEM RF mode/trim frequency window evidence.

The original V2 mode writer stores slots 0..3 after unsigned range
comparisons on the 32-bit raw tune word. The eight range constants are
also present, adjacent and unique, in the archived V1.1.04 image.
This is NOT a PA/band-switch pinout or TX legality table.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from mcu_fingerprint import decoded_payload
from thumb_window import BASE, inspect_window

V1 = Path("firmware/BF_5RH_501_v1_1_04.dat")
V2 = Path("firmware/BF_5RH_501_v2_0_9.dat")
V1_TABLE_PC = 0x08025B60
V2_TABLE_PC = 0x08031BD4
BIAS_AND_WIDTHS = (
    (0xFF307B00, 0x0039FBC0),
    (0xFECED300, 0x005B8D80),
    (0xFDE9F140, 0x004AC4A0),
    (0xFD9DA600, 0x00B71B00),
)
# Source file also tests the V2 range branch and SRAM indexed writes.
V2_WRITER_SITES = (
    (0x08031AEE, "ldr.w", "ip, [pc", 0x2000245C),
    (0x08031AF4, "ldr", "r5, [pc", 0x20000068),
    (0x08031B08, "udiv", "r1, r3, r6", None),
    (0x08031B0E, "ldr", "r1, [pc", BIAS_AND_WIDTHS[0][0]),
    (0x08031B10, "ldr.w", "lr, [pc", BIAS_AND_WIDTHS[0][1]),
    (0x08031B1A, "movs", "r7, #0", None),
    (0x08031B22, "strb", "r7, [r1, r0]", None),
    (0x08031B3A, "ldr.w", "ip, [pc", BIAS_AND_WIDTHS[1][0]),
    (0x08031B3E, "ldr.w", "lr, [pc", BIAS_AND_WIDTHS[1][1]),
    (0x08031B48, "movs", "r7, #1", None),
    (0x08031B4A, "strb", "r7, [r1, r0]", None),
    (0x08031B54, "ldr.w", "ip, [pc", BIAS_AND_WIDTHS[2][0]),
    (0x08031B58, "ldr.w", "lr, [pc", BIAS_AND_WIDTHS[2][1]),
    (0x08031B62, "movs", "r7, #2", None),
    (0x08031B64, "strb", "r7, [r1, r0]", None),
    (0x08031B70, "ldr.w", "ip, [pc", BIAS_AND_WIDTHS[3][0]),
    (0x08031B74, "ldr.w", "lr, [pc", BIAS_AND_WIDTHS[3][1]),
    (0x08031B7E, "movs", "r7, #3", None),
    (0x08031B80, "strb", "r7, [r1, r0]", None),
)


def check_literals(payload: bytes, table_pc: int, version: str):
    start=table_pc-BASE
    values=sum(([b,w] for b,w in BIAS_AND_WIDTHS),[])
    observed=list(struct.unpack_from("<8I",payload,start))
    if observed!=values:
        raise ValueError(f"{version} OEM four-window literal table changed")
    # Unique occurrences discourage accidentally picking an unrelated table.
    for number in values:
        if payload.count(struct.pack("<I",number)) != 1:
            raise ValueError(f"{version} OEM frequency window literal is not unique")


def check_writer(payload: bytes):
    for pc,name,operand,literal in V2_WRITER_SITES:
        lines=inspect_window(payload,pc,pc+4)
        row=lines[0] if lines else None
        if row is None or row["mnemonic"] != name or operand not in row["operands"]:
            raise ValueError(f"V2 RF trim window writer mismatch at 0x{pc:08X}: {row}")
        if literal is not None and row.get("literal_value") != f"0x{literal:08X}":
            raise ValueError(f"V2 RF window literal mismatch at 0x{pc:08X}: {row}")


def verify_original(v1: bytes,v2: bytes) -> dict:
    check_literals(v1,V1_TABLE_PC,"V1")
    check_literals(v2,V2_TABLE_PC,"V2")
    check_writer(v2)
    windows=[]
    for index,(bias,width) in enumerate(BIAS_AND_WIDTHS):
        lower=(-bias)&0xFFFFFFFF
        upper=lower+width
        windows.append({
            "trim_slot_index":index,
            "inclusive_min_hz":lower*10,
            "inclusive_max_hz":upper*10,
            "lower_raw_word":lower,
            "upper_raw_word":upper,
            "raw_word_units_hz":10,
        })
    return {
        "v1_literal_table":f"0x{V1_TABLE_PC:08X}",
        "v2_literal_table":f"0x{V2_TABLE_PC:08X}",
        "v2_mode_writer_entry":"0x08031AEC",
        "v2_writer_verified_sites":len(V2_WRITER_SITES),
        "software_frequency_windows":windows,
        "runtime_map_base":"0x20000072",
        "rf_physical_bandpass_pa_switch_gpio_proven":False,
        "mcu_chip_identified":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json",action="store_true")
    args=p.parse_args()
    result=verify_original(decoded_payload(V1.read_bytes()),decoded_payload(V2.read_bytes()))
    print(json.dumps(result,indent=2,ensure_ascii=False) if args.json else result)

if __name__=="__main__":
    main()
