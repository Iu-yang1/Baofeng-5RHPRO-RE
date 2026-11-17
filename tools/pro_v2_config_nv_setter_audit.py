#!/usr/bin/env python3
"""Exact original V2 61-way config setter / 39-byte restore / NV journal audit.

All evidence comes from the checked archived firmware, not from a device.
Embedded 61-byte Thumb TBB table is DATA, not linearly disassembled code.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from thumb_window import BASE,inspect_window
from pro_v2_board_io_audit import check_site

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
TABLE=0x080164D6
COUNT=61
OFFSETS=bytes([
    31,33,36,39,42,50,58,61,64,67,70,73,76,79,82,85,
    88,91,94,97,103,100,106,109,113,118,127,132,137,142,
    149,154,112,163,168,177,187,196,201,206,112,112,
    220,242,251,239,238,237,236,235,234,112,233,232,
    231,230,229,228,227,226,225,
])
assert len(OFFSETS)==COUNT
FIRST=(
    ["strb"]*4 + ["and"]*2 + ["strb"]*17 + ["strb.w"] +
    ["bic"]*8 + ["b"] + ["bic"]*2 + ["bl"] +
    ["bic"]*3 + ["bl"] + ["b"]*2 + ["bic"]*3 +
    ["b"]*16
)
assert len(FIRST)==COUNT, (len(FIRST),COUNT)
SITES={
    "setter_entry":[
        (0x080164A4,"ldr","r4, [pc",0x20004580),
        (0x080164C8,"mov.w","r5, #0x7980",None),
        (0x080164CC,"cmp.w","ip, #0x3d",None),
        (0x080164D0,"bhs","#0x80165b6",None),
        (0x080164D2,"tbb","[pc, ip]",None),
    ],
    "optional_single_byte_nv_commit":[
        (0x0801677C,"ldr","r0, [sp, #8]",None),
        (0x0801677E,"cmp","r0, #1",None),
        (0x08016780,"bne","#0x801678c",None),
        (0x08016782,"adds","r0, r5, r1",None),
        (0x08016784,"add","r2, sp, #4",None),
        (0x08016786,"movs","r1, #1",None),
        (0x08016788,"bl","#0x80190e0",None),
    ],
    "working_main_restore":[
        (0x0801049C,"mov.w","r4, #0x7980",None),
        (0x080104A2,"movs","r1, #0x38",None),
        (0x080104A6,"bl","#0x80141dc",None),
        (0x080104BA,"ldr","r6, [pc",0x20004580),
        (0x08010518,"ldrb.w","r0, [sp, #0x1e]",None),
        (0x0801051C,"strb","r0, [r6, #0xd]",None),
        (0x0801051E,"ldrb.w","r0, [sp, #0x1f]",None),
        (0x08010522,"strb","r0, [r6, #0xc]",None),
        (0x08010548,"strb.w","r0, [r6, #0x20]",None),
        (0x080105A8,"movs","r0, #0x71",None),
        (0x080105AA,"bl","#0x80141dc",None),
        (0x080105DC,"strb.w","r0, [r6, #0x26]",None),
        (0x080106B2,"ldr","r2, [pc",0x20004580),
        (0x080106B6,"adds","r2, #0x21",None),
        (0x080106B8,"mov.w","r0, #0x7a80",None),
        (0x080106BC,"bl","#0x80141dc",None),
    ],
    "setter_special_cases":[
        (0x080165B0,"strb.w","r0, [r4, #0x20]",None),
        (0x080165B4,"b","#0x801677c",None),
        (0x08016638,"bl","#0x800da10",None),
        (0x08016672,"bl","#0x800caec",None),
        (0x0801671E,"mov.w","r5, #0x7a80",None),
        (0x08016722,"strb.w","r0, [r4, #0x21]",None),
        (0x08016742,"movs","r5, #0x70",None),
        (0x08016748,"movs","r1, #1",None),
        (0x08016778,"strb.w","r0, [r4, #0x24]",None),
    ],
}


def verify_original(payload:bytes)->dict:
    if payload[TABLE-BASE:TABLE-BASE+COUNT] != OFFSETS:
        raise ValueError("OEM setter 61-byte TBB table changed")
    for label,sites in SITES.items():
        for pc,mnem,operand,literal in sites:
            check_site(payload,pc,mnem,operand,literal)
    for idx,offset in enumerate(OFFSETS):
        pc=TABLE+offset*2
        ins=inspect_window(payload,pc,pc+4)
        if not ins or ins[0]["mnemonic"] != FIRST[idx]:
            raise ValueError(f"setter case {idx} at 0x{pc:08X} changed")
    return {
        "original_image":"BF_5RH_501_v2_0_9.dat",
        "setter_entry":"0x080164A0",
        "config_working_sram":"0x20004580",
        "setter_id_count":61,
        "getter_id_count":67,
        "setter_tbb_base":f"0x{TABLE:08X}",
        "noop_ids":[32,40,41,51],
        "setter_calls_with_external_effects":{
            "35":"0x0800DA10","39":"0x0800CAEC",
        },
        "startup_main_nv_read":{"address":"0x7980","length":56},
        "startup_extra_nv_read":{"address":"0x71","length":4},
        "startup_side_nv_read":{"address":"0x7A80","length":1},
        "working_ram_startup_min_span_bytes":39,
        "setter_commit_condition":"third ABI argument r2==1",
        "commit_engine":"0x080190E0",
        "commit_length_bytes":1,
        "source_discrepancies":[
            "setter ID23 writes SRAM+0x20, commits NV0x7980; startup restores SRAM+0x20 from NV0x799B",
            "setter ID13 and ID14 commit NV0x7992/0x7993; startup sources for RAM+0x0C/0x0D are reversed",
        ],
        "mcu_physical_vendor_verified":False,
        "board_pa_ptt_wiring_verified":False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json",action="store_true")
    a=p.parse_args()
    d=verify_original(decoded_payload(IMAGE.read_bytes()))
    print(json.dumps(d,indent=2) if a.json else d)
if __name__=="__main__":
    main()
