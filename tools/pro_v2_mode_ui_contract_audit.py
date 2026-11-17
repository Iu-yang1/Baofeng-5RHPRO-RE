#!/usr/bin/env python3
"""Verify V2 4-trim two-level mode lookup and 67-case config TBB.

This is original OEM Thumb/scatterload evidence, not reconstructed
physical VHF/UHF bands or an already-complete UI menu state machine.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from mcu_fingerprint import decoded_payload
from thumb_window import BASE, inspect_window
from v2_scatterload_decode import decompress_region
from v2_scatterload_regions import REGION_START

V2 = Path("firmware/BF_5RH_501_v2_0_9.dat")
TBB_PC = 0x0800E482
TBB_BASE = TBB_PC + 4
CONFIG_ID_COUNT = 0x43
MENU_OFFSETS = bytes([
    0x22,0x29,0x2F,0x35,0x3B,0x3E,0x41,0x43,0x49,0x50,0x52,0x54,
    0x56,0x58,0x5A,0x5C,0x5E,0x60,0x62,0x68,0x6C,0x6A,0x6E,0x70,
    0x73,0x75,0x78,0x7B,0x7E,0x81,0x84,0x86,0x27,0x88,0x8A,0x8D,
    0x8F,0x92,0x95,0x98,0x27,0x27,0x9B,0x9D,0xA0,0xA3,0xA6,0xA9,
    0xAB,0xAE,0xB1,0xB4,0xB7,0xBA,0xBC,0xBF,0xC1,0xC7,0xC3,0xC7,
    0xC9,0xCC,0xCE,0xD1,0xD4,0xD7,0xDA,
])
assert len(MENU_OFFSETS) == CONFIG_ID_COUNT

RF_SITES = [
    (0x0800DDB8,"ldr","r0, [pc",0x20000072),
    (0x0800DDBA,"sub.w","r1, r0, #0xa",None),
    (0x0800DDBE,"ldrb","r1, [r1, #1]",None),
    (0x0800DDC0,"ldrb","r0, [r0, r1]",None),
    (0x0800DDC2,"ldr","r1, [pc",0x2000246C),
    (0x0800DDC4,"ldr.w","r0, [r1, r0, lsl #2]",None),
    (0x0800DDC8,"bx","lr",None),
    (0x0800AFEC,"bl","#0x800ddb8",None),
    (0x0800AFF0,"add","r0, r4",None),
    (0x0800AFF2,"bl","#0x8005ec6",None),
]
MENU_SITES = [
    (0x0800E47C,"cmp.w","ip, #0x43",None),
    (0x0800E480,"bhs","#0x800e4d4",None),
    (TBB_PC,"tbb","[pc, ip]",None),
]
READONLY_SRAM_BASE = 0x20000000
MODE_LOOKUP_ADDRESS = 0x20000072
MODE_SELECTOR_ADDRESS = 0x20000069
TRIM_SOURCE_BYTES_ADDRESS = 0x20000082


def check_sites(payload: bytes, cases: list[tuple]) -> None:
    for pc, mnemonic, operands, literal in cases:
        lines=inspect_window(payload, pc, pc+4)
        if not lines:
            raise ValueError(f"missing Thumb instruction at 0x{pc:08X}")
        row=lines[0]
        if row["mnemonic"] != mnemonic or operands not in row["operands"]:
            raise ValueError(f"original Thumb changed at 0x{pc:08X}: {row}")
        if literal is not None and row.get("literal_value") != f"0x{literal:08X}":
            raise ValueError(f"original literal changed at 0x{pc:08X}: {row}")


def restored_mode_window(payload: bytes) -> dict:
    off=REGION_START-BASE
    src,run,size,handler=struct.unpack_from("<IIII",payload,off)
    next_src=struct.unpack_from("<I",payload,off+16)[0]
    if run != READONLY_SRAM_BASE or (handler & ~1) != 0x08001F06:
        raise ValueError("V2 scatterload region or decoding callback changed")
    expanded, consumed=decompress_region(payload[src-BASE:next_src-BASE],size)
    def read(addr: int, count: int) -> bytes:
        start=addr-run
        if start<0 or start+count>len(expanded):
            raise ValueError(f"decoded runtime SRAM range unavailable: 0x{addr:08X}")
        return expanded[start:start+count]
    mode=read(MODE_SELECTOR_ADDRESS,1)[0]
    # 16 bytes is the *maximum contiguous window before* trim input at 0x82;
    # the original routine does not expose its runtime-populated valid length.
    window=read(MODE_LOOKUP_ADDRESS, TRIM_SOURCE_BYTES_ADDRESS-MODE_LOOKUP_ADDRESS)
    if mode!=0 or window!=bytes(len(window)):
        raise ValueError("original reset-time RF mode selector/window changed")
    return {
        "active_state_byte_address":f"0x{MODE_SELECTOR_ADDRESS:08X}",
        "active_state_initial_value":mode,
        "mapping_sram_address":f"0x{MODE_LOOKUP_ADDRESS:08X}",
        "next_known_byte_address":f"0x{TRIM_SOURCE_BYTES_ADDRESS:08X}",
        "bounded_adjacent_window_length":len(window),
        "initial_window_all_zero":True,
        "runtime_table_producer_recovered":False,
        "mode_to_vhf_uhf_mapping_verified":False,
        "reset_sram_bytes":len(expanded),
        "decoded_compressed_bytes":consumed,
    }


def verify_original(payload: bytes) -> dict:
    check_sites(payload, RF_SITES)
    check_sites(payload, MENU_SITES)
    table_start=TBB_BASE-BASE
    actual=payload[table_start:table_start+CONFIG_ID_COUNT]
    if actual!=MENU_OFFSETS:
        raise ValueError("V2 menu TBB 67-byte jump table changed")
    mode=restored_mode_window(payload)
    targets=[TBB_BASE+2*x for x in actual]
    return {
        "rfic": {
            "selector_loaded_from":"0x20000069",
            "runtime_mapping_base":"0x20000072",
            "mapping_item_width_bits":8,
            "trim_words_base":"0x2000246C",
            "original_32bit_add_pc":"0x0800AFF0",
            "raw_fd6818_tuning_call_pc":"0x0800AFF2",
            **mode,
        },
        "menu": {
            "configuration_reader_entry":"0x0800E454",
            "tbb_pc":f"0x{TBB_PC:08X}",
            "tbb_base":f"0x{TBB_BASE:08X}",
            "total_configuration_ids":CONFIG_ID_COUNT,
            "id_0x13_target":f"0x{targets[0x13]:08X}",
            "id_0x14_target":f"0x{targets[0x14]:08X}",
            "id_0x15_target":f"0x{targets[0x15]:08X}",
            "id_0x16_target":f"0x{targets[0x16]:08X}",
            "id_0x35_target":f"0x{targets[0x35]:08X}",
            "shared_dispatch_targets":{
                "0x0800E4D4":[x for x,t in enumerate(targets) if t==0x0800E4D4],
                "0x0800E614":[x for x,t in enumerate(targets) if t==0x0800E614],
            },
            "menu_visible_item_count_known":False,
            "user_visible_key_legend_known":False,
        },
        "method":"original Thumb and scatterload bytes, no hardware",
    }


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json",action="store_true")
    args=p.parse_args()
    report=verify_original(decoded_payload(V2.read_bytes()))
    if args.json:
        print(json.dumps(report,indent=2,ensure_ascii=False))
    else:
        print("verified mode lookup and 67-entry menu dispatcher",report)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
