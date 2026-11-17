#!/usr/bin/env python3
"""Bounded OEM V2 static scout: menu write/NV, PA/PTT, AF and HAL evidence.

A halfword-scanned LDR/BL candidate is NOT proven reachable instruction code.
Windows begin at known function boundaries and are for manual CFG inspection.
No live device or NOR programming is performed.
"""
from __future__ import annotations

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from mcu_fingerprint import decoded_payload
from thumb_window import BASE, inspect_window
from thumb_callsites import find_calls
from v2_mcu_identity_xrefs import scan as identity_scan

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
TARGETS={
    "config_getter":0x0800E454,
    "nor_write":0x08006C28,
    "nor_erase_4k":0x08006AA8,
    "journal":0x080190E0,
    "nv_read":0x080141DC,
    "rfic_write":0x08005E8C,
    "tx_enter":0x0800A8A8,
    "tx_tune_state":0x0800AFE4,
    "rfic_control":0x0800B0B4,
    "audio_mode":0x0800A310,
    "gpio_pb6_helper":0x0800DA10,
    "ui_key_event":0x08010AB0,
}
WINDOWS={
 "config_followup":(0x0800E670,0x0800E960),
 "config_neighbor":(0x0800E960,0x0800ED20),
 "menu_event":(0x08010C18,0x08010CCE),
 "tx_prefix":(0x0800A8A8,0x0800A9D8),
 "rfic_switch":(0x0800AFE4,0x0800B0B0),
 "key_poll":(0x0800B0B4,0x0800B180),
 "audio":(0x0800A310,0x0800A3BE),
 "pb6":(0x0800DA10,0x0800DA70),
 "pb1":(0x08009A80,0x08009AC0),
 "pb1_restore":(0x08009B80,0x08009BD0),
 "config_load":(0x0800DE00,0x0800E120),
 "menu_ram_owner_a":(0x0801045C,0x080105C0),
 "menu_ram_owner_b":(0x08010680,0x08010728),
 "menu_ram_owner_c":(0x08016460,0x08016620),
 "nv_transactions":(0x080190E0,0x080191C8),
 "config_setter_dispatch":(0x080164A0,0x080164D6),
 "config_setter_cases":(0x08016514,0x0801679C),
 "config_setter_tail":(0x0801679C,0x080168BC),
 "config_restore_tail":(0x080105A0,0x080106A4),
 "tx_audio_tail":(0x0800A9C0,0x0800AB40),
 "rx_audio_paths":(0x0800AD60,0x0800AF60),
}

def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--focus",choices=["callers","identity"]+list(WINDOWS),required=True)
    p.add_argument("--max-lines",type=int,default=180)
    args=p.parse_args()
    payload=decoded_payload(IMAGE.read_bytes())
    if args.focus=="callers":
        calls=find_calls(payload,list(TARGETS.values()))
        for name,pc in TARGETS.items():
            loc=f"0x{pc:08X}"
            print("CALLEE",name,loc,"CANDIDATES",len(calls[loc]))
            for row in calls[loc][:80]: print("CALL",row["call_pc"],row["instruction"])
    elif args.focus=="identity":
        candidates=identity_scan(payload)["candidates"]
        for entry in candidates:
            if entry["thumb_literal_load_candidates"]:
                print("IDENTITY",entry["address"],entry["label"],
                    "LDR_COUNT",len(entry["thumb_literal_load_candidates"]))
                for row in entry["thumb_literal_load_candidates"][:12]:
                    print("IDENTITY_REF",row["ldr_pc"],row["instruction"])
    else:
        start,end=WINDOWS[args.focus]
        lines=inspect_window(payload,start,end)
        print("WINDOW",args.focus,f"0x{start:08X}",f"0x{end:08X}",
              "LINE_COUNT",len(lines))
        for row in lines[:args.max_lines]:
            print("INST",row["pc"],row["mnemonic"],row["operands"],
                  row.get("literal_value",""))
        if len(lines)>args.max_lines: print("TRUNCATED")
if __name__=="__main__":
    main()
