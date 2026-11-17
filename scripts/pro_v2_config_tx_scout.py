#!/usr/bin/env python3
"""Read-only bounded original V2 configuration handlers / TX state machine scout.

The OEM config dispatcher has 67 entries; instruction windows are *evidence
candidates* until branch boundaries and calling convention are verified.
No connection to hardware, no peripheral writes.
"""
from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))

from mcu_fingerprint import decoded_payload
from thumb_window import BASE, inspect_window
from pro_v2_mode_ui_contract_audit import MENU_OFFSETS, TBB_BASE

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
WINDOWS={
    "config_getter":(0x0800E454,0x0800E486),
    "config_handlers":(0x0800E4CA,0x0800E674),
    "config_getter_tail":(0x0800E674,0x0800E850),
    "ui_event_branch":(0x08010B40,0x08010CCE),
    "tx_state_enter":(0x0800A8A0,0x0800A9C8),
    "tx_state_rfic":(0x0800AFDC,0x0800B0B0),
    "tx_key_wait":(0x0800B0B4,0x0800B152),
}

def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--focus",choices=["all"]+list(WINDOWS),default="config_getter")
    args=p.parse_args()
    payload=decoded_payload(IMAGE.read_bytes())
    selected=WINDOWS if args.focus=="all" else {args.focus:WINDOWS[args.focus]}
    for name,(start,end) in selected.items():
        print("WINDOW",name,hex(start),hex(end))
        for row in inspect_window(payload,start,end):
            print(row["pc"],row["mnemonic"],row["operands"],row.get("literal_value",""))
    print("CONFIG_ENTRIES")
    for idx,offset in enumerate(MENU_OFFSETS):
        print(f"{idx:02d} -> 0x{TBB_BASE+2*offset:08X}")
if __name__=="__main__":
    main()
