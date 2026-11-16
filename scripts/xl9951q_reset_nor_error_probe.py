#!/usr/bin/env python3
"""Read-only bounded original Thumb instruction inspection for startup/error paths."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from v2_pll_runtime_order import V1, V2, verify_reset_to_main, reachable_calls

IMAGES={
"v1":("firmware/BF_5RH_501_v1_1_04.dat",V1,False,[
("reset",0x08001220,0x08001270),
("main",0x08027BE0,0x08027C25),
("recovery",0x0800AB74,0x0800AC16),
("nor_status",0x080030B8,0x08003118),
("nor_program",0x08003118,0x080031A4),
("nor_erase",0x08007C94,0x08007CE0),
("flash_erase",0x08002E70,0x08002ED0),
("flash_write",0x08002EE4,0x08002F30),
("nor_replay",0x0800ED50,0x0800ED6A),
("flash_clear",0x08007C68,0x08007C7C)]),
"v2":("firmware/BF_5RH_501_v2_0_9.dat",V2,True,[
("reset",0x08001220,0x08001270),
("main",0x080340DC,0x08034125),
("recovery",0x08010400,0x080104A0),
("nor_status",0x08006BD8,0x08006C28),
("nor_program",0x08006C28,0x08006CB4),
("nor_erase",0x0800D334,0x0800D380),
("flash_erase",0x08006980,0x080069E0),
("flash_write",0x080069F4,0x08006A40),
("nor_replay",0x08014A28,0x08014A44),
("flash_clear",0x0800D308,0x0800D31C)])}

def main():
    for version,(path,base,is_v2,ranges) in IMAGES.items():
        payload=decoded_payload(Path(path).read_bytes())
        print("########",version,len(payload))
        print("VERIFIED_RESET_TO_MAIN",verify_reset_to_main(payload,base,is_v2))
        for label,start,end in ranges:
            print("BEGIN",version,label)
            for ins in inspect_window(payload,start,end):
                print(ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
            print("END",version,label)
        print("MAIN_CALLS",reachable_calls(payload,base["main"])[:90])

if __name__=="__main__":
    main()
