#!/usr/bin/env python3
"""Disassemble bounded OEM reset and NOR error-flow evidence without device I/O."""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from v2_pll_runtime_order import V1, V2, verify_reset_to_main, reachable_calls

VERSIONS={
  "v1":{
    "image":"firmware/BF_5RH_501_v1_1_04.dat","spec":V1,
    "windows":{
      "reset":(0x08001220,0x08001260),
      "main":(0x08027BE8,0x08027C24),
      "nor_erase":(0x08002F98,0x08002FE4),
      "nor_page_program":(0x08003118,0x080031C0),
      "nor_status":(0x080030C8,0x08003118),
      "nor_erase_abs":(0x08007C94,0x08007CE0),
      "nor_read":(0x08002FE4,0x08003038),
      "nor_read_alt":(0x0800E5CC,0x0800E628),
      "flash_wait":(0x08002EAC,0x08002ED0),
    },
    "restore_callsite":0x08027BFC,
  },
  "v2":{
    "image":"firmware/BF_5RH_501_v2_0_9.dat","spec":V2,
    "windows":{
      "reset":(0x08001220,0x08001260),
      "main":(0x080340E0,0x0803411A),
      "nor_erase":(0x08006AA8,0x08006AF4),
      "nor_page_program":(0x08006C28,0x08006CD0),
      "nor_status":(0x08006BD8,0x08006C28),
      "nor_erase_abs":(0x0800D334,0x0800D380),
      "nor_read":(0x08006AF4,0x08006B48),
      "nor_read_alt":(0x080141DC,0x08014238),
      "flash_wait":(0x080069BC,0x080069E0),
    },
    "restore_callsite":0x080340F4,
  },
}
def main():
  for name,spec in VERSIONS.items():
    data=decoded_payload(Path(spec["image"]).read_bytes())
    print("=== VERSION",name,"BYTES",len(data),"===")
    print("RESET_TO_MAIN",json.dumps(verify_reset_to_main(data,spec["spec"],name=="v2")))
    calls=reachable_calls(data,spec["spec"]["main"])
    print("MAIN_RECOVERY_CALL",[(hex(a),hex(b)) for a,b in calls if a==spec["restore_callsite"]])
    print("MAIN_DIRECT_CALLS",[(hex(a),hex(b)) for a,b in calls if spec["spec"]["main"]<=a<spec["spec"]["main"]+0x60])
    for label,(start,end) in spec["windows"].items():
      print("WINDOW",name,label,hex(start),hex(end))
      for row in inspect_window(data,start,end):
        print(row["pc"],row["mnemonic"],row["operands"],"literal="+row.get("literal_value",""))
if __name__=="__main__":
    main()
