#!/usr/bin/env python3
"""OEM V2 menu UI source reconnaissance: setter callers, draw calls, state transitions.

All addresses are source-level candidate Thumb instructions from archived OEM
V2.0.09 image. Do not treat mixed Thumb/data regions as complete CFGs.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
CALLEES={
  "config_setter":0x080164A0,
  "config_getter":0x0800E454,
  "config_selection":0x0800D010,
  "config_label_or_state":0x0800DE68,
  "menu_select":0x0800E0B8,
  "menu_value":0x0800E064,
  "menu_ui_helper":0x0800E18C,
  "menu_text":0x08010DB4,
  "draw_text":0x08010DE4,
  "panel_command":0x0800752C,
  "panel_data":0x0800755C,
  "original_store":0x080190E0,
  "key_scan":0x08010998,
}
WINDOWS={
 "menu_state_0":(0x0800D000,0x0800D260),
 "menu_state_1":(0x0800DE50,0x0800E084),
 "menu_state_2":(0x0800E080,0x0800E3F0),
 "menu_editor":(0x080167B8,0x08016AD8),
 "menu_page_render":(0x0800EA48,0x0800EDF0),
 "menu_draw_helper":(0x08010D90,0x08011040),
 "menu_key_loop":(0x08010710,0x08010990),
 "menu_cursor":(0x0800C9B0,0x0800CCD0),
 "menu_popup":(0x080182A0,0x08018420),
}
def main()->None:
 p=argparse.ArgumentParser()
 p.add_argument("--focus",choices=["setter_callers","other_callers",*WINDOWS],required=True)
 p.add_argument("--max-calls",type=int,default=40)
 p.add_argument("--max-lines",type=int,default=150)
 a=p.parse_args()
 payload=decoded_payload(IMAGE.read_bytes())
 if a.focus.endswith("callers"):
  keys=["config_setter","menu_select","menu_value","menu_ui_helper","config_label_or_state"] if a.focus=="setter_callers" else list(CALLEES)
  found=find_calls(payload,[CALLEES[k] for k in keys])
  for key in keys:
   addr=CALLEES[key];rows=found[f"0x{addr:08X}"]
   print("CALLEE",key,f"0x{addr:08X}","COUNT",len(rows))
   for row in rows[:a.max_calls]:
    pc=int(row["call_pc"],16)
    print("CALL",row["call_pc"],row["instruction"])
    for line in inspect_window(payload,pc-18,pc+20):
     print("AROUND",line["pc"],line["mnemonic"],line["operands"],line.get("literal_value",""))
 else:
  start,end=WINDOWS[a.focus]
  rows=inspect_window(payload,start,end)
  print("WINDOW",a.focus,f"0x{start:08X}",f"0x{end:08X}",len(rows))
  for line in rows[:a.max_lines]:
   print("INST",line["pc"],line["mnemonic"],line["operands"],line.get("literal_value",""))

if __name__=="__main__":
 main()
