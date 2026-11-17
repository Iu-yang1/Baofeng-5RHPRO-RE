#!/usr/bin/env python3
"""Offline exploratory V1/V2 RF tuning/PTT/UI callflow, archived OEM images only."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls
from v2_pll_runtime_order import reachable_calls
DATA = {
"v2": ("firmware/BF_5RH_501_v2_0_9.dat", [
("fd_tune",0x08005EA0,0x08005F10),
("fd_state",0x0800B060,0x0800B110),
("freq_table",0x0800DD50,0x0800DE90),
("key_decode",0x08010990,0x08010AB0),
("ui_main",0x08015400,0x08015500),
]),
"v1": ("firmware/BF_5RH_501_v1_1_04.dat", [
("fd_tune",0x08002390,0x080023FC),
("fd_state",0x0800754C,0x08007600),
("freq_table",0x0800A23C,0x0800A370),
("key_decode",0x0800B0FC,0x0800B21C),
]),
}
V2_TARGETS=[0x08005EC6,0x08005E8C,0x08005EE0,0x0800DDB8,0x0800B0A0,0x08010998,0x08010A2A,0x0801530C,0x0800752C,0x0800755C]
def main():
 for version,(path,regions) in DATA.items():
  p=decoded_payload(Path(path).read_bytes())
  print("======",version,len(p))
  for label,lo,hi in regions:
   print("BEGIN",version,label)
   for x in inspect_window(p,lo,hi):
    print("INS",x["pc"],x["mnemonic"],x["operands"],x.get("literal_value",""))
   print("END",version,label)
  if version=="v2":
   for key,refs in find_calls(p,V2_TARGETS).items():
    print("CROSSREF",key,len(refs),*[x["call_pc"] for x in refs[:70]])
   for entry in [0x0800DDB8,0x0800B0A0,0x08005EC6,0x08010998]:
    try:
     calls=reachable_calls(p,entry,cap=850)
     print("FUNCTION_CALLS",hex(entry),*[f"{a:#x}->{b:#x}" for a,b in calls[:65]])
    except Exception as ex:print("CFG_EXCEPTION",hex(entry),repr(ex))
if __name__=="__main__":main()
