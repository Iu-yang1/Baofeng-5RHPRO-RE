#!/usr/bin/env python3
"""Source-only focused V2 six-chain disassembly scout (no device access).

Run with --focus one or several names. This tool makes *candidate observations*;
linear windows and halfword-sweep BL references are NOT proof of actual paths.
Use fixed-callsite and CFG checks before accepting a board HAL identity.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls
from v2_scatterload_decode import decompress_region
from v2_scatterload_regions import REGION_START
from thumb_window import BASE

IMAGE = Path("firmware/BF_5RH_501_v2_0_9.dat")

WINDOWS = {
    "mcu": [
        (0x08001280,0x0800135C),
        (0x08031A70,0x08031B34),
        (0x080323D0,0x08032490),
        (0x080340E0,0x08034152),
    ],
    "spi_gpio": [
        (0x080317E0,0x0803189C),
        (0x08006B48,0x08006BEA),
        (0x080317B0,0x08031814),
        (0x080141D8,0x08014230),
        (0x08017200,0x08017338),
        (0x080328D8,0x08032960),
    ],
    "rf_modes": [
        (0x0800DDA8,0x0800DDD8),
        (0x08031AEE,0x08031B90),
        (0x0800AFD0,0x0800B118),
        (0x08012BAC,0x08012C1C),
        (0x0800DA10,0x0800DA78),
    ],
    "ptt_pa": [
        (0x08010990,0x08010A48),
        (0x08010710,0x08010792),
        (0x0800B0B4,0x0800B160),
        (0x0800B050,0x0800B114),
        (0x08009A70,0x08009ABC),
        (0x08009B70,0x08009BC0),
        (0x08011EA8,0x08011F78),
    ],
    "audio": [
        (0x0800A300,0x0800A3C8),
        (0x0800B500,0x0800B650),
        (0x0800BB70,0x0800BC98),
        (0x0800A8D0,0x0800A9FE),
        (0x08006138,0x080061A0),
    ],
    "ui": [
        (0x08010AB0,0x08010CE0),
        (0x0800E454,0x0800E4D6),
        (0x0800E4CA,0x0800E640),
        (0x08010720,0x080107A8),
        (0x08010840,0x080108D8),
        (0x08030A10,0x08030A90),
    ],
}
TARGETS = {
    "mcu":[0x080323DC,0x080340F4,0x08001280],
    "spi_gpio":[0x08031814,0x08017200,0x080328E0],
    "rf_modes":[0x0800DDB8,0x0800AFE4,0x0800DA10,0x0800A428],
    "ptt_pa":[0x08010998,0x0800B050,0x08009A70,0x08011EAC],
    "audio":[0x0800A310,0x0800A398,0x0800B51C],
    "ui":[0x08010AB0,0x0800E454,0x0801071E],
}

def scout(payload: bytes, names: list[str], limit: int) -> dict:
    calls = find_calls(payload,[v for name in names for v in TARGETS[name]])
    report = {}
    for name in names:
        windows = []
        for start,end in WINDOWS[name]:
            rows=inspect_window(payload,start,end)
            windows.append({
                "range":[f"0x{start:08X}",f"0x{end:08X}"],
                "instructions": [
                    [r["pc"],r["mnemonic"],r["operands"],r.get("literal_value")]
                    for r in rows[:limit]
                ],
                "truncated": len(rows)>limit,
            })
        report[name] = {
            "windows": windows,
            "candidate_calls": {
                f"0x{t:08X}":calls.get(f"0x{t:08X}",[])[:40]
                for t in TARGETS[name]
            },
        }
    return report

def original_sram_mode_table(payload: bytes) -> dict:
    off=REGION_START-BASE
    src,dst,size,_=struct.unpack_from("<IIII",payload,off)
    next_src=struct.unpack_from("<I",payload,off+16)[0]
    expanded,used=decompress_region(payload[src-BASE:next_src-BASE],size)
    start=0x20000060-dst
    if start < 0 or start+0x50 > len(expanded):
        raise ValueError("OEM RF mode table is outside restored SRAM")
    values=expanded[start:start+0x50]
    return {
        "sram_address":"0x20000060",
        "bytes":values.hex(" "),
        "mode_selector_initial":expanded[0x20000069-dst],
        "mapping_initial_16":list(expanded[0x20000072-dst:0x20000082-dst]),
        "scope":"only scatterload initialization; runtime state can mutate the mapping",
        "expanded_bytes":len(expanded),
        "consumed_compressed":used,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--focus",action="append",choices=list(WINDOWS),default=[])
    p.add_argument("--limit",type=int,default=120)
    args=p.parse_args()
    payload=decoded_payload(IMAGE.read_bytes())
    report=scout(payload,args.focus or list(WINDOWS),args.limit)
    print('ORIGINAL_SRAM_RF_MODE_TABLE',json.dumps(original_sram_mode_table(payload)))
    for group, data in report.items():
        print("==",group,"==")
        for window in data["windows"]:
            print("WINDOW",*window["range"],"TRUNCATED",window["truncated"])
            for pc,mnem,ops,lit in window["instructions"]:
                print("I",pc,mnem,ops,lit or "")
        for target,callers in data["candidate_calls"].items():
            print("CANDIDATE_CALLS",target,len(callers),
                  " ".join(x["call_pc"] for x in callers))
if __name__=="__main__":
    main()
