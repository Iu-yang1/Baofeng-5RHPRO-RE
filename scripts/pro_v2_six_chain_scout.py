#!/usr/bin/env python3
"""Source-only focused V2 six-chain disassembly scout (no device access).

Run with --focus one or several names. This tool makes *candidate observations*;
linear windows and halfword-sweep BL references are NOT proof of actual paths.
Use fixed-callsite and CFG checks before accepting a board HAL identity.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls

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
        (0x08006B18,0x08006BB8),
        (0x080141D8,0x08014230),
        (0x08017200,0x08017338),
        (0x080328D8,0x08032960),
    ],
    "rf_modes": [
        (0x0800DDA8,0x0800DDD8),
        (0x0800AFD0,0x0800B118),
        (0x08012BAC,0x08012C1C),
        (0x0800DA10,0x0800DA78),
    ],
    "ptt_pa": [
        (0x08010990,0x08010A48),
        (0x08010710,0x08010792),
        (0x0800B050,0x0800B114),
        (0x08009A70,0x08009ABC),
        (0x08009B70,0x08009BC0),
        (0x08011EA8,0x08011F78),
    ],
    "audio": [
        (0x0800A300,0x0800A3C8),
        (0x0800B500,0x0800B650),
        (0x0800BB70,0x0800BC98),
        (0x0800A8B0,0x0800A988),
        (0x08006138,0x080061A0),
    ],
    "ui": [
        (0x08010AB0,0x08010CE0),
        (0x0800E440,0x0800E4E0),
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

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--focus",action="append",choices=list(WINDOWS),default=[])
    p.add_argument("--limit",type=int,default=120)
    args=p.parse_args()
    report=scout(decoded_payload(IMAGE.read_bytes()),args.focus or list(WINDOWS),args.limit)
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
