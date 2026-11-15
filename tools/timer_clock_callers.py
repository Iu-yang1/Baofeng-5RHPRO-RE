#!/usr/bin/env python3
"""Find actual V2 clock-getter/TIM_TimeBaseInit call pairs and ARR values.

The output describes firmware *instructions and conditional timing*, not a
measured timer tick or an identification of what each timer does on the radio.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window
from v2_clock_tree_model import analyze as clock_analyze

CLOCK_GETTER = 0x08030C30
TIMER_INIT = 0x080324F8
# The timer-base source PC is independently observed from each caller; this
# dictionary is only a lookup for a static operand that we verify at runtime.
TIMER_BASE_INSTRUCTIONS = {
    0x0800893C: 0x0800892A,
    0x08009E98: 0x08009E88,
    0x08012344: 0x08012332,
    0x0801714E: 0x0801713E,
    0x080193FC: 0x08019418,
}
REGISTER_BASES = {
    0x40000000: "TIM2",
    0x40000400: "TIM3",
    0x40000800: "TIM4",
}


def _immediate(text: str) -> int | None:
    found = re.search(r"r(?:0|5), #(?:0x[0-9a-f]+|\d+)", text)
    return int(text.split("#")[-1], 0) if found else None


def _timer_base(payload: bytes, clock_call: int) -> int:
    entry = inspect_window(payload, TIMER_BASE_INSTRUCTIONS[clock_call],
                           TIMER_BASE_INSTRUCTIONS[clock_call] + 4)[0]
    if "literal_value" in entry:
        return int(entry["literal_value"], 16)
    if entry["mnemonic"].startswith("mov"):
        val = _immediate(entry["operands"])
        if val is not None:
            return val
    raise ValueError(f"no grounded timer base for caller 0x{clock_call:08X}")


def analyze_callers(payload: bytes) -> dict:
    calls = find_calls(payload, [CLOCK_GETTER, TIMER_INIT])
    clocks = [int(e["call_pc"], 16) for e in calls[f"0x{CLOCK_GETTER:08X}"]]
    timers = [int(e["call_pc"], 16) for e in calls[f"0x{TIMER_INIT:08X}"]]
    tree = clock_analyze(payload)
    pclk1 = tree["reset_default_software_profile"]["pclk1_hz"]
    timer_clock = tree["reset_default_software_profile"]["apb1_timer_clock_hz"]
    out = []
    for clock_call in clocks:
        tim_call = next((t for t in timers if clock_call < t <= clock_call + 0x60), None)
        if tim_call is None:
            continue
        entries = inspect_window(payload, clock_call + 4, tim_call)
        arr = None
        arr_pc = None
        pclk_read = None
        divider = None
        for i, entry in enumerate(entries):
            if entry["mnemonic"].startswith("ldr") and entry["operands"] == "r0, [sp, #0x18]":
                pclk_read = entry["pc"]
            if entry.get("literal_value") == "0x000F4240":
                divider = 1_000_000
            if (entry["mnemonic"].startswith("strh")
                    and entry["operands"] == "r0, [sp, #4]" and i > 0):
                prev = entries[i-1]
                if prev["mnemonic"].startswith("mov"):
                    arr = _immediate(prev["operands"])
                    arr_pc = entry["pc"]
        base = _timer_base(payload, clock_call)
        result = {
            "clock_getter_call": f"0x{clock_call:08X}",
            "timer_init_call": f"0x{tim_call:08X}",
            "tim_base": f"0x{base:08X}",
            "tim_name_candidate": REGISTER_BASES.get(base, "unknown"),
            "pclk1_struct_read": pclk_read,
            "divider_from_literal": divider,
            "arr_immediate_pc": arr_pc,
            "arr_value": arr,
            "prescaler_formula": "floor(PCLK1 / 1_000_000) - 1",
        }
        if arr is not None and divider == 1_000_000 and pclk_read is not None:
            prescaler = pclk1 // divider - 1
            tick_hz = timer_clock // (prescaler + 1)
            result["conditional_48mhz"] = {
                "pclk1_hz": pclk1,
                "timer_input_hz": timer_clock,
                "psc": prescaler,
                "timer_tick_hz": tick_hz,
                "update_interval_us": round((arr + 1) * 1e6 / tick_hz, 3),
                "update_rate_hz": round(tick_hz / (arr + 1), 3),
            }
        out.append(result)
    return {
        "verified_clock_getter_calls": len(clocks),
        "verified_timer_init_calls": len(timers),
        "matched_timer_call_chains": len(out),
        "clock_setup_assumption": "HSE=8MHz, PLL x6, APB1 /2, APB1 TIM clock x2",
        "callers": out,
        "limits": [
            "Disassembled callsites describe possible code paths, not runtime execution.",
            "PCLK1 must reflect the real initialized SRAM prescaler lookup table.",
            "Timer overflows also depend on counter mode and enable state.",
            "Observed 1ms timing does not independently distinguish 48 and 168MHz: the PSC scales with PCLK1.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    report = analyze_callers(decoded_payload(a.image.read_bytes()))
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print("Pairs:", report["matched_timer_call_chains"])
        for entry in report["callers"]:
            print(entry["clock_getter_call"], "->", entry["timer_init_call"],
                  entry["tim_name_candidate"], "ARR", entry["arr_value"],
                  "conditional 48MHz timing", entry.get("conditional_48mhz"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
