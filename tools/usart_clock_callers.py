#!/usr/bin/env python3
"""Extract actual V2 USART_Init callers, baud fields and conditional BRR.

Original register addresses and argument constants are validated against
decoded instructions; predicted BRRs are not measurements of MCU registers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls
from thumb_window import inspect_window
from v2_clock_tree_model import analyze as analyze_clock

USART_INIT = 0x08032CDC
START_BOUNDARY = {
    0x0800CA2A: 0x0800C9C0,
    0x08010306: 0x080102A0,
    0x08018C20: 0x08018BB4,
}
UART_BASES = {
    0x40004400: ("USART2", "PCLK1"),
    0x40004800: ("USART3", "PCLK1"),
    0x40013800: ("USART1", "PCLK2"),
}
ACCEPTED_BAUDS = {2400, 4800, 9600, 19200, 38400, 57600,
                  115200, 230400, 460800, 921600}


def _mov_imm(entry: dict) -> int | None:
    if not entry["mnemonic"].startswith("mov"):
        return None
    match = re.fullmatch(r"r0, #(0x[0-9a-f]+|\d+)", entry["operands"])
    return int(match.group(1), 0) if match else None


def predict_brr16(pclk: int, baud: int) -> int:
    """STM32-compatible oversampling-by-16 BRR estimate.

    For oversampling 16, the mantissa:fraction encoding reduces to rounded
    PCLK/baud. This is not correct if OVER8=1 or register semantics differ.
    """
    if pclk <= 0 or baud <= 0:
        raise ValueError("positive PCLK and baud are required")
    return (pclk + baud//2) // baud


def analyze_callers(payload: bytes) -> dict:
    callers = find_calls(payload, [USART_INIT])[f"0x{USART_INIT:08X}"]
    clock = analyze_clock(payload)
    profile = clock["reset_default_software_profile"]
    alternatives = clock["bit28_preexisting_alternative"]
    output = []
    for item in callers:
        call_pc = int(item["call_pc"], 16)
        start = START_BOUNDARY.get(call_pc)
        if start is None:
            output.append({
                "call_pc": item["call_pc"], "status": "not_inspected",
            })
            continue
        entries = inspect_window(payload, start, call_pc)
        baud_candidates = []
        uart_base_candidates = set()
        for index, entry in enumerate(entries):
            if "literal_value" in entry:
                value = int(entry["literal_value"], 16)
                if value in UART_BASES:
                    uart_base_candidates.add(value)
            value = _mov_imm(entry)
            if value is not None and value in ACCEPTED_BAUDS and index+1 < len(entries):
                nxt = entries[index+1]
                if nxt["mnemonic"].startswith("str") and nxt["operands"].startswith("r0, [sp"):
                    baud_candidates.append({
                        "baud": value,
                        "store_pc": nxt["pc"],
                        "store_instruction": nxt["operands"],
                    })
        if len(baud_candidates) != 1 or len(uart_base_candidates) != 1:
            raise ValueError(f"ambiguous V2 USART caller parameters: {item['call_pc']}")
        baud = baud_candidates[0]
        base = next(iter(uart_base_candidates))
        name, bus = UART_BASES[base]
        pclk = profile["pclk1_hz" if bus == "PCLK1" else "pclk2_hz"]
        alternative_pclk = alternatives["pclk1_hz" if bus == "PCLK1" else "pclk2_hz"]
        output.append({
            "call_pc": item["call_pc"],
            "baud_store_pc": baud["store_pc"],
            "baud_struct_store": baud["store_instruction"],
            "baud": baud["baud"],
            "peripheral_base": f"0x{base:08X}",
            "peripheral_candidate": name,
            "clock_bus_candidate": bus,
            "clock_default_hz": pclk,
            "brr16_default_hypothesis": f"0x{predict_brr16(pclk, baud['baud']):04X}",
            "clock_if_pll_bit28_preset_hz": alternative_pclk,
            "brr16_if_pll_bit28_preset": f"0x{predict_brr16(alternative_pclk, baud['baud']):04X}",
            "confidence": "baud/base evidenced by original Thumb instructions; BRR conditional",
        })
    return {
        "usart_init_callee": f"0x{USART_INIT:08X}",
        "direct_caller_count": len(callers),
        "callers": output,
        "constraints": [
            "Baud and base are literal parameters in reachable initialization code.",
            "Their device roles (GNSS, CPS, console etc.) require RX/TX call graph analysis.",
            "Actual baud on the wire and actual BRR registers were not measured.",
            "BRR computed under 16x oversampling; USART_Init handles OVER8 separately.",
            "Clock model assumes HEXT 8MHz and a zero reset-state extended multiplier bit.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    r = analyze_callers(decoded_payload(args.firmware.read_bytes()))
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        for row in r["callers"]:
            print(row["call_pc"], row.get("peripheral_candidate"), row.get("baud"),
                  "default BRR16", row.get("brr16_default_hypothesis"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
