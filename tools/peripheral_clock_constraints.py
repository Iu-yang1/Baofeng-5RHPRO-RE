#!/usr/bin/env python3
"""UART/timer clock constraints from UV-5RH Pro stock firmware (read-only).

All PCLK candidates are conditional arithmetic for an STM32F1-compatible
peripheral model, NOT a measurement of the actual MCU's oscillator.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from clock_register_trace import analyze
from mcu_fingerprint import decoded_payload

BAUD_RATES = (1200, 2400, 4800, 9600, 19200, 38400, 57600,
              115200, 230400, 460800, 921600)
MIN_PCLK = 1_000_000
MAX_PCLK = 144_000_000


def uart_brr_candidates(value: int) -> list[dict]:
    """USART oversampling-by-16 candidate PCLK = BRR * baud.

    STM32F1 BRR encodes 12-bit mantissa and 4-bit fraction, effectively
    a fixed-point 1/16 USARTDIV. This is conditional on that register model.
    """
    if not 0 < value <= 0xFFFF:
        return []
    return [
        {"baud": baud, "pclk_hz": value * baud}
        for baud in BAUD_RATES
        if MIN_PCLK <= value * baud <= MAX_PCLK
    ]


def summarize(trace: dict) -> dict:
    writes = [entry for entry in trace["register_accesses"]
              if entry["type"] == "write"]
    names = Counter(item["bank"] for item in trace["register_accesses"])
    uart_writes: list[dict] = []
    timer_writes: list[dict] = []
    for entry in writes:
        if entry["bank"].startswith(("USART", "UART")) and entry["register"] == "BRR":
            value = int(entry["write_constant"], 16) if entry["write_constant"] else None
            uart_writes.append({
                "pc": entry["pc"], "peripheral": entry["bank"],
                "brr": entry["write_constant"],
                "conditional_pclk_candidates": uart_brr_candidates(value)
                if value is not None else [],
                "context": entry["context"],
            })
        elif entry["bank"].startswith("TIM") and entry["register"] in ("PSC", "ARR"):
            timer_writes.append({
                "pc": entry["pc"], "peripheral": entry["bank"],
                "register": entry["register"],
                "constant": entry["write_constant"],
                "context": entry["context"],
            })
    # If both values are observed within a short code interval, only report
    # the mathematical divisor. Do not infer period/frequency across calls.
    pairs = []
    for p in timer_writes:
        if p["register"] != "PSC" or p["constant"] is None:
            continue
        for a in timer_writes:
            if a["peripheral"] != p["peripheral"] or a["register"] != "ARR":
                continue
            if a["constant"] is None or abs(int(p["pc"], 16)-int(a["pc"], 16)) > 0x60:
                continue
            psc = int(p["constant"], 16)
            arr = int(a["constant"], 16)
            pairs.append({
                "peripheral": p["peripheral"], "psc_pc": p["pc"],
                "arr_pc": a["pc"], "input_clock_divisor": (psc+1)*(arr+1),
                "limits": "same-instance, nearby static stores; control flow and actual clock unverified",
            })
    crm_cfg_sites = [
        {"pc": e["pc"], "type": e["type"], "context": e["context"]}
        for e in trace["register_accesses"]
        if e["bank"] == "CRM/RCC" and e["register"] == "CFG/CFGR"
        and e["type"] == "write"
    ]
    return {
        "scope": trace["scope"],
        "candidate_instruction_count": trace["unique_instruction_candidates"],
        "access_sites_by_peripheral": dict(sorted(names.items())),
        "uart_brr_write_sites": uart_writes,
        "timer_divisor_write_sites": timer_writes,
        "nearby_timer_psc_arr_pairs": pairs,
        "crm_cfg_write_sites": crm_cfg_sites,
        "observed_brr_constant_count": sum(v["brr"] is not None for v in uart_writes),
        "limitations": [
            "These are statically reachable instruction sites, not measured register transactions.",
            "UART BRR=PCLK/baud only under STM32F1-compatible oversampling-by-16 semantics.",
            "Unknown BRR writes may be calculated at runtime or passed through registers.",
            "Timer prescaler has no absolute time meaning without real TIMxCLK and ARR.",
            "APB timer clock may be doubled when APB prescaler is not 1.",
            "Absence of a write does not prove the firmware never executes it.",
            "Do not equate a PLL encoding or candidate peripheral layout with an MCU identity.",
        ],
    }


def report(payload: bytes, scope: str = "reset") -> dict:
    return summarize(analyze(payload, scope=scope))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--scope", choices=("reset", "vectors"), default="reset")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    results = []
    for path in args.images:
        result = report(decoded_payload(path.read_bytes()), args.scope)
        result["file"] = str(path)
        results.append(result)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0
    for r in results:
        print(f"== {r['file']} ({r['scope']}) ==")
        print("Decoded candidate instructions:", r["candidate_instruction_count"])
        print("Peripheral access sites:", r["access_sites_by_peripheral"])
        print("UART BRR write sites / constant values:", len(r["uart_brr_write_sites"]),
              r["observed_brr_constant_count"])
        for item in r["uart_brr_write_sites"][:40]:
            print(" ", item["pc"], item["peripheral"], item["brr"],
                  "possible PCLK:", item["conditional_pclk_candidates"][:9])
        print("Timer PSC / ARR write sites:", len(r["timer_divisor_write_sites"]))
        for item in r["timer_divisor_write_sites"][:60]:
            print(" ", item["pc"], item["peripheral"], item["register"], item["constant"])
        print("Nearby PSC/ARR pairs:", r["nearby_timer_psc_arr_pairs"][:20])
        print("CRM CFG stores:", len(r["crm_cfg_write_sites"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
