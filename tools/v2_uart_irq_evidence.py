#!/usr/bin/env python3
"""Read-only UART/IRQ evidence map for the UV-5RH Pro V2.0.09 image.

Literal cross-references are disassembled instruction *candidates*. Never
infer a physical pin, device role, or interrupt activity from these alone.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_callsites import find_calls

BASE = 0x08001000
SITES = {
    0x40004400: "USART2",
    0x40004800: "USART3",
    0x40013800: "USART1",
    0x40010000: "AFIO",
    0x40010800: "GPIOA",
    0x40010C00: "GPIOB",
    0x40011000: "GPIOC",
    0x40011400: "GPIOD",
    0x40020000: "DMA1",
    0x40020400: "DMA2",
}
IRQ_NUMBERS = {
    "DMA1_Channel4": 14,
    "DMA1_Channel5": 15,
    "USART1": 37,
    "USART2": 38,
    "USART3": 39,
}
SDK_HELPERS = {
    "USART_Init_candidate": 0x08032CDC,
    "USART_Cmd_candidate": 0x08032C3C,
    "USART_ITConfig_candidate": 0x08032CAC,
    "USART_clock_getter": 0x08030C30,
}


def literal_references(payload: bytes) -> list[dict]:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    output = []
    for offset in range(0, len(payload)-3, 2):
        first = struct.unpack_from("<H", payload, offset)[0]
        if (first & 0xF800) != 0x4800 and (first & 0xFFF0) not in (0xF85F, 0xF8DF):
            continue
        pc = BASE + offset
        ins = next(md.disasm(payload[offset:offset+4], pc, count=1), None)
        if ins is None or not ins.mnemonic.startswith("ldr"):
            continue
        for op in ins.operands[1:]:
            if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index:
                continue
            location = ((pc + 4) & ~3) + op.mem.disp
            if not (BASE <= location <= BASE+len(payload)-4) or location % 4:
                continue
            value = struct.unpack_from("<I", payload, location-BASE)[0]
            if value not in SITES:
                continue
            output.append({
                "pc": f"0x{pc:08X}",
                "instruction": f"{ins.mnemonic} {ins.op_str}",
                "pool_pc": f"0x{location:08X}",
                "literal": f"0x{value:08X}",
                "peripheral": SITES[value],
            })
    return output


def vector_evidence(payload: bytes) -> dict:
    if len(payload) < 256:
        raise ValueError("candidate 64-entry vector table incomplete")
    result = {}
    for name, irqn in IRQ_NUMBERS.items():
        word = struct.unpack_from("<I", payload, 4*(16+irqn))[0]
        result[name] = {
            "irqn_under_stm32f1_map": irqn,
            "vector_index": 16+irqn,
            "value": f"0x{word:08X}",
            "plausible_thumb_handler": bool(
                word & 1 and BASE <= (word & ~1) < BASE+len(payload)
            ),
        }
    return result


def analyze(payload: bytes) -> dict:
    refs = literal_references(payload)
    calls = find_calls(payload, list(SDK_HELPERS.values()))
    summary = Counter(r["peripheral"] for r in refs)
    return {
        "firmware_base_assumption": f"0x{BASE:08X}",
        "register_literal_site_counts": dict(sorted(summary.items())),
        "register_literal_references": refs,
        "candidate_usart_irq_vectors": vector_evidence(payload),
        "sdk_candidate_direct_caller_counts": {
            name: len(calls[f"0x{address:08X}"])
            for name,address in SDK_HELPERS.items()
        },
        "sdk_candidate_caller_samples": {
            name: calls[f"0x{address:08X}"][:32]
            for name,address in SDK_HELPERS.items()
        },
        "limitations": [
            "All-image halfword-sweep can decode data as Thumb and miss indirect references.",
            "IRQ numbers are candidates according to STM32F1-compatible vector ordering.",
            "None of these xrefs demonstrates the UART-to-GNSS or K-port pin mapping.",
            "Some code in the image may not execute on this hardware revision.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    result = analyze(decoded_payload(args.image.read_bytes()))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("Peripheral literal references:", result["register_literal_site_counts"])
        print("USART IRQ candidates:", result["candidate_usart_irq_vectors"])
        print("SDK helper direct caller counts:", result["sdk_candidate_direct_caller_counts"])
        for row in result["register_literal_references"]:
            if row["peripheral"].startswith("USART"):
                print("UART_REF",row["peripheral"],row["pc"],row["instruction"])
        for name,rows in result["sdk_candidate_caller_samples"].items():
            print("CALLS", name, " ".join(x["call_pc"] for x in rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
