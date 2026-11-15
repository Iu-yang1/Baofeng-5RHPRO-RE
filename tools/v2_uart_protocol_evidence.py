#!/usr/bin/env python3
"""Validate concrete V2 UART handler and protocol fingerprints from Thumb code.

This reports direct source-level evidence, not a pinout or known implementation
of Baofeng's proprietary protocol. No serial communication or firmware write.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from v2_uart_irq_evidence import vector_evidence


def _one(payload: bytes, pc: int) -> dict:
    matches = inspect_window(payload, pc, pc + 4)
    if not matches or matches[0]["pc"] != f"0x{pc:08X}":
        raise ValueError(f"disassembly did not start at 0x{pc:08X}")
    return matches[0]


def _verify(payload: bytes, pc: int, mnemonic: str,
            operand_fragment: str, literal: str | None = None) -> dict:
    item = _one(payload, pc)
    if not item["mnemonic"].startswith(mnemonic) or operand_fragment not in item["operands"]:
        raise ValueError(f"V2 protocol fingerprint mismatch at 0x{pc:08X}")
    if literal is not None and item.get("literal_value") != literal:
        raise ValueError(f"V2 protocol literal changed at 0x{pc:08X}")
    return {
        "pc": item["pc"],
        "instruction": f'{item["mnemonic"]} {item["operands"]}',
        **({"literal_value": item["literal_value"]} if "literal_value" in item else {}),
    }


def analyze(payload: bytes) -> dict:
    vectors = vector_evidence(payload)
    gnss = [
        _verify(payload, 0x08032BAA, "ldr", "r4, [pc", "0x40004400"),
        _verify(payload, 0x08032BCC, "ldr", "r0, [pc", "0x4002006C"),
        _verify(payload, 0x08032BDE, "b", "#0x800f1cc"),
        _verify(payload, 0x0800F204, "ldr", "r0, [pc", "0x4002006C"),
        _verify(payload, 0x0800F222, "ldr", "r8, [pc", "0x2000EB88"),
        _verify(payload, 0x0800F22A, "cmp", "r0, #0x24"),
        _verify(payload, 0x0800F234, "cmp", "r1, #0x47"),
        _verify(payload, 0x0800F244, "cmp", "r1, #0x47"),
        _verify(payload, 0x0800F24A, "cmp", "r0, #0x41"),
        _verify(payload, 0x08010388, "mov", "r0, #0x500"),
    ]
    protocol = [
        _verify(payload, 0x08032BEE, "ldr", "r4, [pc", "0x40004800"),
        _verify(payload, 0x08032C10, "ldr", "r0, [pc", "0x40020030"),
        _verify(payload, 0x0800CA9E, "ldr", "r0, [pc", "0x40004800"),
        _verify(payload, 0x0800CAA6, "ldr", "r0, [pc", "0x2000F218"),
        _verify(payload, 0x0800CAAC, "mov", "r0, #0xc8"),
        _verify(payload, 0x080063CE, "ldr", "r5, [pc", "0x40004800"),
        _verify(payload, 0x080063D0, "ldr", "sb, [pc", "0x20001850"),
        _verify(payload, 0x080063DA, "ldrb", "r0, [sb, #2]"),
        _verify(payload, 0x080063DE, "eors", "r6, r0"),
        _verify(payload, 0x080063F4, "bl", "#0x8032d98"),
    ]
    console = [
        _verify(payload, 0x08032B44, "ldr", "r7, [pc", "0x40013800"),
        _verify(payload, 0x08032B46, "movw", "r1, #0x525"),
        _verify(payload, 0x08032B54, "ldr", "r4, [pc", "0x200000FE"),
        _verify(payload, 0x08032B56, "movs", "r5, #0x14"),
        _verify(payload, 0x08032B58, "ldr", "r6, [pc", "0x200045A7"),
        _verify(payload, 0x08032B6E, "bl", "#0x8032d90"),
    ]
    return {
        "target": "Baofeng UV-5RH Pro stock V2.0.09",
        "gnss_nmea_rx": {
            "uart": "USART2",
            "baud": 9600,
            "irq_vector": vectors["USART2"],
            "dma_source_register": "0x4002006C",
            "dma_candidate": "DMA1_Channel6 under STM32F1-compatible addressing",
            "destination_buffer_sram": "0x2000EB88",
            "dma_transfer_length": 1280,
            "sentence_prefix": "$??GGA",
            "interpretation": "GPS/GNSS NMEA parser; UART device association strongly supported",
            "instruction_evidence": gnss,
        },
        "private_serial_protocol_candidate": {
            "uart": "USART3",
            "baud": 19200,
            "irq_vector": vectors["USART3"],
            "dma_source_register": "0x40020030",
            "dma_candidate": "DMA1_Channel3 under STM32F1-compatible addressing",
            "destination_buffer_sram": "0x2000F218",
            "dma_transfer_length": 200,
            "tx_byte_encoding": "byte XOR byte_at_0x20001852",
            "role": "not yet established; CPS/programming is a candidate, not a finding",
            "instruction_evidence": protocol,
        },
        "usart1_irq_ring": {
            "uart": "USART1",
            "baud": 115200,
            "irq_vector": vectors["USART1"],
            "irq_receive_event_constant": "0x0525",
            "rx_index_sram": "0x200000FE",
            "rx_ring_sram": "0x200045A7",
            "ring_capacity_bytes": 20,
            "role": "not established",
            "instruction_evidence": console,
        },
        "limitations": [
            "Peripheral labels and DMA channel numbers follow candidate STM32F1 map.",
            "The instruction evidence does not determine actual MCU or physical pin assignment.",
            "Private XOR path may be encoded for a service other than programming.",
            "The existence of a parser does not prove which NMEA sentence types are enabled on a physical radio.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = analyze(decoded_payload(args.firmware.read_bytes()))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for name in ("gnss_nmea_rx", "private_serial_protocol_candidate", "usart1_irq_ring"):
            item = result[name]
            print(name, item["uart"], item["baud"], "evidence", len(item["instruction_evidence"]))
            for row in item["instruction_evidence"]:
                print(" ",row["pc"],row["instruction"],row.get("literal_value", ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
