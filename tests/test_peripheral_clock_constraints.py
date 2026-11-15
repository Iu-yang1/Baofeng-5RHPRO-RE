"""Validate conditional UART/timer divisors without assuming an MCU clock."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from clock_register_trace import analyze  # noqa: E402
from peripheral_clock_constraints import (  # noqa: E402
    report, summarize, uart_brr_candidates,
)
from mcu_fingerprint import decoded_payload  # noqa: E402


def synthetic_uart_package() -> bytes:
    payload = bytearray(0x400)
    struct.pack_into("<II", payload, 0, 0x20001000, 0x08001101)
    # LDR r0, [pc,#8] loads USART1 0x40013800 at +0x10C
    # MOVS r1,#150; STR r1,[r0,#8] = BRR; BX LR
    struct.pack_into("<HHHHI", payload, 0x100,
                     0x4802, 0x2196, 0x6081, 0x4770, 0)
    struct.pack_into("<I", payload, 0x10C, 0x40013800)
    # Extraneous data word is not an instruction-backed xref.
    struct.pack_into("<I", payload, 0x300, 0x40013808)
    header = bytearray(b"\xff" * 0x50)
    header[:7] = b"BaoFeng"
    header[0x10:0x16] = b"BF_5RH"
    header[0x20:0x28] = b"V1.0.0.0"
    header[0x30:0x38] = b"V2.0.0.0"
    struct.pack_into(">I", header, 0x40, len(payload))
    return bytes(header) + bytes(x ^ 0xC8 for x in payload)


def access(pc: int, bank: str, reg: str, value: str | None) -> dict:
    return {
        "pc": f"0x{pc:08X}", "type": "write",
        "bank": bank, "register": reg, "write_constant": value,
        "context": [],
    }


class PeripheralClockConstraintsTests(unittest.TestCase):
    def test_uart_model_is_conditional_and_exact_arithmetic(self):
        rates = uart_brr_candidates(0x0271)  # 625 divisor
        self.assertIn({"baud": 115200, "pclk_hz": 72_000_000}, rates)
        self.assertNotIn({"baud": 115200, "pclk_hz": 48_000_000}, rates)
        self.assertEqual(uart_brr_candidates(0), [])

    def test_detects_statically_reachable_usart_brr_store(self):
        p = decoded_payload(synthetic_uart_package())
        trace = analyze(p)
        rows = [x for x in trace["register_accesses"] if x["register"] == "BRR"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["address"], "0x40013808")
        self.assertEqual(rows[0]["write_constant"], "0x00000096")
        summary = report(p)
        self.assertEqual(summary["observed_brr_constant_count"], 1)
        self.assertEqual(summary["uart_brr_write_sites"][0]["peripheral"], "USART1")

    def test_timer_nearby_register_pair_yields_divisor_only(self):
        sample = {
            "scope": "reset", "unique_instruction_candidates": 8,
            "register_accesses": [
                access(0x08001100, "TIM2", "PSC", "0x00000047"),
                access(0x08001118, "TIM2", "ARR", "0x000003E7"),
            ],
        }
        s = summarize(sample)
        self.assertEqual(s["nearby_timer_psc_arr_pairs"][0]["input_clock_divisor"], 72_000)
        self.assertNotIn("frequency_hz", s["nearby_timer_psc_arr_pairs"][0])

    def test_different_timer_or_distant_write_does_not_get_paired(self):
        sample = {
            "scope": "reset", "unique_instruction_candidates": 12,
            "register_accesses": [
                access(0x08001100, "TIM2", "PSC", "0x00000047"),
                access(0x08001118, "TIM3", "ARR", "0x000003E7"),
                access(0x08002200, "TIM2", "ARR", "0x000003E7"),
                access(0x08001120, "TIM2", "ARR", None),
            ],
        }
        self.assertEqual(summarize(sample)["nearby_timer_psc_arr_pairs"], [])

    def test_uart_runtime_value_not_assumed_constant(self):
        sample = {
            "scope": "vectors", "unique_instruction_candidates": 4,
            "register_accesses": [
                access(0x08001100, "USART2", "BRR", None),
            ],
        }
        s = summarize(sample)
        self.assertEqual(s["observed_brr_constant_count"], 0)
        self.assertEqual(s["uart_brr_write_sites"][0]["conditional_pclk_candidates"], [])


if __name__ == "__main__":
    unittest.main()
