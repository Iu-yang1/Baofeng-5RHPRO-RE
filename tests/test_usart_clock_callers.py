"""Verify V2 original USART callers, baud fields and conditional BRR math."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from usart_clock_callers import analyze_callers, predict_brr16  # noqa: E402


class USARTCallerClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_callers(decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        ))

    def test_three_uart_initializer_calls_have_explicit_baud_values(self):
        self.assertEqual(self.report["direct_caller_count"], 3)
        actual = [(x["peripheral_candidate"], x["baud"])
                  for x in self.report["callers"]]
        self.assertEqual(actual, [
            ("USART3", 19200), ("USART2", 9600), ("USART1", 115200),
        ])

    def test_predicted_brr_under_48mhz_software_model(self):
        vals = {x["peripheral_candidate"]: x["brr16_default_hypothesis"]
                for x in self.report["callers"]}
        self.assertEqual(vals, {
            "USART3": "0x04E2", "USART2": "0x09C4", "USART1": "0x01A1",
        })

    def test_preserved_pll_high_bit_changes_brr(self):
        vals = {x["peripheral_candidate"]: x["brr16_if_pll_bit28_preset"]
                for x in self.report["callers"]}
        self.assertEqual(vals, {
            "USART3": "0x1117", "USART2": "0x222E", "USART1": "0x05B2",
        })

    def test_uses_round_to_nearest_for_16x(self):
        self.assertEqual(predict_brr16(48_000_000, 115200), 417)
        self.assertEqual(predict_brr16(24_000_000, 19200), 1250)
        with self.assertRaises(ValueError):
            predict_brr16(0, 19200)


if __name__ == "__main__":
    unittest.main()
