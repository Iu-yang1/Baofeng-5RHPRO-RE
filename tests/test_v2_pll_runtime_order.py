"""Offline, original-byte tests for reset/main/PLL/USART/TIM sequencing."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_pll_runtime_order import analyze, verify_reset_to_main, V1, V2  # noqa: E402


class RuntimeClockOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = decoded_payload((ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes())
        cls.v1 = decoded_payload((ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes())
        cls.report = analyze(cls.v2, cls.v1)

    def test_reset_statically_targets_main_before_pll(self):
        r = self.report["reset_to_main"]
        self.assertEqual(r["reset_vector"], "0x0800123D")
        self.assertEqual(r["post_scatterload_main_pointer_at_0x0800122C"], "0x080340E1")
        self.assertEqual(r["main_pll_call"], "0x080340EA")
        self.assertEqual(self.report["main_early_calls"][:2], [
            {"call": "0x080340E6", "callee": "0x080309BC"},
            {"call": "0x080340EA", "callee": "0x080173DC"},
        ])

    def test_clock_getter_and_tim3_init_are_reachable_after_pll_call(self):
        paths = self.report["main_to_peripheral_callsite_paths"]
        self.assertEqual(
            paths["0x080193FC"][0]["path"][0]["call"], "0x080340EA"
        )
        self.assertEqual(
            paths["0x08019426"][0]["path"][-1]["callee"], "0x080324F8"
        )

    def test_all_three_usart_init_calls_have_main_paths(self):
        paths = self.report["main_to_peripheral_callsite_paths"]
        for pc in ("0x0800CA2A", "0x08010306", "0x08018C20"):
            with self.subTest(pc=pc):
                self.assertIn(pc, paths)
                first = paths[pc][0]["path"][0]["call"]
                self.assertGreater(int(first, 16), 0x080340EA)
                self.assertEqual(paths[pc][0]["path"][-1]["callee"], "0x08032CDC")

    def test_48mhz_reset_and_128mhz_conditional_predictions(self):
        model = self.report["clock_and_peripheral_hypotheses"]
        self.assertEqual(model["early_reset_sysclk_hz"], 48_000_000)
        self.assertEqual(model["post_rom_pll_request_sysclk_hz"], 128_000_000)
        by_name = {x["name"]: x for x in model["usart_brr16_comparison"]}
        self.assertEqual({k: v["post_128mhz_brr16_hypothesis"] for k, v in by_name.items()}, {
            "USART1": "0x0457", "USART2": "0x1A0B", "USART3": "0x0D05"
        })
        tim = model["post_128mhz_hypothesis"]
        self.assertEqual(tim["tim3_psc_if_live_pclk1"], 63)
        self.assertEqual(tim["tim3_update_us"], 1000.0)
        self.assertEqual(model["read_live_clock_evidence"]["USART_Init_clock_getter_call"],
                         "0x08032D18")

    def test_v1_uses_the_same_reset_main_pll_structure(self):
        v1 = self.report["v1_cross_version"]
        self.assertEqual(v1["post_scatterload_main_pointer_at_0x0800122C"], "0x08027BE9")
        self.assertEqual(v1["main_pll_call"], "0x08027BF2")
        self.assertEqual(v1["pll_driver"], "0x0802622A")

    def test_real_payload_mutation_invalidates_reset_link(self):
        modified = bytearray(self.v2)
        modified[0x0800122C - 0x08001000] ^= 0x20
        with self.assertRaises(ValueError):
            verify_reset_to_main(bytes(modified), V2, True)

    def test_real_payload_mutation_invalidates_pll_call(self):
        modified = bytearray(self.v2)
        modified[0x080340EA - 0x08001000] ^= 0x01
        with self.assertRaises(ValueError):
            verify_reset_to_main(bytes(modified), V2, True)

    def test_v1_payload_mutation_invalidates_main_link(self):
        modified = bytearray(self.v1)
        modified[0x0800122C - 0x08001000] ^= 0x04
        with self.assertRaises(ValueError):
            verify_reset_to_main(bytes(modified), V1, False)


if __name__ == "__main__":
    unittest.main()
