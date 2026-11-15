"""Ground TIM2/3/4 initialization timings in original V2.0.09 instructions."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from timer_clock_callers import analyze_callers  # noqa: E402


class TimerCallerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_callers(decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        ))

    def test_all_five_timer_initializers_have_clock_getter_calls(self):
        r = self.report
        self.assertEqual(r["matched_timer_call_chains"], 5)
        self.assertEqual(r["verified_timer_init_calls"], 5)
        self.assertGreaterEqual(r["verified_clock_getter_calls"], 6)

    def test_timer_bases_and_arr_are_extracted_from_instructions(self):
        actual = [
            (x["tim_name_candidate"], x["arr_value"])
            for x in self.report["callers"]
        ]
        self.assertEqual(actual, [
            ("TIM4", 208),
            ("TIM2", 125),
            ("TIM4", 104),
            ("TIM4", 125),
            ("TIM3", 1999),
        ])

    def test_one_millisecond_timer_ticks_under_48mhz_assumption(self):
        entry = next(x for x in self.report["callers"] if x["arr_value"] == 1999)
        self.assertEqual(entry["conditional_48mhz"]["psc"], 23)
        self.assertEqual(entry["conditional_48mhz"]["timer_tick_hz"], 2_000_000)
        self.assertEqual(entry["conditional_48mhz"]["update_interval_us"], 1000.0)
        self.assertTrue(all(x["divider_from_literal"] == 1_000_000
                            for x in self.report["callers"]))


if __name__ == "__main__":
    unittest.main()
