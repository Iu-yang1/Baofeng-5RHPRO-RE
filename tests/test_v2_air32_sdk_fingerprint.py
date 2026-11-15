"""Regression tests for the stock AIR32-SDK lineage signature (not silicon ID)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_air32_sdk_fingerprint import analyze  # noqa: E402


class Air32SdkFingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )
        cls.v1 = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes()
        )

    def test_full_signature_is_present_in_original_stock_image(self):
        report = analyze(self.v2, self.v1)
        self.assertEqual(len(report["verified_helper_literal_pool"]), 10)
        self.assertEqual(report["rom_callback"], "[0x1FFFD000 + 0x0C]")
        self.assertEqual(report["reset_clock_software_hypothesis_hz"], 48_000_000)
        self.assertEqual(report["callsite"]["conditional_target_frequency_hz"], 128_000_000)
        self.assertEqual(report["physical_mcu_id"], "unconfirmed")
        self.assertIn("256 KiB", report["flash_size_conflict"])
        self.assertIn("AIR32F103 SDK", report["lineage"])

    def test_mutated_rom_key_is_rejected(self):
        payload = bytearray(self.v2)
        payload[0x080013E8 - 0x08001000] ^= 0x10
        with self.assertRaisesRegex(ValueError, "AIR32 SDK literal mismatch"):
            analyze(bytes(payload))

    def test_mutated_sram_window_setting_is_rejected(self):
        payload = bytearray(self.v2)
        payload[0x080013F8 - 0x08001000] ^= 0x01
        with self.assertRaisesRegex(ValueError, "AIR32 SDK literal mismatch"):
            analyze(bytes(payload))

    def test_mutated_pll_multiplier_is_rejected(self):
        payload = bytearray(self.v2)
        # Explicit caller instruction at 0x08032380: MOV.W r1,#0x380000.
        payload[0x08032380 - 0x08001000] ^= 0x01
        with self.assertRaises(ValueError):
            analyze(bytes(payload))


if __name__ == "__main__":
    unittest.main()
