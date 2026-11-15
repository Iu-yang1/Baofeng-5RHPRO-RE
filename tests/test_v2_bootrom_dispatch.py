"""Original ROM dispatch instruction and V1/V2 equality regression tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_bootrom_dispatch import analyze, choose_path  # noqa: E402


class StockBootROMDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )
        cls.v1 = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes()
        )

    def test_uid_low_word_and_rom_callback_fingerprints(self):
        result = analyze(self.v2)
        self.assertEqual(result["uid_register_read"], "0x1FFFF7E8")
        self.assertEqual(result["read_field"], "UID[31:24] of UID low word, NOT 96-bit UID series byte")
        self.assertEqual(result["rom_callback_offset"], 12)
        self.assertEqual(result["recognized_decision_bytes"], ["0x1A","0x1B","0x1C"])
        self.assertGreaterEqual(len(result["verified_instructions"]), 20)

    def test_v1_v2_same_bootrom_dispatch_window(self):
        report = analyze(self.v2, self.v1)
        r = report["v1_v2_window_comparison"]
        self.assertEqual(r["length"], 0xD8)
        self.assertEqual(r["matching_bytes"], 0xD8)
        self.assertTrue(r["byte_for_byte_identical"])

    def test_synthetic_branches_are_only_descriptions(self):
        self.assertIn("ROM offset 0x0C", choose_path(0x1A)["dispatch"])
        self.assertIn("ROM offset 0x0C", choose_path(0x1B)["dispatch"])
        self.assertIn("temporarily adjust CRM_CFG", choose_path(0x1C)["dispatch"])
        self.assertIn("skip the ROM call", choose_path(0x19)["dispatch"])
        with self.assertRaises(ValueError):
            choose_path(-1)
        with self.assertRaises(ValueError):
            choose_path(256)

    def test_wrong_binary_does_not_reuse_old_fingerprint(self):
        modified = bytearray(self.v2)
        modified[0x080012A2 - 0x08001000] ^= 0x20
        with self.assertRaisesRegex(ValueError, "startup instruction mismatch"):
            analyze(bytes(modified))


if __name__ == "__main__":
    unittest.main()
