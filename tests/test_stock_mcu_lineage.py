"""Original six-version firmware lineage evidence, without probing any device."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from stock_mcu_lineage import (  # noqa: E402
    DEFAULT_IMAGES, LITERALS, analyze, assess, stock_window,
)


class SixVersionMCULineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.images = {
            name: decoded_payload((ROOT / "firmware" / name).read_bytes())
            for name in DEFAULT_IMAGES
        }
        cls.output = analyze(cls.images)

    def test_complete_stock_version_inventory(self):
        self.assertEqual(set(self.output["versions"]), set(DEFAULT_IMAGES))
        self.assertEqual(len(DEFAULT_IMAGES), 6)

    def test_original_v1_v2_shared_rom_helper_bytes(self):
        for name in ("BF_5RH_501_v1_1_04.dat",
                     "BF_5RH_501_v2_0_9.dat"):
            with self.subTest(name=name):
                row = self.output["versions"][name]
                self.assertTrue(row["helper_exactly_same_as_v2_0_9"])
                self.assertEqual(row["helper_matching_bytes_vs_v2_0_9"], 0xD8)
                self.assertEqual(row["helper_window_bytes"], 0xD8)

    def test_all_six_factory_releases_share_identical_helper_bytes(self):
        reference = self.output["versions"]["BF_5RH_501_v2_0_9.dat"]
        for name, row in self.output["versions"].items():
            with self.subTest(name=name):
                self.assertTrue(row["helper_exactly_same_as_v2_0_9"])
                self.assertEqual(
                    row["helper_window_sha256"],
                    reference["helper_window_sha256"],
                )
                self.assertEqual(row["aligned_magic_constant_words_present"], 9)
                self.assertEqual(
                    set(row["nonliteral_or_unreferenced_constant_words"]),
                    {"0x40016C18", "0xA5A5A5A5", "0x5A5A5A5A"},
                )

    def test_original_images_all_report_actual_counts(self):
        self.assertEqual(len(LITERALS), 12)
        for name, row in self.output["versions"].items():
            with self.subTest(name=name):
                self.assertEqual(
                    len(row["aligned_literal_counts"]), len(LITERALS)
                )
                self.assertEqual(
                    len(row["helper_window_sha256"]), 64
                )
                self.assertLessEqual(
                    row["helper_matching_bytes_vs_v2_0_9"], 0xD8
                )

    def test_mutated_helper_distinguishes_code_versions(self):
        ref = self.images["BF_5RH_501_v2_0_9.dat"]
        modified = bytearray(ref)
        modified[0x08001280 - 0x08001000] ^= 0x01
        result = assess(bytes(modified), ref)
        self.assertFalse(result["helper_exactly_same_as_v2_0_9"])
        self.assertEqual(result["helper_matching_bytes_vs_v2_0_9"], 0xD8 - 1)

    def test_missing_reference_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze({"other": b"\x00" * 0x1000})

    def test_no_claim_of_live_silicon_identity(self):
        self.assertIn(
            "not silicon supplier", self.output["limits"][1]
        )
        self.assertEqual(
            stock_window(self.images["BF_5RH_501_v2_0_9.dat"]),
            stock_window(self.images["BF_5RH_501_v1_1_04.dat"]),
        )


if __name__ == "__main__":
    unittest.main()
