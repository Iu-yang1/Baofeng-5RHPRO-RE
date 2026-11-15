"""Regression tests for UID-dispatched CFGR writes and limited MMIO xrefs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_rom_cfgr_mmio_audit import (  # noqa: E402
    analyze, branch_cfgr_effect, scan_local_rcc_writes,
)


class BootROMCFGRMMIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = decoded_payload((ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes())
        cls.v1 = decoded_payload((ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes())
        cls.report = analyze(cls.v2, cls.v1)

    def test_exact_1c_mask_register_and_full_register_sequence(self):
        r = self.report["rom_dispatch"]
        self.assertEqual(r["uid_1c_pre_mask"], "0xEFC3FFFF")
        self.assertEqual(r["uid_1c_cleared_bits_mask"], "0x103C0000")
        self.assertEqual(r["uid_1c_pre_write_sites"], ["0x080012F0", "0x080012F8"])
        self.assertEqual(r["common_cfgr_write_pc"], "0x08001316")
        self.assertEqual(r["uid_1c_example_input_cfgr_0"], "0x00380000")
        self.assertEqual(r["common_example_input_cfgr_0"], "0x00010000")
        self.assertGreaterEqual(len(r["instruction_checks"]), 28)

    def test_uid_rom_register_abi_is_correct_per_branch(self):
        r = self.report["rom_dispatch"]
        branches = {b["uid_lowword_high_byte"]: b for b in r["branches"]}
        self.assertEqual(branches["0x1A"]["callback_abi"], branches["0x1B"]["callback_abi"])
        self.assertEqual(branches["0x1A"]["callback_abi"]["r3"], "0x00000001")
        self.assertEqual(branches["0x1C"]["callback_abi"]["r0"], "0x00000001")
        self.assertEqual(branches["0x1C"]["callback_abi"]["r3"], "ROM callback pointer")
        self.assertIsNone(branches["0x55"]["callback_abi"])
        self.assertTrue(r["v1_v2_shared_window"]["byte_for_byte_identical"])

    def test_rom_register_writes_appear_in_local_literal_scan(self):
        results = self.report["v2_rcc_literal_local_scan"]["straight_line_store_candidates"]
        locations = {(row["store_pc"], row["address"]) for row in results}
        for expected in (
            ("0x080012F0", "0x40021004"),
            ("0x080012F8", "0x40021004"),
            ("0x08001316", "0x40021004"),
            ("0x08001342", "0x400210F0"),
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, locations)

    def test_real_mask_literal_corruption_is_rejected(self):
        p = bytearray(self.v2)
        p[0x08001408 - 0x08001000] ^= 0x01
        with self.assertRaises(ValueError):
            branch_cfgr_effect(bytes(p))

    def test_real_branch_instruction_corruption_is_rejected(self):
        p = bytearray(self.v2)
        p[0x080012F0 - 0x08001000] ^= 0x01
        with self.assertRaises(ValueError):
            branch_cfgr_effect(bytes(p))

    def test_v1_and_v2_have_independent_scanned_mmio_metadata(self):
        for key in ("v1_rcc_literal_local_scan", "v2_rcc_literal_local_scan"):
            scan = self.report[key]
            self.assertTrue(scan["literal_load_candidate_sites"])
            self.assertGreater(len(scan["straight_line_store_candidates"]), 0)
            self.assertIn("Neither completeness", scan["not_proven"])


if __name__ == "__main__":
    unittest.main()
