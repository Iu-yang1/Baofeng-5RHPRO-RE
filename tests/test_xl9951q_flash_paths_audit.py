"""Regression for stock V1/V2 Flash driver and read-only host protocol audit."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from xl9951q_flash_paths_audit import (  # noqa: E402
    BASE, STOCK, V1_DRIVER, V2_DRIVER, CLUSTER_SIZE, SCRATCH_ADDRESS,
    analyze, audit_flash_driver, audit_updater, word,
)


class StockFlashPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.firmware = {
            name: decoded_payload((ROOT / spec["path"]).read_bytes())
            for name, spec in STOCK.items()
        }
        cls.source = (ROOT / "fw_updater.py").read_text(encoding="utf-8")
        cls.pe = (ROOT / "UpgradeTool/bin/Release/net20/Radio.exe").read_bytes()

    def test_original_flash_driver_is_byte_identical(self):
        v1 = self.firmware["v1"]
        v2 = self.firmware["v2"]
        self.assertEqual(
            v1[V1_DRIVER - BASE:V1_DRIVER - BASE + CLUSTER_SIZE],
            v2[V2_DRIVER - BASE:V2_DRIVER - BASE + CLUSTER_SIZE],
        )

    def test_instruction_and_callsites_in_both_original_images(self):
        for edition in STOCK:
            with self.subTest(edition=edition):
                report = audit_flash_driver(self.firmware[edition], edition)
                self.assertEqual(len(report["flash_controller_literals"]), 5)
                self.assertEqual(len(report["direct_bl_callsites"]), 3)
                self.assertEqual(report["flash_controller_base"], "0x40022000")

    def test_high_flash_scratch_candidate_is_not_package_extent(self):
        for edition, spec in STOCK.items():
            with self.subTest(edition=edition):
                payload = self.firmware[edition]
                for address in spec["scratch_literals"]:
                    self.assertEqual(word(payload, address), SCRATCH_ADDRESS)
                self.assertLess(BASE + len(payload), SCRATCH_ADDRESS)

    def test_flash_literal_mutation_is_detected(self):
        payload = bytearray(self.firmware["v2"])
        address = V2_DRIVER + 0x38 - BASE
        payload[address] ^= 1
        with self.assertRaises(ValueError):
            audit_flash_driver(bytes(payload), "v2")

    def test_flash_program_instruction_mutation_is_detected(self):
        payload = bytearray(self.firmware["v2"])
        address = V2_DRIVER + 0x98 - BASE
        payload[address] ^= 0xFF
        with self.assertRaises(ValueError):
            audit_flash_driver(bytes(payload), "v2")

    def test_flash_unlock_key_mutation_is_detected(self):
        payload = bytearray(self.firmware["v1"])
        payload[V1_DRIVER + 0xD0 - BASE] ^= 0x01
        with self.assertRaises(ValueError):
            audit_flash_driver(bytes(payload), "v1")

    def test_actual_updater_protocol_constants(self):
        report = audit_updater(self.source)
        self.assertEqual(report["host_declared_max_bytes"], 524288)
        self.assertEqual(report["data"]["block_size_bytes"], 1024)
        self.assertEqual(
            report["erase_command_hex"],
            "462d4552415345ff2806881913031820",
        )
        self.assertEqual(report["handshake"]["v2_response_ascii"], "V2_00_00")

    def test_updater_protocol_mutation_is_detected(self):
        tampered = self.source.replace("BLOCK_SIZE = 1024", "BLOCK_SIZE = 512")
        self.assertNotEqual(tampered, self.source)
        with self.assertRaises(ValueError):
            audit_updater(tampered)

    def test_original_firmware_and_pe_report(self):
        r = analyze(self.firmware, self.source, self.pe)
        self.assertEqual(r["verified_v1_v2_flash_driver_identical_bytes"], 220)
        self.assertEqual(r["versions"]["v1"]["host_block_count"], 456)
        self.assertEqual(r["versions"]["v2"]["host_block_count"], 392)
        self.assertEqual(r["v2_high_flash_application_caller"]["copy_or_iteration_unit_bytes"], 4096)
        self.assertFalse(r["v2_high_flash_application_caller"]["physical_page_size_confirmed"])
        self.assertIn("START_ADDR", r["oem_upgrader_pe"]["ascii_metadata_token_offsets"])


if __name__ == "__main__":
    unittest.main()
