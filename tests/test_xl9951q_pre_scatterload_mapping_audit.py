"""Read-only original-firmware stage ordering and compressed high Flash source."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from xl9951q_pre_scatterload_mapping_audit import (  # noqa: E402
    IMAGE_BASE, analyze, describe_source_span,
)


class HighFlashSpanTests(unittest.TestCase):
    def test_valid_source_in_decoded_package(self):
        row = describe_source_span(0x70000, IMAGE_BASE + 0x60A54, 101)
        self.assertEqual(row["source_package_offset_bytes"], 0x60A54)
        self.assertEqual(row["bytes_consumed_from_package"], 101)
        self.assertEqual(row["minimum_linear_window_kib_from_0x08000000"], 391)
        self.assertTrue(row["source_is_contained_in_original_package"])

    def test_reject_missing_truncated_and_outside(self):
        for size, address, count in (
            (0x100, IMAGE_BASE - 4, 4),
            (0x100, IMAGE_BASE, 0),
            (0x100, IMAGE_BASE + 0xFF, 4),
            (0x100, IMAGE_BASE, -1),
            (0, IMAGE_BASE, 1),
        ):
            with self.subTest(size=size, address=address, count=count):
                with self.assertRaises(ValueError):
                    describe_source_span(size, address, count)


class ActualStockMappingOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v1 = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes()
        )
        cls.v2 = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )
        cls.result = analyze(cls.v2, cls.v1)

    def test_v2_original_compressed_source_is_in_upgrade_payload(self):
        data = self.result["v2"]["scatterload_source"]
        self.assertEqual(data["source_address"], "0x08061A54")
        self.assertEqual(data["source_package_offset_bytes"], 0x60A54)
        self.assertEqual(data["package_size_bytes"], 401408)
        self.assertTrue(data["source_is_contained_in_original_package"])
        self.assertGreater(data["bytes_consumed_from_package"], 0)
        self.assertLess(
            data["source_package_offset_bytes"]+data["bytes_consumed_from_package"],
            data["package_size_bytes"]+1,
        )
        self.assertEqual(len(data["compressed_source_sha256"]), 64)

    def test_compressed_sram_is_reconstructed_from_high_program_source(self):
        restore = self.result["v2"]["sram_restore"]
        self.assertEqual(restore["size_bytes"], 7084)
        self.assertEqual(
            restore["decompressed_sha256"],
            "78b4cd40871079ecc1ceacf33f1379a8c76ea84a2b3b7155b98c4753d5ae7627",
        )
        self.assertEqual(
            restore["compressed_bytes_consumed"],
            self.result["v2"]["scatterload_source"]["bytes_consumed_from_package"],
        )

    def test_v2_helper_stage_follows_scatterload_and_main(self):
        data = self.result["v2"]
        self.assertEqual(data["rom_helper_bl_sites"], ["0x08032386"])
        self.assertEqual(data["reset_to_main"]["main_entry"], "0x080340E0")
        self.assertEqual(
            data["air32_sdk_qspi_control_sites"]["control_mmio"], "0x4002228C"
        )
        self.assertEqual(
            data["air32_sdk_qspi_control_sites"]["unlock_store_pc"], "0x0800129E"
        )
        self.assertEqual(
            data["air32_sdk_qspi_control_sites"]["restore_store_pc"], "0x0800133A"
        )

    def test_v1_has_same_shared_helper_but_separate_application_callsite(self):
        v1 = self.result["v1"]
        self.assertTrue(v1["same_216_byte_rom_helper_as_v2"])
        self.assertEqual(v1["rom_helper_direct_bl_sites"], ["0x08026252"])
        self.assertEqual(v1["verified_reset_to_main"]["main_entry"], "0x08027BE8")

    def test_no_claim_that_external_spi_nor_is_xip(self):
        hypotheses = self.result["hypotheses"]
        self.assertIn("not established", hypotheses["gt25q16a_external_nor_xip_alias"])
        self.assertIn(
            "after the already completed scatterload",
            hypotheses["air32_sdk_qspi_unlock_as_external_spi_nor_mapper"],
        )
        self.assertIn(
            "native on-chip capacity still not measured",
            hypotheses["ordinary_contiguous_program_flash"],
        )

    def test_modified_high_source_is_detected_by_decompress_digest(self):
        wrong = bytearray(self.v2)
        wrong[0x08061A54-IMAGE_BASE + 1] ^= 0x80
        with self.assertRaises(ValueError):
            analyze(bytes(wrong), self.v1)

    def test_modified_rom_helper_is_rejected(self):
        wrong = bytearray(self.v2)
        wrong[0x080013E8-IMAGE_BASE] ^= 1
        with self.assertRaises(ValueError):
            analyze(bytes(wrong), self.v1)


if __name__ == "__main__":
    unittest.main()
