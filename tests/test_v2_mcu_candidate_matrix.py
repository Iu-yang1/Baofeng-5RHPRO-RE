"""MCU exclusion and vendor device-id tests based on actual V2 firmware."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from at32_readonly_id_decode import inspect  # noqa: E402
from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_mcu_candidate_matrix import analyze, compare_spec, SPECS  # noqa: E402


class MCUFamilyIdentificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )
        cls.report = analyze(cls.payload)

    def test_source_comes_from_original_scatterload(self):
        evidence = self.report["evidence"]
        self.assertEqual(evidence["actual_scatterload_source_pc"], "0x08061A54")
        self.assertEqual(evidence["initial_sp"], "0x20011308")
        self.assertEqual(evidence["initial_sp_offset_from_sram"], 70408)
        self.assertEqual(evidence["independent_usart_instances"], 3)
        self.assertEqual(evidence["highest_dma_channel_candidate"], 6)

    def test_at32f421_rejected_independently(self):
        candidate = next(c for c in self.report["candidates"] if c["part"] == "AT32F421C8T7")
        self.assertEqual(candidate["status"], "excluded_by_original_evidence")
        self.assertEqual(len(candidate["failures"]), 5)

    def test_f403a_and_f407_are_candidates_not_identified(self):
        for row in self.report["candidates"]:
            if row["part"].startswith(("AT32F403A", "AT32F407")):
                self.assertEqual(row["status"], "not_excluded_not_identified")

    def test_gd32f303_ret6_ram_shortfall(self):
        selected = next(c for c in self.report["candidates"] if c["part"] == "GD32F303RET6")
        self.assertEqual(selected["status"], "excluded_by_original_evidence")
        self.assertEqual(len(selected["failures"]), 1)

    def test_gd32f303_rgt6_not_excluded(self):
        selected = next(c for c in self.report["candidates"] if c["part"] == "GD32F303RGT6")
        self.assertEqual(selected["status"], "not_excluded_not_identified")

    def test_official_pid_maps_exact_part(self):
        r = inspect(0x410FC241, 0x700502CE, 0x07)
        self.assertEqual(r["core_by_cpuid"], "Cortex-M4")
        self.assertEqual(r["match_in_official_pid_table"]["part"], "AT32F403ARET7")
        self.assertTrue(r["pid_project_family_consistent"])

    def test_project_code_mismatch_is_detected(self):
        r = inspect(0x410FC241, 0x700502D2, 0x07)
        self.assertFalse(r["pid_project_family_consistent"])

    def test_unknown_pid_no_wrong_fabrication(self):
        r = inspect(0x410FC241, 0xDEADBEEF, 0x09)
        self.assertIsNone(r["match_in_official_pid_table"])
        self.assertEqual(r["artery_project_family_hint"], "AT32F421")

    def test_core_only_not_vendor(self):
        r = inspect(0x410FC231, None, None)
        self.assertEqual(r["core_by_cpuid"], "Cortex-M3")
        self.assertIsNone(r["match_in_official_pid_table"])

    def test_published_mega_hunt_skusk_vs_64pin_high_flash_image(self):
        by_part = {row["part"]: row for row in self.report["candidates"]}
        for part, reason in (
            ("MH2103ARPT6", "Flash"),
            ("MH2103AVET6", "package"),
            ("MH2103AVGT6", "package"),
            ("AIR32F103VET6", "package"),
        ):
            with self.subTest(part=part):
                row = by_part[part]
                self.assertEqual(row["status"], "excluded_by_original_evidence")
                self.assertEqual(len(row["failures"]), 1)
                self.assertIn(reason, row["failures"][0])
        self.assertIn(
            "physical_mcu", self.report["lineage_vs_hardware"]
        )
        self.assertIn(
            "published-SKU conflict", self.report["interpretation"]
        )

    def test_source_range_comparison(self):
        m = {
            "part": "synthetic", "flash_kib": 256, "ram_kib": 96,
            "usarts": 3, "dma_channels": None, "package": "LQFP64",
            "source": "test",
        }
        row = compare_spec(m, self.report["evidence"])
        self.assertEqual(len(row["failures"]), 1)
        self.assertIn("Flash", row["failures"][0])


if __name__ == "__main__":
    unittest.main()
