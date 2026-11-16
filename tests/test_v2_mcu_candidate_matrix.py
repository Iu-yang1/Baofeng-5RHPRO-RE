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
        self.assertEqual(evidence["last_read_scatterload_source_address"], "0x08062AEA")
        self.assertEqual(evidence["highest_read_scatterload_source_offset"], 0x62AEA)
        self.assertEqual(evidence["minimum_program_readable_window_kib"], 395)
        self.assertEqual(evidence["initial_sp"], "0x20011308")
        self.assertEqual(evidence["initial_sp_offset_from_sram"], 70408)
        self.assertEqual(evidence["independent_usart_instances"], 3)
        self.assertEqual(evidence["highest_dma_channel_candidate"], 6)

    def test_at32f421_rejected_independently(self):
        candidate = next(c for c in self.report["candidates"] if c["part"] == "AT32F421C8T7")
        self.assertEqual(candidate["status"], "published_standard_part_mismatch")
        self.assertEqual(len(candidate["failures"]), 5)

    def test_f403a_f407_have_enough_resources_but_wrong_package(self):
        for row in self.report["candidates"]:
            if row["part"].startswith(("AT32F403A", "AT32F407")):
                self.assertEqual(row["resource_status"], "resource_compatible_not_identified")
                self.assertEqual(row["package_status"], "published_package_mismatch")
                self.assertEqual(row["status"], "published_standard_part_mismatch")

    def test_gd32f303_ret6_ram_shortfall(self):
        selected = next(c for c in self.report["candidates"] if c["part"] == "GD32F303RET6")
        self.assertEqual(selected["status"], "published_standard_part_mismatch")
        self.assertEqual(len(selected["resource_failures"]), 1)
        self.assertEqual(len(selected["failures"]), 2)

    def test_gd32f303_rgt6_resource_match_but_lqfp_package_fails(self):
        selected = next(c for c in self.report["candidates"] if c["part"] == "GD32F303RGT6")
        self.assertEqual(selected["resource_status"], "resource_compatible_not_identified")
        self.assertEqual(selected["package_status"], "published_package_mismatch")
        self.assertEqual(selected["status"], "published_standard_part_mismatch")

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

    def test_qfn64_corrects_all_previous_lqfp_shortlists(self):
        self.assertEqual(self.report["evidence"]["board_package_family"], "QFN")
        self.assertEqual(self.report["evidence"]["board_package_pin_count"], 64)
        self.assertIn("user-recounted", self.report["evidence"]["board_package_source"])
        for row in self.report["candidates"]:
            with self.subTest(part=row["part"]):
                self.assertEqual(row["package_status"], "published_package_mismatch")
                self.assertEqual(row["status"], "published_standard_part_mismatch")
                self.assertIn("QFN64", row["failures"][-1])

    def test_mh2103a_flash_and_package_are_separate_constraints(self):
        by_part = {row["part"]: row for row in self.report["candidates"]}
        for part in ("MH2103ARPT6", "AIR32F103RPT6"):
            self.assertEqual(len(by_part[part]["resource_failures"]), 1)
            self.assertEqual(len(by_part[part]["failures"]), 2)
        for part in ("MH2103AVET6", "MH2103AVGT6", "AIR32F103VET6"):
            self.assertEqual(by_part[part]["resource_failures"], [])
            self.assertEqual(len(by_part[part]["failures"]), 1)

    def test_xl9951q_catalogue_is_only_package_marking_evidence(self):
        evidence = self.report["evidence"]
        catalog = evidence["matching_jlcpcb_catalog_record"]
        self.assertEqual(evidence["observed_top_marking_candidate"], "XL9951Q")
        self.assertEqual(catalog["part_number"], "XL9951Q")
        self.assertEqual(catalog["jlcpcb_part_number"], "C9900238147")
        self.assertEqual(catalog["published_package"], "QFN-64_8x8")
        self.assertEqual(catalog["listed_body_size_mm"], [8, 8])
        self.assertEqual(catalog["listed_manufacturer_field"], "JLCPCB Assembly")
        self.assertFalse(catalog["manufacturer_field_is_silicon_vendor_evidence"])
        self.assertIsNone(catalog["cpu_core"])
        self.assertIsNone(catalog["flash_kib"])
        self.assertIsNone(catalog["ram_kib"])

    def test_qfn64_package_only_matches_package_not_mcu_identity(self):
        evidence = self.report["evidence"]
        synthetic = {
            "part": "unidentified-QFN64",
            "flash_kib": 512,
            "ram_kib": 96,
            "usarts": 3,
            "dma_channels": None,
            "package": "QFN64",
            "source": "synthetic test only",
        }
        result = compare_spec(synthetic, evidence)
        self.assertEqual(result["status"], "not_excluded_not_identified")
        self.assertEqual(result["resource_status"], "resource_compatible_not_identified")
        self.assertEqual(result["package_status"], "published_package_match_not_mcu_identification")
        self.assertEqual(result["failures"], [])

    def test_catalogue_package_qfn64_8x8_parsed_as_64_pins(self):
        # JLCPCB's 8x8 dimensions are not part of the pad count.
        fixture = {
            "part": "fictional-silicon-with-catalogue-package",
            "flash_kib": 512,
            "ram_kib": 96,
            "usarts": 3,
            "dma_channels": None,
            "package": "QFN-64_8x8",
            "source": "synthetic",
        }
        report = compare_spec(fixture, self.report["evidence"])
        self.assertEqual(report["status"], "not_excluded_not_identified")
        self.assertEqual(report["package_status"],
                         "published_package_match_not_mcu_identification")

    def test_source_range_comparison(self):
        m = {
            "part": "synthetic", "flash_kib": 256, "ram_kib": 96,
            "usarts": 3, "dma_channels": None, "package": "QFN64",
            "source": "test",
        }
        row = compare_spec(m, self.report["evidence"])
        self.assertEqual(len(row["failures"]), 1)
        self.assertIn("Flash", row["failures"][0])


if __name__ == "__main__":
    unittest.main()
