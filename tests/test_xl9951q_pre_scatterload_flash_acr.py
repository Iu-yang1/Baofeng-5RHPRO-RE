"""Original V1/V2 pre-scatterload FLASH_ACR instruction and literal evidence."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from xl9951q_pre_scatterload_flash_acr import (  # noqa: E402
    analyze, inspect_clock_init, inspect_reset_wrapper, VERSIONS,
)


class OriginalResetFlashAcrTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = {
            name: decoded_payload(
                (ROOT / f"firmware/BF_5RH_501_{ver}.dat").read_bytes()
            )
            for name, ver in (("v1", "v1_1_04"), ("v2", "v2_0_9"))
        }
        cls.report = analyze(cls.payloads["v1"], cls.payloads["v2"])

    def test_two_original_early_clock_functions_are_identical(self):
        c = self.report["shared_early_clock_function"]
        self.assertTrue(c["exact_bytes"])
        self.assertEqual(c["matching_bytes"], 168)
        self.assertEqual(c["size_bytes"], 168)
        self.assertEqual(c["old_pc"], "0x08025B80")
        self.assertEqual(c["new_pc"], "0x08031BF4")

    def test_pre_scatterload_acr_and_rcc_register_literals(self):
        for name, item in self.report["versions"].items():
            with self.subTest(version=name):
                c = item["early_clock_function"]
                self.assertEqual(c["peripheral_literal_targets"],
                                 ["0x40021000", "0x40022000"])
                self.assertEqual(c["flash_acr_pc_relative_load"]["literal_value"],
                                 "0x40022000")
                self.assertEqual(
                    len(c["flash_acr_change_sequence"]), 6
                )
                self.assertTrue(c["does_not_reference_unlock_register_as_literal"])

    def test_both_reset_wrappers_call_only_early_clock_helper(self):
        for version in ("v1", "v2"):
            with self.subTest(version=version):
                row = self.report["versions"][version]["reset_wrapper"]
                self.assertEqual(
                    row["clock_helper_bl_site"],
                    f"0x{VERSIONS[version]['clock_bl']:08X}",
                )
                self.assertEqual(len(row["calls_in_bounded_reset_wrapper"]), 1)
                self.assertEqual(row["vtor_register"], "0xE000ED08")
                self.assertEqual(row["vtor_software_write_value"], "0x08000000")
                self.assertEqual(row["rcc_base"], "0x40021000")

    def test_separates_early_flash_acr_from_later_air32_rom_qspi(self):
        row = self.report["xip_assessment"]
        self.assertTrue(row["known_early_flash_controller_access"])
        self.assertTrue(row["early_acr_is_not_qspi_unlock"])
        self.assertFalse(row["confirmed_external_nor_xip_mapper"])
        self.assertIn("post-scatterload", row["separate_application_rom_unlock"])
        self.assertIn("OEM bootloader or mask ROM",
                      " ".join(self.report["limits"]))

    def test_flipped_flash_control_literal_fails(self):
        payload = bytearray(self.payloads["v2"])
        off = VERSIONS["v2"]["clock"] - 0x08001000 + 0xA4
        payload[off] ^= 0x01
        with self.assertRaises(ValueError):
            inspect_clock_init(bytes(payload), VERSIONS["v2"]["clock"])

    def test_changed_flash_acr_store_fails(self):
        payload = bytearray(self.payloads["v2"])
        pc = VERSIONS["v2"]["clock"] + 0x48
        payload[pc - 0x08001000] ^= 0x10
        with self.assertRaises(ValueError):
            inspect_clock_init(bytes(payload), VERSIONS["v2"]["clock"])

    def test_changed_reset_vtor_literal_fails(self):
        payload = bytearray(self.payloads["v1"])
        # The following constant pool contains the VTOR register address.
        pc = VERSIONS["v1"]["reset_clock_wrapper"] + 0x4C
        payload[pc - 0x08001000] ^= 0x01
        with self.assertRaises(ValueError):
            inspect_reset_wrapper(bytes(payload), "v1")

    def test_modified_identical_function_fails_cross_version_guard(self):
        v2 = bytearray(self.payloads["v2"])
        v2[VERSIONS["v2"]["clock"] - 0x08001000] ^= 1
        with self.assertRaisesRegex(ValueError, "functions differ"):
            analyze(self.payloads["v1"], bytes(v2))


if __name__ == "__main__":
    unittest.main()
