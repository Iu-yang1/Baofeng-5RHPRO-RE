"""Offline tests for the experimental UV-5RH Pro UART MCU-ID receiver."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from probe_radio_mcu_uart import parse_line  # noqa: E402


class UARTDiagnosticDecoderTests(unittest.TestCase):
    def test_full_example_identifiers_cross_check_and_redact_uid(self):
        result = parse_line(
            "UV5RHPRO-ID/1,CPUID=0x410FC241,FSIZE_RAW=0x0200,"
            "DBG_ID=0x700502CE,AT_PROJECT=0x07,AIR_UID0_MASK=0x1A6A5CDX\r\n"
        )
        self.assertEqual(
            result["interpretation"]["arm_cpuid"]["core_name"], "Cortex-M4"
        )
        self.assertEqual(
            result["interpretation"]["artery_device_id"]["pid_table_match"]["model"],
            "AT32F403ARET7",
        )
        self.assertEqual(
            result["interpretation"]["air32_uid_family_pattern"][
                "matches_documented_air32_uid_pattern"],
            "AIR32F103RPT6",
        )
        self.assertTrue(any("conflicts" in x for x in result["interpretation"]["limits"]))
        self.assertNotIn("1A6A5CD0", str(result))

    def test_core_only_if_vendor_access_faults(self):
        result = parse_line("UV5RHPRO-ID/1,CPUID=0x411FC231\r\n")
        self.assertEqual(result["interpretation"]["arm_cpuid"]["core_name"],
                         "Cortex-M3")
        self.assertIsNone(result["interpretation"]["flash_capacity"][
            "reported_flash_size_kib"])

    def test_reject_noise_partial_bad_length_and_duplicate_fields(self):
        invalid = (
            "bad", "UV5RHPRO-ID/1,CPUID=0x0",
            "UV5RHPRO-ID/1,FSIZE_RAW=0x0200",
            "UV5RHPRO-ID/1,CPUID=0x410FC241,CPUID=0x410FC241",
            "UV5RHPRO-ID/1,CPUID=0x410FC241,AIR_UID0_MASK=0x1A6A5CD0",
        )
        for line in invalid:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))


if __name__ == "__main__":
    unittest.main()
