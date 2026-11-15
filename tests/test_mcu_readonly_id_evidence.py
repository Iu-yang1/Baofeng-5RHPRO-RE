"""ARM/Artery/AIR32 read-only ID decoder and original firmware xref tests."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from mcu_readonly_id_evidence import interpret, FLASH_REQUIRED_KIB  # noqa: E402
from v2_mcu_identity_xrefs import scan  # noqa: E402


class MCUReadonlyDecodeTests(unittest.TestCase):
    def test_air32_all_six_documented_models_and_masked_nibble(self):
        pairs = (
            (0x1A5A5BB, "AIR32F103CBT6"),
            (0x1A5A5CC, "AIR32F103CCT6"),
            (0x1A6A5CD, "AIR32F103RPT6"),
            (0x1A8A6DD, "AIR32F103VET6"),
            (0x1A8A6ED, "AIR32F103VGT6"),
            (0x1A9A6DD, "AIR32F103ZET6"),
        )
        for pattern, expected in pairs:
            for nibble in (0, 7, 15):
                with self.subTest(expected=expected, nibble=nibble):
                    uid = pattern << 4 | nibble
                    output = interpret(uid_first_word=uid)
                    self.assertEqual(
                        output["air32_uid_family_pattern"]["matches_documented_air32_uid_pattern"],
                        expected,
                    )
                    self.assertNotIn(f"0x{uid:08X}", json.dumps(output))

    def test_nonmatching_air32_header_does_not_identify_brand(self):
        for uid in (0x1B6A5CD1, 0x1C6A5CD1, 0x1A6A5CE2):
            a = interpret(uid_first_word=uid)["air32_uid_family_pattern"]
            self.assertIsNone(a["matches_documented_air32_uid_pattern"])
        self.assertIsNone(interpret()["air32_uid_family_pattern"]["uid_high_byte"])

    def test_flash_window_size_threshold_and_unknown(self):
        self.assertEqual(FLASH_REQUIRED_KIB, 391)
        for size, result in ((256, False), (390, False), (391, True),
                             (512, True), (1024, True), (0, None),
                             (0xFFFF, None)):
            with self.subTest(size=size):
                self.assertIs(interpret(flash_size_halfword=size)
                              ["flash_capacity"]["meets_firmware_address_requirement"],
                              result)

    def test_cpuid_m3_m4_and_no_brand_guess(self):
        for word, name in ((0x411FC231, "Cortex-M3"),
                           (0x410FC241, "Cortex-M4"),
                           (0x410FC201, "Cortex-M0"),
                           (0x410FC601, "Cortex-M0+")):
            with self.subTest(word=word):
                c = interpret(cpuid=word)["arm_cpuid"]
                self.assertEqual(c["core_name"], name)
                self.assertTrue(c["not_the_silicon_vendor"])

    def test_official_lqfp64_at32_pid_and_project_byte(self):
        known = (
            (0x700502CE, 0x07, "AT32F403ARET7"),
            (0x70050345, 0x07, "AT32F403ARGT7"),
            (0x700502D2, 0x08, "AT32F407RET7"),
            (0x7005034C, 0x08, "AT32F407RGT7"),
        )
        for pid, project, part in known:
            with self.subTest(part=part):
                a = interpret(debug_id=pid, project_byte=project)["artery_device_id"]
                self.assertEqual(a["pid_table_match"]["model"], part)
                self.assertTrue(a["pid_and_project_consistent"])
        a = interpret(debug_id=0x700502CE, project_byte=0x08)["artery_device_id"]
        self.assertFalse(a["pid_and_project_consistent"])
        unknown = interpret(debug_id=0x12345678)["artery_device_id"]
        self.assertIsNone(unknown["pid_table_match"])

    def test_dpidr_is_not_cpu_memory_or_target_vendor_id(self):
        d = interpret(dpidr=0x2BA01477)["swd_dp_id"]
        self.assertEqual(d["manufacturer_jedec_11bit"], "0x23B")
        self.assertTrue(d["manufacturer_is_arm"])
        self.assertEqual(d["debug_port_partno"], "0xBA")
        self.assertTrue(d["is_swd_dp_register_not_mem32"])

    def test_cross_evidence_conflicts_explicit(self):
        m3_at = interpret(cpuid=0x411FC231, debug_id=0x700502CE)
        self.assertTrue(any("conflicts" in x for x in m3_at["limits"]))
        m4_air = interpret(cpuid=0x410FC241, uid_first_word=0x1A6A5CD7)
        self.assertTrue(any("conflicts" in x for x in m4_air["limits"]))

    def test_reject_wrong_widths(self):
        for data in (
            {"uid_first_word": -1},
            {"flash_size_halfword": 0x10000},
            {"project_byte": 256},
            {"dpidr": 0x100000000},
        ):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    interpret(**data)


class StockMCUIdentityXrefTests(unittest.TestCase):
    def test_original_firmware_uid_read_is_not_a_live_device_id(self):
        for image in ("BF_5RH_501_v1_1_04.dat",
                      "BF_5RH_501_v2_0_9.dat"):
            with self.subTest(image=image):
                payload = decoded_payload((ROOT / "firmware" / image).read_bytes())
                refs = {r["address"]: r for r in scan(payload)["candidates"]}
                self.assertTrue(refs["0x1FFFF7E8"]["thumb_literal_load_candidates"])
                self.assertEqual(
                    refs["0x1FFFF7E8"]["thumb_literal_load_candidates"][0]["ldr_pc"],
                    "0x080012A2",
                )
                for address in ("0xE000ED00", "0xE0042000", "0x1FFFF7F3"):
                    self.assertEqual(refs[address]["aligned_raw_word_occurrences"], 0)
                    self.assertEqual(refs[address]["thumb_literal_load_candidates"], [])
                # Not observing a literal never proves absence of MCU ID access.
                self.assertIn("not rule out a family", scan(payload)["limitations"][0])


if __name__ == "__main__":
    unittest.main()
