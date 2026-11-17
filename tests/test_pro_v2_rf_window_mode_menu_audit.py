"""Original OEM V1/V2 four-window RF mode and V2 menu dispatch audits."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))

from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_rf_window_audit import (
    BIAS_AND_WIDTHS,V1_TABLE_PC,V2_TABLE_PC,V2_WRITER_SITES,
    check_literals,check_writer,verify_original as verify_rf,
)
from pro_v2_mode_ui_contract_audit import (
    MENU_OFFSETS, CONFIG_ID_COUNT,TBB_BASE,TBB_PC,
    RF_SITES,MENU_SITES,check_sites,restored_mode_window,
    verify_original as verify_menu,
)


class V2ModeAndMenuEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v1=decoded_payload(
            (ROOT/"firmware/BF_5RH_501_v1_1_04.dat").read_bytes())
        cls.v2=decoded_payload(
            (ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_v1_v2_software_window_ranges_are_identical(self):
        result=verify_rf(self.v1,self.v2)
        intervals=[(x["inclusive_min_hz"],x["inclusive_max_hz"])
                   for x in result["software_frequency_windows"]]
        self.assertEqual(intervals,[
            (136_000_000,174_000_000),
            (200_000_000,260_000_000),
            (350_000_000,399_000_000),
            (400_000_000,520_000_000),
        ])
        self.assertEqual(result["out_of_window_fallback_trim_slot"],0)
        self.assertFalse(result["rf_physical_bandpass_pa_switch_gpio_proven"])
        self.assertEqual(result["v2_writer_verified_sites"],len(V2_WRITER_SITES))

    def test_original_67_case_configuration_tbb_and_runtime_lookup(self):
        result=verify_menu(self.v2)
        r=result["rfic"]
        ui=result["menu"]
        self.assertEqual(r["active_state_byte_address"],"0x20000069")
        self.assertEqual(r["mapping_sram_address"],"0x20000072")
        self.assertEqual(r["bounded_adjacent_window_length"],16)
        self.assertTrue(r["initial_window_all_zero"])
        self.assertFalse(r["runtime_table_producer_recovered"])
        self.assertEqual(ui["total_configuration_ids"],67)
        self.assertEqual(ui["id_0x13_target"],"0x0800E556")
        self.assertEqual(ui["id_0x14_target"],"0x0800E55E")
        self.assertEqual(ui["id_0x15_target"],"0x0800E55A")
        self.assertEqual(ui["id_0x16_target"],"0x0800E562")
        self.assertEqual(ui["shared_dispatch_targets"]["0x0800E4D4"],[32,40,41])
        self.assertFalse(ui["menu_visible_item_count_known"])

    def test_mutated_original_range_table_or_writer_is_rejected(self):
        for pc in [V1_TABLE_PC,V1_TABLE_PC+0x1C]:
            with self.subTest(source="V1",pc=hex(pc)):
                changed=bytearray(self.v1);changed[pc-BASE]^=1
                with self.assertRaises(ValueError):
                    check_literals(bytes(changed),V1_TABLE_PC,"V1")
        for pc in [V2_TABLE_PC,V2_TABLE_PC+0x1C]:
            with self.subTest(source="V2",pc=hex(pc)):
                changed=bytearray(self.v2);changed[pc-BASE]^=1
                with self.assertRaises(ValueError):
                    check_literals(bytes(changed),V2_TABLE_PC,"V2")
        for pc in [0x08031B0E,0x08031B4A,0x08031B7C,0x08031BA2]:
            with self.subTest(writer_pc=hex(pc)):
                changed=bytearray(self.v2);changed[pc-BASE]^=1
                with self.assertRaises(ValueError):
                    check_writer(bytes(changed))

    def test_mutated_oem_tbb_or_register_lookup_is_rejected(self):
        for pc in [TBB_PC,TBB_BASE,TBB_BASE+0x13,TBB_BASE+0x42,
                   0x0800DDB8,0x0800DDC0,0x0800DDC4,0x0800E47C]:
            with self.subTest(pc=hex(pc)):
                changed=bytearray(self.v2);changed[pc-BASE]^=1
                with self.assertRaises(ValueError):
                    verify_menu(bytes(changed))

    def test_rust_oem_menu_offsets_identical_to_verified_image(self):
        src=(ROOT/"firmware-pro/core/src/oem_menu.rs").read_text(encoding="utf-8")
        start=src.index("pub const OEM_CONFIG_TBB_OFFSETS:")
        field=src[start:src.index("];",start)]
        import re
        found=bytes(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})\b",field))
        self.assertEqual(found,MENU_OFFSETS)
        self.assertEqual(CONFIG_ID_COUNT,len(found))

    def test_rust_mode_windows_correspond_to_source_and_do_not_gate_tx(self):
        src=(ROOT/"firmware-pro/core/src/rf_mode.rs").read_text(encoding="utf-8")
        for value in (
            "13_600_000, 17_400_000",
            "20_000_000, 26_000_000",
            "35_000_000, 39_900_000",
            "40_000_000, 52_000_000",
            "OEM_MODE_SELECTOR_SRAM",
            "OemRuntimeModeLookup",
            "oem_trim_slot_for_raw_word",
        ):
            self.assertIn(value,src)
        self.assertNotIn("PA_EN: Pin",src)


if __name__=="__main__":
    unittest.main()
