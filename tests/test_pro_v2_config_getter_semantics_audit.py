"""Original V2 67-branch configuration getter, bounds repairs and Rust mirror."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_config_getter_semantics_audit import (
    CONFIG_BASE, FIRST_OPCODES, MENU_OFFSETS, TBB_BASE,
    LIMITED, verify_original
)

class OriginalConfigGetterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload=decoded_payload(
            (ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )

    def test_67_cases_are_stored_fields_not_visible_menu_names(self):
        d=verify_original(self.payload)
        self.assertEqual(d["oem_working_sram_base"],"0x20004580")
        self.assertEqual(d["config_ids"],67)
        self.assertEqual(d["observed_getter_minimum_working_span_bytes"],38)
        self.assertEqual(len(d["side_effectful_bounds_repairs"]),7)
        self.assertFalse(d["full_visible_menu_state_machine_recovered"])
        self.assertEqual(d["constant_zero_config_ids"],[32,40,41])
        self.assertEqual(d["constant_one_config_ids"],[57,59])

    def test_original_side_effectful_getter_branches_are_verified(self):
        for i,offset,max_value,replacement in [
            (0,0,2,0),(1,1,2,0),(2,2,10,0),(3,3,10,0),
            (7,6,1,0),(8,7,10,5),(18,20,4,0),
        ]:
            self.assertEqual(LIMITED[i],(offset,max_value,replacement))

    def test_original_case_first_instructions_are_mutation_sensitive(self):
        for id_,offset in enumerate(MENU_OFFSETS):
            with self.subTest(id=id_):
                changed=bytearray(self.payload)
                pc=TBB_BASE+2*offset
                changed[pc-BASE] ^= 0xFF
                with self.assertRaises((ValueError,IndexError)):
                    verify_original(bytes(changed))

    def test_rust_case_table_count_and_field_span(self):
        src=(ROOT/"firmware-pro/core/src/oem_config_getter.rs").read_text(encoding="utf8")
        table=src.split("pub const OEM_GETTER_CASES:",1)[1].split("];",1)[0]
        import re
        entries=re.findall(r"\b(?:Limited|Direct|Bits)\s*\{|\bConstant\(",table)
        self.assertEqual(len(entries),len(FIRST_OPCODES))
        self.assertIn("OEM_CONFIG_STORAGE_LEN: usize = 0x26",src)
        self.assertIn("if *v > max { *v = replacement; }",src)

if __name__=="__main__":
    unittest.main()
