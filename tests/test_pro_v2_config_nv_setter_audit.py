"""Original 61-case OEM configuration setter and NV roundtrip evidence."""
from __future__ import annotations
import unittest
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_config_nv_setter_audit import OFFSETS,TABLE,COUNT,SITES,verify_original

class SourceConfigSetterAndNvRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_original_61_case_table_save_and_restore_contract(self):
        result=verify_original(self.img)
        self.assertEqual(result["setter_id_count"],61)
        self.assertEqual(result["getter_id_count"],67)
        self.assertEqual(result["noop_ids"],[32,40,41,51])
        self.assertEqual(result["startup_main_nv_read"],{"address":"0x7980","length":56})
        self.assertEqual(result["startup_extra_nv_read"],{"address":"0x71","length":4})
        self.assertEqual(result["startup_side_nv_read"],{"address":"0x7A80","length":1})
        self.assertEqual(result["working_ram_startup_min_span_bytes"],39)
        self.assertEqual(result["commit_length_bytes"],1)
        self.assertEqual(result["commit_engine"],"0x080190E0")
        self.assertEqual(len(result["source_discrepancies"]),2)

    def test_every_setter_handler_mutation_rejected(self):
        for idx,byte_offset in enumerate(OFFSETS):
            with self.subTest(id=idx):
                p=bytearray(self.img)
                pc=TABLE+2*byte_offset
                p[pc-BASE:pc-BASE+2]=b"\x00\xBF" # Thumb NOP
                with self.assertRaises(ValueError):
                    verify_original(bytes(p))

    def test_tbb_and_journal_argument_mutations_rejected(self):
        for pc in [TABLE,TABLE+COUNT-1,0x080164CC,
                   0x0801677C,0x0801677E,0x08016782,
                   0x08016786,0x08016788,0x080106B8]:
            with self.subTest(pc=hex(pc)):
                p=bytearray(self.img)
                p[pc-BASE]^=0xFF
                with self.assertRaises(ValueError):
                    verify_original(bytes(p))

    def test_rust_setter_offsets_and_boot_structure_size_match_image(self):
        core=ROOT/"firmware-pro/core/src"
        setter=(core/"oem_config_setter.rs").read_text(encoding="utf8")
        config=(core/"oem_config_getter.rs").read_text(encoding="utf8")
        restore=(core/"oem_config_restore.rs").read_text(encoding="utf8")
        import re
        rows=setter.split("pub const OEM_SETTER_TBB_OFFSETS:",1)[1].split("];",1)[0]
        # Ignore comments and array type declaration.
        nums=[int(x) for x in re.findall(r"\b\d+\b",rows.split("= [",1)[-1])]
        self.assertEqual(nums,list(OFFSETS))
        self.assertIn("OEM_CONFIG_STORAGE_LEN: usize = 0x27",config)
        self.assertIn("OEM_MAIN_TO_WORKING_MAP",restore)
        self.assertIn("0x0801_64A0",setter)

if __name__=="__main__":
    unittest.main()
