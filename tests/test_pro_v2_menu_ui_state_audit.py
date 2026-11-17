"""Original V2 UI monitor, editor callsites and text framebuffer regression."""
from __future__ import annotations
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_menu_ui_state_audit import SITES,verify_original

class MenuUiSourceAuditTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

 def test_oem_menu_flag_and_glyph_callers_present(self):
  report=verify_original(self.image)
  self.assertEqual(report["active_menu_flag_byte"],"0x2000182A bit0")
  self.assertEqual(report["ui_status_flag"],"halfword +0x10 bit7")
  self.assertEqual(report["original_text_draw_entry"],"0x08010DE4")
  self.assertEqual(report["original_framebuffer"],"0x20004B76")
  self.assertFalse(report["full_oem_keymap_and_visual_string_assets_restored"])

 def test_source_mutation_of_every_fixed_state_instruction_fails(self):
  for group,sites in SITES.items():
   for pc,*_ in sites:
    with self.subTest(group=group,pc=hex(pc)):
     changed=bytearray(self.image)
     changed[pc-BASE:pc-BASE+2]=b"\x00\xBF"
     with self.assertRaises(ValueError):
      verify_original(bytes(changed))

 def test_core_has_distinct_source_poll_and_independent_editing_ui(self):
  core=ROOT/"firmware-pro/core/src"
  poll=(core/"oem_menu_ui.rs").read_text(encoding="utf8")
  renderer=(core/"menu_lcd.rs").read_text(encoding="utf8")
  nv=(core/"oem_nv_compat.rs").read_text(encoding="utf8")
  self.assertIn("OEM_MENU_POLL_ENTRY:u32=0x0801_67B8",poll)
  self.assertIn("OemMenuPollResult",poll)
  self.assertIn("MenuAction",poll)
  self.assertIn("render_menu_diagnostics",renderer)
  self.assertIn("OemNvWriteLayout",nv)

if __name__=="__main__":
 unittest.main()
