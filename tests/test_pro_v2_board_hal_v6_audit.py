"""Original software GPIO/SPI2/SPI3 and LCD/keypad HAL provenance."""
from __future__ import annotations
import unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_board_hal_v6_audit import SITES,verify_original

class HalSourceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.image=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

 def test_oem_software_mmio_and_physical_identity_are_not_conflated(self):
  report=verify_original(self.image)
  self.assertFalse(report["actual_physical_pad_identity_confirmed"])
  self.assertFalse(report["whole_device_bootloader_and_pa_ptt_confirmed"])
  self.assertEqual(len(report["matched_sites"]),5)

 def test_all_mmio_source_instructions_mutation_sensitive(self):
  for group,sites in SITES.items():
   for pc,*_ in sites:
    with self.subTest(group=group,pc=hex(pc)):
     b=bytearray(self.image)
     b[pc-BASE:pc-BASE+2]=b"\x00\xBF"
     with self.assertRaises(ValueError): verify_original(bytes(b))

 def test_new_hal_uses_original_software_addresses_and_keeps_raw_transfer_errors(self):
  hal=(ROOT/"firmware-pro/core/src/oem_board_hal.rs").read_text(encoding="utf8")
  for name in ("OEM_COMPAT_GPIO_IDR_OFFSET","OEM_COMPAT_GPIO_BSRR_OFFSET",
    "OEM_COMPAT_GPIO_BRR_OFFSET","OEM_CORTEX_M_CPUID_ADDR",
    "configure_original_spi3_registers","OemSpi2PanelBus",
    "OemPanelResetAdapter","scan_original_two_pass_keypad",
    "SpiAndDeselect"):
   self.assertIn(name,hal)

if __name__=="__main__":
 unittest.main()
