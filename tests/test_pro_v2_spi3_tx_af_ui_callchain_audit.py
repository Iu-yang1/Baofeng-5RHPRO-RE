"""Regression tests for V2 SPI3 setup and TX/audio/UI software callsites.

Physical package pads and analog circuit nets are deliberately unknown.
"""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_spi3_tx_af_ui_callchain_audit import SITES,verify_original

class Spi3TxAudioUiCallchainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_oem_spi3_rfic_audio_ui_gpio_sites(self):
        report=verify_original(self.v2)
        self.assertEqual(set(report["verified_software_sites"]),set(SITES))
        self.assertEqual(report["spi3"]["spi3_mmio_base"],"0x40003C00")
        self.assertEqual(report["spi3"]["software_gpio_b_bits"],[3,4,5])
        self.assertEqual(report["spi3"]["initial_cr1_config_fields_or"],"0x0317")
        self.assertFalse(report["spi3"]["physical_qfn_pad_mapping_verified"])
        self.assertFalse(report["rf_audio"]["physical_tx_pa_and_mic_path_verified"])
        self.assertFalse(report["rf_audio"]["speaker_tda2822_lm2904b_wiring_verified"])
        self.assertFalse(report["gpio_ptt"]["physical_ptt_input_verified"])
        self.assertFalse(report["gpio_ptt"]["physical_pa_bias_enable_verified"])

    def test_original_critical_instruction_mutations_fail(self):
        for label in SITES:
            for pc,*_ in SITES[label]:
                with self.subTest(chain=label,pc=hex(pc)):
                    changed=bytearray(self.v2)
                    changed[pc-BASE]^=1
                    with self.assertRaises(ValueError):
                        verify_original(bytes(changed))

    def test_software_init_source_not_claimed_physical_pinout(self):
        board=(ROOT/"firmware-pro/core/src/board_v2.rs").read_text(encoding="utf-8")
        spi=(ROOT/"firmware-pro/core/src/spi3_nv.rs").read_text(encoding="utf-8")
        for token in ("OEM_SPI3_NV_CS_SOFTWARE", "GPIOB_COMPAT_BASE","SPI3_COMPAT_BASE"):
            self.assertIn(token,board)
        for token in ("OEM_SPI3_REGISTER_BASE", "OEM_SPI3_CR1_CONFIG_OR",
                      "oem_spi3_cr1_after_configuration",
                      "OEM_SPI3_CR2_CLEAR_MASK"):
            self.assertIn(token,spi)

if __name__=="__main__":
    unittest.main()
