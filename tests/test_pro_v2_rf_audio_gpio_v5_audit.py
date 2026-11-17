"""Source-backed audio mode and GPIOB6 shadow linkage regression."""
from __future__ import annotations
import unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from mcu_fingerprint import decoded_payload
from thumb_window import BASE
from pro_v2_rf_audio_gpio_v5_audit import SITES,verify_original

class GpioAfSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img=decoded_payload((ROOT/"firmware/BF_5RH_501_v2_0_9.dat").read_bytes())

    def test_source_gpio_audio_split_is_proven_without_analog_wiring(self):
        report=verify_original(self.img)
        self.assertTrue(report["config_setter_id35_calls_pb6_helper_before_field_update"])
        self.assertEqual(report["pb6_state_sram"],"0x200017FC")
        self.assertEqual(report["audio_nonzero_register_operations"],[
            "read REG43","write REG43 & ~0x7E00","write REG13=0x03FF",
        ])
        self.assertFalse(report["physical_pa_mute_ptt_or_audio_wiring_confirmed"])

    def test_mutating_original_source_sites_is_rejected(self):
        for label,sites in SITES.items():
            for pc,*_ in sites:
                with self.subTest(group=label,pc=hex(pc)):
                    changed=bytearray(self.img)
                    changed[pc-BASE:pc-BASE+2]=b"\x00\xBF"
                    with self.assertRaises(ValueError):
                        verify_original(bytes(changed))

    def test_rust_core_explicitly_does_not_assume_physical_pa(self):
        src=(ROOT/"firmware-pro/core/src/board_v2.rs").read_text(encoding="utf8")
        audio=(ROOT/"firmware-pro/core/src/audio.rs").read_text(encoding="utf8")
        assert "OEM_PB6_SHADOW_SRAM" in src
        assert "apply_tail" in src
        assert "apply_oem_af_nonzero_subpath" in audio
        assert "0x7E00" in audio
        assert "0x6042" in audio

if __name__=="__main__":
    unittest.main()
