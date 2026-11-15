"""Verify that MCU identity register xrefs reflect actual V2 firmware bytes."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_mcu_identity_xrefs import scan, BASE  # noqa: E402


class V2MCUIdentityXrefTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = decoded_payload(
            (ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes()
        )

    def test_uid_load_but_no_mcu_pid_table_reference(self):
        r = scan(self.payload)
        entries = {v["address"]: v for v in r["candidates"]}
        self.assertEqual(
            entries["0x1FFFF7E8"]["thumb_literal_load_candidates"][0]["ldr_pc"],
            "0x080012A2",
        )
        self.assertEqual(entries["0xE0042000"]["aligned_raw_word_occurrences"], 0)
        self.assertEqual(entries["0x1FFFF7F3"]["aligned_raw_word_occurrences"], 0)
        self.assertEqual(len(entries["0x40022000"]["thumb_literal_load_candidates"]), 7)

    def test_uid_xref_removed_when_literal_word_is_changed(self):
        payload = bytearray(self.payload)
        addr = 0x08001400-BASE
        payload[addr:addr+4] = bytes(4)
        r = scan(bytes(payload))
        uid = next(x for x in r["candidates"] if x["address"] == "0x1FFFF7E8")
        self.assertEqual(uid["thumb_literal_load_candidates"], [])


if __name__ == "__main__":
    unittest.main()
