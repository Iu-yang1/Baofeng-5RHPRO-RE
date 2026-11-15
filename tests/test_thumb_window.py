"""Tests for bounded Thumb window and literal-pool rendering."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from thumb_window import BASE, inspect_window  # noqa: E402


class ThumbWindowTests(unittest.TestCase):
    def test_resolves_pc_relative_constant(self):
        data = bytearray(0x80)
        # LDR r0,[pc,#4] at BASE+0x20 -> aligned PC + 4 = +0x24; +4 = +0x28.
        struct.pack_into("<H", data, 0x20, 0x4801)
        struct.pack_into("<H", data, 0x22, 0x4770)
        struct.pack_into("<I", data, 0x28, 0xFF00FF00)
        entries = inspect_window(bytes(data), BASE+0x20, BASE+0x24)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["literal_address"], "0x08001028")
        self.assertEqual(entries[0]["literal_value"], "0xFF00FF00")

    def test_out_of_image(self):
        with self.assertRaises(ValueError):
            inspect_window(bytes(0x40), BASE+0x20, BASE+0x100)

    def test_unaligned_window(self):
        with self.assertRaises(ValueError):
            inspect_window(bytes(0x40), BASE+1, BASE+0x30)


if __name__ == "__main__":
    unittest.main()
