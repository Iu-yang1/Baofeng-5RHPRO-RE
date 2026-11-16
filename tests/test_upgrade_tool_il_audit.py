"""OEM Release UpgradeTool .NET IL contract regression (read-only)."""
from __future__ import annotations
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
HAVE_IL = bool(importlib.util.find_spec("dnfile") and importlib.util.find_spec("dncil"))


@unittest.skipUnless(HAVE_IL, "dnfile/dncil not installed; dedicated IL workflow runs full tests")
class UpgradeToolIlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from upgrade_tool_il_audit import collect, verify_upgrade_il, DATA_PATH
        cls.verify = staticmethod(verify_upgrade_il)
        cls.snapshot = collect(ROOT / DATA_PATH)

    def test_original_release_method_tokens_and_protocol(self):
        report = self.verify(self.snapshot)
        self.assertEqual(report["method_body_count"], 482)
        self.assertFalse(report["read_entry"]["flash_backup_implemented"])
        self.assertEqual(report["write_entry"]["wire_chunk_bytes"], 1024)
        self.assertEqual(report["write_entry"]["file_header_skipped_bytes"], 80)
        self.assertEqual(report["write_entry"]["hardcoded_cpu_flash_addresses"], [])

    def test_read_method_stub_mutation_is_detected(self):
        mutated = copy.deepcopy(self.snapshot)
        method = next(m for m in mutated["selected"] if m["token"] == "0x0600018D")
        method["instructions"][0]["opcode"] = "nop"
        with self.assertRaises(ValueError):
            self.verify(mutated)

    def test_block_size_il_mutation_is_detected(self):
        mutated = copy.deepcopy(self.snapshot)
        method = next(m for m in mutated["selected"] if m["token"] == "0x0600018E")
        item = next(x for x in method["instructions"] if x["pe_offset"] == "0x00009558")
        item["operand"] = 512
        with self.assertRaises(ValueError):
            self.verify(mutated)

    def test_release_digest_mutation_is_detected(self):
        mutated = copy.deepcopy(self.snapshot)
        mutated["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.verify(mutated)

    def test_il_offsets_are_method_relative(self):
        method = next(m for m in self.snapshot["selected"] if m["token"] == "0x0600018D")
        self.assertEqual(method["instructions"][0]["il_offset"], "IL_0000")
        self.assertEqual(method["instructions"][0]["pe_offset"], "0x00009155")


if __name__ == "__main__":
    unittest.main()
