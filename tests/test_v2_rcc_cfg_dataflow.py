"""Synthetic Thumb and stock firmware tests for CFG RCC address propagation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from capstone.arm import ARM_REG_R0  # noqa: E402
from mcu_fingerprint import decoded_payload  # noqa: E402
from v2_rcc_cfg_dataflow import (  # noqa: E402
    State, const, meet, valid, mov_pair_seeds, scan, walk_cfg,
)

# Assembled with clang -target armv7m-none-eabi -mcpu=cortex-m3.
# Static bytes only; no emulator, device, or execution of radio firmware.
BRANCH_SPLIT = bytes.fromhex(
    "41f20400 00e0 00de c4f20200 0160 7047 00000000"
)
RAM_ALIAS = bytes.fromhex(
    "40f20010 c2f20000 41f20402 c4f20202 "
    "0260 0368 1960 7047 00000000"
)
CALL_KILLS = bytes.fromhex(
    "41f20400 00f004f8 c4f20200 0160 7047 7047 00000000"
)
REGISTER_CALL = bytes.fromhex(
    "41f22123 c0f60003 9847 7047 00000000"
)
UNPAIRED_MOVT = bytes.fromhex("c4f20200 0160 7047 00000000")
STACK_ALIAS = bytes.fromhex(
    "81b0 41f20402 c4f20202 0092 009b 1960 01b0 7047 00000000"
)
RAM_ALIAS_AFTER_CALL = bytes.fromhex(
    "40f20010 c2f20000 41f20402 c4f20202 "
    "0260 00f003f8 0368 1960 7047 7047 00000000"
)


def sites(result: dict) -> set[tuple[str, str]]:
    return {(e["pc"], e["address"]) for e in result["candidate_stores"]}


class ThumbDataflowSyntheticTests(unittest.TestCase):
    def test_movw_movt_survives_basic_block_branch(self):
        r = walk_cfg(BRANCH_SPLIT, 0x08001000)
        self.assertIn(("0x0800100C", "0x40021004"), sites(r))
        self.assertFalse(r["budget_exhausted"])

    def test_ram_roundtrip_recovers_rcc_pointer(self):
        r = walk_cfg(RAM_ALIAS, 0x08001000)
        self.assertIn(("0x08001014", "0x40021004"), sites(r))
        self.assertFalse(r["budget_exhausted"])

    def test_mov_pair_scan_discovers_sram_provenance_seed(self):
        self.assertIn(0x08001000, mov_pair_seeds(RAM_ALIAS))
        self.assertIn(0x08001008, mov_pair_seeds(RAM_ALIAS))
        self.assertIn(("0x08001014", "0x40021004"),
                      {(e["pc"], e["address"]) for e in scan(RAM_ALIAS)["cfg_candidate_stores"]})

    def test_stack_slot_pointer_roundtrip(self):
        self.assertIn(("0x0800100E", "0x40021004"),
                      sites(walk_cfg(STACK_ALIAS, 0x08001000)))

    def test_unmodeled_call_invalidates_sram_memory_and_volatile_registers(self):
        self.assertNotIn(("0x08001018", "0x40021004"),
                         sites(walk_cfg(RAM_ALIAS_AFTER_CALL, 0x08001000)))

    def test_callee_clobber_prevents_false_pointer_completion(self):
        self.assertNotIn(("0x0800100C", "0x40021004"),
                         sites(walk_cfg(CALL_KILLS, 0x08001000)))
        self.assertFalse(walk_cfg(CALL_KILLS, 0x08001000)["candidate_stores"])

    def test_unpaired_movt_does_not_assume_zero_low_halfword(self):
        self.assertEqual(sites(walk_cfg(UNPAIRED_MOVT, 0x08001000)), set())

    def test_register_indirect_call_is_recorded_as_candidate(self):
        r = walk_cfg(REGISTER_CALL, 0x08001000)
        self.assertIn({
            "pc": "0x08001008", "target": "0x08001221", "mnemonic": "blx",
            "target_provenance": "register constant, not runtime execution",
        }, r["register_indirect_branches"])

    def test_merge_removes_disagreeing_known_bits(self):
        s1 = State(regs={ARM_REG_R0: const(0x40021004)})
        s2 = State(regs={ARM_REG_R0: const(0x40022004)})
        merged = s1.combined(s2)
        self.assertFalse(valid(merged.regs[ARM_REG_R0]))
        self.assertEqual(meet(const(0x40021004), const(0x40021004)),
                         const(0x40021004))


class RealStockDataflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = decoded_payload((ROOT / "firmware/BF_5RH_501_v2_0_9.dat").read_bytes())
        cls.v1 = decoded_payload((ROOT / "firmware/BF_5RH_501_v1_1_04.dat").read_bytes())
        cls.v2scan = scan(cls.v2)
        cls.v1scan = scan(cls.v1)

    def test_both_images_retain_original_validated_30_site_baseline(self):
        for r in (self.v1scan, self.v2scan):
            self.assertEqual(r["old_linear_unique_store_count"], 30)
            self.assertEqual(r["seed_count_by_type"]["pc_relative_literal"], 26)
            self.assertTrue(any("unresolved" in note for note in r["limits"]))

    def test_cross_block_scan_adds_thirteen_real_stock_writes_per_version(self):
        for scan_result in (self.v1scan, self.v2scan):
            self.assertEqual(scan_result["cfg_candidate_store_count"], 43)
            self.assertEqual(len(scan_result["new_vs_linear_candidates"]), 13)
            self.assertFalse(scan_result["exhausted_seeds"])
            self.assertEqual(scan_result["seed_count_by_type"]["movw_movt_candidate"], 0)

    def test_reset_indirect_pointer_and_rom_callback_bounded_context(self):
        roots = self.v2scan["verified_entry_context"]
        self.assertIn("reset_vector_entry", roots)
        self.assertIn("shared_rom_helper", roots)
        startup = roots["reset_vector_entry"]["register_indirect_branches"]
        self.assertTrue(any(x["pc"] == "0x0800123E" and
                            x["target"] == "0x080323DD" for x in startup))
        rom = roots["shared_rom_helper"]["register_indirect_branches"]
        self.assertTrue(any(x["pc"] == "0x080012BC" and x["target"] is None
                            for x in rom))

    def test_v2_original_rom_cfgr_sites_found_via_cfg(self):
        known = {(s["pc"], s["address"]) for s in self.v2scan["cfg_candidate_stores"]}
        self.assertIn(("0x080012F0", "0x40021004"), known)
        self.assertIn(("0x080012F8", "0x40021004"), known)
        self.assertIn(("0x08001316", "0x40021004"), known)

    def test_real_literal_corruption_changes_candidate_seed_inventory(self):
        modified = bytearray(self.v2)
        # This literal is the RCC gate base at a verified startup LDR site.
        modified[0x080013E4 - 0x08001000] ^= 0x40
        altered = scan(bytes(modified))
        self.assertNotEqual(self.v2scan["seed_count_by_type"]["pc_relative_literal"],
                            altered["seed_count_by_type"]["pc_relative_literal"])


if __name__ == "__main__":
    unittest.main()
