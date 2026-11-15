"""Bounded actual Thumb memory-dereference evidence for four identity mechanisms."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from mcu_fingerprint import decoded_payload  # noqa: E402
from v1_v2_mcu_id_cfg_reads import (  # noqa: E402
    affected_registers, find_seeds, inspect_stock, trace_from,
)

# Assembled with clang -target armv7m-none-eabi -mcpu=cortex-m3 -mthumb.
# Code layout:
# 0x00: LDR literal -> B -> LDR UID0
# 0x10: MOVW/MOVT 0x1FFFF7E0 -> LDRH [base], LDRB [base+0x13]
# 0x1e: MOVW/MOVT 0xE000ED00 -> LDR
# 0x2a: MOVW/MOVT 0xE0042000 -> LDR
# 0x36: MOVT 0x1FFF without known low half -> LDR (not a target)
FIXTURE = bytes.fromhex(
    "024800e000bf066870470000e8f7ff1f"
    "4ff2e070c1f6ff700188c27c7047"
    "4ef60050cef2000001687047"
    "42f20000cef2040001687047"
    "c1f6ff7001687047"
)
# Same-register MOVW/MOVT for UID0, with local SRAM spill and reload.
BRANCH_MOVPAIR = bytes.fromhex("4ff2e87000e000bfc1f6ff7001687047")
SRAM_ALIAS = bytes.fromhex(
    "40f20010c2f200004ff2e872c1f6ff72"
    "0260036819687047"
)


def addresses(result: dict) -> set[tuple[str, str, str]]:
    return {
        (x["pc"], x["address"], x["direction"])
        for x in result["memory_access_candidates"]
    }


class SyntheticIdentityCFGTests(unittest.TestCase):
    def test_literal_uid0_is_dereferenced_after_branch(self):
        found = trace_from(FIXTURE, 0x08001000)
        self.assertIn(("0x08001006", "0x1FFFF7E8", "read"), addresses(found))
        self.assertFalse(found["budget_exhausted"])

    def test_movw_movt_recovers_flash_project_cpuid_and_pid(self):
        found = {
            0x08001010: ("0x08001018", "0x1FFFF7E0", "read"),
            0x0800101E: ("0x08001026", "0xE000ED00", "read"),
            0x0800102A: ("0x08001032", "0xE0042000", "read"),
        }
        for seed, expected in found.items():
            with self.subTest(seed=seed):
                self.assertIn(expected, addresses(trace_from(FIXTURE, seed)))
        project = trace_from(FIXTURE, 0x08001010)["memory_access_candidates"]
        self.assertTrue(any(x["pc"] == "0x0800101A" and
                            x["address"] == "0x1FFFF7F3" and
                            x["width_bytes"] == 1 and
                            x["match"]["register"] == "0x1FFFF7F0"
                            for x in project))

    def test_seed_detection_includes_literal_and_pair_origins(self):
        sources = find_seeds(FIXTURE)
        actual = {r["seed"]: r["kind"] for r in sources}
        self.assertEqual(actual[0x08001000], "PC-relative nearby ID literal")
        for pc in (0x08001010, 0x0800101E, 0x0800102A):
            self.assertEqual(actual[pc], "MOVW/MOVT possible ID address")

    def test_movw_branch_movt_keeps_uid_address(self):
        self.assertIn(("0x0800100C", "0x1FFFF7E8", "read"),
                      addresses(trace_from(BRANCH_MOVPAIR, 0x08001000)))
        roots = find_seeds(BRANCH_MOVPAIR)
        self.assertTrue(any(x["seed"] == 0x08001000 and
                            x["kind"] == "MOVW/MOVT possible ID address"
                            for x in roots))

    def test_sram_pointer_alias_and_derived_register_access(self):
        result = trace_from(SRAM_ALIAS, 0x08001000)
        self.assertIn(("0x08001014", "0x1FFFF7E8", "read"), addresses(result))

    def test_unpaired_movt_not_interpreted_as_known_pointer(self):
        self.assertEqual(addresses(trace_from(FIXTURE, 0x08001036)), set())

    def test_access_width_is_not_confused_with_nearby_register(self):
        self.assertEqual(affected_registers(0x1FFFF7E6, 1), [])
        self.assertEqual(affected_registers(0x1FFFF7F3, 1)[0]["register"],
                         "0x1FFFF7F0")
        self.assertFalse(affected_registers(0x1FFFF7F3, 1)[0]["exact_start"])
        self.assertEqual(affected_registers(0xE000ED00, 4)[0]["exact_start"], True)


class OriginalStockIdentityCFGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = {
            v: decoded_payload((ROOT / "firmware" / f"BF_5RH_501_{v}.dat").read_bytes())
            for v in ("v1_1_04", "v2_0_9")
        }
        cls.report = {v: inspect_stock(payload) for v, payload in cls.payloads.items()}

    def test_real_shared_rom_helper_uid0_dereference_from_entry(self):
        for version, report in self.report.items():
            with self.subTest(version=version):
                self.assertEqual(report["candidate_source_count"], 7)
                self.assertEqual(report["source_types"]["MOVW/MOVT possible ID address"], 0)
                self.assertEqual(report["unique_candidate_accesses"], 1)
                self.assertEqual(
                    sorted(x["loaded_value"] for x in report["all_sources"]),
                    sorted(["0x1FFFF7E8", "0xE000ED08", "0xE000ED08",
                            "0xE000ED0C", "0xE000ED0C",
                            "0xE000ED10", "0xE000ED10"]),
                )
                self.assertFalse(report["source_budget_exhausted"])
                self.assertTrue(report["original_helper_uid0_read_reachable_from_entry"])
                self.assertFalse(report["helper_budget_exhausted"])
                matches = [x for x in report["candidate_id_accesses"]
                           if x["pc"] == "0x080012A4" and
                           x["address"] == "0x1FFFF7E8"]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["direction"], "read")
                self.assertEqual(matches[0]["width_bytes"], 4)

    def test_original_verification_rejects_modified_uid_pointer(self):
        payload = bytearray(self.payloads["v2_0_9"])
        payload[0x08001400 - 0x08001000] ^= 0x01
        with self.assertRaises(ValueError):
            inspect_stock(bytes(payload))


if __name__ == "__main__":
    unittest.main()
