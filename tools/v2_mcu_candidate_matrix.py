#!/usr/bin/env python3
"""Compare original UV-5RH Pro V2 instruction evidence to MCU public specifications.

The user verified that the MCU is QFN and physically counted 64 terminals.
Do not infer pad mapping from the former photographed LQFP64 assumption.
A pass means "not excluded by these tests"; it NEVER identifies the MCU.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from mcu_fingerprint import decoded_payload
from v2_memory_layout import analyze as memory_layout
from v2_uart_protocol_evidence import analyze as uart_protocol

FLASH_BASE = 0x08000000
# Recovered ARM scatterload descriptor: this flash address is actually read
# by the startup decompressor, rather than simply being present in a .dat.
SCATTERLOAD_COMPRESSED_SOURCE = 0x08061A54
# User-confirmed package technology and physically counted terminals.
OBSERVED_PACKAGE_FAMILY = "QFN"
OBSERVED_PACKAGE_PIN_COUNT = 64

# Memory, USART and packages derived from original manufacturer product pages,
# not from the ordinary UV-5RH reference firmware. Peripheral versions must
# still be matched to a real silicon ID and register behavior.
SPECS = (
    {
        "part": "AT32F421C8T7",
        "flash_kib": 64, "ram_kib": 16, "usarts": 2,
        "dma_channels": 5, "package": "LQFP48",
        "source": "https://arterytek.com/en/product/AT32F421.jsp",
    },
    {
        "part": "AT32F403ARET7",
        "flash_kib": 512, "ram_kib": 96, "usarts": 3,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://arterytek.com/en/product/AT32F403A.jsp",
    },
    {
        "part": "AT32F403ARGT7",
        "flash_kib": 1024, "ram_kib": 96, "usarts": 3,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://arterytek.com/en/product/AT32F403A.jsp",
    },
    {
        "part": "AT32F407RET7",
        "flash_kib": 512, "ram_kib": 96, "usarts": 4,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://arterytek.com/en/product/AT32F407.jsp",
    },
    {
        "part": "AT32F407RGT7",
        "flash_kib": 1024, "ram_kib": 96, "usarts": 4,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://arterytek.com/en/product/AT32F407.jsp",
    },
    {
        "part": "AIR32F103RPT6",
        "flash_kib": 256, "ram_kib": 96, "usarts": 5,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://c.vue2.cn/attachment/20220605164850945_AIR32F103芯片数据手册1.0.0.pdf",
    },
    {
        "part": "AIR32F103VET6",
        "flash_kib": 512, "ram_kib": 96, "usarts": 5,
        "dma_channels": None, "package": "LQFP100",
        "source": "https://wiki.luatos.com/chips/air32f103/switchFromSxx.html",
    },
    {
        "part": "MH2103ARPT6",
        "flash_kib": 256, "ram_kib": 96, "usarts": 5,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://www.megahuntmicro.com/article/40/24.html",
    },
    {
        "part": "MH2103AVET6",
        "flash_kib": 512, "ram_kib": 96, "usarts": 5,
        "dma_channels": None, "package": "LQFP100",
        "source": "https://www.megahuntmicro.com/article/40/24.html",
    },
    {
        "part": "MH2103AVGT6",
        "flash_kib": 1024, "ram_kib": 96, "usarts": 5,
        "dma_channels": None, "package": "LQFP100",
        "source": "https://www.megahuntmicro.com/article/40/24.html",
    },
    {
        "part": "GD32F303RET6",
        "flash_kib": 512, "ram_kib": 64, "usarts": 3,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://www.gigadevice.com.cn/product/mcu/main-stream-mcus",
    },
    {
        "part": "GD32F303RGT6",
        "flash_kib": 1024, "ram_kib": 96, "usarts": 3,
        "dma_channels": None, "package": "LQFP64",
        "source": "https://www.gigadevice.com.cn/product/mcu/mcus-product-selector/gd32f303rgt6",
    },
)


def compare_spec(spec: dict, evidence: dict) -> dict:
    resource_failures = []
    if spec["flash_kib"] * 1024 <= evidence["highest_executed_flash_source_offset"]:
        resource_failures.append("insufficient addressable program Flash for startup's actual source address")
    if spec["ram_kib"] * 1024 < evidence["initial_sp_offset_from_sram"]:
        resource_failures.append("initial MSP and zero region extend beyond specified SRAM")
    if spec["usarts"] < evidence["independent_usart_instances"]:
        resource_failures.append("fewer USART instances than original code initializes")
    # A label like QFN-64_8x8 contains 64 pins; 8x8 is body size, not pins.
    package_match = re.match(r"^(LQFP|QFN)[-_]?(\d+)(?:[_-]|$)", spec["package"].upper())
    if package_match is None:
        raise ValueError(f"unsupported published package format: {spec['package']}")
    published_family, count = package_match.groups()
    package_mismatch = (
        published_family != evidence["board_package_family"]
        or int(count) != evidence["board_package_pin_count"]
    )
    if (spec["dma_channels"] is not None and
            spec["dma_channels"] < evidence["highest_dma_channel_candidate"]):
        resource_failures.append("too few DMA channels for the USART2 DMA register usage")

    failures = list(resource_failures)
    if package_mismatch:
        failures.append("published standard package differs from user-confirmed QFN64")
    return {
        "part": spec["part"],
        "status": "published_standard_part_mismatch" if failures else "not_excluded_not_identified",
        "resource_status": "published_resource_mismatch" if resource_failures else "resource_compatible_not_identified",
        "package_status": ("published_package_mismatch" if package_mismatch
                           else "published_package_match_not_mcu_identification"),
        "resource_failures": resource_failures,
        "failures": failures,
        "official_spec": spec,
    }


def analyze(payload: bytes) -> dict:
    memory = memory_layout(payload)
    serial = uart_protocol(payload)
    usarts = {
        serial["gnss_nmea_rx"]["uart"],
        serial["private_serial_protocol_candidate"]["uart"],
        serial["usart1_irq_ring"]["uart"],
    }
    evidence = {
        "payload_bytes": len(payload),
        "flash_base_hypothesis": f"0x{FLASH_BASE:08X}",
        "actual_scatterload_source_pc": f"0x{SCATTERLOAD_COMPRESSED_SOURCE:08X}",
        "highest_executed_flash_source_offset": SCATTERLOAD_COMPRESSED_SOURCE-FLASH_BASE,
        "initial_sp": memory["initial_msp_candidate"],
        "initial_sp_offset_from_sram": int(memory["initial_msp_candidate"], 16)-0x20000000,
        "data_bytes": memory["data_region"]["length"],
        "zero_region_bytes": memory["zero_region"]["length"],
        "independent_usart_instances": len(usarts),
        "original_code_usart_instances": sorted(usarts),
        "highest_dma_channel_candidate": 6,
        "board_package_family": OBSERVED_PACKAGE_FAMILY,
        "board_package_pin_count": OBSERVED_PACKAGE_PIN_COUNT,
        "board_package_source": "user-recounted QFN package with 64 physical terminals",
        "observed_top_marking_candidate": "XL9951Q",
        "matching_jlcpcb_catalog_record": {
            "part_number": "XL9951Q",
            "jlcpcb_part_number": "C9900238147",
            "published_package": "QFN-64_8x8",
            "listed_body_size_mm": [8, 8],
            "listed_manufacturer_field": "JLCPCB Assembly",
            "manufacturer_field_is_silicon_vendor_evidence": False,
            "flash_kib": None,
            "ram_kib": None,
            "cpu_core": None,
            "source": "https://jlcpcb.com/partdetail/JLCPCBAssembly-XL9951Q/C9900238147",
            "evidence_level": (
                "independent catalogue confirmation of matching marking and "
                "package, not a manufacturer datasheet or verified die identification"
            ),
        },
        "previous_photo_package_inference": "LQFP64 photo classification was incorrect; QFN64 now confirmed by user",
        "evidence_note": "Original decoded image + user-confirmed and counted QFN64 package; flash source proven by scatterload; memory and peripheral mapping conditional on Cortex-M/STM32-compatible architecture.",
    }
    if not memory["data_then_zero_contiguous"] or not memory["last_region_end_equals_initial_msp"]:
        raise ValueError("V2 scatterload RAM data no longer matches initial MSP")
    return {
        "firmware": "UV-5RH Pro stock v2_0_09",
        "evidence": evidence,
        "candidates": [compare_spec(spec, evidence) for spec in SPECS],
        "interpretation": (
            "Standard part numbers are tested against the stock image assuming "
            "the high 0x08061A54 startup source is directly mapped program Flash. "
            "A mismatch is a published-SKU conflict, not a proof that an OEM "
            "version or remapped flash architecture cannot execute this firmware. "
            "The user has counted 64 terminals and confirmed the QFN package. "
            "Earlier LQFP64 photo classification was incorrect. A QFN64 "
            "package match would not identify the MCU model or brand."
        ),
        "lineage_vs_hardware": {
            "sdk_family": "AIR32F103 / MH32F103A / MH2103A compatible code signature",
            "physical_mcu": "unidentified",
            "important_conflict": (
                "Published AIR32F103RPT6 and MH2103ARPT6 are both "
                "LQFP64 / 256KiB flash, conflicting with the confirmed QFN "
                "package family and the high Flash address. Higher capacity "
                "standard MH2103A packages in the checked catalog are LQFP, "
                "which contradicts the user-confirmed QFN64 physical package."
            ),
        },
        "unresolved": [
            "Actual CPUID, AT32 DEBUG_IDCODE PID, project model byte, and Flash size ID",
            "Whether AIR32-compatible SDK code runs on higher-Flash, differently marked silicon",
            "Compatibility of PLL extended bit interpretation with vendor CRM_CFG",
            "XL9951Q matches JLCPCB catalogue C9900238147 QFN-64_8x8, but die vendor and actual specifications remain unpublished",
            "Actual physical Flash and SRAM boundaries, board wiring and revision",
            "Whether ROM, alias mapping or external NOR contributes to the high Flash-readable window",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firmware", type=Path)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    result = analyze(decoded_payload(args.firmware.read_bytes()))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        e = result["evidence"]
        print("Evidence:", e)
        for row in result["candidates"]:
            print(row["part"], row["status"], "; ".join(row["failures"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
