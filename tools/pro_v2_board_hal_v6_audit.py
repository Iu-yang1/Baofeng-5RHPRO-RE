#!/usr/bin/env python3
"""Read-only stock V2 software HAL register provenance audit.

Verifies precise Thumb callsites that justify the new register-level
adapters. Physical QFN64 pads/clock setup are NOT proven here.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from pro_v2_board_io_audit import check_site
IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
SITES={
 "panel_spi2_cs_and_data":[
  (0x0800752C,"ldr","r1, [pc",0x40010C14),
  (0x08007532,"orr","r2, r2, #0x1000",None),
  (0x08007538,"ldr","r1, [pc",0x40010814),
  (0x08007542,"bl","#0x8031864",None),
  (0x0800755C,"ldr","r1, [pc",0x40010C14),
  (0x08007568,"ldr","r1, [pc",0x40010810),
  (0x08007572,"bl","#0x8031864",None),
  (0x08031866,"ldr","r5, [pc",0x40003800),
 ],
 "spi3_clock_gpio_cr1_cr2_crc":[
  (0x08006B5C,"movs","r0, #0x38",None),
  (0x08006B6A,"ldr","r4, [pc",0x40010C00),
  (0x08006BB0,"ldr","r4, [pc",0x40003C00),
  (0x08006BBA,"bl","#0x80317dc",None),
  (0x08006BC2,"bl","#0x80317b2",None),
  (0x080317E2,"and","r3, r2, #0x3040",None),
  (0x08031804,"strh","r2, [r0]",None),
  (0x08031808,"bic","r2, r2, #0x800",None),
  (0x08031810,"strh","r1, [r0, #0x10]",None),
 ],
 "panel_reset_software_PA8":[
  (0x0801501E,"ldr","r4, [pc",0x40010810),
  (0x08015022,"orr","r0, r0, #0x100",None),
  (0x08015028,"movs","r0, #0x14",None),
  (0x08015038,"movs","r0, #0xc8",None),
  (0x08015052,"movs","r0, #0x64",None),
 ],
 "keyboard_gpioC_two_pass":[
  (0x080109AE,"ldr","r4, [pc",0x40011000),
  (0x080109E0,"and","r5, r0, #0x3c0",None),
  (0x08010A1C,"and","r0, r0, #0x3e",None),
  (0x08010A22,"lsrs","r1, r5, #1",None),
  (0x08010A3A,"cmp","r5, #0x16",None),
 ],
 "gpioB6_software_shadow":[
  (0x0800DA12,"ldr","r4, [pc",0x200017FC),
  (0x0800DA34,"ldr","r0, [pc",0x40010C10),
  (0x0800DA38,"orr","r1, r1, #0x40",None),
  (0x0800DA46,"ldr","r0, [pc",0x40010C10),
  (0x0800DA50,"str","r1, [r0]",None),
 ],
}

def verify_original(payload:bytes)->dict:
 for group,sites in SITES.items():
  for pc,mnem,operand,literal in sites:
   check_site(payload,pc,mnem,operand,literal)
 return {
  "source":"original V2 Thumb MMIO software",
  "matched_sites":{group:len(sites) for group,sites in SITES.items()},
  "supported_interfaces":["GPIO Port A/B/C compatible IDR/BSRR/BRR",
    "SPI2 panel CS/DC + source-defined command/data",
    "SPI3 CR1/CR2/CRCPR setup",
    "GPIOA bit8 panel reset","GPIOC 22-key two-pass scan",
    "GPIOB bit6 software output/observer"],
  "actual_physical_pad_identity_confirmed":False,
  "full_clock_setup_and_alternate_function_confirmed":False,
  "whole_device_bootloader_and_pa_ptt_confirmed":False,
 }

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--json",action="store_true")
 a=p.parse_args()
 result=verify_original(decoded_payload(IMAGE.read_bytes()))
 print(json.dumps(result,indent=2,ensure_ascii=False) if a.json else result)
if __name__=="__main__":
 main()
