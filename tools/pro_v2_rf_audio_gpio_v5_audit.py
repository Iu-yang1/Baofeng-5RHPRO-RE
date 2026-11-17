#!/usr/bin/env python3
"""Verify original RFIC audio option and GPIOB6 software-shadow paths.

The tested bytes prove software registers, not a QFN physical PA/PTT,
speaker amplifier, microphone wiring or speaker mute function.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from pro_v2_board_io_audit import check_site

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
SITES={
 "PB6_on_off":[
  (0x0800DA12,"ldr","r4, [pc",0x200017FC),
  (0x0800DA16,"cbz","r0, #0x800da46",None),
  (0x0800DA1C,"bl","#0x80014a4",None),
  (0x0800DA26,"bl","#0x80014a4",None),
  (0x0800DA2A,"bl","#0x80102a0",None),
  (0x0800DA2E,"movs","r0, #0x32",None),
  (0x0800DA30,"bl","#0x8006800",None),
  (0x0800DA34,"ldr","r0, [pc",0x40010C10),
  (0x0800DA38,"orr","r1, r1, #0x40",None),
  (0x0800DA40,"strb","r0, [r4]",None),
  (0x0800DA42,"strh","r5, [r4, #2]",None),
  (0x0800DA46,"ldr","r0, [pc",0x40010C10),
  (0x0800DA48,"adds","r0, r0, #4",None),
  (0x0800DA4C,"orr","r1, r1, #0x40",None),
  (0x0800DA52,"strb","r5, [r4]",None),
 ],
 "config_setter_software_PB6_interlock_candidate":[
  (0x08016638,"bl","#0x800da10",None),
  (0x0801663C,"ldrb","r0, [r4, #0x18]",None),
  (0x08016642,"bic","r0, r0, #0x80",None),
  (0x08016646,"orr.w","r0, r0, r1, lsl #7",None),
 ],
 "AF_option_nonzero":[
  (0x0800A354,"push","{r3, lr}",None),
  (0x0800A356,"cbz","r0, #0x800a37e",None),
  (0x0800A35A,"movs","r0, #0x43",None),
  (0x0800A35C,"bl","#0x8005e42",None),
  (0x0800A364,"bic","r1, r0, #0x7e00",None),
  (0x0800A36C,"movs","r0, #0x43",None),
  (0x0800A36E,"bl","#0x8005e8c",None),
  (0x0800A372,"movw","r1, #0x3ff",None),
  (0x0800A376,"movs","r0, #0x13",None),
  (0x0800A378,"bl","#0x8005e8c",None),
 ],
 "AF_option_zero_branch_opaque_helper":[
  (0x0800A37E,"ldr","r1, [pc",0x20001B84),
  (0x0800A380,"movw","r0, #0x6042",None),
  (0x0800A384,"strh","r0, [r1, #0xe]",None),
  (0x0800A388,"bl","#0x800b51c",None),
  (0x0800A38E,"bl","#0x800a310",None),
 ],
}


def verify_original(payload:bytes)->dict:
    for label,sites in SITES.items():
        for pc,opcode,operands,literal in sites:
            check_site(payload,pc,opcode,operands,literal)
    return {
      "source_groups":{name:len(sites) for name,sites in SITES.items()},
      "pb6_software_pin":"GPIOB bit6",
      "pb6_state_sram":"0x200017FC",
      "pb6_pre_enable_calls":["0x080014A4","0x080014A4","0x080102A0","delay(0x32)"],
      "config_setter_id35_calls_pb6_helper_before_field_update":True,
      "audio_nonzero_register_operations":[
          "read REG43","write REG43 & ~0x7E00","write REG13=0x03FF",
      ],
      "audio_zero_branch_calls_opaque_0x0800B51C_before_mode0":True,
      "physical_pa_mute_ptt_or_audio_wiring_confirmed":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json",action="store_true")
    a=p.parse_args()
    d=verify_original(decoded_payload(IMAGE.read_bytes()))
    print(json.dumps(d,indent=2) if a.json else d)
if __name__=="__main__":
    main()
