#!/usr/bin/env python3
"""OEM V2 source audit: menu state poll, framebuffer/text path, setter use.

This verifies source-backed ORIGINAL menu fragments. The new interactive
menu labels and layout are independent debug UI, not OEM pixel replicas.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from mcu_fingerprint import decoded_payload
from pro_v2_board_io_audit import check_site
IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")

SITES={
 "original_ui_activity_and_selector":[
  (0x0800E064,"push","{r4, lr}",None),
  (0x0800E066,"bl","#0x800e0b8",None),
  (0x0800E06C,"bl","#0x800e0c8",None),
  (0x0800E072,"ldr","r0, [pc",0x20000104),
  (0x0800E074,"ldrb","r0, [r0, #3]",None),
  (0x0800E0B8,"ldr","r0, [pc",0x20001826),
  (0x0800E0BA,"ldrb","r0, [r0, #4]",None),
  (0x0800E0BC,"and","r0, r0, #1",None),
 ],
 "original_poll_state_transition":[
  (0x080167BA,"ldr","r4, [pc",0x20000104),
  (0x080167BC,"ldrh","r0, [r4, #0x10]",None),
  (0x080167BE,"lsls","r1, r0, #0x18",None),
  (0x080167C0,"bmi","#0x8016812",None),
  (0x080167C2,"bl","#0x800e0b8",None),
  (0x080167C8,"bl","#0x800e064",None),
  (0x080167CE,"bl","#0x800d010",None),
  (0x080167D2,"cmp","r0, r5",None),
  (0x080167D6,"mov","r0, r5",None),
  (0x080167D8,"bl","#0x800d080",None),
  (0x080167DE,"bl","#0x800e454",None),
  (0x080167E2,"cbz","r0, #0x80167fe",None),
  (0x080167E6,"bl","#0x800de68",None),
  (0x080167EE,"bl","#0x800cb28",None),
  (0x080167F4,"bl","#0x8014230",None),
  (0x080167FE,"movw","r1, #0xffff",None),
  (0x08016804,"movs","r0, #1",None),
  (0x08016806,"strb","r0, [r4]",None),
  (0x0801680A,"orr","r0, r0, #0x80",None),
  (0x0801680E,"strh","r0, [r4, #0x10]",None),
  (0x08016812,"bic","r0, r0, #0x80",None),
  (0x08016818,"movs","r0, #4",None),
  (0x0801681A,"strb","r0, [r4]",None),
 ],
 "verified_oem_text_framebuffer_path":[
  (0x08010DB4,"push","{r4, r5, r6, r7, lr}",None),
  (0x08010DB6,"ldr","r7, [pc",0x20004B76),
  (0x08010DC8,"strh.w","r6, [r5, r4, lsl #1]",None),
  (0x08010DE4,"push.w","{r0, r1, r2, r3",None),
  (0x08010DFA,"ldrb.w","r1, [fp, r3]",None),
  (0x08010DFE,"cbz","r1, #0x8010e08",None),
  (0x08010E16,"movs","r0, #8",None),
  (0x08010E20,"movs","r0, #0x18",None),
 ],
 "original_editor_explicit_persistence_caller":[
  (0x0801D460,"movs","r2, #1",None),
  (0x0801D462,"movs","r0, #0x19",None),
  (0x0801D464,"bl","#0x80164a0",None),
  (0x0801D46E,"movs","r0, #1",None),
  (0x0801D470,"bl","#0x8016794",None),
  (0x08020A5C,"movs","r2, #1",None),
  (0x08020A60,"movs","r0, #0x11",None),
  (0x08020A62,"bl","#0x80164a0",None),
 ],
}

def verify_original(payload:bytes)->dict:
 for group,sites in SITES.items():
  for pc,opcode,operand,literal in sites:
   check_site(payload,pc,opcode,operand,literal)
 return {
  "source_version":"BF_5RH_501_v2_0_9.dat",
  "groups":{key:len(sites) for key,sites in SITES.items()},
  "active_menu_flag_byte":"0x2000182A bit0",
  "ui_status_sram":"0x20000104",
  "ui_status_flag":"halfword +0x10 bit7",
  "selection_source":"0x0800E064",
  "previous_selection_source":"0x0800D010",
  "source_zero_config_marker":"0xFFFF",
  "original_text_draw_entry":"0x08010DE4",
  "original_framebuffer":"0x20004B76",
  "config_setter":"0x080164A0",
  "full_oem_keymap_and_visual_string_assets_restored":False,
  "physical_board_validation":False,
 }

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--json",action="store_true")
 args=p.parse_args()
 report=verify_original(decoded_payload(IMAGE.read_bytes()))
 print(json.dumps(report,ensure_ascii=False,indent=2) if args.json else report)
if __name__=="__main__":
 main()
