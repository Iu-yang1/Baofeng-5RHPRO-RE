#!/usr/bin/env python3
"""Read-only exploratory evidence for UV-5RH Pro original V2 board functions."""
from __future__ import annotations
import struct
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_window import BASE,inspect_window
from thumb_callsites import find_calls
from v2_scatterload_decode import decompress_region
from v2_scatterload_regions import REGION_START

IMAGE=Path("firmware/BF_5RH_501_v2_0_9.dat")
REGIONS = {
  "calibration_candidates": [(0x0800DEE8,0x0800E160),(0x08031B50,0x08031C00),(0x0800A420,0x0800A7C0),(0x0800A7F0,0x0800A920)],
  "rfic_ptt_audio": [(0x0800AF80,0x0800B16A),(0x0800A310,0x0800A3C0),(0x0800B510,0x0800B650),(0x0800B780,0x0800B950)],
  "lcd_init": [(0x08015040,0x08015222)],
  "lcd_ui": [(0x08015220,0x080153B0),(0x08010AB0,0x08010CF0)],
  "mcu_boot": [(0x08001220,0x08001288),(0x080340E0,0x08034150)]
}
MMIO = {
  0x40010800:"GPIOA_CRL",0x40010804:"GPIOA_CRH",0x40010808:"GPIOA_IDR",
  0x4001080C:"GPIOA_ODR",0x40010810:"GPIOA_BSRR",0x40010814:"GPIOA_BRR",
  0x40010C00:"GPIOB_CRL",0x40010C04:"GPIOB_CRH",0x40010C08:"GPIOB_IDR",
  0x40010C0C:"GPIOB_ODR",0x40010C10:"GPIOB_BSRR",0x40010C14:"GPIOB_BRR",
  0x40011000:"GPIOC_CRL",0x40011004:"GPIOC_CRH",0x40011008:"GPIOC_IDR",
  0x4001100C:"GPIOC_ODR",0x40011010:"GPIOC_BSRR",0x40011014:"GPIOC_BRR",
  0x40003800:"SPI2_CR1",0x40003C00:"SPI3_CR1",0x40012400:"ADC1_SR",
  0x40021000:"RCC_CR",0x40022000:"FLASH_ACR",0x0807F800:"MCU_JOURNAL",
  0x2000246C:"RF_TUNE_TABLE",0x2000245C:"RF_MODE_TABLE",
  0x20001B84:"FD_STATE",0x20004B76:"LCD_BUFFER",
}
def get_sram(payload):
 off=REGION_START-BASE
 src,dst,n,fun=struct.unpack_from("<IIII",payload,off)
 next_src=struct.unpack_from("<I",payload,off+16)[0]
 img,used=decompress_region(payload[src-BASE:next_src-BASE],n)
 return dst,img
def print_windows(payload):
 for group,ranges in REGIONS.items():
  for lo,hi in ranges:
   print("REGION",group,f"0x{lo:08X}",f"0x{hi:08X}")
   for row in inspect_window(payload,lo,hi):
    print("I",row["pc"],row["mnemonic"],row["operands"],row.get("literal_value",""))
   print("END_REGION",group)
def print_literal_sites(payload):
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 for addr,name in MMIO.items():
  raw=struct.pack("<I",addr)
  locs=[BASE+i for i in range(0,len(payload)-3,4) if payload[i:i+4]==raw]
  sites=[]
  for lit in locs:
   for pc in range(max(BASE,lit-512),lit,2):
    o=pc-BASE
    x=next(md.disasm(payload[o:o+4],pc,count=1),None)
    if x is None or not x.mnemonic.startswith("ldr"):continue
    if any(op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC and
           (((pc+4)&~3)+op.mem.disp)==lit for op in x.operands):
     sites.append(pc)
  print("MMIO",name,hex(addr),"pool",len(locs),"ldr_candidates",len(sites),
        "pcs",*[hex(x) for x in sites[:75]])
def print_calls(payload):
 targets=[0x08005E8C,0x08005E42,0x08005EC6,0x08010998,
          0x0800752C,0x0800755C,0x0800AFE4,0x0800A428,
          0x0800A310,0x0800B51C,0x0800DE08]
 for k,rows in find_calls(payload,targets).items():
  print("CALLS",k,len(rows),*[v["call_pc"] for v in rows[:150]])
def main():
 payload=decoded_payload(IMAGE.read_bytes())
 dst,init=get_sram(payload)
 print("INIT_SRAM",hex(dst),len(init),
       "RF_TUNE_TABLE_IS_ZERO_INIT_BSS",0x2000246C>=dst+len(init))
 print("STOCK_VECTOR",hex(struct.unpack_from("<I",payload,0)[0]),
       hex(struct.unpack_from("<I",payload,4)[0]))
 print_literal_sites(payload)
 print_calls(payload)
 print_windows(payload)
if __name__=="__main__":main()
