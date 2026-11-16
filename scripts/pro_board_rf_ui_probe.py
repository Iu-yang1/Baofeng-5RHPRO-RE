#!/usr/bin/env python3
"""One-off read-only OEM GPIO/serial bus/RF/UI function reconnaissance.

All outputs are candidate static Thumb code, not real MCU pin assignments.
"""
from __future__ import annotations
import struct
import sys
from collections import Counter
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
from mcu_fingerprint import decoded_payload
from thumb_window import inspect_window
from thumb_callsites import find_calls
from v2_scatterload_decode import decompress_region
from v2_scatterload_regions import REGION_START

BASE=0x08001000
MMIO={
 0x40010000:"AFIO",0x40010400:"EXTI",0x40010800:"GPIOA",
 0x40010C00:"GPIOB",0x40011000:"GPIOC",0x40011400:"GPIOD",
 0x40011800:"GPIOE",0x40011C00:"GPIOF",0x40012000:"GPIOG",
 0x40012C00:"TIM1",0x40013000:"SPI1",0x40013400:"TIM8",
 0x40005400:"I2C1",0x40005800:"I2C2",0x40003800:"SPI2",
 0x40003C00:"SPI3",0x40004400:"USART2",0x40004800:"USART3",
 0x40013800:"USART1",0x40021000:"RCC"
}
def scan(payload:bytes):
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    refs={}
    for off in range(0,len(payload)-3,2):
        half=struct.unpack_from("<H",payload,off)[0]
        if (half & 0xF800)!=0x4800 and (half&0xFFF0) not in (0xF85F,0xF8DF):
            continue
        pc=BASE+off
        inst=next(md.disasm(payload[off:off+4],pc,count=1),None)
        if not inst or not inst.mnemonic.startswith("ldr"):continue
        for op in inst.operands[1:]:
            if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index:continue
            loc=((pc+4)&~3)+op.mem.disp
            if loc<BASE or loc+4>BASE+len(payload) or loc%4:continue
            val=struct.unpack_from("<I",payload,loc-BASE)[0]
            if val not in MMIO:continue
            refs[pc]=(MMIO[val],val,loc)
    return refs

def context(payload,pc,lo=32,hi=68):
    st=max(BASE,(pc-lo)&~1);en=min(BASE+len(payload),(pc+hi)&~1)
    # Misaligned linear disassembly often yields false code; print from the
    # candidate LDR itself and a bounded surrounding aligned segment.
    rows=inspect_window(payload,pc,min(en,pc+hi))
    return " ; ".join(f"{r['pc']}:{r['mnemonic']} {r['operands']}" for r in rows[:28])

def main():
    for version,src in [("v1","firmware/BF_5RH_501_v1_1_04.dat"),("v2","firmware/BF_5RH_501_v2_0_9.dat")]:
        p=decoded_payload(Path(src).read_bytes());ref=scan(p)
        print("====",version,"====")
        print("MMIO_COUNTS",dict(Counter(name for name,_,_ in ref.values())))
        print("MMIO_XREFS_BEGIN")
        for pc,(name,value,literal) in sorted(ref.items()):
            if name not in ("GPIOA","GPIOB","GPIOC","GPIOD","GPIOE","AFIO","SPI1","I2C1","I2C2"):
                continue
            print("GPIO_REF",f"0x{pc:08X}",name,f"pool:0x{literal:08X}","POST",context(p,pc,hi=58))
        print("MMIO_XREFS_END")

        if version=="v2":
            load,run,size,handler=struct.unpack_from("<IIII",p,REGION_START-BASE)
            next_load=struct.unpack_from("<I",p,REGION_START-BASE+16)[0]
            data,consumed=decompress_region(p[load-BASE:next_load-BASE],size)
            print("KEY_TABLE_START",f"0x{0x200000A6:08X}","length",22)
            for ix in range(22):
                idx=0xA6+4*ix
                print("KEY_TABLE",ix,"word",f"0x{int.from_bytes(data[idx:idx+4],'little'):08X}",
                      "key_mask",f"0x{int.from_bytes(data[idx:idx+2],'little'):04X}")
            print("KEY_TABLE_END")
        if version=="v2":
            narrow=[
                (0x0800A3D0,0x0800A480),
                (0x0800AF84,0x0800B038),
                (0x0800B878,0x0800B8D8),
                (0x080074BC,0x080075E4),
                (0x08010840,0x0801092C)
            ]
            for st,en in narrow:
                print("RF_UI_BEGIN",f"0x{st:08X}")
                for ins in inspect_window(p,st,en):
                    print("RF_UI",ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
                print("RF_UI_END",f"0x{st:08X}")
        if version=="v2":
            ui_targets=[0x0800752C,0x0800755C,0x0800758C,0x080074C8,0x08014CE4,
                        0x08014D22,0x08014D38,0x08014D48,0x08014D58,
                        0x08014D68,0x08014D76,0x08014D86,0x08014D94,0x08014DA2]
            xrefs=find_calls(p,ui_targets)
            for dest,sites in xrefs.items():
                print("DISPLAY_XREF",dest,len(sites),[r["call_pc"] for r in sites][:85])
            for start,end in [
                (0x08007520,0x0800758A),(0x08014C9C,0x08014DCE),
                (0x08006DE0,0x08006F04),(0x080138D0,0x08013B90)
            ]:
                print("DISPLAY_BEGIN",f"0x{start:08X}")
                for ins in inspect_window(p,start,end):
                    print("DISPLAY",ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
                print("DISPLAY_END",f"0x{start:08X}")
        if version=="v2":
            for st,en in [(0x08015030,0x08015150),(0x08015150,0x0801525C),
                          (0x0801525C,0x0801539C),(0x0800AFC0,0x0800B0AC)]:
                print("LCD_INIT_BEGIN",f"0x{st:08X}")
                for r in inspect_window(p,st,en):
                    print("LCD_INIT",r["pc"],r["mnemonic"],r["operands"],r.get("literal_value",""))
                print("LCD_INIT_END",f"0x{st:08X}")
        if version=="v2":
            for st,en in [(0x0801514C,0x0801525C),(0x08015000,0x08015038)]:
                print("PANEL_INIT_BEGIN",f"0x{st:08X}")
                for r in inspect_window(p,st,en):
                    print("PANEL_INIT",r["pc"],r["mnemonic"],r["operands"],r.get("literal_value",""))
                print("PANEL_INIT_END",f"0x{st:08X}")
        if version=="v2":
            for st,en in [(0x0801514C,0x0801525C),(0x0800DD90,0x0800DE6C)]:
                print("FREQ_PANEL_BEGIN",f"0x{st:08X}")
                for r in inspect_window(p,st,en):
                    print("FREQ_PANEL",r["pc"],r["mnemonic"],r["operands"],r.get("literal_value",""))
                print("FREQ_PANEL_END",f"0x{st:08X}")
        verify={
          "v1":[(0x08002310,0x08002416),(0x08002470,0x080024F0),
                (0x0800B100,0x0800B1BE)],
          "v2":[(0x08005E00,0x08005F14),(0x08031860,0x080318A0)]
        }
        for st,en in verify[version]:
            print("VALIDATE_BEGIN",version,f"0x{st:08X}")
            for ins in inspect_window(p,st,en):
                print("VALIDATE",ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
            print("VALIDATE_END",version,f"0x{st:08X}")
        more={
          "v1":[(0x08002380,0x08002418),(0x08002478,0x08002514),
                (0x08002508,0x0800270A),(0x08024D20,0x08024D7C)],
          "v2":[(0x08005E80,0x08005F2C),(0x08005F90,0x08006028),
                (0x08006020,0x08006218),(0x08030D60,0x08030DF0),
                (0x080316F8,0x0803173C)]
        }
        for start,end in more[version]:
            print("RADIO_BEGIN",version,f"0x{start:08X}")
            for ins in inspect_window(p,start,end):
                print("RADIO",ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
            print("RADIO_END",version,f"0x{start:08X}")
        focus={
         "v1":[(0x08024D70,0x08024E40),(0x080256C0,0x08025730)],
         "v2":[(0x08030DD0,0x08030E98),(0x08031738,0x080317C0),
               (0x08010968,0x080109AE),(0x08010A20,0x08010A4A)]
        }
        for start,end in focus[version]:
            print("CONTROL_BEGIN",version,f"0x{start:08X}")
            for ins in inspect_window(p,start,end):
                print("CONTROL",ins["pc"],ins["mnemonic"],ins["operands"],ins.get("literal_value",""))
            print("CONTROL_END",version,f"0x{start:08X}")
        if version=="v2":
            target_calls=[
              0x08005E42,0x08005E8C,0x08005EC6,0x08005EE0,0x08005F04,
              0x08030DF0,0x08030E44,0x08031708,0x0803176E,
              0x08031864,0x08032EB8,0x08010998,0x08010A4C
            ]
            caller_sets=find_calls(p,target_calls)
            for dest,rows in caller_sets.items():
                print("ROLE_XREF",dest,len(rows),[r["call_pc"] for r in rows][:75])
        target_groups={
            "v1":[0x08002410,0x08002480,0x08003690,0x08003784,0x08024E44,
                  0x08024EC0,0x08024FC0,0x08025010,0x080250A0],
            "v2":[0x08005F28,0x08005F94,0x080071A0,0x08007206,0x08007294,
                  0x08030EB8,0x08030F34,0x08030FC0,0x08031020,
                  0x08031084,0x080310E8,0x08031148,0x080312F0]
        }
        calls=find_calls(p,target_groups[version])
        for dest,sites in calls.items():
            print("BUS_CALLS",dest,len(sites),[x["call_pc"] for x in sites][:100])

        windows={
          "v1":[(0x08002408,0x08002480),(0x08003680,0x080036F0),
                (0x08003778,0x080037C0),(0x08024E40,0x08024EB0)],
          "v2":[(0x08005F20,0x08005F90),(0x08007194,0x08007200),
                (0x08007286,0x080072D0),(0x08007320,0x08007388),
                (0x080109A0,0x08010A50),(0x08010B30,0x08010BC0),
                (0x080172B2,0x080172F4),(0x08030EB0,0x08030F38),
                (0x08030F30,0x08030FC0),(0x08030FBA,0x08031022),
                (0x0803101A,0x08031086),(0x0803107E,0x08031114),
                (0x0803110A,0x08031160),(0x080312EA,0x08031350)]
        }
        for start,end in windows[version]:
            print("HOTSPOT_BEGIN",version,f"0x{start:08X}",f"0x{end:08X}")
            for row in inspect_window(p,start,end):
                print("HOT",row["pc"],row["mnemonic"],row["operands"],row.get("literal_value",""))
            print("HOTSPOT_END",version,f"0x{start:08X}")

if __name__=="__main__":
    main()
