//! Source-reconstructed V2.0.09 configuration getter at 0x0800E454.
//!
//! Reads the OEM SRAM structure rooted at 0x20004580, dispatches via
//! its original 67-case TBB table, and reproduces the proven bounds
//! repairs. Configuration IDs are not physical keys or menu labels.
//! This models one OEM *getter*, not yet menu editing or NV saving.

use crate::oem_menu::OriginalConfigId;

pub const OEM_CONFIG_SRAM_BASE: u32 = 0x2000_4580;
/// The getter reaches +0x25, but original startup also writes +0x26.
/// Preserve that extra working byte; it is not exposed by the 67-ID getter.
pub const OEM_CONFIG_STORAGE_LEN: usize = 0x27;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigRead {
    Direct { offset: u8 },
    Bits { offset: u8, shift: u8, mask: u8 },
    Limited { offset: u8, max: u8, replacement: u8 },
    Constant(u8),
}

use ConfigRead::{Bits, Constant, Direct, Limited};

/// One case per original TBB configuration ID (0..0x42).
/// Every offset/bitfield comes from 0x0800E4CA..0x0800E63E.
pub const OEM_GETTER_CASES: [ConfigRead; 67] = [
    Limited { offset:0,max:2,replacement:0 },         // 00
    Limited { offset:1,max:2,replacement:0 },         // 01
    Limited { offset:2,max:10,replacement:0 },        // 02
    Limited { offset:3,max:10,replacement:0 },        // 03
    Bits { offset:4,shift:4,mask:15 },                 // 04
    Bits { offset:4,shift:0,mask:15 },                 // 05
    Direct { offset:5 },                              // 06
    Limited { offset:6,max:1,replacement:0 },         // 07
    Limited { offset:7,max:10,replacement:5 },        // 08
    Direct { offset:8 },                              // 09
    Direct { offset:9 },                              // 0A
    Direct { offset:10 },                             // 0B
    Direct { offset:11 },                             // 0C
    Direct { offset:12 },                             // 0D
    Direct { offset:13 },                             // 0E
    Direct { offset:14 },                             // 0F
    Direct { offset:16 },                             // 10
    Direct { offset:19 },                             // 11
    Limited { offset:20,max:4,replacement:0 },        // 12
    Direct { offset:28 },                             // 13
    Direct { offset:30 },                             // 14
    Direct { offset:29 },                             // 15
    Direct { offset:31 },                             // 16
    Direct { offset:32 },                             // 17
    Bits { offset:21,shift:7,mask:1 },                 // 18
    Bits { offset:21,shift:6,mask:1 },                 // 19
    Bits { offset:21,shift:5,mask:1 },                 // 1A
    Bits { offset:21,shift:4,mask:1 },                 // 1B
    Bits { offset:21,shift:2,mask:3 },                 // 1C
    Bits { offset:21,shift:0,mask:3 },                 // 1D
    Bits { offset:22,shift:7,mask:1 },                 // 1E
    Bits { offset:22,shift:6,mask:1 },                 // 1F
    Constant(0),                                      // 20
    Bits { offset:23,shift:7,mask:1 },                 // 21
    Bits { offset:23,shift:5,mask:3 },                 // 22
    Bits { offset:24,shift:7,mask:1 },                 // 23
    Bits { offset:24,shift:5,mask:3 },                 // 24
    Bits { offset:24,shift:4,mask:1 },                 // 25
    Bits { offset:24,shift:3,mask:1 },                 // 26
    Bits { offset:25,shift:7,mask:1 },                 // 27
    Constant(0),                                      // 28
    Constant(0),                                      // 29
    Bits { offset:26,shift:7,mask:1 },                 // 2A
    Bits { offset:26,shift:5,mask:3 },                 // 2B
    Bits { offset:26,shift:3,mask:1 },                 // 2C
    Bits { offset:26,shift:2,mask:1 },                 // 2D
    Bits { offset:26,shift:0,mask:3 },                 // 2E
    Bits { offset:27,shift:5,mask:7 },                 // 2F
    Bits { offset:27,shift:4,mask:1 },                 // 30
    Bits { offset:27,shift:3,mask:1 },                 // 31
    Bits { offset:27,shift:2,mask:1 },                 // 32
    Bits { offset:27,shift:0,mask:1 },                 // 33
    Direct { offset:33 },                             // 34
    Direct { offset:15 },                             // 35
    Direct { offset:34 },                             // 36
    Direct { offset:17 },                             // 37
    Direct { offset:18 },                             // 38
    Constant(1),                                      // 39
    Bits { offset:35,shift:6,mask:1 },                 // 3A
    Constant(1),                                      // 3B
    Direct { offset:36 },                             // 3C
    Bits { offset:37,shift:7,mask:1 },                 // 3D
    Bits { offset:37,shift:6,mask:1 },                 // 3E
    Bits { offset:37,shift:5,mask:1 },                 // 3F
    Bits { offset:37,shift:4,mask:1 },                 // 40
    Bits { offset:37,shift:3,mask:1 },                 // 41
    Bits { offset:37,shift:2,mask:1 },                 // 42
];

/// 38-byte restored SRAM *working structure*, not the NOR on-disk format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OemWorkingConfig {
    pub bytes: [u8; OEM_CONFIG_STORAGE_LEN],
}

impl OemWorkingConfig {
    pub const fn new(bytes: [u8; OEM_CONFIG_STORAGE_LEN]) -> Self {
        Self { bytes }
    }

    /// Original 0x0800E454 treats IDs >= 0x43 as default zero.
    /// Invalid stored field values are repaired *in working SRAM*,
    /// matching the OEM's side-effectful read behavior.
    pub fn read(&mut self, id: OriginalConfigId) -> u8 {
        let Some(case) = OEM_GETTER_CASES.get(id.0 as usize) else {
            return 0;
        };
        match *case {
            Direct { offset } => self.bytes[offset as usize],
            Bits { offset, shift, mask } =>
                (self.bytes[offset as usize] >> shift) & mask,
            Limited { offset, max, replacement } => {
                let v = &mut self.bytes[offset as usize];
                if *v > max { *v = replacement; }
                *v
            }
            Constant(v) => v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_case_has_source_bounded_working_ram_offsets() {
        assert_eq!(OEM_GETTER_CASES.len(), 0x43);
        for case in OEM_GETTER_CASES {
            match case {
                Direct { offset }|Bits { offset,.. }|Limited { offset,.. } =>
                    assert!((offset as usize) < OEM_CONFIG_STORAGE_LEN),
                Constant(_) => (),
            }
        }
    }

    #[test]
    fn raw_nibbles_and_bitfields_follow_original_cases() {
        let mut bytes=[0u8; OEM_CONFIG_STORAGE_LEN];
        for (i,b) in bytes.iter_mut().enumerate() { *b=i as u8; }
        bytes[4]=0xBA; bytes[21]=0xDA; bytes[22]=0xC0;
        bytes[23]=0xE0; bytes[24]=0xB8; bytes[25]=0xC0;
        bytes[26]=0xAD; bytes[27]=0xDD; bytes[35]=0x40;
        bytes[37]=0xDC;
        let mut cfg=OemWorkingConfig::new(bytes);
        assert_eq!(cfg.read(OriginalConfigId(4)),0xB);
        assert_eq!(cfg.read(OriginalConfigId(5)),0xA);
        assert_eq!(cfg.read(OriginalConfigId(0x1C)),2);
        assert_eq!(cfg.read(OriginalConfigId(0x1D)),2);
        assert_eq!(cfg.read(OriginalConfigId(0x1E)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x1F)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x22)),3);
        assert_eq!(cfg.read(OriginalConfigId(0x24)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x2B)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x2F)),6);
        assert_eq!(cfg.read(OriginalConfigId(0x3A)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x3D)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x3E)),1);
        assert_eq!(cfg.read(OriginalConfigId(0x3F)),0);
    }

    #[test]
    fn original_repairs_modify_working_values_in_place() {
        let mut cfg=OemWorkingConfig::new([0xFF; OEM_CONFIG_STORAGE_LEN]);
        for (id,offset,reset) in [
            (0,0,0),(1,1,0),(2,2,0),(3,3,0),
            (7,6,0),(8,7,5),(18,20,0),
        ] {
            assert_eq!(cfg.read(OriginalConfigId(id)),reset);
            assert_eq!(cfg.bytes[offset],reset);
        }
        cfg.bytes[2]=10;cfg.bytes[7]=10;cfg.bytes[20]=4;
        assert_eq!(cfg.read(OriginalConfigId(2)),10);
        assert_eq!(cfg.read(OriginalConfigId(8)),10);
        assert_eq!(cfg.read(OriginalConfigId(18)),4);
    }

    #[test]
    fn default_and_constant_cases_do_not_read_other_sram() {
        let mut cfg=OemWorkingConfig::new([0xFF;OEM_CONFIG_STORAGE_LEN]);
        for id in [0x20,0x28,0x29,0x43,0xFF] {
            assert_eq!(cfg.read(OriginalConfigId(id)),0);
        }
        for id in [0x39,0x3B] {
            assert_eq!(cfg.read(OriginalConfigId(id)),1);
        }
        assert_eq!(cfg.bytes,[0xFF;OEM_CONFIG_STORAGE_LEN]);
    }

    #[test]
    fn conditional_key_pair_reads_real_working_fields() {
        let mut cfg=OemWorkingConfig::new([0; OEM_CONFIG_STORAGE_LEN]);
        cfg.bytes[28]=16;cfg.bytes[30]=11;
        cfg.bytes[29]=9;cfg.bytes[31]=16;
        assert_eq!(cfg.read(OriginalConfigId(0x13)),16);
        assert_eq!(cfg.read(OriginalConfigId(0x14)),11);
        assert_eq!(cfg.read(OriginalConfigId(0x15)),9);
        assert_eq!(cfg.read(OriginalConfigId(0x16)),16);
    }
}
