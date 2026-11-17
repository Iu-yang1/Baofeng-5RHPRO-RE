//! Original V2 configuration setter entry 0x080164A0 (61-case TBB).
//!
//! This is a *software-only model* of the original working SRAM write and
//! optional single-byte journal submission at 0x0801677C..0x08016788.
//! Case ID, raw value, and commit selector are original ABI arguments.
//! It is not a physical PA/PTT controller or an implemented SPI-NOR backend.
//! Side-effecting helper calls for IDs 0x23 and 0x27 must remain separately
//! integrated at their original source order: they are reported, not guessed.

use crate::oem_config_getter::{ConfigRead, OemWorkingConfig, OEM_GETTER_CASES};

pub const OEM_SETTER_ENTRY: u32 = 0x0801_64A0;
pub const OEM_SETTER_TBB: u32 = 0x0801_64D2;
pub const OEM_SETTER_TABLE: u32 = 0x0801_64D6;
pub const OEM_SETTER_COUNT: usize = 0x3D;

/// Exact unsigned byte offsets at 0x080164D6, one for each setter case.
/// Target = OEM_SETTER_TABLE + 2*offset; physical menu labels unknown.
pub const OEM_SETTER_TBB_OFFSETS: [u8; OEM_SETTER_COUNT] = [
    31,33,36,39,42,50,58,61,64,67,70,73,76,79,82,85,
    88,91,94,97,103,100,106,109,113,118,127,132,137,142,
    149,154,112,163,168,177,187,196,201,206,112,112,
    220,242,251,239,238,237,236,235,234,112,233,232,
    231,230,229,228,227,226,225,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OemSetterPreCall {
    /// Original source 0x08016638 BL 0x0800DA10, argument=raw value.
    SoftwareHelperDa10,
    /// Original source 0x08016672 BL 0x0800CAEC, argument=raw value.
    SoftwareHelperCaec,
}

pub const fn original_pre_call(config_id:u8) -> Option<OemSetterPreCall> {
    match config_id {
        0x23 => Some(OemSetterPreCall::SoftwareHelperDa10),
        0x27 => Some(OemSetterPreCall::SoftwareHelperCaec),
        _ => None,
    }
}

/// Exact original logical-NV address selected before the optional
/// 0x080190E0 single-byte journal update. An absent value is an OEM
/// no-op setter case, NOT a new arbitrary TX/config restriction.
pub const fn original_nv_address(id:u8) -> Option<u32> {
    let address = match id {
        0 => 0x7980, 1 => 0x7981, 2 => 0x7986, 3 => 0x7987,
        4|5 => 0x798A, 6 => 0x798B, 7 => 0x798C,
        8 => 0x798D, 9 => 0x798E, 10 => 0x798F,
        11 => 0x7990, 12 => 0x7991, 13 => 0x7992,
        14 => 0x7993, 15 => 0x7994, 16 => 0x799A,
        17 => 0x7988, 18 => 0x7989,
        19 => 0x79B0, 20 => 0x79B1, 21 => 0x79B2,
        22 => 0x79B3,
        // Source 0x080165B0 falls through with default r1=0.
        // The startup loader restores b[32] from 0x799B instead.
        // Preserve that discrepancy for analysis, do not silently fix it.
        23 => 0x7980,
        24..=29 => 0x79A0, 30..=31 => 0x79A1,
        32|40|41|51 => return None,
        33..=34 => 0x79A2, 35..=38 => 0x79A3,
        39 => 0x79A4, 42..=46 => 0x79A5,
        47..=50|52 => {
            if id == 52 { 0x7A80 } else { 0x79A6 }
        },
        53 => 0x7999, 54 => 0x7998,
        55 => 0x799E, 56 => 0x799F,
        57..=59 => 0x71, 60 => 0x72,
        _ => return None,
    };
    Some(address)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalByteJournalRequest {
    pub logical_address:u32,
    pub value:u8,
    /// OEM only calls 0x080190E0 when third argument equals 1.
    pub requested_by_caller:bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalConfigMutation {
    pub config_id:u8,
    pub working_offset:u8,
    pub working_value:u8,
    pub journal: OriginalByteJournalRequest,
    pub pre_call:Option<OemSetterPreCall>,
}

/// Abstract original **logical one-byte transaction** (0x080190E0).
/// This is not a raw SPI-NOR write or a confirmed external flash driver.
pub trait LogicalNvJournal {
    type Error;
    fn update_one(&mut self, logical_address:u32, value:u8)->Result<(),Self::Error>;
}

impl OriginalConfigMutation {
    /// Execute the requested one-byte transaction. If caller did not pass
    /// r2==1 the OEM changes SRAM only and does not perform this call.
    pub fn commit<W:LogicalNvJournal>(&self, writer:&mut W)->Result<(),W::Error> {
        if self.journal.requested_by_caller {
            writer.update_one(self.journal.logical_address,self.journal.value)?;
        }
        Ok(())
    }
}

/// Reconstruct one direct source writer *after* any original opaque pre-call.
/// The original writer stores the raw input byte or bitfield without value
/// width clamping; spilled high bits are not artificially blocked here.
pub fn apply_original_setter(
    working:&mut OemWorkingConfig,
    config_id:u8,
    raw_value:u8,
    commit_flag:u32,
)->Option<OriginalConfigMutation> {
    let address=original_nv_address(config_id)?;
    let spec=match config_id {
        // The getter reports hardcoded 1 for IDs 0x39 and 0x3B,
        // but their setter branches still modify b[35] bit7/bit5.
        57 => ConfigRead::Bits { offset:35, shift:7, mask:1 },
        59 => ConfigRead::Bits { offset:35, shift:5, mask:1 },
        _ => OEM_GETTER_CASES[config_id as usize],
    };
    let (offset,stored)=match spec {
        ConfigRead::Direct {offset}|ConfigRead::Limited {offset,..} =>
            (offset,raw_value),
        ConfigRead::Bits {offset,shift,mask} =>{
            let old=working.bytes[offset as usize];
            let clear_mask=!(mask << shift);
            (offset,(old & clear_mask) | raw_value.wrapping_shl(shift as u32))
        },
        ConfigRead::Constant(_) => return None,
    };
    working.bytes[offset as usize]=stored;
    Some(OriginalConfigMutation {
        config_id,working_offset:offset,working_value:stored,
        journal:OriginalByteJournalRequest {
            logical_address:address,value:stored,requested_by_caller:commit_flag==1,
        },
        pre_call:original_pre_call(config_id),
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::oem_config_getter::OEM_CONFIG_STORAGE_LEN;
    use std::vec::Vec;
    #[derive(Default)] struct Writer { writes:Vec<(u32,u8)> }
    impl LogicalNvJournal for Writer {
        type Error=();
        fn update_one(&mut self,address:u32,value:u8)->Result<(),Self::Error> {
            self.writes.push((address,value));Ok(())
        }
    }

    #[test]
    fn all_61_original_setter_targets_resolve_to_thumb_handlers() {
        assert_eq!(OEM_SETTER_TBB_OFFSETS.len(),61);
        for &entry in &OEM_SETTER_TBB_OFFSETS {
            let pc=OEM_SETTER_TABLE+2*entry as u32;
            assert!((0x08016514..=0x080166CC).contains(&pc));
        }
        for id in [32,40,41,51] {
            assert_eq!(original_nv_address(id),None);
        }
        assert_eq!(original_nv_address(61),None);
    }

    #[test]
    fn byte_setters_update_working_sram_then_journal_when_requested() {
        let mut s=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut writer=Writer::default();
        let m=apply_original_setter(&mut s,2,17,1).unwrap();
        assert_eq!(m.working_offset,2);
        assert_eq!(s.bytes[2],17); // source setter does not clamp to getter limit10
        assert_eq!(m.journal.logical_address,0x7986);
        m.commit(&mut writer).unwrap();
        assert_eq!(writer.writes, std::vec![(0x7986,17)]);
        assert_eq!(s.read(crate::oem_menu::OriginalConfigId(2)),0);
        assert_eq!(s.bytes[2],0); // getter's original read-repair remains separate
    }

    #[test]
    fn packed_setters_preserve_other_fields_and_no_spurious_restrictions() {
        let mut s=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        s.bytes[4]=0xAB;s.bytes[21]=0xAD;s.bytes[35]=0;
        let m=apply_original_setter(&mut s,4,2,0).unwrap();
        assert_eq!(s.bytes[4],0x2B);
        assert_eq!(m.journal.logical_address,0x798A);
        let m=apply_original_setter(&mut s,28,1,0).unwrap();
        assert_eq!(s.bytes[21],0xA5);
        assert_eq!(m.journal.logical_address,0x79A0);
        // Source writes do not mask raw bits to the width of a getter.
        apply_original_setter(&mut s,25,3,0).unwrap();
        assert_eq!(s.bytes[21],0xE5);
        let mut w=Writer::default();
        m.commit(&mut w).unwrap();
        assert!(w.writes.is_empty());
    }

    #[test]
    fn original_oem_pre_call_and_noncommitting_behavior_are_visible() {
        let mut s=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mut w=Writer::default();
        let m=apply_original_setter(&mut s,35,1,9).unwrap();
        assert_eq!(m.pre_call,Some(OemSetterPreCall::SoftwareHelperDa10));
        assert_eq!(m.journal.logical_address,0x79A3);
        m.commit(&mut w).unwrap();
        assert_eq!(w.writes.len(),0);
        let m=apply_original_setter(&mut s,39,1,1).unwrap();
        assert_eq!(m.pre_call,Some(OemSetterPreCall::SoftwareHelperCaec));
        assert_eq!(m.journal.logical_address,0x79A4);
        m.commit(&mut w).unwrap();
        assert_eq!(w.writes, std::vec![(0x79A4,0x80)]);
    }

    #[test]
    fn special_settings_and_source_discrepancy_are_explicit() {
        let mut s=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let a=apply_original_setter(&mut s,52,0x33,1).unwrap();
        assert_eq!(a.working_offset,33);
        assert_eq!(a.journal.logical_address,0x7A80);
        let b=apply_original_setter(&mut s,57,1,1).unwrap();
        assert_eq!(b.working_offset,35);
        assert_eq!(s.bytes[35],0x80);
        assert_eq!(b.journal.logical_address,0x71);
        let c=apply_original_setter(&mut s,60,0x82,1).unwrap();
        assert_eq!(c.working_offset,36);
        assert_eq!(c.journal.logical_address,0x72);
        let suspect=apply_original_setter(&mut s,23,0x12,1).unwrap();
        assert_eq!(suspect.working_offset,32);
        assert_eq!(suspect.journal.logical_address,0x7980);
    }

    #[test]
    fn source_noop_setters_do_not_mutate_or_commit() {
        let mut s=OemWorkingConfig::new([0xA5;OEM_CONFIG_STORAGE_LEN]);
        for id in [32,40,41,51,61,255] {
            assert_eq!(apply_original_setter(&mut s,id,0,1),None);
        }
        assert_eq!(s.bytes,[0xA5;OEM_CONFIG_STORAGE_LEN]);
    }
}
