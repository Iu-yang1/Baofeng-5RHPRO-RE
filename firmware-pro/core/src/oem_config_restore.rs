//! Original V2 startup working-config loader, source 0x0801049E..0x080106BC.
//!
//! Archived V2 does NOT memcpy a 38-byte settings struct from NOR.
//! It reads 0x38 bytes at logical 0x7980, 4 bytes at 0x71, and later
//! 1 byte at 0x7A80, reorders fields, and performs selected repairs.
//! The last restore writes SRAM offset +0x26, beyond the 67-case getter's
//! highest referenced +0x25, so the working image needs 39 bytes.
//! This models only those confirmed three reads, not every boot operation.

use crate::nv_store::LogicalNvReader;
use crate::oem_config_getter::{OemWorkingConfig, OEM_CONFIG_STORAGE_LEN};

pub const OEM_CONFIG_MAIN_NV: u32=0x7980;
pub const OEM_CONFIG_MAIN_BYTES:usize=0x38;
pub const OEM_CONFIG_EXTRA_NV:u32=0x71;
pub const OEM_CONFIG_EXTRA_BYTES:usize=4;
pub const OEM_CONFIG_SIDE_NV:u32=0x7A80;
pub const OEM_CONFIG_SIDE_BYTES:usize=1;

/// (working SRAM byte offset, offset within 0x7980 record).
/// The original startup swaps the source slots for working bytes12/13.
pub const OEM_MAIN_TO_WORKING_MAP: [(u8,u8);34]=[
    (0,0),(1,1),(2,6),(3,7),
    (4,10),(5,11),(6,12),(7,13),
    (8,14),(9,15),(10,16),(11,17),
    (12,19),(13,18),(14,20),(15,25),
    (16,26),(17,30),(18,31),(19,8),
    (20,9),(21,32),(22,33),(23,34),
    (24,35),(25,36),(26,37),(27,38),
    (28,48),(29,49),(30,50),(31,51),
    (32,27),(34,24),
];

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum OemSettingsReadStage { Main, Extra, Side }

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct OemSettingsReadError<E> {
    pub stage:OemSettingsReadStage,
    pub source:E,
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct OriginalNvConfigSnapshot {
    pub main:[u8;OEM_CONFIG_MAIN_BYTES],
    pub extra:[u8;OEM_CONFIG_EXTRA_BYTES],
    pub side:u8,
}

pub fn read_original_config_snapshot<R:LogicalNvReader>(
    reader:&mut R,
)->Result<OriginalNvConfigSnapshot,OemSettingsReadError<R::Error>> {
    let mut main=[0u8;OEM_CONFIG_MAIN_BYTES];
    reader.read(OEM_CONFIG_MAIN_NV,&mut main)
        .map_err(|source|OemSettingsReadError{stage:OemSettingsReadStage::Main,source})?;
    let mut extra=[0u8;OEM_CONFIG_EXTRA_BYTES];
    reader.read(OEM_CONFIG_EXTRA_NV,&mut extra)
        .map_err(|source|OemSettingsReadError{stage:OemSettingsReadStage::Extra,source})?;
    let mut side=[0u8;OEM_CONFIG_SIDE_BYTES];
    reader.read(OEM_CONFIG_SIDE_NV,&mut side)
        .map_err(|source|OemSettingsReadError{stage:OemSettingsReadStage::Side,source})?;
    Ok(OriginalNvConfigSnapshot {main,extra,side:side[0]})
}

impl OriginalNvConfigSnapshot {
    /// Rebuild only the source-verified 39-byte software working view.
    /// Additional boot side effects (radio mode, RFIC, LCD, bank selection)
    /// are not performed or inferred by this method.
    pub fn restore_known_working_fields(&self)->OemWorkingConfig {
        let mut bytes=[0u8;OEM_CONFIG_STORAGE_LEN];
        for (working,source) in OEM_MAIN_TO_WORKING_MAP {
            bytes[working as usize]=self.main[source as usize];
        }
        bytes[33]=self.side;
        bytes[35..39].copy_from_slice(&self.extra);

        // These repairs are performed by the startup loader itself,
        // independently of the getter's later on-read sanitization.
        if bytes[8]>10 {bytes[8]=0;}
        if bytes[15]>2 {bytes[15]=0;}
        if bytes[18]==0 || bytes[18]>0x50 {bytes[18]=1;}
        if bytes[36]>4 {bytes[36]=0;}
        if bytes[37]==0xFF {bytes[37]=0xA0;}
        OemWorkingConfig::new(bytes)
    }
}

/// The restored source byte for working offset 32 is main[0x1B],
/// whereas OEM setter ID0x17 commits to main[0]. This mismatch is
/// preserved as evidence; an independent corrected writer can choose
/// the restore-consistent address without changing original behavior.
pub const fn restored_main_nv_address(working_offset:u8)->Option<u32> {
    let mut i=0;
    while i<OEM_MAIN_TO_WORKING_MAP.len() {
        let (dest,src)=OEM_MAIN_TO_WORKING_MAP[i];
        if dest==working_offset {return Some(OEM_CONFIG_MAIN_NV+src as u32);}
        i+=1;
    }
    None
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Reader { calls:Vec<(u32,usize)>,fail:Option<usize> }
    impl LogicalNvReader for Reader {
        type Error=&'static str;
        fn read(&mut self,address:u32,output:&mut [u8])->Result<(),Self::Error> {
            self.calls.push((address,output.len()));
            if self.fail==Some(self.calls.len()){return Err("nv");}
            for (i,b) in output.iter_mut().enumerate() {*b=i as u8;}
            Ok(())
        }
    }

    #[test]
    fn original_three_logical_nv_read_addresses_and_lengths() {
        let mut r=Reader {calls:Vec::new(),fail:None};
        let snapshot=read_original_config_snapshot(&mut r).unwrap();
        assert_eq!(r.calls,std::vec![(0x7980,0x38),(0x71,4),(0x7A80,1)]);
        assert_eq!(snapshot.main[55],55);
        assert_eq!(snapshot.extra,[0,1,2,3]);
        assert_eq!(snapshot.side,0);
    }

    #[test]
    fn every_read_error_stops_at_its_real_stage() {
        for (k,stage) in [
            (1,OemSettingsReadStage::Main),
            (2,OemSettingsReadStage::Extra),
            (3,OemSettingsReadStage::Side),
        ] {
            let mut r=Reader {calls:Vec::new(),fail:Some(k)};
            let err=read_original_config_snapshot(&mut r).unwrap_err();
            assert_eq!(err.stage,stage);
            assert_eq!(r.calls.len(),k);
        }
    }

    #[test]
    fn startup_reorders_fields_and_restores_byte_beyond_getter_span() {
        let mut source=OriginalNvConfigSnapshot {
            main:[0;OEM_CONFIG_MAIN_BYTES],extra:[0;4],side:0x92,
        };
        for (i,b) in source.main.iter_mut().enumerate(){*b=i as u8;}
        source.main[14]=0xFF; // startup repairs b[8]
        source.main[25]=0xFF; // startup repairs b[15]
        source.main[31]=0;    // startup repairs b[18]
        source.extra=[0xE1,5,0xFF,0xBE];
        let c=source.restore_known_working_fields();
        assert_eq!(c.bytes[0],0);
        assert_eq!(c.bytes[2],6);
        assert_eq!(c.bytes[12],19); // source main[19]
        assert_eq!(c.bytes[13],18); // source main[18]
        assert_eq!(c.bytes[32],27); // source main[0x1B]
        assert_eq!(c.bytes[33],0x92);
        assert_eq!(c.bytes[34],24);
        assert_eq!(c.bytes[35],0xE1);
        assert_eq!(c.bytes[36],0);
        assert_eq!(c.bytes[37],0xA0);
        assert_eq!(c.bytes[38],0xBE); // +0x26, a 39th byte
        assert_eq!(c.bytes[8],0);
        assert_eq!(c.bytes[15],0);
        assert_eq!(c.bytes[18],1);
    }

    #[test]
    fn original_nv_setter_and_restore_addresses_expose_two_discrepancies() {
        use crate::oem_config_setter::original_nv_address;
        assert_eq!(original_nv_address(12),Some(0x7991));
        assert_eq!(restored_main_nv_address(11),Some(0x7991));
        assert_eq!(original_nv_address(13),Some(0x7992));
        assert_eq!(restored_main_nv_address(12),Some(0x7993));
        assert_eq!(original_nv_address(14),Some(0x7993));
        assert_eq!(restored_main_nv_address(13),Some(0x7992));
        assert_eq!(original_nv_address(23),Some(0x7980));
        assert_eq!(restored_main_nv_address(32),Some(0x799B));
    }
}
