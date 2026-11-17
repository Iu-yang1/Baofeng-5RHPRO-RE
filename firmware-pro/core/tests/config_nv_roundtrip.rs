//! End-to-end host-only OEM configuration NV→RAM→UI/setter→NV trace.
//!
//! No real MCU, GPIO or SPI writes. Real NV writes would require a
//! separately validated board driver and transaction recovery backend.

use uv5rh_pro_core::nv_store::LogicalNvReader;
use uv5rh_pro_core::oem_config_restore::{
    read_original_config_snapshot, OriginalNvConfigSnapshot,
    OEM_CONFIG_MAIN_BYTES,
};
use uv5rh_pro_core::oem_config_setter::{
    apply_original_setter, LogicalNvJournal,
};
use uv5rh_pro_core::oem_menu::OriginalConfigId;
use std::vec::Vec;

struct NvFixture {
    reads: Vec<(u32, usize)>,
    writes: Vec<(u32, u8)>,
    main: [u8; OEM_CONFIG_MAIN_BYTES],
    extra: [u8; 4],
    side: [u8; 1],
}

impl NvFixture {
    fn new() -> Self {
        Self {
            reads: Vec::new(),
            writes: Vec::new(),
            main: [0; OEM_CONFIG_MAIN_BYTES],
            extra: [0; 4],
            side: [0; 1],
        }
    }
}

impl LogicalNvReader for NvFixture {
    type Error = &'static str;
    fn read(&mut self, address: u32, output: &mut [u8]) -> Result<(), Self::Error> {
        self.reads.push((address,output.len()));
        let data: &[u8] = match address {
            0x7980 => &self.main,
            0x71 => &self.extra,
            0x7A80 => &self.side,
            _ => return Err("wrong NV logical address"),
        };
        output.copy_from_slice(data);
        Ok(())
    }
}

impl LogicalNvJournal for NvFixture {
    type Error = &'static str;
    fn update_one(&mut self, address: u32, value: u8) -> Result<(), Self::Error> {
        self.writes.push((address,value));
        if (0x7980..0x7980+OEM_CONFIG_MAIN_BYTES as u32).contains(&address) {
            self.main[(address - 0x7980) as usize] = value;
        } else if (0x71..0x75).contains(&address) {
            self.extra[(address - 0x71) as usize] = value;
        } else if address == 0x7A80 {
            self.side[0] = value;
        } else {
            return Err("unknown logical address in fixture");
        }
        Ok(())
    }
}

fn load(fixture: &mut NvFixture) -> OriginalNvConfigSnapshot {
    read_original_config_snapshot(fixture).unwrap()
}

#[test]
fn whole_byte_original_nv_roundtrip_on_restored_field() {
    let mut fixture=NvFixture::new();
    fixture.main[6]=4; // getter ID02 uses working b[2]
    let mut working=load(&mut fixture).restore_known_working_fields();
    assert_eq!(working.read(OriginalConfigId(2)),4);
    let plan=apply_original_setter(&mut working,2,7,1).unwrap();
    assert_eq!(plan.journal.logical_address,0x7986);
    assert_eq!(plan.working_offset,2);
    plan.commit(&mut fixture).unwrap();
    let after=load(&mut fixture).restore_known_working_fields();
    assert_eq!(fixture.writes, vec![(0x7986,7)]);
    assert_eq!(after.bytes[2],7);
}

#[test]
fn packed_field_original_nv_roundtrip_preserves_neighbor_bits() {
    let mut fixture=NvFixture::new();
    fixture.main[10]=0xD2; // getter IDs04 and 05 share working b[4]
    let mut working=load(&mut fixture).restore_known_working_fields();
    assert_eq!(working.read(OriginalConfigId(4)),13);
    assert_eq!(working.read(OriginalConfigId(5)),2);
    let plan=apply_original_setter(&mut working,5,9,1).unwrap();
    assert_eq!(plan.journal.logical_address,0x798A);
    assert_eq!(plan.working_value,0xD9);
    plan.commit(&mut fixture).unwrap();
    let mut after=load(&mut fixture).restore_known_working_fields();
    assert_eq!(after.read(OriginalConfigId(4)),13);
    assert_eq!(after.read(OriginalConfigId(5)),9);
    assert_eq!(fixture.writes,vec![(0x798A,0xD9)]);
}

#[test]
fn ram_only_change_is_not_falsely_claimed_persistent() {
    let mut fixture=NvFixture::new();
    fixture.main[6]=3;
    let mut working=load(&mut fixture).restore_known_working_fields();
    let p=apply_original_setter(&mut working,2,8,0).unwrap();
    p.commit(&mut fixture).unwrap();
    assert_eq!(working.bytes[2],8);
    let after=load(&mut fixture).restore_known_working_fields();
    assert_eq!(after.bytes[2],3);
    assert!(fixture.writes.is_empty());
}

#[test]
fn original_swapped_nv_addresses_are_exposed_in_roundtrip() {
    let mut fixture=NvFixture::new();
    let mut working=load(&mut fixture).restore_known_working_fields();
    let p=apply_original_setter(&mut working,13,5,1).unwrap();
    assert_eq!(p.working_offset,12);
    assert_eq!(p.journal.logical_address,0x7992);
    p.commit(&mut fixture).unwrap();
    let after=load(&mut fixture).restore_known_working_fields();
    assert_eq!(fixture.main[18],5);
    assert_eq!(after.bytes[13],5); // OEM restores to opposite working field.
    assert_ne!(after.bytes[12],5);
}

#[test]
fn original_id23_nv_address_discrepancy_not_hidden() {
    let mut fixture=NvFixture::new();
    let mut working=load(&mut fixture).restore_known_working_fields();
    let p=apply_original_setter(&mut working,23,0x11,1).unwrap();
    assert_eq!(p.working_offset,32);
    assert_eq!(p.journal.logical_address,0x7980);
    p.commit(&mut fixture).unwrap();
    assert_eq!(working.bytes[32],0x11);
    let after=load(&mut fixture).restore_known_working_fields();
    assert_eq!(after.bytes[0],0x11);
    assert_eq!(after.bytes[32],0);
    assert_eq!(fixture.writes,vec![(0x7980,0x11)]);
}
