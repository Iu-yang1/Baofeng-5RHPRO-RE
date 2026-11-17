//! End-to-end source-calibrated V2 compatibility matrix for every writable ID.
//!
//! Test flow is original 39-byte SRAM restore -> OEM setter -> one-byte
//! logical NV transaction -> simulated reboot through OEM loader.
//! Both exact OEM behaviour and opt-in loader-consistent persistence are
//! evaluated. No device Flash or external NOR is accessed.

use uv5rh_pro_core::oem_config_getter::OemWorkingConfig;
use uv5rh_pro_core::oem_config_restore::{
    OriginalNvConfigSnapshot, OEM_CONFIG_MAIN_BYTES,
};
use uv5rh_pro_core::oem_config_setter::{
    apply_original_setter, LogicalNvJournal,
};
use uv5rh_pro_core::oem_nv_compat::{
    commit_with_layout, OemNvWriteLayout,
};

struct RebootFixture {
    snapshot:OriginalNvConfigSnapshot,
    writes:Vec<(u32,u8)>,
}
impl RebootFixture {
    fn new()->Self {
        let mut main=[0u8;OEM_CONFIG_MAIN_BYTES];
        main[31]=1; // OEM boot repairs working +0x12 from zero to one.
        Self {
            snapshot:OriginalNvConfigSnapshot{main,extra:[0;4],side:0},
            writes:Vec::new(),
        }
    }
    fn boot(&self)->OemWorkingConfig {
        self.snapshot.restore_known_working_fields()
    }
}
impl LogicalNvJournal for RebootFixture {
    type Error=&'static str;
    fn update_one(&mut self,address:u32,value:u8)->Result<(),Self::Error> {
        self.writes.push((address,value));
        if (0x7980..0x7980+OEM_CONFIG_MAIN_BYTES as u32).contains(&address) {
            self.snapshot.main[(address-0x7980) as usize]=value;
        } else if (0x71..0x75).contains(&address) {
            self.snapshot.extra[(address-0x71) as usize]=value;
        } else if address==0x7A80 {
            self.snapshot.side=value;
        } else {
            return Err("unexpected logical NV address");
        }
        Ok(())
    }
}

fn run_matrix(policy:OemNvWriteLayout)->Vec<(u8,u8,u8)> {
    let mut mismatches=Vec::new();
    for id in 0u8..61 {
        let mut fixture=RebootFixture::new();
        let mut working=fixture.boot();
        let Some(plan)=apply_original_setter(&mut working,id,1,1) else {
            assert!([32,40,41,51].contains(&id));
            continue;
        };
        commit_with_layout(&plan,policy,&mut fixture).unwrap();
        let after=fixture.boot();
        let before_byte=working.bytes[plan.working_offset as usize];
        let after_byte=after.bytes[plan.working_offset as usize];
        if before_byte!=after_byte {
            mismatches.push((id,before_byte,after_byte));
        }
    }
    mismatches
}

#[test]
fn all_57_writable_ids_survive_reboot_with_loader_aligned_nv_policy() {
    assert_eq!(run_matrix(OemNvWriteLayout::LoaderConsistent),vec![]);
}

#[test]
fn original_rom_mismatch_is_reproducible_only_for_three_settings() {
    let mismatch=run_matrix(OemNvWriteLayout::OriginalSetter);
    assert_eq!(mismatch,vec![(13,1,0),(14,1,0),(23,1,0)]);
}

#[test]
fn original_id23_fallback_overwrites_other_unrelated_config_address() {
    let mut fixture=RebootFixture::new();
    fixture.snapshot.main[0]=2;
    let mut working=fixture.boot();
    let plan=apply_original_setter(&mut working,23,1,1).unwrap();
    commit_with_layout(&plan,OemNvWriteLayout::OriginalSetter,&mut fixture).unwrap();
    let after=fixture.boot();
    assert_eq!(fixture.writes,vec![(0x7980,1)]);
    assert_eq!(after.bytes[0],1);  // collateral update to config ID0
    assert_eq!(after.bytes[32],0); // requested ID23 did not persist
}

#[test]
fn loader_aligned_id23_does_not_overwrite_id0_and_persists_after_reboot() {
    let mut fixture=RebootFixture::new();
    fixture.snapshot.main[0]=2;
    let mut working=fixture.boot();
    let plan=apply_original_setter(&mut working,23,1,1).unwrap();
    commit_with_layout(&plan,OemNvWriteLayout::LoaderConsistent,&mut fixture).unwrap();
    let after=fixture.boot();
    assert_eq!(fixture.writes,vec![(0x799B,1)]);
    assert_eq!(after.bytes[0],2);
    assert_eq!(after.bytes[32],1);
}

#[test]
fn raw_loader_byte_for_id13_is_crossed_into_id14_only_under_original_policy() {
    let mut original=RebootFixture::new();
    let mut working=original.boot();
    let plan=apply_original_setter(&mut working,13,1,1).unwrap();
    commit_with_layout(&plan,OemNvWriteLayout::OriginalSetter,&mut original).unwrap();
    let after=original.boot();
    assert_eq!(after.bytes[12],0);
    assert_eq!(after.bytes[13],1);

    let mut aligned=RebootFixture::new();
    let mut working=aligned.boot();
    let plan=apply_original_setter(&mut working,13,1,1).unwrap();
    commit_with_layout(&plan,OemNvWriteLayout::LoaderConsistent,&mut aligned).unwrap();
    let after=aligned.boot();
    assert_eq!(after.bytes[12],1);
    assert_eq!(after.bytes[13],0);
}
