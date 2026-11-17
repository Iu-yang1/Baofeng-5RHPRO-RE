//! OEM V2 configuration save/restore compatibility at logical NV byte level.
//!
//! The original setter and reset loader disagree for IDs 0x0D, 0x0E,
//! and 0x17. Keep exact-original behaviour available; allow the *independent*
//! firmware to choose source-loader-consistent addresses. No MCU/NOR
//! transaction is executed until a separately tested journal is supplied.

use crate::oem_config_restore::restored_main_nv_address;
use crate::oem_config_setter::{LogicalNvJournal, OriginalConfigMutation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OemNvWriteLayout {
    /// Byte-accurate original V2 setter address (including defects).
    OriginalSetter,
    /// Use the original *loader's* address for the working byte,
    /// so the field is read back after reboot. Opt-in firmware policy.
    LoaderConsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OemAddressPair {
    pub original_setter: u32,
    pub original_loader: u32,
}

impl OemAddressPair {
    pub const fn is_consistent(self) -> bool {
        self.original_setter == self.original_loader
    }
}

pub const fn loader_address_for_working_byte(offset: u8) -> Option<u32> {
    match offset {
        33 => Some(0x7A80),
        35..=38 => Some(0x71 + offset as u32 - 35),
        _ => restored_main_nv_address(offset),
    }
}

pub const fn addresses_for_mutation(mutation: &OriginalConfigMutation) -> Option<OemAddressPair> {
    let Some(loader) = loader_address_for_working_byte(mutation.working_offset) else {
        return None;
    };
    Some(OemAddressPair {
        original_setter: mutation.journal.logical_address,
        original_loader: loader,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum OemCompatWriteError<E> {
    UnmappedOriginalWorkingByte(u8),
    Journal(E),
}

pub fn commit_with_layout<W: LogicalNvJournal>(
    mutation: &OriginalConfigMutation,
    layout: OemNvWriteLayout,
    writer: &mut W,
) -> Result<Option<u32>, OemCompatWriteError<W::Error>> {
    if !mutation.journal.requested_by_caller {
        return Ok(None);
    }
    let address = match layout {
        OemNvWriteLayout::OriginalSetter => mutation.journal.logical_address,
        OemNvWriteLayout::LoaderConsistent => {
            loader_address_for_working_byte(mutation.working_offset)
                .ok_or(OemCompatWriteError::UnmappedOriginalWorkingByte(
                    mutation.working_offset))?
        }
    };
    writer.update_one(address, mutation.journal.value)
        .map_err(OemCompatWriteError::Journal)?;
    Ok(Some(address))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::oem_config_getter::{OemWorkingConfig, OEM_CONFIG_STORAGE_LEN};
    use crate::oem_config_setter::apply_original_setter;
    use std::vec::Vec;

    #[derive(Default)]
    struct Nv {writes:Vec<(u32,u8)>, fail:bool}
    impl LogicalNvJournal for Nv {
        type Error=&'static str;
        fn update_one(&mut self,address:u32,value:u8)->Result<(),Self::Error> {
            if self.fail {return Err("journal");}
            self.writes.push((address,value));Ok(())
        }
    }

    #[test]
    fn all_writable_oem_id_mappings_are_compared_with_loader_field_by_field() {
        let mut differences=Vec::new();
        for id in 0..61u8 {
            let mut working=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
            let Some(mutation)=apply_original_setter(&mut working,id,1,1) else {
                assert!([32,40,41,51].contains(&id));
                continue;
            };
            let pair=addresses_for_mutation(&mutation).unwrap();
            if !pair.is_consistent() {differences.push((id,pair));}
        }
        assert_eq!(differences,std::vec![
            (13,OemAddressPair{original_setter:0x7992,original_loader:0x7993}),
            (14,OemAddressPair{original_setter:0x7993,original_loader:0x7992}),
            (23,OemAddressPair{original_setter:0x7980,original_loader:0x799B}),
        ]);
    }

    #[test]
    fn source_and_loader_aligned_writes_are_both_available_without_extra_gates() {
        for (id,raw,original,aligned) in [
            (13,7,0x7992,0x7993),
            (14,9,0x7993,0x7992),
            (23,6,0x7980,0x799B),
        ] {
            let mut working=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
            let mutation=apply_original_setter(&mut working,id,raw,1).unwrap();
            let mut nv=Nv::default();
            assert_eq!(commit_with_layout(&mutation,OemNvWriteLayout::OriginalSetter,
                &mut nv),Ok(Some(original)));
            assert_eq!(commit_with_layout(&mutation,OemNvWriteLayout::LoaderConsistent,
                &mut nv),Ok(Some(aligned)));
            assert_eq!(nv.writes,std::vec![(original,raw),(aligned,raw)]);
        }
    }

    #[test]
    fn caller_ram_only_and_failed_journal_behave_as_original_transaction_contract() {
        let mut config=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        let mem_only=apply_original_setter(&mut config,23,2,0).unwrap();
        let mut nv=Nv::default();
        assert_eq!(commit_with_layout(&mem_only,OemNvWriteLayout::LoaderConsistent,
            &mut nv),Ok(None));
        assert!(nv.writes.is_empty());
        let persistent=apply_original_setter(&mut config,13,3,1).unwrap();
        nv.fail=true;
        assert_eq!(commit_with_layout(&persistent,OemNvWriteLayout::LoaderConsistent,
            &mut nv),Err(OemCompatWriteError::Journal("journal")));
        assert!(nv.writes.is_empty());
    }

    #[test]
    fn unmapped_working_byte_is_not_silently_written_to_another_nv_location() {
        assert_eq!(loader_address_for_working_byte(38),Some(0x74));
        assert_eq!(loader_address_for_working_byte(33),Some(0x7A80));
        assert_eq!(loader_address_for_working_byte(0xFF),None);
    }
}
