//! OEM V2 special-key condition branch at 0x08010B46..0x08010C16.
//!
//! This models the branch's *software event result only*. Scanned key
//! indices 0x13/0x14 are not independently identified physical keycaps.
//! The source reconfigures GPIOC matrix pins on success, but no physical
//! pinout, menu label, or speaker/PTT/PA signal is inferred here.

use crate::keypad::{conditional_oem_settings_pair, KeyIndex};
use crate::oem_config_getter::OemWorkingConfig;
use crate::oem_menu::OriginalConfigId;

/// Opaque observations of three OEM helper calls. For a special-key branch,
/// all three must return zero. The helpers' names/physical meaning are not
/// established solely by the caller's Thumb instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalKeyBranchChecks {
    pub dab4_result: u8,
    pub e17c_result: u8,
    pub e70c_result: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginalMatrixEvent {
    /// 0x08010BAC..0x08010BB2 sets bit14 in its UI state flag word.
    SetSoftwareStateBit14,
    /// 0x08010C10..0x08010C16 sets bit15 in its UI state flag word.
    SetSoftwareStateBit15,
}

/// Determine whether OEM V2 would enter one of the two special-key
/// matrix-switch branches after reading four working-SRAM config fields.
/// Source conditions are: either selected setting==0x10, three helper
/// results all zero, and configuration ID6 nonzero.
pub fn original_special_key_event(
    config: &mut OemWorkingConfig,
    key: KeyIndex,
    checks: OriginalKeyBranchChecks,
) -> Option<OriginalMatrixEvent> {
    let pair=conditional_oem_settings_pair(key)?;
    let first=config.read(OriginalConfigId(pair[0]));
    let second=config.read(OriginalConfigId(pair[1]));
    if first != 0x10 && second != 0x10 {
        return None;
    }
    if checks.dab4_result != 0
        || checks.e17c_result != 0
        || checks.e70c_result != 0
        || config.read(OriginalConfigId(6)) == 0
    {
        return None;
    }
    match key.0 {
        0x13=>Some(OriginalMatrixEvent::SetSoftwareStateBit14),
        0x14=>Some(OriginalMatrixEvent::SetSoftwareStateBit15),
        _=>None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oem_config_getter::OEM_CONFIG_STORAGE_LEN;

    const CLEARED:OriginalKeyBranchChecks=OriginalKeyBranchChecks{
        dab4_result:0,e17c_result:0,e70c_result:0,
    };
    #[test]
    fn two_original_key_indices_resolve_distinct_ui_flag_bits() {
        let mut c=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        c.bytes[5]=1;
        c.bytes[28]=16;
        c.bytes[31]=16;
        assert_eq!(
            original_special_key_event(&mut c,KeyIndex(0x13),CLEARED),
            Some(OriginalMatrixEvent::SetSoftwareStateBit14)
        );
        assert_eq!(
            original_special_key_event(&mut c,KeyIndex(0x14),CLEARED),
            Some(OriginalMatrixEvent::SetSoftwareStateBit15)
        );
    }
    #[test]
    fn compares_either_field_with_original_threshold_0x10() {
        let mut c=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        c.bytes[5]=1;
        c.bytes[30]=16;
        assert_eq!(
            original_special_key_event(&mut c,KeyIndex(0x13),CLEARED),
            Some(OriginalMatrixEvent::SetSoftwareStateBit14)
        );
        c.bytes[30]=0;
        assert_eq!(original_special_key_event(&mut c,KeyIndex(0x13),CLEARED),None);
        c.bytes[29]=16;
        assert_eq!(
            original_special_key_event(&mut c,KeyIndex(0x14),CLEARED),
            Some(OriginalMatrixEvent::SetSoftwareStateBit15)
        );
    }
    #[test]
    fn all_three_source_helper_results_and_config_six_are_observed() {
        let mut c=OemWorkingConfig::new([0;OEM_CONFIG_STORAGE_LEN]);
        c.bytes[28]=16;c.bytes[5]=1;
        for blocked in [
            OriginalKeyBranchChecks{dab4_result:1,..CLEARED},
            OriginalKeyBranchChecks{e17c_result:1,..CLEARED},
            OriginalKeyBranchChecks{e70c_result:1,..CLEARED},
        ] {
            assert_eq!(original_special_key_event(&mut c,KeyIndex(0x13),blocked),None);
        }
        c.bytes[5]=0;
        assert_eq!(original_special_key_event(&mut c,KeyIndex(0x13),CLEARED),None);
        c.bytes[5]=1;
        assert_eq!(original_special_key_event(&mut c,KeyIndex(0x12),CLEARED),None);
    }
}
