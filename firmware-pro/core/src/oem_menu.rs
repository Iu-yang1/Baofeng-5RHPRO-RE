//! UV-5RH Pro V2.0.09 OEM menu *configuration reader* dispatch map.
//!
//! Original Thumb 0x0800E454 is a 0x43-entry (67 case) TBB dispatcher.
//! These are ORIGINAL CONFIGURATION IDs, not 22 keypad scan indices, not
//! user-facing labels and not a complete navigable menu/UI state machine.
//! Raw handler addresses are offsets in the original OEM application;
//! they are for offline cross-reference only, not callable function pointers.

pub const OEM_CONFIG_ENTRY: u32 = 0x0800_E454;
pub const OEM_CONFIG_DISPATCH_TBB: u32 = 0x0800_E482;
pub const OEM_CONFIG_TABLE_BASE: u32 = OEM_CONFIG_DISPATCH_TBB + 4;
pub const OEM_CONFIG_COUNT: usize = 0x43;

/// Original 67 unsigned-byte entries in Thumb TBB [PC, IP] at 0x0800E482.
/// Branch destination = 0x0800E486 + 2 * table[id].
pub const OEM_CONFIG_TBB_OFFSETS: [u8; OEM_CONFIG_COUNT] = [
    0x22, 0x29, 0x2F, 0x35, 0x3B, 0x3E, 0x41, 0x43,
    0x49, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C,
    0x5E, 0x60, 0x62, 0x68, 0x6C, 0x6A, 0x6E, 0x70,
    0x73, 0x75, 0x78, 0x7B, 0x7E, 0x81, 0x84, 0x86,
    0x27, 0x88, 0x8A, 0x8D, 0x8F, 0x92, 0x95, 0x98,
    0x27, 0x27, 0x9B, 0x9D, 0xA0, 0xA3, 0xA6, 0xA9,
    0xAB, 0xAE, 0xB1, 0xB4, 0xB7, 0xBA, 0xBC, 0xBF,
    0xC1, 0xC7, 0xC3, 0xC7, 0xC9, 0xCC, 0xCE, 0xD1,
    0xD4, 0xD7, 0xDA,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalConfigId(pub u8);

impl OriginalConfigId {
    /// Return OEM code target as a *research address*.
    /// Values >= 0x43 take the original out-of-range branch to the
    /// common return handler at 0x0800E4D4, not a valid setting.
    pub const fn dispatch_target(self) -> Option<u32> {
        if (self.0 as usize) < OEM_CONFIG_COUNT {
            Some(OEM_CONFIG_TABLE_BASE + 2 * OEM_CONFIG_TBB_OFFSETS[self.0 as usize] as u32)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_67_oem_config_cases_have_original_branch_targets() {
        assert_eq!(OEM_CONFIG_TBB_OFFSETS.len(), 67);
        for id in 0..67u8 {
            let target=OriginalConfigId(id).dispatch_target().unwrap();
            assert_eq!(target & 1, 0);
            assert!((0x0800_E4CA..=0x0800_E63A).contains(&target));
        }
        assert_eq!(OriginalConfigId(0x43).dispatch_target(), None);
        assert_eq!(OriginalConfigId(0xFF).dispatch_target(), None);
    }

    #[test]
    fn conditional_key_pair_config_ids_resolve_to_four_distinct_cases() {
        assert_eq!(OriginalConfigId(0x13).dispatch_target(), Some(0x0800_E556));
        assert_eq!(OriginalConfigId(0x14).dispatch_target(), Some(0x0800_E55E));
        assert_eq!(OriginalConfigId(0x15).dispatch_target(), Some(0x0800_E55A));
        assert_eq!(OriginalConfigId(0x16).dispatch_target(), Some(0x0800_E562));
    }

    #[test]
    fn multiple_original_config_ids_share_handler_addresses() {
        // The original dispatcher routes these IDs to the SAME case.
        // That does not establish any UI menu label or whether they are live.
        assert_eq!(OriginalConfigId(0x20).dispatch_target(), Some(0x0800_E4D4));
        assert_eq!(OriginalConfigId(0x28).dispatch_target(), Some(0x0800_E4D4));
        assert_eq!(OriginalConfigId(0x29).dispatch_target(), Some(0x0800_E4D4));
        assert_eq!(OriginalConfigId(0x39).dispatch_target(), OriginalConfigId(0x3B).dispatch_target());
    }
}
