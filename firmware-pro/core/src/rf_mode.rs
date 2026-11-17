//! Original V2 two-stage runtime selection of four RF trim words.
//!
//! OEM 0x0800DDB8:
//!  s = RAM8[0x20000069]
//!  i = RAM8[0x20000072 + s]
//!  delta = RAM32[0x2000246C + 4*i]
//!
//! Original scatterload initializes the nearby mapping window to zero.
//! Consequently its actual band/path association is *runtime-dependent*.
//! A caller must supply the live mapping bytes, not infer them from reset.

pub const OEM_MODE_SELECTOR_SRAM: u32 = 0x2000_0069;
pub const OEM_MODE_TO_TRIM_SRAM: u32 = 0x2000_0072;
pub const OEM_TRIM_WORDS_SRAM: u32 = 0x2000_246C;
pub const OEM_NEXT_TRIM_SOURCE_SRAM: u32 = 0x2000_0082;

/// The 16-byte space until the next known byte array is a bounding
/// neighborhood, NOT a proven count of active or initialized modes.
pub const OEM_ADJACENT_MAPPING_WINDOW_BYTES: usize =
    (OEM_NEXT_TRIM_SOURCE_SRAM - OEM_MODE_TO_TRIM_SRAM) as usize;

/// Raw OEM runtime lookup, supplied by a board state snapshot.
/// Deliberately no guessed mappings like 'index 0 = VHF RX'.
#[derive(Debug, Clone, Copy)]
pub struct OemRuntimeModeLookup<'a> {
    pub populated_bytes: &'a [u8],
}

impl<'a> OemRuntimeModeLookup<'a> {
    pub const fn new(populated_bytes: &'a [u8]) -> Self {
        Self { populated_bytes }
    }

    /// Return a per-radio trim index, not a hardware band or Tx/Rx mode.
    pub fn trim_index(&self, runtime_selector: u8) -> Option<u8> {
        self.populated_bytes.get(runtime_selector as usize).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_addresses_match_original_two_level_lookup() {
        assert_eq!(OEM_MODE_SELECTOR_SRAM, 0x20000069);
        assert_eq!(OEM_MODE_TO_TRIM_SRAM, 0x20000072);
        assert_eq!(OEM_TRIM_WORDS_SRAM, 0x2000246C);
        assert_eq!(OEM_ADJACENT_MAPPING_WINDOW_BYTES, 16);
    }
    #[test]
    fn arbitrary_live_mapping_is_not_inferred_from_reset_zeroes() {
        let runtime_map = OemRuntimeModeLookup::new(&[2, 0, 3, 1]);
        assert_eq!(runtime_map.trim_index(0), Some(2));
        assert_eq!(runtime_map.trim_index(1), Some(0));
        assert_eq!(runtime_map.trim_index(2), Some(3));
        assert_eq!(runtime_map.trim_index(3), Some(1));
        assert_eq!(runtime_map.trim_index(4), None);
        assert_eq!(OemRuntimeModeLookup::new(&[]).trim_index(0), None);
    }
}

/// Exact four *software frequency windows* in the OEM V2 writer at
/// 0x08031AEE..0x08031B80. The eight raw comparison constants also
/// occur in the V1.1.04 original image at 0x08025B60..0x08025B7C.
/// Values are FD6818 10-Hz raw tuning-word units, NOT a TX permission
/// table, amplifier GPIO map or complete physical RF front-end.
pub const OEM_TRIM_FREQUENCY_WINDOWS_RAW: [(u32, u32); 4] = [
    (13_600_000, 17_400_000), // 136-174 MHz
    (20_000_000, 26_000_000), // 200-260 MHz
    (35_000_000, 39_900_000), // 350-399 MHz
    (40_000_000, 52_000_000), // 400-520 MHz
];

/// OEM executes unsigned range comparisons and writes indices 0, 1, 2, 3
/// to its SRAM mapping slot when a window matches. If none matches,
/// 0x08031B7C branches to 0x08031BA2 which writes the initial R7=0;
/// this is a calibration fallback, **not** a transmit/receive gate.
pub const fn oem_trim_slot_for_raw_word(raw_tuning_word: u32) -> u8 {
    let mut n = 0;
    while n < 4 {
        let (lower, upper) = OEM_TRIM_FREQUENCY_WINDOWS_RAW[n];
        if raw_tuning_word >= lower && raw_tuning_word <= upper {
            return n as u8;
        }
        n += 1;
    }
    0
}

#[cfg(test)]
mod original_rf_window_tests {
    use super::*;

    #[test]
    fn all_four_original_windows_include_both_endpoints() {
        for (idx, (lo, hi)) in OEM_TRIM_FREQUENCY_WINDOWS_RAW.iter().enumerate() {
            assert_eq!(oem_trim_slot_for_raw_word(*lo), idx as u8);
            assert_eq!(oem_trim_slot_for_raw_word(*hi), idx as u8);
            assert_eq!(oem_trim_slot_for_raw_word(lo-1), 0);
            assert_eq!(oem_trim_slot_for_raw_word(hi+1), 0);
        }
    }

    #[test]
    fn original_out_of_window_fallback_is_zero_not_transmit_lock() {
        for hz in [130_000_000u64, 175_000_000, 349_000_000, 399_500_000, 550_000_000] {
            assert_eq!(oem_trim_slot_for_raw_word((hz / 10) as u32), 0);
        }
        assert_eq!(oem_trim_slot_for_raw_word(145_500_000 / 10), 0);
        assert_eq!(oem_trim_slot_for_raw_word(230_000_000 / 10), 1);
        assert_eq!(oem_trim_slot_for_raw_word(370_000_000 / 10), 2);
        assert_eq!(oem_trim_slot_for_raw_word(435_000_000 / 10), 3);
    }
}
