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
