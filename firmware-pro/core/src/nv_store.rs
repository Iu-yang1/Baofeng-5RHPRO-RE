//! Read-only logical OEM NV transport for UV-5RH Pro V2.0.09.
//!
//! Addresses are offsets in the STOCK APPLICATION'S LOGICAL storage protocol,
//! NOT MCU flash addresses, NOR physical offsets, or a programming interface.
//! No per-radio calibration bytes are embedded in this crate.

use crate::nv_rf::{
    nv_record_address, OemFrequencyTrims, RawNvRfBankPair, OEM_FREQUENCY_TRIM_NV_ADDRESS,
    OEM_NV_RECORD_BYTES, OEM_FREQUENCY_TRIM_COUNT,
};

/// A backend for the original application's logical NV read operation.
/// Only reads are exposed; an MCU-specific transport remains to be identified.
pub trait LogicalNvReader {
    type Error;
    fn read(&mut self, logical_address: u32, out: &mut [u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OemNvReadStage {
    FrequencyTrims,
    FirstProfile,
    SecondProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OemNvReadError<E> {
    pub stage: OemNvReadStage,
    pub source: E,
}

/// Retains the original four trim bytes and both unlabelled 64-word profiles.
/// The two profile selectors are deliberately caller-supplied. Their physical
/// meaning and field descriptions are not established by the firmware image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OemNvSnapshot {
    pub frequency_trims: OemFrequencyTrims,
    pub raw_profiles: RawNvRfBankPair,
}

/// Reconstructs the three separate OEM logical NV reads without imposing a
/// storage-chip identity, a device-specific calibration default, or a guessed
/// mode-to-band table. Returns no snapshot if any read fails.
pub fn read_oem_nv_snapshot<R: LogicalNvReader>(
    reader: &mut R,
    profile_selectors: [u8; 2],
) -> Result<OemNvSnapshot, OemNvReadError<R::Error>> {
    let mut trim_bytes = [0u8; OEM_FREQUENCY_TRIM_COUNT];
    reader.read(OEM_FREQUENCY_TRIM_NV_ADDRESS, &mut trim_bytes)
        .map_err(|source| OemNvReadError { stage: OemNvReadStage::FrequencyTrims, source })?;

    let mut first = [0u8; OEM_NV_RECORD_BYTES];
    reader.read(nv_record_address(profile_selectors[0]), &mut first)
        .map_err(|source| OemNvReadError { stage: OemNvReadStage::FirstProfile, source })?;

    let mut second = [0u8; OEM_NV_RECORD_BYTES];
    reader.read(nv_record_address(profile_selectors[1]), &mut second)
        .map_err(|source| OemNvReadError { stage: OemNvReadStage::SecondProfile, source })?;

    Ok(OemNvSnapshot {
        frequency_trims: OemFrequencyTrims::new(trim_bytes),
        raw_profiles: RawNvRfBankPair::from_original_records(&first, &second),
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Reader {
        calls: Vec<(u32, usize)>,
        fail_on: Option<usize>,
        trims: [u8; 4],
        first: [u8; OEM_NV_RECORD_BYTES],
        second: [u8; OEM_NV_RECORD_BYTES],
    }

    impl Default for Reader {
        fn default() -> Self {
            let mut first = [0u8; OEM_NV_RECORD_BYTES];
            let mut second = [0u8; OEM_NV_RECORD_BYTES];
            first[0..4].copy_from_slice(&[0xA5, 0x5A, 0x12, 0x34]);
            second[0..4].copy_from_slice(&[0xBE, 0xEF, 0xAB, 0xCD]);
            Self {
                calls: Vec::new(), fail_on: None,
                trims: [0x00, 0x28, 0x60, 0x61], first, second,
            }
        }
    }

    impl LogicalNvReader for Reader {
        type Error = &'static str;
        fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), Self::Error> {
            self.calls.push((address, out.len()));
            if self.fail_on == Some(self.calls.len()) { return Err("NV read"); }
            let data: &[u8] = match address {
                0xC5C0 => &self.trims,
                0x7BC0 => &self.first,
                0x7C58 => &self.second,
                _ => return Err("unexpected logical address"),
            };
            out.copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn original_logical_reads_preserve_four_trims_and_both_opaque_banks() {
        let mut reader = Reader::default();
        let snapshot = read_oem_nv_snapshot(&mut reader, [2, 3]).unwrap();
        assert_eq!(reader.calls, std::vec![
            (0xC5C0, 4), (0x7BC0, 0x82), (0x7C58, 0x82),
        ]);
        assert_eq!(snapshot.frequency_trims.original_bytes, [0x00, 0x28, 0x60, 0x61]);
        assert_eq!(snapshot.frequency_trims.word_at(0), Some((-200i32) as u32));
        assert_eq!(snapshot.frequency_trims.word_at(1), Some(0));
        assert_eq!(snapshot.frequency_trims.word_at(2), Some(280));
        assert_eq!(snapshot.frequency_trims.word_at(3), Some(0));
        assert_eq!(snapshot.raw_profiles.first.raw_header, [0xA5, 0x5A]);
        assert_eq!(snapshot.raw_profiles.first.values[0], 0x1234);
        assert_eq!(snapshot.raw_profiles.second.raw_header, [0xBE, 0xEF]);
        assert_eq!(snapshot.raw_profiles.second.values[0], 0xABCD);
    }

    #[test]
    fn each_failed_stage_stops_subsequent_nv_reads() {
        for (fail_on, expected_stage) in [
            (1, OemNvReadStage::FrequencyTrims),
            (2, OemNvReadStage::FirstProfile),
            (3, OemNvReadStage::SecondProfile),
        ] {
            let mut reader = Reader { fail_on: Some(fail_on), ..Reader::default() };
            let error = read_oem_nv_snapshot(&mut reader, [2, 3]).unwrap_err();
            assert_eq!(error.stage, expected_stage);
            assert_eq!(error.source, "NV read");
            assert_eq!(reader.calls.len(), fail_on);
        }
    }

    #[test]
    fn profile_selectors_are_caller_supplied_not_hardcoded_band_names() {
        let mut reader = Reader::default();
        let error = read_oem_nv_snapshot(&mut reader, [3, 2]).unwrap();
        assert_eq!(reader.calls[1].0, 0x7C58);
        assert_eq!(reader.calls[2].0, 0x7BC0);
        assert_eq!(error.raw_profiles.first.values[0], 0xABCD);
        assert_eq!(error.raw_profiles.second.values[0], 0x1234);
    }
}
