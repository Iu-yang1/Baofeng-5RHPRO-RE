//! Host-only integration test for the OEM read-only NV -> FD6818 path.
//! The test data are synthetic and MUST NOT be used as radio calibration.

use uv5rh_pro_core::fd6818::{Fd6818, FrequencyWriteError};
use uv5rh_pro_core::nv_store::{read_oem_nv_snapshot, LogicalNvReader};
use uv5rh_pro_core::rda5807m::I2cRegisterBus;

#[derive(Default)]
struct SyntheticNv {
    reads: Vec<(u32, usize)>,
}
impl LogicalNvReader for SyntheticNv {
    type Error = &'static str;

    fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        self.reads.push((address, out.len()));
        match address {
            0xC5C0 => out.copy_from_slice(&[0x28, 0x27, 0x29, 0xFF]),
            0x7BC0 | 0x7C58 => {
                assert_eq!(out.len(), 0x82);
                for byte in out.iter_mut() { *byte = 0; }
            }
            _ => return Err("unknown OEM logical address"),
        }
        Ok(())
    }
}

#[derive(Default)]
struct SyntheticI2c {
    writes: Vec<(u8, Vec<u8>)>,
}
impl I2cRegisterBus for SyntheticI2c {
    type Error = &'static str;

    fn write(&mut self, address: u8, data: &[u8]) -> Result<(), Self::Error> {
        self.writes.push((address, data.to_vec()));
        Ok(())
    }
    fn write_read(
        &mut self, _: u8, _: &[u8], _: &mut [u8]
    ) -> Result<(), Self::Error> { unreachable!() }
}

#[test]
fn logical_nv_to_original_raw_word_to_rfic_registers() {
    let mut nv = SyntheticNv::default();
    let snapshot = read_oem_nv_snapshot(&mut nv, [2, 3]).unwrap();
    let mut rfic = Fd6818::new(SyntheticI2c::default());
    // Software index 1 has raw trim 0x27, or -5 in FD6818 10-Hz units.
    rfic.write_oem_corrected_tuning_word_for_mode(
        0x1234_5678, &snapshot.frequency_trims, 1
    ).unwrap();
    let word = 0x1234_5678u32.wrapping_sub(5).to_be_bytes();
    assert_eq!(rfic.into_bus().writes, vec![
        (0x71, vec![0x39, word[0], word[1]]),
        (0x71, vec![0x38, word[2], word[3]]),
    ]);
    assert_eq!(nv.reads, vec![(0xC5C0, 4), (0x7BC0, 130), (0x7C58, 130)]);
}

#[test]
fn invalid_high_raw_trim_is_neutral_but_original_byte_is_preserved() {
    let mut nv = SyntheticNv::default();
    let snapshot = read_oem_nv_snapshot(&mut nv, [2, 3]).unwrap();
    assert_eq!(snapshot.frequency_trims.original_bytes[3], 0xFF);
    let mut rfic = Fd6818::new(SyntheticI2c::default());
    rfic.write_frequency_hz_with_oem_mode_trim(
        145_500_000, &snapshot.frequency_trims, 3
    ).unwrap();
    let word = 14_550_000u32.to_be_bytes();
    assert_eq!(rfic.into_bus().writes, vec![
        (0x71, vec![0x39, word[0], word[1]]),
        (0x71, vec![0x38, word[2], word[3]]),
    ]);
}

#[test]
fn unrecognized_stock_index_does_not_tune_rfic() {
    let mut nv = SyntheticNv::default();
    let snapshot = read_oem_nv_snapshot(&mut nv, [2, 3]).unwrap();
    let mut rfic = Fd6818::new(SyntheticI2c::default());
    assert_eq!(
        rfic.write_oem_corrected_tuning_word_for_mode(
            0x1234_5678, &snapshot.frequency_trims, 4
        ),
        Err(FrequencyWriteError::UnknownTrimIndex(4))
    );
    assert!(rfic.into_bus().writes.is_empty());
}
