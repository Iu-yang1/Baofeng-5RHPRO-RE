//! Stock V2.0.09 decoded GPIO/peripheral software contract.
//!
//! These are port-bit names from a STM32F1-like MMIO model, NOT
//! verified physical QFN64 pad numbers or a complete hardware HAL.
//! GPIO modes, clock muxing, PA bias, LCD reset and physical wiring
//! still require dedicated board-level validation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port { A, B, C, D, E }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    pub port: Port,
    pub bit: u8,
}

impl Pin {
    pub const fn mask(self) -> u16 { 1u16 << self.bit }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareI2cPins { pub scl: Pin, pub sda: Pin }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelPins { pub chip_select: Pin, pub command_data: Pin }

pub const FD6818: SoftwareI2cPins = SoftwareI2cPins {
    scl: Pin { port: Port::A, bit: 14 },
    sda: Pin { port: Port::C, bit: 15 },
};

pub const BROADCAST_FM: SoftwareI2cPins = SoftwareI2cPins {
    scl: Pin { port: Port::C, bit: 14 },
    sda: Pin { port: Port::A, bit: 11 },
};

/// OEM 0x0801501C..0x08015048 pulses GPIOA bit8 high-low-high.
/// This establishes a software LCD-reset output, NOT a QFN package pad.
pub const PANEL_RESET: Pin = Pin { port: Port::A, bit: 8 };

/// GPIOB signals with both set/reset callsites in original V2 code.
/// Their exact physical signal names are not established by static disasm.
pub const OEM_SWITCH_PB6: Pin = Pin { port: Port::B, bit: 6 };
pub const OEM_SWITCH_PB8: Pin = Pin { port: Port::B, bit: 8 };
/// GPIOB bit14 is set in the RDA5807M initialization neighborhood.
pub const OEM_SWITCH_PB14: Pin = Pin { port: Port::B, bit: 14 };
/// GPIOA bit1 changes during 0x080328E0 state processing.
pub const OEM_SWITCH_PA1: Pin = Pin { port: Port::A, bit: 1 };
/// GPIOD bit2 is set during original global board initialization.
pub const OEM_BOOT_PD2: Pin = Pin { port: Port::D, bit: 2 };

pub const GPIOA_COMPAT_BASE: u32 = 0x4001_0800;
pub const GPIOB_COMPAT_BASE: u32 = 0x4001_0C00;
pub const GPIOC_COMPAT_BASE: u32 = 0x4001_1000;
pub const GPIOD_COMPAT_BASE: u32 = 0x4001_1400;
pub const GPIOE_COMPAT_BASE: u32 = 0x4001_1800;
pub const SPI2_COMPAT_BASE: u32 = 0x4000_3800;
pub const SPI3_COMPAT_BASE: u32 = 0x4000_3C00;
pub const MCU_FLASH_BASE_OBSERVED: u32 = 0x0800_1000;
pub const OEM_STACK_TOP_OBSERVED: u32 = 0x2001_1308;
pub const OEM_JOURNAL_MARKER: u32 = 0x0807_F800;

/// Abstract access to *software* GPIO port bit IDs; a physical QFN pad
/// mapping and GPIO electrical configuration remain a separate HAL binding.
pub trait BoardGpio {
    type Error;
    fn set_level(&mut self, pin: Pin, high: bool) -> Result<(), Self::Error>;
    fn sample(&mut self, pin: Pin) -> Result<bool, Self::Error>;
}

pub const PANEL_SPI2: PanelPins = PanelPins {
    chip_select: Pin { port: Port::B, bit: 12 },
    command_data: Pin { port: Port::A, bit: 12 },
};

/// Standalone active-low bit sampled by original keypad function.
/// Not yet attributed to PTT or a physical keypad legend.
pub const AUXILIARY_KEY_GPIO: Pin = Pin { port: Port::A, bit: 9 };

pub const KEYPAD_PORT: Port = Port::C;
pub const KEYPAD_FIRST_IDR_MASK: u16 = 0x03C0;
pub const KEYPAD_SECOND_IDR_MASK: u16 = 0x003E;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartConfiguration {
    pub peripheral_register_base: u32,
    pub nominal_baud: u32,
}

/// OEM V2 software UART/DMA code links this port to NMEA/GNSS.
pub const GNSS_UART: UartConfiguration = UartConfiguration {
    peripheral_register_base: 0x4000_4400,
    nominal_baud: 9600,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovered_i2c_ports_are_distinct() {
        assert_eq!(FD6818.scl, Pin { port: Port::A, bit: 14 });
        assert_eq!(FD6818.sda.mask(), 0x8000);
        assert_eq!(BROADCAST_FM.scl, Pin { port: Port::C, bit: 14 });
        assert_eq!(BROADCAST_FM.sda.mask(), 0x0800);
        assert_ne!(FD6818, BROADCAST_FM);
    }

    #[test]
    fn lcd_command_data_and_chip_select_are_separate_pins() {
        assert_eq!(PANEL_SPI2.command_data, Pin { port: Port::A, bit: 12 });
        assert_eq!(PANEL_SPI2.chip_select, Pin { port: Port::B, bit: 12 });
        assert_eq!(PANEL_SPI2.command_data.mask(), 0x1000);
    }

    #[test]
    fn keypad_masks_and_gnss_uart_match_original_code() {
        assert_eq!(KEYPAD_FIRST_IDR_MASK, 0x03C0);
        assert_eq!(KEYPAD_SECOND_IDR_MASK, 0x003E);
        assert_eq!(GNSS_UART.peripheral_register_base, 0x4000_4400);
        assert_eq!(GNSS_UART.nominal_baud, 9600);
    }

    #[test]
    fn auxiliary_key_is_separate_from_gpio_c_matrix() {
        assert_eq!(AUXILIARY_KEY_GPIO, Pin { port: Port::A, bit: 9 });
        assert_eq!(AUXILIARY_KEY_GPIO.mask(), 0x0200);
    }

    #[test]
    fn reconstructed_switches_and_reset_are_port_bit_observations() {
        assert_eq!(PANEL_RESET, Pin { port: Port::A, bit: 8 });
        assert_eq!(OEM_SWITCH_PB6.mask(), 1 << 6);
        assert_eq!(OEM_SWITCH_PB8.mask(), 1 << 8);
        assert_eq!(OEM_SWITCH_PB14.mask(), 1 << 14);
        assert_eq!(OEM_SWITCH_PA1.mask(), 2);
        assert_eq!(OEM_BOOT_PD2.port, Port::D);
        assert_eq!(OEM_STACK_TOP_OBSERVED, 0x20011308);
        assert_eq!(OEM_JOURNAL_MARKER, 0x0807F800);
    }

}
