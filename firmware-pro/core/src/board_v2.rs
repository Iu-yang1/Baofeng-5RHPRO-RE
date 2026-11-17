//! Stock V2.0.09 decoded GPIO/peripheral software contract.
//!
//! These are port-bit names from a STM32F1-like MMIO model, NOT
//! verified physical QFN64 pad numbers or a complete hardware HAL.
//! GPIO modes, clock muxing, PA bias, LCD reset and physical wiring
//! still require dedicated board-level validation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port { A, B, C }

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

}
