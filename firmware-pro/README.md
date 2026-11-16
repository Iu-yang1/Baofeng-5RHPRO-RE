# UV-5RH Pro independent firmware workspace (P1)

This directory is **not a flashable firmware image**. The real Pro MCU, bootloader
recovery behavior, startup/linker script and board pin mapping remain unverified.

## Experimental MCU ID UART firmware (source only)

A minimal Cortex-M3/M4 Thumb diagnostic source is now available at
[diagnostics/mcu-id-uart](diagnostics/mcu-id-uart/README.md). It can be
cross-compiled into an ELF and emits CPUID and optional vendor ID fields
through a **candidate USART1** UART path. Its startup address, programming
cable UART wiring, clock state, compatibility and recovery path have **not**
been verified on the target. It is not an installable Baofeng update file.
The PC [serial listener](../tools/probe_radio_mcu_uart.py) only receives
bytes and never uploads or erases firmware.

Current independent Rust module:
- `core/`: dependency-free `no_std` NMEA frame/checksum parser tested on host.
- Data ingestion is expected to use the proven V2 original firmware path
  USART2 at 9600 bit/s with IDLE interrupt + DMA reception; the hardware-specific
  implementation is intentionally not present here.

Host build and test:

```sh
cargo test --manifest-path firmware-pro/core/Cargo.toml --offline
cargo check --manifest-path firmware-pro/core/Cargo.toml --lib --offline
```

Future modules will include protocol handling (GPS fields, APRS/AX.25),
radio-state transitions, the FD6818 interface, LCD control and board HAL.
Do not copy a standard UV-5RH `at32f421-pac`, `memory.x`, or GPIO map
into this firmware until the **UV-5RH Pro** MCU/pinout is independently identified.

The reference projects `bf-5rh-firmware-open` and `bf-k61-firmware-aura`
are GPL-3.0; their source was not copied into this core module.

Chinese engineering design and acceptance milestones:
[UV-5RH Pro firmware architecture V1](../docs/uv5rh-pro-firmware-architecture-v1.zh-CN.md).

## OEM reverse-engineered RF/UI contracts (2026-11-17)

The [cross-version hardware-software evidence report](../docs/pro-v2-board-rf-ui-static-audit.zh-CN.md)
confirms the following independently developed `no_std` modules, all
host-testable without a real MCU or device access:

- `core/src/keypad.rs`: original 22-key lookup, two-phase GPIOC scan mask
  `0x03C0/0x003E`; real physical button legends remain unassigned.
- `core/src/fd6818.rs`: the **FD6818** (not FD6818B) OEM two-wire register
  contract, I2C 7-bit `0x71`, big-endian 16-bit words; register `0x39/0x38`
  accepts a raw 32-bit tuning word, **not Hz**.
- `core/src/rda5807m.rs`: separate broadcast FM indexed I2C 7-bit `0x11`,
  command prefix then 16-bit big-endian data.
- `core/src/lcd.rs`: software 160×128 RGB565 framebuffer and SPI2
  command/data/rectangle scanout via `0x2A/0x2B/0x2C`, display controller
  ST7735-like but actual chip/orientation/offset unmeasured.
- `core/src/board_v2.rs`: candidate **GPIO port-bit contract only**
  (RF PA14/PC15, FM PC14/PA11, LCD PB12/PA12), not a physical QFN64 pad
  map, a fully clocked HAL, or a verified radio startup.

The original OEM panel clear loops use `CMP #0xA0` and `CMP #0x80` with
320-byte rows, so 160×128 is based on executed-code candidates and the
original SRAM framebuffer, not an arbitrary reference-radio display size.

The independent RF application logic still needs Hz-to-FD6818 tuning math,
FD6818 RX/TX state calibration, PA control, RF timing, menu/key legends,
LCD init/reset/rotation and target-CPU startup. These are explicit unverified
implementation tasks, not additional default locks on supported functions.
