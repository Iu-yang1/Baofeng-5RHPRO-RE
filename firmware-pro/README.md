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
