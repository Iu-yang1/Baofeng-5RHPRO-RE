# Baofeng UV-5RH Pro Reverse Engineering

This fork is the development workspace for an alternative-firmware research project targeting the **Baofeng UV-5RH Pro**.

Original reverse-engineering archive: https://github.com/kholdfuzion/Baofeng-5RHPRO-RE

## Current status

**P0: read-only offline package inspection, hardware identification, and reference-firmware research.**

There is no verified, flashable replacement firmware in this repository yet.

Target-radio menu reports **Firmware `v2_0_09`** and **Software `v1_1_04`**. These two fields are recorded exactly; they do **not** prove that both upgrade files should be flashed, or establish the MCU/PCB revision.

### Offline analysis (Python 3.10+; Capstone 5 required for instruction tracing)

```sh
python tools/firmware_inspect.py --strict firmware/*.dat
python tools/firmware_inspect.py --json firmware/BF_5RH_501_v2_0_9.dat
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/clock_register_trace.py firmware/BF_5RH_501_v2_0_9.dat
python tools/thumb_window.py firmware/BF_5RH_501_v2_0_9.dat --start 0x08031BF4 --end 0x08031C98
```

The inspection tool prints package signatures, raw version fields, payload sizes, SHA-256, XOR marker clues, and Cortex-M vector heuristics. It cannot communicate with or reprogram a radio. GitHub Actions runs the same checks against all six archived firmware images and publishes a metadata-only inventory.

Read [P0 research and acceptance criteria (简体中文)](docs/p0-firmware-research.zh-CN.md), [V2.0.09 clock initialization disassembly (简体中文)](docs/v2-0-09-clock-init-disassembly.zh-CN.md), and [portability review of the Rust UV-5RH firmware (简体中文)](docs/reference-firmware-portability.zh-CN.md).

**Clock-reconstruction status:** the decoded V2.0.09 startup code enables an external high-speed clock, programs PLL source/multiplier fields and switches the system clock. Register interpretations currently follow the AT32F403A/407-compatible map; the exact MCU, physical crystal frequency and absolute CPU frequency are not verified. Tools do not connect to radio hardware.

### UART/TIM cross-version SDK fingerprint

The V2 firmware contains a UART baud-rate calculation matching the structure of the STM32F4 Standard Peripheral Library `USART_Init` routine, including OVER8-sensitive fraction rounding. USART and timer instruction windows in archived V1 and V2 firmware align at the same `+0xC134` offset and each tested 24-byte window matches exactly. **This suggests shared SDK routines, not that the actual MCU is an STM32F4.**

Run (Python 3.10+, Capstone 5):

```sh
python tools/peripheral_clock_constraints.py firmware/BF_5RH_501_v2_0_9.dat
python tools/compare_sdk_windows.py firmware/BF_5RH_501_v1_1_04.dat firmware/BF_5RH_501_v2_0_9.dat --pair 0x08026C50:0x08032D84:24 --pair 0x0802640C:0x08032540:24
```

See [V2 UART/TIM SDK fingerprint report (简体中文)](docs/v2-0-09-uart-timer-sdk-fingerprint.zh-CN.md).

## Original collected utilities

- `fwtool.py`: package XOR packing/unpacking tool.
- `fw_updater.py`: serial update tool; **erases and writes radio Flash**.
- `font_updater.py`: font update tool; **writes to radio storage**.
- `firmware/`: collected original upgrade packages.
- `CPS_5RH/`, `FontTool/`, `UpgradeTool/`: vendor utility binaries.

The presence of a firmware updater is **not** proof that a full Flash backup or recovery of a nonbooting device is possible.

## Related work

- [sophiel-meow/bf-5rh-firmware-open](https://github.com/sophiel-meow/bf-5rh-firmware-open) — experimental Rust firmware for **UV-5RH/5RM**, not a drop-in UV-5RH Pro image. The project is GPL-3.0; direct source reuse requires honoring its license.
