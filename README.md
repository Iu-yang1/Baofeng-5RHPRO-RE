# Baofeng UV-5RH Pro Reverse Engineering

This fork is the development workspace for an alternative-firmware research project targeting the **Baofeng UV-5RH Pro**.

Original reverse-engineering archive: https://github.com/kholdfuzion/Baofeng-5RHPRO-RE

## Current status

**P0: read-only offline package inspection, hardware identification, and reference-firmware research.**

There is no verified, flashable replacement firmware in this repository yet.

Target-radio menu reports **Firmware `v2_0_09`** and **Software `v1_1_04`**. These two fields are recorded exactly; they do **not** prove that both upgrade files should be flashed, or establish the MCU/PCB revision.

### Offline analysis (Python 3.10+, standard library only)

```sh
python tools/firmware_inspect.py --strict firmware/*.dat
python tools/firmware_inspect.py --json firmware/BF_5RH_501_v2_0_9.dat
python -m unittest discover -s tests -v
```

The inspection tool prints package signatures, raw version fields, payload sizes, SHA-256, XOR marker clues, and Cortex-M vector heuristics. It cannot communicate with or reprogram a radio. GitHub Actions runs the same checks against all six archived firmware images and publishes a metadata-only inventory.

Read [P0 research and acceptance criteria (简体中文)](docs/p0-firmware-research.zh-CN.md) and [portability review of the Rust UV-5RH firmware (简体中文)](docs/reference-firmware-portability.zh-CN.md).

## Original collected utilities

- `fwtool.py`: package XOR packing/unpacking tool.
- `fw_updater.py`: serial update tool; **erases and writes radio Flash**.
- `font_updater.py`: font update tool; **writes to radio storage**.
- `firmware/`: collected original upgrade packages.
- `CPS_5RH/`, `FontTool/`, `UpgradeTool/`: vendor utility binaries.

The presence of a firmware updater is **not** proof that a full Flash backup or recovery of a nonbooting device is possible.

## Related work

- [sophiel-meow/bf-5rh-firmware-open](https://github.com/sophiel-meow/bf-5rh-firmware-open) — experimental Rust firmware for **UV-5RH/5RM**, not a drop-in UV-5RH Pro image. The project is GPL-3.0; direct source reuse requires honoring its license.
