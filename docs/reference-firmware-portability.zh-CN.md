# bf-5rh-firmware-open 移植评估

参考仓库：https://github.com/sophiel-meow/bf-5rh-firmware-open

核对范围：参考仓库 master，2026-11-15 读取的 Git tree `e52b2360af7b3152df72f1255682503a0555bb98`。该工程 README 明确面向 **UV-5RH/5RM**，并非 UV-5RH Pro。许可为 **GPL-3.0**。

## 可以借鉴的部分

| 模块 | 参考文件 | 复用方案 | 条件 |
| --- | --- | --- | --- |
| FM 收发与状态机 | `src/device/radio.rs`, `src/app/tx.rs` | 优先参考抽象接口和状态机 | Pro RFIC 与外部音频/功放链路核实 |
| FD6818B 驱动 | `src/drivers/fd6818b.rs` | 高价值的寄存器、CTCSS/DCS、RSSI 参考 | 读取 Pro 芯片标识并确认兼容寄存器 |
| LCD 绘制 | `src/drivers/st7735.rs`, `src/ui/` | 可复用 embedded-graphics 的思想与 UI 层组织 | 先确认 Pro LCD 控制器、接口、分辨率 |
| CPS、配置、信道 | `src/cps/`, `src/flash_map.rs` | 可以复用数据模型和序列化测试的思路 | Pro 配置区、记录长度和地址必须独立确定 |
| 简易卫星功能 | `apps/satellite/`, `sgp4mini/` | 可参考卫星轨道计算、跟踪工作流 | 必须验证 Pro 的时钟、GNSS、存储及 CPU 资源 |
| 串口与外部 NOR | `src/hal/uart.rs`, `src/drivers/norflash.rs` | 参考协议与驱动接口 | 引脚、时序、Flash 芯片识别后才能移植 |

## 绝对不可直接套用的板级假设

1. 参考代码的 `at32f421-pac/`、`memory.x` 及 `src/main.rs` 是 **AT32F421C8T7 / Cortex-M4** 特定实现，链接脚本给出的 Flash 位置是 `0x08001000`、60 KiB 应用空间和 16 KiB RAM。不能据此宣称 UV-5RH Pro 也是这一 MCU、容量或地址布局。
2. 参考代码 `src/board/rf.rs` 将 RFIC 的 3-wire 控制指定在 PA2/PA3/PC13，`src/board/lcd.rs` 把屏幕指定在 SPI2 和若干 PB GPIO，音频使能 PB7。这是**普通 UV-5RH 特定硬件的引脚定义**，Pro 尚未验证。
3. 参考屏幕驱动是 ST7735、160×128。不能据此认定 Pro 的显示控制器、旋转方向或分辨率。
4. 参考工具使用其自身的普通 UV-5RH/5RM 包装、刷写协议，不能替代本站现有 Pro 专用 `fwtool.py` / `fw_updater.py`。
5. 当前参考仓库未提供明确的 Pro GNSS 驱动，不能因为有卫星应用或位置数据结构，就断言能直接读取 Pro GPS。

## 推荐实现方向

- **先离线验证 Pro 镜像布局**，明确向量表、执行基址、MCU 架构、版本差异。
- 将 **RadioCore、Display、Storage、GNSS、Input、Board** 分层；仅在已验证的硬件抽象层里绑定具体寄存器与引脚。
- 首批可评估移植对象：FD6818B 寄存器/频率控制、CTCSS/DCS 与 FM 状态机；其次为 embedded-graphics UI 和轨道计算。
- 完成同机型 PCB、固件版本、硬件标识核实后再建立 Pro 链接脚本和可执行固件。
- 如果**直接复制、修改或链接**参考工程 GPL-3.0 代码，必须履行相应 GPL-3.0 源码和分发义务；仅研究思路、独立实现不等于直接复制代码。后续决定代码移植范围时需同步核对许可证。

## 当前结论

参考工程能显著降低 **FM 功能、射频寄存器操作、嵌入式 UI、存储数据结构** 的研发成本，但不能消除 Pro 的板级硬件鉴别、引导流程和固件映射逆向工作。这份文件是基于公开源码的静态分析，不是 Pro 实机兼容性测试。
