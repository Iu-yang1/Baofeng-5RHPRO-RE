# UV-5RH Pro：通过写频线回传 MCU ID 的 UART 诊断固件原型

**状态：源码已经在 PC 上通过 Cortex-M3 Thumb / Clang+LLD 交叉编译，尚未在 UV-5RH Pro 实机验证。本目录不生成可刷入的 .dat 升级包。**

## 可行性与工程边界

UV-5RH Pro 使用串口式写频接口。仓库内 `fw_updater.py` 能通过写频线执行固件升级，但流程包含 `F-ERASE`：**固件程序自身只读寄存器不等于安装过程不写 Flash**。当前没有证据证实原厂 CPS 支持任意 MCU 地址读取或 RAM 临时执行，因此不能假称该原型已能无损读取实际芯片 ID。

本目录提供最小独立 Cortex-M3/M4 Thumb 固件的**构建源码**：

- `diag.c`：启动向量、候选 STM32F1 风格 USART1/PA9 输出、CPUID、F_SIZE、厂商 DEBUG_IDCODE、AT32 Project ID 和脱敏 AIR32 UID0 标记。没有任何 RF 芯片/PTT/PA 或 Flash 擦写操作。
- `linker.ld`：假设原厂应用地址为 `0x08001000`、使用 32 KiB SRAM，仅做编译实验，并非已核对的真实板级内存布局。
- `Makefile`：生成 ELF，不输出可刷机固件容器。
- `tools/probe_radio_mcu_uart.py`：PC 侧**纯接收** COM 端口诊断文本，不发送命令。

### 尚未核实的硬件条件

1. 主控的 RCC/GPIOA/USART1 寄存器与 STM32F1 兼容；实际写频线 TX 对应 USART1/PA9。
2. bootloader 跳转后 PCLK2 为 8 MHz，因而默认配置 9600 baud 可用。即使 PC 端正常连接 115200 baud 的原厂 CPS，也不代表实验程序在 8 MHz 假设下能输出。
3. 未证实所有厂商识别地址都可安全读取。不存在的 MMIO 区间可能触发 BusFault/HardFault；可在构建时将 `VENDOR_READS=0` 只读 ARM CPUID。
4. **尚未验证错误镜像能否仅凭写频线重新进入升级模式并恢复原厂固件。** 在得到启动、串口连接和恢复证据前，不要把该 ELF 转换为 .dat 或直接刷入电台。

这些都是会导致无法读取或损坏原厂程序的具体工程故障模式。它们不是一般无线电功能限制。

## 编译

需要 clang + LLD、make、readelf。在仓库根目录：

```sh
cd firmware-pro/diagnostics/mcu-id-uart
make
readelf -h build/id_probe.elf
readelf -S build/id_probe.elf
```

更换候选时钟或仅输出 CPUID：

```sh
make clean && make PCLK2_HZ=8000000 BAUD=9600 VENDOR_READS=0
```

构建成功只证明 ARMv7-M 指令、符号和启动向量可链接，**不代表电台可以安全启动**。不能将 ELF 改名为升级包。

## 串口回传与 PC 接收

下列仅是**人工构造的示例字段，不是你的电台实测**：

```text
UV5RHPRO-ID/1,CPUID=0x410FC241,FSIZE_RAW=0x0200,DBG_ID=0x700502CE,AT_PROJECT=0x07,AIR_UID0_MASK=0x1A6A5CDX
```

- CPUID：`0xE000ED00` 的 ARM 内核标识。
- FSIZE_RAW：`0x1FFFF7E0` 16-bit，须按真实厂家解释。
- DBG_ID：`0xE0042000` 32-bit 设备调试 ID，非 SW-DP DPIDR。
- AT_PROJECT：`0x1FFFF7F3` 项目/系列标记。
- AIR_UID0_MASK：只输出 UID0 高 28 位，末位替换为 X。
- **DPIDR 不能从 CPU 通过普通 MMIO 读出**，所以本固件不虚构该字段。

如果未来成功运行诊断固件，可通过普通写频线在 PC 端监听（以下命令**不会发送任何串口字节**）：

```powershell
python -m pip install pyserial
python tools/probe_radio_mcu_uart.py --port COM5 --baud 9600 --seconds 15
```

或者将上面的示例行放进 sample.txt，对解析器进行无硬件测试：

```sh
python tools/probe_radio_mcu_uart.py --file sample.txt
```

**下一步**优先通过原厂 CPS 报文和 V2 固件继续核实串口的物理路径，然后证明能够在升级失败时恢复原厂版本。如果确认原厂协议存在只读 ID 查询能力，则无需再刷写诊断固件。
