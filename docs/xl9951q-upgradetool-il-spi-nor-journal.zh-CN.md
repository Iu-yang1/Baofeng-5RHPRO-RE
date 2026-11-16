# XL9951Q / UV-5RH Pro：原厂 UpgradeTool IL 与应用高地址 SPI NOR 暂存链路审计

日期：2026-11-16。基线：PR #23 后的 `master`，原厂 V1.1.04 / V2.0.09 固件，仓库原厂 `UpgradeTool/bin/Release/net20/Radio.exe`。所有结论均来自**离线静态取证**；没有启动升级器、连接串口、读取实机、写频或擦写。

## 1. 两套存储路径必须分开理解

| 地址或范围 | 证据等级 | 功能 |
| --- | --- | --- |
| `0x0807F800` | V1/V2 应用层直接 LDR + FLASH_CR/FLASH_AR/STRH 链 | MCU Flash 地址空间中的日志或暂存元数据**候选**，不是升级 Bootloader 的地址证明 |
| `0x001FE000` | V1/V2 应用层将偏移传入 SPI NOR `0x20` 擦除和 `0x02` 编程例程 | SPI NOR 末尾区域附近的一处 4 KiB 备份/暂存扇区**候选** |
| `0x000000–0x1FFFFF` | 2 MiB GT25Q16A 的标称容量与 24 位 SPI NOR 寻址相容 | **容量对照，不是代码已验证的完整分区表** |
| UpgradeTool 发送的 `0x00000000` 起相对数据偏移 | 实际 PE IL 构造发包 | 是升级协议中的传输偏移；设备如何转换为 `0x080xxxxx` 或其他目标地址**仍未知** |

应用曾在启动 scatterload 前设置 `0x40022000` 的 Flash ACR，和此次的 FLASH_CR/AR 编程指令是两类完全不同的证据；均不能单凭自身认定 XL9951Q 的晶圆厂。

## 2. SPI NOR 访问指令：明确的命令与数据流

在 V2 原厂程序中：

| V2 Thumb PC | 指令、寄存器或调用 | 可支持的解释 |
| --- | --- | --- |
| `0x08006B06` | `MOVS R0,#3`，随后写出 24 位地址，再接收数据 | `0x03` Read Data |
| `0x08006C56` | `MOVS R0,#2`，随后写 24 位地址和负载 | `0x02` Page Program |
| `0x08006ABE` / `0x0800D34A` | `MOVS R0,#0x20` 后输出地址 | `0x20` 4 KiB Sector Erase |
| `0x08006BE6` | `MOVS R0,#5`，读取返回状态并轮询 | `0x05` Read Status |
| `0x08006C10` | `MOVS R0,#6` | `0x06` Write Enable |
| `0x08006BB0` | `LDR` literal `0x40003C00` | STM32F1 兼容命名的 SPI3 外设 |
| `0x08006B44` 等 | literal `0x40010814`，并且指令中通过减去 4 访问 `0x40010810` | 在 STM32F1 兼容布局下分别是 GPIOA BRR（复位输出位）与 BSRR（置位输出位）；代码针对 bit15 进行片选控制候选操作 |

同时，V1 的对应命令位置包括 `0x08002FF6` (03)、`0x08003146` (02)、`0x08002FAE` (20)、`0x08007CAA` (20)、`0x080030D6` (05)、`0x08003100` (06)。不是仅在镜像中搜索到某个常量，而是已核对真实 Thumb 指令、PC 相对文字池及 BL 调用关系。

这充分证明原厂**应用软件实现了普通 SPI NOR 访问协议**。高置信地与板载 2 MiB GT25Q16A 的用途相容；无法脱离实机证明该器件具体负责了所有调用，也**不构成外部 SPI NOR XIP 映射证据**。

## 3. 应用高地址写入：两版同构流程

V1 入口 `0x08012D98`，V2 入口 `0x080190E0`，均存在以下调用顺序：

1. 将 `0x0807F800` 传给 MCU Flash 擦除函数（V2 `0x080190FE`）；
2. 将目标偏移按 `0x1000` (4096 B) 对齐，读入 SRAM 暂存缓冲区：V1 `0x20002CA8`，V2 `0x20003580`；
3. 取 SPI NOR 偏移 **`0x001FE000`**，调用 SPI NOR `0x20` 擦除，再把 4096 B 缓冲区写入该偏移；
4. 将当前原目标偏移作为元数据，调用 MCU Flash 编程函数，向 `0x0807F800` 写入；
5. 再从目标 SPI NOR 扇区读入缓冲区，必要时对目标扇区调用 `0x20` 擦除；把修改后的数据按 4096 B 单元写回目标 NOR 地址；
6. 结束时将 `0x00000001` 写向 `0x0807F804`。

这是**备份数据扇区 + MCU Flash 元数据标志**的结构，说明软件显式区分 MCU Flash 与外部 NOR。更新：后续研究已经在 V1/V2 应用中定位并核对早期初始化期间的恢复调用、4096 B 备份比较与恢复分支，详见[后续恢复状态机取证](xl9951q-journal-cold-start-recovery.zh-CN.md)。尽管软件恢复分支确实存在，仍不能据此声称已经实机验证可靠原子事务、事务回滚或断电容错。尤其是 SPI NOR `0x20` 命令指示的 4096 B 擦除粒度，**不可转用为 XL9951Q 片内 Flash 的物理页大小**。

在一个标称 2 MiB 的 SPI NOR 中，`0x001FE000` 是倒数第二个 4 KiB 扇区的起点，`0x001FF000` 后一个扇区的用途仍未证实。不能把 2 MiB 顶部 8 KiB 全部宣称为已确认的固件分区。

## 4. 原厂 Windows UpgradeTool：已验证具体方法体

`UpgradeTool/bin/Release/net20/Radio.exe`：

- 文件大小：**108,544 B**；
- SHA-256：`782ea95bc3b6bbb8100b2f80e65eefc59fedf1ea007c2ed393136b3caa62ae19`；
- 静态解析的 IL 方法体：**482**；
- `MethodDef 0x0600018C UpdateFirmware`：依据 `get_IsRead` 选择读取或写入委托，启动线程；
- `MethodDef 0x0600018D DoReadData`：**IL 代码仅 1 字节，`IL_0000: ret`**，没有设备读回/备份逻辑；
- `MethodDef 0x0600018E DoWriteData`：**1667 B IL**，负责固件文件装载、握手、擦除请求、分包发送、ACK 和结束帧。

**地址记法纠正：** 工具初版将 `0x9155` 这样的 PE 文件偏移显示为 `IL_9155`，不是方法内相对 IL 偏移。现已同时输出 `pe_offset` 和真正的 `il_offset`，即 `DoReadData` 的 `ret` 位于 PE 文件偏移 `0x9155`、方法内 `IL_0000`。

### 4.1 与 `fw_updater.py` 交叉一致的协议细节

| 主机原厂 IL 证据 | 可证事实 | 未能证明 |
| --- | --- | --- |
| `DoWriteData` 的 `CMD_DOWNLOAD` / `CMD_NEW_HARDWARE` / `CMD_UPDATE` 分支 | 请求 `DOWNLOAD`、依版本应答选择新旧硬件握手 | 芯片型号/真实 Bootloader 分区 |
| `CMD_FLASH[1]` + `28 06 88 19 13 03 18 20` | 16 B 擦除请求帧，前缀为 `F-ERASE` | 后 8 B 对应真实擦除范围、页数或设备容量 |
| `0x400=1024` 和 `0x50=80` 常量 | 1024 B 分包；从 .dat 的第 80 字节主体开始发送 | 1024 B 是 Flash 物理页尺寸 |
| 四次 `shr` / `conv.u1` + 数据头 `00` | **4 B 大端相对偏移 + 1 B 保留值 + 原始固件包主体数据** | 接收端实际写入的 MCU 绝对地址 |
| 单字节 ACK 检查以及末端 `END FF FF` + 4 B 加法和 | 传输级完成判断 | 设备全镜像 Flash 读回、CRC 或数字签名校验 |
| 接收到终止 ACK 后进入 `Communication success` 分支 | 成功提示是主机通信状态结果 | 固件启动成功或掉电后恢复可靠 |

当前 IL 的 `DoWriteData` 方法没有直接加载 `0x080xxxxx` 的 MCU 绝对地址常量。因此它对地址转换没有明确主机侧实现，不能由其数据偏移推出从 Flash `0x08001000` 还是别的区域写起。**真正需要审计的是设备端 Bootloader/ROM 收包程序，但该程序主体仍不在现有 .dat 包里。**

## 5. 工具、回归和后续证据边界

新增离线工具：

```sh
python -m pip install "capstone==5.0.6" "dnfile==0.18.0" "dncil==1.0.2"
python tools/xl9951q_high_flash_nor_audit.py --json
python tools/upgrade_tool_il_audit.py --verify
python -m unittest discover -s tests -v
```

前两者依次验证 V1/V2 Thumb SPI NOR 读写擦指令、内部 Flash 日志点和高地址调用顺序，以及 Release UpgradeTool 中实际 MethodDef IL 的原始方法结构和协议构造。测试包含恶意变异的指令、文字池、方法体和块长负例；CI 只上传证据 JSON，不发布固件镜像。

依然未解决：XL9951Q 的晶圆厂与 die、片内 Flash 真实容量、片内擦除页大小、Bootloader 的相对地址转换、完整 SPI NOR 分区表、恢复例程的全部故障分支及实际掉电可靠性。**应用层恢复状态机已由后续静态审计证实，但实机恢复效果仍为 UNCONFIRMED。**

参考：ST [RM0008](https://www.st.com/resource/en/reference_manual/cd00171190.pdf) 用于 STM32F1 兼容寄存器地址**对照**；不得将 ST 手册当成 XL9951Q 原厂规格。Mandiant [dncil](https://github.com/mandiant/dncil) / [dnfile](https://github.com/malwarefrank/dnfile) 为本次离线 .NET IL 解析工具。 
