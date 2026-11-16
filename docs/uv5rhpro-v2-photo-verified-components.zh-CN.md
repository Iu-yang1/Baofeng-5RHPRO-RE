# UV-5RH Pro V2：主板照片与器件标记对照（2026-11-16，QFN64 修正）

目标机：BAOFENG UV-5RH Pro，用户报告固件 \`v2_0_09\`、软件 \`v1_1_04\`。
照片证据：用户在本次对话中提交两张主板实拍图，文件名 \`IMG20261115155726.jpg\`（局部）与 \`IMG20261115155641.jpg\`（主板全貌）。本报告**只登记照片观察，不将用户原始照片重新公开上传到仓库**。

## 1. 关键识别结果

| 照片位置/原丝印 | 身份及可信度 | 备注 |
| --- | --- | --- |
| 全貌照底部靠右、或局部照片左下，8 引脚 SOP：\`G / 330 / 516A-UGLI\`（用户最初抄为 \`S16A-UGL I\`） | **聚辰 Giantec GT25Q16A-UGLI-TR**，16 Mbit / **2 MiB SPI NOR Flash**，**高可信** | 与聚辰官方 V2.2 数据手册 **第 79 页 Top Side Marking** 中 \`G YWW 516A-UGLI\` 和 SOP8 150 mil 完全对应；\`330\` 与 YWW 日期编码格式吻合，但不在没有追溯记录时绝对化某个生产日期 |
| 全貌照底部较大的方形多引脚器件，局部照左上：\`XL99?1Q\`（照片视觉近似 \`XL99F1Q\`，用户曾抄为 \`XL9951Q\`），下一行 \`2404CJW9\` 近似 | **主 MCU 的最强实体候选**；但**无法确认具体厂家/料号** | **用户确认 QFN-64（实际清点 64 个端子）**。之前照片识别 LQFP64 的判断错误；JLCPCB 收录同标记的 XL9951Q / C9900238147 / QFN-64_8x8。该目录未公开 MCU 内核、容量、晶圆厂或官方数据手册。
| 全貌照左上 GNSS 模块：\`ATGM336H\` / \`5N31\` | **中科微 ATGM336H-5N31**，高可信 | 已从先前的“ATGM336H 系列、5N/6N 待定”收敛到 **5N31**，芯片族典型为 AT6558；NMEA/卫星能力须按 5N31 而非 6N 手册研究 |
| 局部照中央：\`FD6818 CS4055XA\` | **FD6818 RFIC**，高可信 | 明确为 FD6818，不应自动替换为 FD6818B 驱动 |
| 用户另外确认 | **TDA2822 系列音频功放、3PEAK LM2904B 双运算放大器、两颗 HTL7G06S011P RF 功率管** | 接受用户的器件确认；照片不充分时，不从这一确认进一步推断音频连线和 PA 偏置控制 |
| 全貌照中下部分 10 引脚广播 IC：\`5807M TN550\` | **RDA5807M 广播 FM 调谐器**，较高可信 | 应有独立于 FD6818 的广播接收控制接口 |

## 2. 决定性证据：聚辰官方 GT25Q16A 丝印表

- [Giantec GT25Q16A 16 Mbit SPI NOR Flash datasheet V2.2](https://www.giantec-semi.com/uploads/pdf/250709/GT25Q16A%20U%20DS_V2.2.pdf)，**第 79/80 页**，两列内容：\`GT25Q16A-UGLI-TR\`、\`G YWW 516A-UGLI\`；**SOP8 150 mil**。
- **存储容量**：16 Mbit = 2,097,152 byte（2 MiB）；不是 16 MiB，也不是 MCU 的内部 Flash。
- **典型硬件接口**：标准 SPI、Dual SPI、Quad SPI；供电范围 1.65–3.6 V。
- **只读探测指令**：JEDEC RDID \`0x9F\`，预期返回 \`C4 60 15\`（第 32 页）；\`0x03\` 为普通读取（先发 24 位地址），\`0x5A\` 为只读 SFDP。
- **SOP8 管脚（俯视、左上为 Pin 1）**：1=/CS，2=DO/IO1，3=/WP/IO2，4=GND，5=DI/IO0，6=CLK，7=/HOLD/IO3，8=VCC。
- 不可把升级包中的 \`XOR 0xC8\` 和 JEDEC 厂商码 \`C4\` 关联；二者属于完全不同的协议和来源。
- **不能仅凭 PCB 焊有 2 MiB SPI NOR，就推断 V2 的 392 KiB 升级镜像从此芯片执行**。还需追踪 MCU 原厂程序 SPI 初始化、片外存储访问及固件包与 NOR 内容的关联。

## 3. MCU 进一步收敛，但不是完成识别

**原有 LQFP64 的外伸引脚判断已被用户实物检查推翻。** [JLCPCB XL9951Q / C9900238147](https://jlcpcb.com/partdetail/JLCPCBAssembly-XL9951Q/C9900238147) 登记封装为 QFN-64_8x8；8×8 mm 是目录值，本机实际封装尺寸尚未测量。页面的 Manufacturer 字段为 JLCPCB Assembly，不能据此推断实际晶圆制造商；CPU/Flash/SRAM 均未公布。

这与 V2.0.09 静态分析形成两组独立支持：
1. 原厂镜像经 \`XOR 0xC8\` 解混淆后包含 Cortex-M/Thumb-2 形式的向量表与指令；
2. \`0x40021000\` CRM/RCC、\`0x40022000\` Flash、\`0x400108xx\`/ \`0x40010Cxx\` GPIO 等地址符合 STM32F1/AT32F403A 类寄存器布局。

但是，**外观 + 指令集 + 外设地址不能唯一识别 MCU 厂商**。OEM/委托生产的顶部自定义丝印也可能没有公开数据手册。不能用 \`XL99?1Q\` 的文本猜测 GPIO 引脚、芯片 Flash 大小或 Cortex-M4F。

优先补充的实测是：\`SW-DP DPIDR\`、\`CPUID\`、实际芯片厂商 Device ID/DBGMCU 寄存器、复位/RCC/Flash 初始化的精确指令，或确认主板 Pin 1 / 电源 / SWD 调试通路。

## 4. 下一轮硬件/固件开发任务

**P0：先不改写 Flash**
- 将 \`GT25Q16A\` 纳入设备 HAL 存储映射研究；先确认其是否实际连接 MCU SPI 以及片选引脚，而不是复制普通 UV-5RH 的 NOR 地址分配。
- 若能得到正确电气访问条件，优先只读 \`0x9F\` JEDEC ID，随后按需备份完整 2 MiB 并校验 SHA-256；**避免在板上与 MCU 同时驱动 SPI 造成总线冲突**。不发 \`WREN 0x06\`、\`WRSR 0x01\` 或任何擦写命令。
- 按照 \`ATGM336H-5N31\` 的 NMEA/UART 特性追踪现有固件 GNSS 服务，不借用 6N 的指令/卫星系统假设。
- **撤回旧 LQFP-64 pin-map**。用户目前优先纯软件分析；即使将来调查管脚，也不能直接使用 LQFP64 标准料号的脚位定义来解释 QFN64 焊盘。

## 5. 相关来源

1. [聚辰原厂 GT25Q16A Datasheet V2.2](https://www.giantec-semi.com/uploads/pdf/250709/GT25Q16A%20U%20DS_V2.2.pdf)；丝印列表第 79 页、Manufacturer/Device Identification 第 32 页。
2. [Giantec GT25Q16A-UGLI-TR 产品目录](https://www.oneyac.com/product/30856192.html)。
3. [中科微 ATGM336H-5N31 产品资料](https://www.lcsc.com/product-detail/C90770.html)。
4. [V2.0.09 静态反汇编阶段性报告](v2-0-09-static-disassembly.zh-CN.md)。
5. [JLCPCB：XL9951Q / C9900238147 / QFN-64_8x8](https://jlcpcb.com/partdetail/JLCPCBAssembly-XL9951Q/C9900238147)，无芯片制造商数据手册。
6. [先前尚未见照片的手抄芯片清单](uv5rhpro-v2-board-chip-markings.zh-CN.md)，其中原始抄录需保留，证据状态以本照片核实结果为准。
