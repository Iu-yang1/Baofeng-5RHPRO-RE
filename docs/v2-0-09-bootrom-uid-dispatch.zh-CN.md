# UV-5RH Pro V2.0.09：芯片 UID、ROM 回调和特殊寄存器证据

日期：2026-11-15。分析对象为本仓库原厂 BF_5RH_501_v2_0_9.dat，交叉验证 BF_5RH_501_v1_1_04.dat。本文只呈现离线 Thumb 反汇编与公开手册结论；**没有读取实机 MCU ID、SWD 或 96-bit UID**。

## 一、先更正执行时机

先前把地址 0x08001260 称为“Reset 直接执行的启动代码”，证据不足。现在追踪出具体直接调用链：

| 层级 | V1.1.04 | V2.0.09 |
| --- | --- | --- |
| 应用上层调用点 | 0x080111F2 | 0x080173DE |
| 包装函数入口 | 0x0802622A | 0x0803235E |
| ROM 辅助函数调用点 | 0x08026252 | 0x08032386 |
| ROM 辅助函数入口 | 0x08001260 | 0x08001260 |
| 条件 ROM 回调 | [0x1FFFD000+0x0C] | [0x1FFFD000+0x0C] |

因此该代码存在于应用的一条静态可达路径，但没有证据证明每次上电都执行。包装函数对 ROM 辅助函数的参数是 **R0=0x00010000、R1=0x00380000、R2=1**。ROM 真实函数体尚未读回，不能将这些值臆断为扇区容量、Flash 起始地址或读保护操作模式。

**重要的跨版本结果：V1 和 V2 的 0x08001280 至 0x08001357 区间共 216/216 字节完全相同。** 相同机器码表示代码复用，不意味着两版板卡必然焊接相同 MCU。

## 二、UID 分支不是厂商系列 ID

原厂 0x080012A2 通过字面量加载 **0x1FFFF7E8**；0x080012A4 从该地址读 32-bit 数据；0x080012A8、0x080012C2、0x080012DC 则把这个字的 bits31:24 与 **0x1A、0x1B、0x1C** 比较。

根据 [Artery AT32F403A/407/407A RM V2.06 §1.3.2](https://www.arterychip.com/download/RM/RM_AT32F403A_407_EN_V2.06.pdf)：

| 地址 | 官方定义 |
| --- | --- |
| 0x1FFFF7E8 | UID[31:0] |
| 0x1FFFF7EC | UID[63:32] |
| 0x1FFFF7F0 | UID[95:64]；高 8 位 UID[95:88] 才是系列标识 |

官方文档给出 AT32F403A 系列标识 0x07、AT32F407/407A 为 0x08。所以比较 UID[31:24] 的 0x1A/0x1B/0x1C **不能解释成检测 AT32F403A/407/421 的芯片型号**。分支用途仍未知，也不需要读取、保存或公布用户设备的真实 UID 才能判断 MCU。

## 三、ROM 和特殊寄存器实际操作

| 原厂指令 | 地址或值 | 可证事实 |
| --- | --- | --- |
| 0x080012AE、0x080012C8、0x080012FA | 0x1FFFD000 | 获取 Boot ROM 表指针 |
| 0x080012B6、0x080012D0、0x08001300 | 指针偏移 +0x0C | 读取入口，随后经 BLX 调用 |
| 0x0800127C–0x08001286 | 0x40016C00 | 连续写入 A7D93A86、AB12DFCD、CDED3526 |
| 0x0800128C / 0x08001296 / 0x0800131C | 0x40016C18 | 读取、暂存、修改、恢复 |
| 0x08001298 / 0x0800129E | 0x4002228C | 写入 A5A5A5A5 |
| 0x08001334 / 0x0800133A | 0x4002228C | 再写入 5A5A5A5A |

在 AT32F403A/407 公开手册中，0x1FFFD000 落在系统 ROM 区间；0x40016C00 归属 I2S2EXT 所在地址窗口；但这段代码对相关地址使用魔数和状态恢复，**不能按普通 I2S 驱动理解**。0x4002228C 处于 FLASH 控制器 0x40022000 起的外设地址范围内，其 +0x28C 偏移没有在已核对的普通 FLASH 命名寄存器表（偏移 0x00 至 0xF8）中定义。

这些互补键值可能关联专有初始化/状态切换，但**没有证据证明其实际含义是解除读保护、sLib、FLASH 擦写或时钟切换**。不要在未知 MCU 上复制执行。

资料：[AT32F403A/407 RM V2.02 FLASH 寄存器表](https://fregat.ru/upload/iblock/aef/wuyt5y5nrvejbmnge0k07nwh1vqobj0m/RM_AT32F403A_407_EN__V2.02.pdf)；[Artery 403A/407 至 435/437 迁移指南（I2S2EXT 基址）](https://www.arterychip.com/download/MG/MG0018_Migrating_from_AT32F403A_407_to_AT32F435_437_V2.0.3.pdf)。

## 四、对 MCU 候选的实际影响

- **AT32F421C8T7 标准型号继续排除**：原厂应用 Flash 地址、超过 64 KiB 的 SRAM 初始栈顶、3 路 USART、DMA CH6 和 LQFP64 封装都不符合 421。
- **AT32F403A/407 仍是合理候选，不是确认结果**。地址映射、ROM 区间和大容量资源相符，但 CRM_CFG bit28 计算和 0x4002228C 特殊访问不能简单对照官方公开位域。
- **GD32F303RGT6 等资源匹配型号仍需保留**。仅凭一组 STM32 风格外围基址及这段特殊代码不能推断唯一供应商。
- 当前没有任何 V2 设备现场的 CPUID、DEBUG_IDCODE、Flash 容量读回，也没有通过顶层芯片丝印确认商品型号。

因此新固件 firmware-pro/core 继续保持硬件无关；不启用未经识别的 MCU PAC、GPIO pinout、memory.x，也不采用普通 UV-5RH 的固件打包及刷机流程。

## 五、下一步按 amoxu 思路进行真正的只读鉴别

用户若能确认 SWCLK、SWDIO、GND 和 3.3V 参考焊盘，可使用 J-Link/CMSIS-DAP 的 SWD 只读模式，取得 **非唯一芯片身份字段**：

~~~text
mem32 0xE000ED00 1
mem32 0xE0042000 1
mem16 0x1FFFF7E0 1
mem8  0x1FFFF7F3 1
~~~

这些指令需在硬件连线、电平和适用的 Debug 目标确定后执行；除第一条 ARM CPUID 外，其余地址因真实芯片不同可能不适用。失败时记录错误，不进行擦除、解锁、Option Byte 写入或强制复位保护。为识别型号 **不需要读取 UID 的 96 位私人唯一值**。

已有工具 tools/at32_readonly_id_decode.py 可解析官方表中的 AT32F403A/407 DEBUG_IDCODE；若型号不是这些芯片，则保留未知结果。

## 六、完整复现

~~~sh
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/v2_bootrom_dispatch.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat
python tools/thumb_callsites.py firmware/BF_5RH_501_v2_0_9.dat --target 0x08001260 --target 0x0803235E
~~~

以上工具均只读取归档原厂固件，不进行模拟写入 Flash、不调用硬件 ROM、不生成可刷机文件。可观察的仅是机器码指令地址、常量、合成条件分支和代码复用状态。
