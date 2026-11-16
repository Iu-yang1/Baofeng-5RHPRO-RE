# UV-5RH Pro：六版原厂固件谱系与 MH2103A / AIR32 / AT32 具体型号交叉筛选

日期：2026-11-16。**只研究归档文件及公开的官方芯片型号资料，没有连接电台或写入任何数据**。此报告讨论的是“可运行原厂程序的芯片技术谱系”，不能把“使用某套 SDK”直接等同于“焊有该品牌的芯片”。

## 核心发现一：六版固件共享同一段关键 ROM 辅助函数机器码

实际使用仓库的 XOR 0xC8 校验解码器，逐份读取如下六个文件；将程序区
\`0x08001280–0x08001357\`（216 字节）与 V2.0.09 比较：

| 文件 | 解码载荷 | ROM helper 216 字节匹配 |
| --- | ---: | --- |
| \`BF_5RH_501_v1_0_92.dat\` | 458752 B = 448 KiB | 216 / 216 |
| \`BF_5RH_501_v1_0_97.dat\` | 458752 B = 448 KiB | 216 / 216 |
| \`BF_5RH_501_v1_1_00.dat\` | 462848 B = 452 KiB | 216 / 216 |
| \`BF_5RH_501_v1_1_04.dat\` | 466944 B = 456 KiB | 216 / 216 |
| \`BF_5RH_501_v2_0_7.dat\` | 401408 B = 392 KiB | 216 / 216 |
| \`BF_5RH_501_v2_0_9.dat\` | 401408 B = 392 KiB | 216 / 216 |

全部 **6/6** 通过字节完全一致检查，并保留同一套 ROM helper 中的 UID0 分支及特殊寄存器/ROM 调用相关代码。这表明跨版本长期复用相同平台级软件，更有理由专门分析其 SDK 来源。

所有版本均存在 12 项已选“关键值”中的 9 个对齐 32-bit 字面量，包括：
\`0x1FFFF7E8\`、\`0x1FFFD000\`、\`0x400210F0\`、
\`0x40016C00\`、\`0x4002228C\`、三级解锁密钥
\`0xA7D93A86\`、\`0xAB12DFCD\`、\`0xCDED3526\`，及 \`0x200183FF\`。
**不能说其余三个值“没有使用”**：
\`0x40016C18\` 可从基址+偏移构造；
\`0xA5A5A5A5\`、\`0x5A5A5A5A\` 可由 Thumb 指令立即数表示。
对真实读取/写入含义的强证据已在
[ROM 分支指令校验](v2-0-09-bootrom-uid-dispatch.zh-CN.md)和
[AIR32 SDK 源代码指纹校验](v2-0-09-air32-sdk-fingerprint.zh-CN.md)
中完成；不要将原始文字池计数当成动态可达证明。

## 核心发现二：兆讯恒达原厂的 MH2103A 确实有高容量型号，但不能跨封装拼接规格

[兆讯恒达 MH2103A 原厂产品页](https://www.megahuntmicro.com/article/40/24.html)
明确给出 **Cortex-M3、216 MHz、128/256/512/1024 KiB Flash、32/64/96 KiB SRAM**，以及 LQFP48/64/100/144 系列封装。这只是**系列组合**。

具体料号公开选型信息下，需要逐个核对：

| 标准公开型号 | 标称 Flash / SRAM | 标准封装 | 与本机 LQFP64、V2 0x08061A54 及 RAM 地址要求 |
| --- | --- | --- | --- |
| AIR32F103RPT6 | 256 / 96 KiB | LQFP64 | Flash 直接线性映射假设下不匹配 |
| MH2103ARPT6 | 256 / 96 KiB | LQFP64 | Flash 直接线性映射假设下不匹配 |
| MH2103AVET6 | 512 / 96 KiB | LQFP100 | Flash 可以解释；**封装不匹配** |
| MH2103AVGT6 | 1024 / 96 KiB | LQFP100 | Flash 可以解释；**封装不匹配** |
| AIR32F103VET6 | 512 / 96 KiB | LQFP100 | **封装不匹配** |
| AT32F403ARET7 | 512 / 96 KiB | LQFP64 | 资源合格，特有 ROM 接口不匹配公开资料 |
| AT32F403ARGT7 | 1024 / 96 KiB | LQFP64 | 资源合格，特有 ROM 接口不匹配公开资料 |

资源约束来自 [原厂 V2 实际 scatterload 与内存布局](v2-0-09-mcu-identification-amoxu.zh-CN.md)：
压缩数据源实际从 \`0x08061A54\` 读取（相对 0x08000000 偏移
\`0x61A54\`），常规线性程序窗口须至少覆盖 **391 KiB**；初始 MSP
\`0x20011308\` 对应 **70408 字节以上的 SRAM 地址空间**。程序包总大小
与片内 Flash 容量不自动等价，仍可能存在异常映射/别名；外置
GT25Q16A 2 MiB SPI NOR 已由照片独立确认，但**没有证据证明将其映射到
0x08060000 或用于当前 scatterload**。

资料：
- [兆讯恒达 MH2103A 官方系列](https://www.megahuntmicro.com/article/40/24.html)
- [兆讯恒达官方 MCU 选型入口](https://www.megahuntmicro.com/lists/10.html)，逐 SKU 选型行
- [合宙 AIR32F103 官方资料](https://wiki.luatos.com/chips/air32f103/mcu.html)和
  [从 SXX32 迁移时的 UID0 识别表](https://wiki.luatos.com/chips/air32f103/switchFromSxx.html)
- [雅特力 AT32F403A 产品列表](https://arterytek.com/en/product/AT32F403A.jsp)
- [社区维护的 AIR32/MH32F103A/MH2103A 兼容模板](https://github.com/IOsetting/air32f103-template)，非厂商芯片鉴别凭证

**证据强度应明确分层**：

1. **强**：六版原厂文件包含相同 216 字节代码、V1/V2 原厂实际 Thumb 访问
   \`0x1FFFF7E8\`，三级魔数 + \`0x1FFFD00C\` 与开源 AIR32 SDK 对应。
   这是**代码谱系鉴定**，不是实时器件测量。
2. **中强**：MH2103A/MH32F103A 与 AIR32F103 的软件兼容关系（社区模板）
   和兆讯恒达 M3/高容量 SKU 的官方资源，是**同源芯片候选**的支持。
   不能说公开的 MH2103ARPT6 自带 512 KiB。
3. **独立但不充分**：照片 LQFP64、模糊 \`XL99?1Q\` 顶面码、
   2 MiB 外部 NOR；没有可核验公开顶面码解码规则，不把 \`XL\` 字母
   直接推断为特定制造商。
4. **仍未得到**：实机 CPUID、F_SIZE、厂商 PID、内部/外部地址映射真值。
   单靠 SDK 编译产物在逻辑上不能唯一恢复 CPU 真实商标或 SKU。

## 复现及可继续解决的问题

\`\`\`sh
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/stock_mcu_lineage.py --json
python tools/v2_mcu_candidate_matrix.py firmware/BF_5RH_501_v2_0_9.dat --json
\`\`\`

CI 将六版报告归档为 \`stock-six-version-mcu-lineage.json\`，同时更新
\`v2-mcu-matrix.json\`。工具只读取固件包字节，不发送串口指令。

下阶段仍可在软件侧提高可信度：追踪 \`0x4002228C\` 附近的 QSPI/Flash
初始化与 scatterload 的程序读取时间顺序，确认是否存在对外部 NOR
或存储器别名的**可证实**映射；将 UID0 分支的实际调用时序与 6 个版本
的完整调用图比较。若无法证明映射或 ROM 语义，则物理商业型号应继续
保留为 **UNKNOWN**，不通过估计置信度伪造精确料号。
