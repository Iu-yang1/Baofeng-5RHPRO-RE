# UV-5RH Pro V2.0.09：原厂固件系统时钟初始化反汇编

分析日期：2026-11-15  
镜像：\`firmware/BF_5RH_501_v2_0_9.dat\`（原档）；\`0x50\` 字节包头后按 XOR \`0xC8\` 解混淆。  
基址假定：\`0x08001000\`；Reset 向量：\`0x0800123D\`（最低位 Thumb 状态），对应反汇编地址 \`0x0800123C\`。  
**本报告是离线静态分析，不代表在用户实机捕获了寄存器值或执行频率。**

## 1. amoxu 参考仓库审计与适用边界

参考：[amoxu/Baofeng-UV-5RM-5RH-RE](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE)，\`main\` 分支。

| 参考组件 | 判断 | 原因 |
| --- | --- | --- |
| \`reverse_engineering/bao_fw_tool.py\`（OK2MOP） | **不能直接用在 Pro** | 普通 UV-5RH 的 \`.BF\` 包：16 字节头，两段数据；分块 1 KiB，\`KDHT\`/\`RBGI\` 条件 XOR；Pro 用 \`.dat\` 80 字节头、逐字节 XOR \`0xC8\` |
| \`reverse_engineering/uv5rm-wrap-tool\` | **不能直接用在 Pro** | 相同的 \`.BF\` 拆包及分块方案，适配普通版分区和加密流程 |
| \`reverse_engineering/decrypt.c\`, \`encrypt.c\` | 仅供理解算法设计，**不复用加密逻辑** | 与 Pro 格式不同 |
| \`reverse_engineering/bf-uv5rm-btldr-dumper/src/at32f421_clock.c\` | 可借鉴 CRM 工作流程，**不能作为 Pro 频率证据** | 目标为普通版 AT32F421，且 120 MHz PLL 设置在该文件中多数被注释，实际代码只调用 \`crm_reset()\` |
| \`README.md\` 的 Ghidra、dump、启动基址识别方法 | **可直接借鉴方法论** | 先验证包结构、静态反汇编、查外设寄存器、形成交叉证据 |

参考工程仓库声明 BSD-3-Clause；个别文件（如 OK2MOP 的 Python 工具）有单独版权/许可说明。本分支**未复制其源码**，只参考流程并实现了独立的 Pro 静态分析工具。

## 2. 启动链：从 Reset 到时钟配置

原厂 Reset Handler 顶部：

\`\`\`asm
0x0800123C  ldr  r0, [pc,#0x18]
0x0800123E  blx  r0              ; 解出的目标 Thumb 地址 0x080323DD
0x08001240  ldr  r0, [pc,#0x18]
0x08001242  bx   r0              ; 目标 0x08001221
\`\`\`

在 \`0x080323DC\` 处，已读取常量池 \`0x0803241C = 0x40021000\`，这是 AT32F403A/407 类似布局的 CRM 寄存器组起点。关键操作如下：

| PC | 对 CRM 寄存器的操作 | 静态含义 |
| --- | --- | --- |
| \`0x080323E2\` | \`CTRL |= 0x1\` | 使能 HICK 内部高速 RC |
| \`0x080323EA\` | LDR pool \`0x08032420 = 0xF8FF0000\` | 用于清理时钟配置字段 |
| \`0x080323EC\` | \`CFG &= 0xF8FF0000\` | 清理时钟输出/分频等字段的一部分 |
| \`0x080323F2\` | LDR pool \`0x08032424 = 0xFEF6FFFF\` | CTRL 复位掩码 |
| \`0x080323F4\` | \`CTRL &= 0xFEF6FFFF\` | 清理相关时钟使能/故障字段 |
| \`0x080323FA\` | \`CTRL &= ~0x40000\` | 清除 HEXTBYP |
| \`0x08032402\` | \`CFG &= ~0x7F0000\` | 清理中低位 PLL / USB 时钟字段 |
| \`0x08032408\` | \`r1 = 0x009F0000\` | 准备清除 CRM 时钟中断标志 |
| \`0x0803240C\` | \`CLKINT = 0x009F0000\` | 写 CRM 中断清标志寄存器 |
| \`0x0803240E\` | \`BL 0x08031BF4\` | **调用时钟配置函数** |

这是直接从原始 V2 镜像的 PC-relative literal 解引用与 Thumb 指令取得的初始化路径。寄存器位名基于**候选 AT32F403A/407**手册，而非 MCU 厂商已确认。

## 3. \`0x08031BF4\`：外部晶振、PLL 与系统时钟

按 AT32F403A/407 CRM 位定义解释的实际指令：

| 指令 PC | 关键行为 | 判断 |
| --- | --- | --- |
| \`0x08031BF8\` | \`r0 = [pool 0x08031C94] = 0x40021000\` | 指向 CRM |
| \`0x08031C00\` | \`CTRL |= 0x00010000\` | **HEXTEN=1**：开启外部高速时钟 |
| \`0x08031C06\` | \`r3 = 0x00000F00\` | 准备最多 3840 次 HEXT 就绪轮询计数 |
| \`0x08031C0C\` | \`r1 = CTRL & 0x00020000\` | 判断 **HEXTSTBL** 就绪位 |
| \`0x08031C20\` | \`BNE 0x08031C0A\` | 未就绪则继续轮询，至计数条件满足 |
| \`0x08031C24\` | \`LSLS r1,#14\`，后接 \`BPL 0x08031C90\` | 最终未就绪则提前返回，**跳过 PLL 配置** |
| \`0x08031C30\` | \`FLASH_PSR |= 0x10\` | 候选 **prefetch enable** |
| \`0x08031C38\` | \`FLASH_PSR &= ~3\` | 清除 Flash 等待周期字段低两位 |
| \`0x08031C40\` | \`FLASH_PSR |= 2\` | 设置候选 **2 wait cycles** |
| \`0x08031C50\` | \`CFG |= 0x400\` | APB1DIV[10:8]=100，即 **APB1 /2** |
| \`0x08031C58\` | \`CFG &= ~0x003F0000\` | 清除 PLLRCS、PLLHEXTDIV 及倍频字段低四位 |
| \`0x08031C60\` | \`CFG |= 0x00110000\` | PLLRCS=HEXT、PLLHEXTDIV=0、PLLMULT 低四位=0100 |
| \`0x08031C68\` | \`CTRL |= 0x01000000\` | 使能 PLL |
| \`0x08031C70\` | \`LSLS r1,#6\` 后 \`BPL 0x08031C6E\` | 等待 **PLLSTBL bit25**；此循环未见超时退出 |
| \`0x08031C76\` | \`CFG &= ~3\` | 清除 SCLKSEL |
| \`0x08031C7E\` | \`CFG |= 2\` | SCLKSEL=PLL |
| \`0x08031C86\` | \`UBFX r1,#2,#2\`，随后 \`CMP #2\` 循环 | 等待 SCLKSTS=2，确认切换到 PLL |

**重要：按该候选手册的倍频编码，PLLMULT 低四位 \`0100\` 对应 ×6；高两位来自 CFG bits30:29。** 该局部函数只清除低位倍频字段，未在同一函数中证明 bits30:29 的最终值。按照上电复位默认值和目前捕获的 CRM 复位例程，**最可能配置为 HEXT ×6**，但精确倍率仍应核对高位写入的全部引用。不能单凭本报告宣称具体系统主频。

公式（条件式）：

\`\`\`text
在 PLLMULT 高位 = 00、HEXT 未预分频、SCLK 选择 PLL 时：
f_PLL = 6 × f_HEXT
f_SCLK = f_PLL
f_AHB  = f_SCLK  （假定 AHBDIV 仍为复位 /1）
f_APB1 = f_AHB / 2
f_APB2 = f_AHB   （假定 APB2DIV 仍为复位 /1）
\`\`\`

\`f_HEXT\` 尚未由固件静态分析确定。晶振可能有设备定制差异，不能直接把另一个收发信机的 8/12/16 MHz 写为这台机器的真实晶振值。

### 3.1 一条值得保留的可靠性结论

HEXT 等待循环包含有限轮询和失败返回，但 PLLSTBL 与 SCLKSTS 等待循环在该反汇编区域没有观察到超时退出。因此未来替代固件应实现**有明确超时与回退路径的时钟切换状态机**。这是由可指出的故障模式支持的可靠性设计，不属于无依据禁用功能。

## 4. 其他 CRM 路径：不是“所有写指令都在启动时执行”

从 Reset 根扩展静态代码图，发现另一份类似 CRM 复位函数：\`0x08030BF0\`，包含 \`CTRL |= 1\`、\`CFG &= 0xF8FF0000\`、\`CTRL &= 0xFEF6FFFF\`、\`CLKINT = 0x009F0000\` 等指令。

同时有大量 CRM 读写出现在 \`0x08030Cxx\` 等其他函数。它们是**从 Reset 可静态到达的候选函数**，不能推导成设备每次启动顺序依次执行的所有步骤。这是区分静态反汇编与实机跟踪的必要边界。

统计结果（2026-11-15 CI）：

| 从 Reset 向外遍历的静态候选 | V2.0.09 |
| --- | ---: |
| 候选 Thumb 指令 | **28,751** |
| CRM/RCC 读 / 写 | **52 / 39 处** |
| Flash 控制器读 / 写 | **12 / 12 处** |
| SysTick 读 / 写 | **7 / 13 处** |
| PWR 读 / 写 | **3 / 2 处** |

**统计数字为指令地址数而不是运行时写寄存器的次数。** CFG 遍历未做完整别名分析或路径谓词求值，可能遗漏其他实际引用或把未执行的代码纳入静态图。

## 5. 复现与验证

\`\`\`bash
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/clock_register_trace.py firmware/BF_5RH_501_v2_0_9.dat
python tools/clock_register_trace.py --show-context --pc-from 0x08031BF4 --pc-to 0x08031C90 firmware/BF_5RH_501_v2_0_9.dat
python tools/thumb_window.py firmware/BF_5RH_501_v2_0_9.dat --start 0x08031BF4 --end 0x08031C98
python tools/clock_register_trace.py --scope vectors --json firmware/BF_5RH_501_v1_1_04.dat firmware/BF_5RH_501_v2_0_9.dat > clock-v1-v2.json
\`\`\`

GitHub workflow \`.github/workflows/v2-clock-trace.yml\` 会自动验证所有 Python 单元测试、两份原厂固件的地址候选，产生仅包含指令元数据、不包含原始固件正文的 JSON 产物。

现有回归覆盖：标准读取/写入、静态常量写入、间接启动跳板、未引用的假常量不被算成寄存器写、Thumb 字面量池、镜像边界。**没有实机设备测试，不宣称硬件主频已测量。**

## 6. 外部资料（芯片家族对照，不是 MCU 身份证明）

- [Artery AT32F403A/407/407A Reference Manual Rev 2.06](https://www.arterychip.com/download/RM/RM_AT32F403A_407_EN_V2.06.pdf)，第 4 章 CRM（约 60–74 页），定义 CRM_CTRL/CFG、PLL 输入选择、倍频编码和 APB 分频；
- [Artery AT32F403A/407/407A Reference Manual Rev 2.02](https://doc.platan.ru/pdf/datasheets/artery/RM_AT32F403A_407_EN_V2_02.pdf)，第 62–64 页，描述 CTRL/CFG 位域；
- [amoxu Baofeng-UV-5RM-5RH-RE](https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE)，普通 UV-5RH/5RM 的包格式、逆向方法及 AT32F421 时钟代码参考。

**下一轮：** 全文件检索 \`CRM_CFG\` bit29:30 的写引用、HEXT 频率相关常量和原厂 UART 波特率/分频调用；在此基础上再给出 \`f_SCLK\` 的绝对数值候选，仍不使用硬件操作。
