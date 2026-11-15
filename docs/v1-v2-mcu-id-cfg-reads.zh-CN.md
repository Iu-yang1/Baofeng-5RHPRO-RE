# UV-5RH Pro V1/V2：UID、Flash F_SIZE、CPUID、AT32 PID 的指令级读取审计

日期：2026-11-15。前置研究：[厂商 ID 寄存器及官方型号规则](v1-v2-mcu-readonly-id-evidence.zh-CN.md)，[原厂 UID 分支与 ROM 调用](v2-0-09-bootrom-uid-dispatch.zh-CN.md)。

**仅离线研究。没有 SWD/调试器通信，没有 MCU 实际 UID/CPUID/F_SIZE/PID、ROM 内容或 Flash 操作。本文所称“读取”仅指固件内存在可静态还原的 Thumb 内存读指令，不能推论已在实机上执行。**

## 1. 发现：从文字池候选改为跟踪实际内存访问

此前 `v2_mcu_identity_xrefs.py` 确认原厂两版都出现 `0x1FFFF7E8` 的单一 PC 相对文字池加载点。**文字池加载只是把目标地址写入寄存器，尚不能证明读取了地址中的数据。**

本轮工具 [`tools/v1_v2_mcu_id_cfg_reads.py`](../tools/v1_v2_mcu_id_cfg_reads.py) 增加了：

- 以 PC-relative `LDR` 加载的**身份寄存器附近**字面量为候选入口，不把这些地址加载本身当作身份信息读取；
- 检查相同寄存器的 `MOVW/MOVT` 地址拼装（两指令间距离不超过 96 字节），从拼装起点执行有界 CFG 分支及常量传播；
- 跟踪 `LDR`、`LDRH`、`LDRB` 的**有效地址和访问宽度**，因此 `LDRB [0x1FFFF7E0 + 0x13]` 可识别为读取 `0x1FFFF7F3` 的 AT32 Project ID；
- 复用 `thumb_rcc_abstract.py` 的寄存器常量、`MOVW/MOVT`、本地栈和 SRAM 指针中转，以及调用后失效规则；
- 单独从已由原厂指令检查验证的 `0x08001260` ROM 辅助函数入口追踪 `0x080012A4` 的 UID0 读取，避免仅凭任意解码起点宣称真实可达。

扫描命中的语义是 **may-path candidate**，不是执行踪迹，也没有获得任何实际 UID 值。

## 2. 两版原厂静态分析结果

| 项目 | V1.1.04 | V2.0.09 |
| --- | ---: | ---: |
| PC-relative 目标地址附近候选源 | 7 | 7 |
| MOVW/MOVT 目标地址候选源 | 0 | 0 |
| 唯一确定目标/指令的身份访问候选 | **1** | **1** |
| 已验证帮助函数入口可到达 UID0 读取 | **是** | **是** |
| 单个候选超出指令预算 | 0 | 0 |

唯一确定的身份读取是两版共同的：

```text
0x080012A2   LDR R0, [PC,#0x15C]  ; literal at 0x08001400 = 0x1FFFF7E8
0x080012A4   LDR R6, [R0]         ; width 4, reads UID0[31:0]
```

`0x080012A8`、`0x080012C2`、`0x080012DC` 随后分别与 `0x1A/0x1B/0x1C` 比较最高字节。它们与 AIR32F103 公开 UID0 模式具有软件上的相容性，但不代表实机必然选中任一分支。

### 其余六项候选地址位于 ARM SCB，不是 CPUID

| 字面量目标寄存器 | V1 候选加载 PC | V2 候选加载 PC | 标准寄存器语义 |
| --- | --- | --- | --- |
| `0xE000ED0C` | `0x08024920` | `0x08030964` | AIRCR：应用中断、复位控制 |
| `0xE000ED08` | `0x0802497E` | `0x080309C2` | VTOR：向量表偏移 |
| `0xE000ED0C` | `0x0802498C` | `0x080309D0` | AIRCR |
| `0xE000ED10` | `0x08024A66` | `0x08030ADA` | SCR：系统控制/睡眠 |
| `0xE000ED10` | `0x08024A88` | `0x08030AFC` | SCR |
| `0xE000ED08` | `0x080262DE` | `0x08032412` | VTOR |

这些是**六个加载相关 SCB 地址的静态候选**，不等同于全部 SCB 指令已确认执行；本轮身份地址匹配器不会把它们计成 CPUID。相应寄存器命名可交叉核对 [Arm Cortex-M3 TRM](https://documentation-service.arm.com/static/5f2286f2f3ce30357bc28b2a) 和 [Microchip Cortex-M3 SCB 地址表](https://onlinedocs.microchip.com/oxy/GUID-199548F4-607C-436B-80C7-E4F280C1CAD2-en-US-1/GUID-F648BDD6-C734-4071-A948-48D189A00AE9.html)。

## 3. 哪些身份读取仍未被发现？

在本轮**已识别源入口、指令语义和 CFG 预算**内，没有解析到以下身份寄存器的实际读指令：

| 目标 | 地址 | 结果 |
| --- | --- | --- |
| Flash F_SIZE | `0x1FFFF7E0` | 无命中 |
| ARM CPUID | `0xE000ED00` | 无命中（周边 VTOR/AIRCR/SCR **不等于** CPUID） |
| AT32 DEBUG_IDCODE | `0xE0042000` | 无命中 |
| AT32 Project ID | `0x1FFFF7F3` | 无命中 |
| UID 中高字 | `0x1FFFF7EC` / `0x1FFFF7F0` | 无命中 |

**这里的“无命中”不是“完全不存在”。** 未覆盖跨函数传入的基址、任意运算组合、未定位到的局部入口、嵌入式 ROM 函数体、间接调用、DMA、全部 IT 条件执行及硬件级地址别名；对于候选路径中的未知调用，寄存器/内存状态也会被清除。无论扫描预算是否耗尽，都不能据此完成全程序的否定证明。

## 4. 对 AIR32/MH32 与 AT32 候选的影响

原厂固件没有新增可直接认定物理厂商的身份信息。**验证过的 UID0 读取 + 三路最高字节比较，仍是最强的程序层面芯片兼容差异处理证据**，但全部可以来自统一 SDK，而不必由实际芯片型号决定。

另一方面，雅特力 [AT32F403A/407 产品页面](https://atkap.arterytek.com/en/product/AT32F403A.jsp) 明确提供最大 1024 KiB Flash 和可配置资源；这一容量优势无法自动证明标准 AT32 兼容原厂 `0x40016C00` 三级魔数、`0x4002228C` 扩展访问和 `0x1FFFD00C` 的 ROM 回调。继续保留 AT32 标准型号及 AIR32/MH32 同源定制型号为独立候选。

雅特力 [AT32F403A/407 Errata V2.0.16](https://atktwftp.arterychip.com/download/Errata/ES0002_AT32F403A_407_Errata_Sheet_V2.0.16_EN.pdf) 还披露 `0x1FFFF7F1` bits[6:4] 的掩膜版本编码，可在未来获取可靠实机只读 Project ID 与 DEBUG_IDCODE 后，作为晶圆修订级**附加交叉证据**。不要因已知这些寄存器地址就推断用户硬件的值。

## 5. 复现、验收与下一步

```sh
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/v1_v2_mcu_id_cfg_reads.py firmware/BF_5RH_501_v2_0_9.dat \
  --v1 firmware/BF_5RH_501_v1_1_04.dat --show-accesses
python tools/v1_v2_mcu_id_cfg_reads.py firmware/BF_5RH_501_v2_0_9.dat \
  --v1 firmware/BF_5RH_501_v1_1_04.dat --json
```

测试包含自生成 Cortex-M3 Thumb 指令样本：`MOVW`→分支→`MOVT`→UID0 读取，SRAM 指针中转，`LDRH` F_SIZE，`LDRB` Project ID，直接 CPUID/PID 读取和未知低半字的拒绝路径；并用两份原厂固件固定 7/1/0 输出及原字节变异拒绝。GitHub Actions 留存 `v1-v2-mcu-id-cfg-reads.json`，不包含任何实机唯一标识符。

**下一阶段最有信息增益的动作仍然是实机只读 CPUID、F_SIZE、DEBUG_IDCODE、Project ID 联合取证；如果保持纯软件研究，则应构建真正的跨函数参数来源分析，证明这些身份地址是否通过堆栈、RAM 全局表或 ROM 接口间接传入。** 不进行刷机，不把实际型号当作已经确认。
