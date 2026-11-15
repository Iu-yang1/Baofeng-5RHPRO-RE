# UV-5RH Pro V2.0.09：ROM 时钟兼容分支与 RCC 直接寄存器写入审计

研究日期：2026-11-15。基线：原厂 V2.0.09 和 V1.1.04 固件，经过已验证包完整性和 XOR 解码后分析。**纯离线研究；未访问实机 SWD、任何物理 UID、ROM 字节、射频设备或执行刷写。**

## 研究目的和结论

此前已通过 [PR #14](v2-0-09-pll-runtime-order-peripherals.zh-CN.md) 确认，从 Reset→scatterload→应用 main 的必经软件入口中，包含 AIR32 风格 PLL ×16 请求，且位于 USART/TIM3 初始化之前。本轮进一步确定：

1. `UID[31:24]` 为 `0x1C` 时，原厂函数 `0x08001260` **在 ROM 调用前直接写两次 `RCC_CFGR`**。第一步清除 bit 28 和 bits 21:18，第二步通过按位 OR 写入 `PLLMUL_16=0x00380000`；`0x1A/0x1B` 分支不执行此专有前置写入。
2. `0x1A` 与 `0x1B` 对 ROM 回调提供 `(R0,R1,R2,R3)=(0x00380000,1,0,1)`。`0x1C` 分支是 `R0=1,R1=0,R2=1`，而 `R3` 保留的是回调指针（供 `BLX R3` 使用），**不可把 `R3` 当成第 4 个固定参数 `1`**。所有这些都是*调用点 ARM 寄存器的静态状态*；无法推导未知 ROM 入口真正的函数原型/内部写入序列。
3. 所有条件分支归并后，原厂函数都有 `RCC_CFGR = (RCC_CFGR & ~0x00030000) | 0x00010000` 的公共更新：清 PLL 输入预分频/时钟源位 17:16，并强制写入 `PLLSRC=HSE`，随后恢复 `0x40016C18` SRAM 参数、反向上锁并关闭 `0x400210F0` 门控。
4. 采用**有严格边界的**程序分析器，在 V1、V2 镜像中各找到 26 个 `RCC` 相关基址文字池加载候选，经过逐指令常量传播和唯一指令/目标地址去重后，各有 **30 个直接存储候选**。均处于 ROM 支持函数/标准 RCC 函数/复位初始化代码地址簇；未从这些明确追踪的常量加载直线代码中发现主应用运行状态直接写 `RCC_CFGR`。
5. 这不能证明应用运行期不存在额外动态改频：函数指针、全局 RAM 指针中转、跨分支数据流、直接拼出寄存器地址的多指令 `MOVW/MOVT`、ROM 本体、DMA 与别名映射均**不在此次限定扫描范围内**。上述 26/30 是分析器的结果，不是所有潜在写入的上界。

## 1. ROM 分支逐指令重建

`0x080012A2` 加载 `0x1FFFF7E8`，`0x080012A4` 取 32 位值，`0x080012A8 / 0x080012C2 / 0x080012DC` 比较它的 bits 31:24。**它不是已确认的型号或厂商 ID**。分支对照：

| 读取字节 | ROM 之前的 RCC_CFGR 操作 | ROM 表与调用现场 |
| --- | --- | --- |
| `0x1A` | 无额外专属 CFGR 预写入 | `[0x1FFFD000+0x0C]`，`R0=0x380000,R1=1,R2=0,R3=1`；`BLX IP` |
| `0x1B` | 同上 | 同上 |
| `0x1C` | `0x080012F0`: `CFGR &= 0xEFC3FFFF`；`0x080012F8`: `CFGR |= 0x00380000` | 同一 ROM 表项，`R0=1,R1=0,R2=1`；`BLX R3` |
| 其他值 | 无专属预写入 | 跳过 ROM 调用，进入公共收尾 |

逐位验证：

```text
CFGR pre-write @0x1C:
  clear_mask = ~0xEFC3FFFF & 0xFFFFFFFF = 0x103C0000
  bits clear = 28, 21, 20, 19, 18
  CFGR_1 = CFGR_original & 0xEFC3FFFF
  CFGR_2 = CFGR_1 | 0x00380000

All branches, after optional ROM callback:
  CFGR_3 = (CFGR_after_ROM & ~0x00030000) | 0x00010000
  0x400210F0 = 0
```

`CFGR_after_ROM` **不能当作 `CFGR_2`**；ROM 入口内部对 PLL/Flash 的修改不在原厂镜像中。对 `0x1C`，bit 28 在 ROM 调用前被清除，但不证明 ROM 返回后保持 0。即便如此，本地 PLL 倍频低位已显式请求 ×16；加上共享的 HSE 选择，128 MHz 仍是有依据的 *8 MHz HSE 条件性应用请求*，不是实机测量。

特殊写入中 `0x4002228C=A5A5A5A5` 与结束 `0x5A5A5A5A`、`0x40016C00` 三级密钥和 `0x40016C18` 临时 SRAM 配置与 [AIR32F103 SDK 的 AIR_RCC_PLLConfig](https://github.com/openLuat/luatos-soc-air32f103/blob/c10eaeb13dd133f35bc9d8ed1137072897339db2/Libraries/AIR32F10xLib/src/air32f10x_rcc_ex.c) 高度吻合。SDK 同源仍不等于器件型号确认，标准 AIR32F103RPT6 的 256 KiB Flash 容量矛盾尚未解决。

## 2. 有界的 RCC MMIO 写入索引

`tools/v2_rom_cfgr_mmio_audit.py` 对固定基址 `0x40021000`、`0x40021004`、`0x400210F0` 的有效候选 Thumb PC-relative `LDR` 进行查找，并在每处加载后至多追踪 32 条**连续直线指令**。支持 `LDR literal`、寄存器 `MOV`、含立即数的 `ADD/SUB`，遇到分支/函数调用立刻停止，不把代码顺序或地址接近误称为可达关系。

对 V2，去重后已锁定 30 个局部存储目标（部分代码点列举）：

| 类别 | 关键指令地址 | 对象 |
| --- | --- | --- |
| ROM UID 分支及恢复 | `0x080012F0`, `0x080012F8`, `0x08001316` | `0x40021004` CFGR |
| ROM 隐藏寄存器门控 | `0x08001278`, `0x08001342` | `0x400210F0` |
| 标准 RCC 预分频相关 | `0x08030D0E`, `0x08030D6E`, `0x08030D84` | `0x40021004` CFGR |
| 标准 RCC 系统时钟选择 | `0x08030DBE` | `0x40021004` CFGR |
| Reset CRM 初始化 | `0x080323EE`, `0x08032406` | `0x40021004` CFGR |
| 早期 PLL 开启流程 | `0x08031C04` 等 | `0x40021000` CR |

V1 在对应地址布局中也恢复 26 个基址加载候选、30 个去重写入候选；其主要 RCC 库代码已重定位至 `0x08024xxx` 和 `0x080262xx`，ROM 共同辅助函数保留原地址。完整逐项 PC 列表存放在 [CI JSON 工件](https://github.com/Iu-yang1/Baofeng-5RHPRO-RE/actions) 中，可重新生成。

本轮保留上次 [PR #14 的已验证直接 BL 索引](v2-0-09-pll-runtime-order-peripherals.zh-CN.md)，未发现新的标准 RCC 辅助函数运行态调用；**但这项结论严格限于已识别的标准函数入口及直线常量传播，不是全程序 MMIO 写入完备证明**。

## 3. 下阶段需解决的具体问题

- **ROM 本体缺失：** `0x1FFFD00C` 仅是系统 ROM 函数表项；原厂镜像不提供目标函数机器码。无法在不取得 ROM 实现的前提下证明 Flash wait state、隐藏 PLL 配置、最终时钟状态。
- **数据流缺口：** 应进一步建立整函数 CFG 和跨基本块的寄存器/堆栈常量传播，检查 `MOVW/MOVT` 组合地址、全局 RAM 中转及 `STR/STRH/STRB` 的 RCC 别名目标。当前已完成的是优先级高、错误率低的局部扫描，不能对全镜像改频做绝对排除。
- **型号判定：** UID 判定值尚不能解释为商业 MCU 型号；尤其不能依据 SDK 代码就选择规格与固件资源不匹配的 AIR32F103RPT6 linker script。

## 4. 可复现验收

```sh
python -m pip install "capstone==5.0.6"
python -m unittest discover -s tests -v
python tools/v2_rom_cfgr_mmio_audit.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --json
python tools/v2_rom_cfgr_mmio_audit.py firmware/BF_5RH_501_v2_0_9.dat --v1 firmware/BF_5RH_501_v1_1_04.dat --show-writes
```

新测试用原厂真实指令验证所有关键位运算、ROM 参数和 V1/V2 共享字节；再人为修改 CFGR 掩码和 `STR` 指令，要求工具拒绝。扫描路径独立保留 V1/V2 数据，不生成固件、不连接硬件。也不把通过主机测试等同实测时钟或芯片身份。

参考：<https://wiki-zh.luatos.org/chips/air32f103/enhancement.html>（AIR32 高速 PLL 官方文档）、[之前 AIR32 SDK 指纹研究](v2-0-09-air32-sdk-fingerprint.zh-CN.md)。
