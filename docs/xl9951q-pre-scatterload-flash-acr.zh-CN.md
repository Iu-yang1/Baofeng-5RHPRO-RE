# XL9951Q / UV-5RH Pro：Reset → ARM scatterload 前的 RCC、Flash ACR 和 VTOR 审计

日期：2026-11-16。原厂 V1.1.04 与 V2.0.09 纯软件静态取证。只读取仓库存档的原厂升级包并解析 Thumb 指令，**不连接电台、不进行串口通信、不擦写 Flash、不使用调试器**。

## 1. 纠正上一轮仍未细分的 Flash 初始化结论

先前 [高 Flash 地址和应用阶段 QSPI 解锁报告](xl9951q-boot-high-flash-vs-qspi-audit.zh-CN.md) 已验证：应用主入口调用的 `0x08001260` AIR32 样式 QSPI/ROM helper **晚于** ARM scatterload，不能单独解释在读取 `0x08061A54` 之前已经建立的存储映射。本轮继续沿 Reset 前置时钟初始化函数向下检查，发现：

**V1/V2 在 scatterload 之前实际写过 Flash 控制寄存器的基址 `0x40022000`；其指令是预取及访问等待周期配置，而不是已经证实的外部 NOR 映射。**

这是比“启动前没碰过 Flash”更严格、也更准确的说法。

## 2. 两版原厂完全相同的早期时钟初始化函数

| 验证项 | V1.1.04 | V2.0.09 |
| --- | --- | --- |
| Reset 阶段 RCC 包装函数 | `0x080262A8` | `0x080323DC` |
| 包装函数对时钟函数的 BL | `0x080262DA` | `0x0803240E` |
| 早期时钟函数 | `0x08025B80` | `0x08031BF4` |
| 时钟函数及文字池对比 | **168/168 B 完全相同** | **168/168 B 完全相同** |
| 时钟函数 PC-relative 基址文字池 | `0x40021000`, `0x40022000` | `0x40021000`, `0x40022000` |
| Reset 包装函数的中断向量表写入 | `0xE000ED08 ← 0x08000000` | `0xE000ED08 ← 0x08000000` |

代码和 literal pool 对比范围：

- V1 `0x08025B80..0x08025C27`，连续 **168 B**；
- V2 `0x08031BF4..0x08031C9B`，连续 **168 B**。

该窗口的前 160 B 作为 Thumb 指令线性反汇编，后 8 B 为两个 32-bit PC 相对文字池常量。函数自身未发现其他直接 `BL/BLX`，Reset 包装函数的限定范围内也只有通往早期时钟函数的一处 `BL`。两版 *完全相同的机器码* 是可靠的固件代码谱系证据，但并不指认使用了同一颗物理芯片。

## 3. 早期 Flash ACR 写入的指令级证据

两版函数的代码相对偏移相同：

| 相对函数基址 | Thumb 指令 | 静态数据流解释 |
| --- | --- | --- |
| `+0x04` | `LDR R0, [PC, #0x98]` | 载入 `0x40021000`（RCC/CRM） |
| `+0x38` | `LDR R1, [PC, #0x68]` | 载入 `0x40022000`（Flash 控制器基址） |
| `+0x3A` | `LDR R2, [R1]` | 读取 Flash 访问控制寄存器 |
| `+0x3C` | `ORR R2, R2, #0x10` | 设置 bit4（兼容实现为预取使能） |
| `+0x40` | `STR R2, [R1]` | 写回 Flash ACR |
| `+0x44` | `BIC R2, R2, #3` | 清除 bit1:0（**没有清 bit2**） |
| `+0x48` | `STR R2, [R1]` | 写回 Flash ACR |
| `+0x4C` | `ORR R2, R2, #2` | 将 bit1 设置为 1 |
| `+0x50` | `STR R2, [R1]` | 写回 Flash ACR |

对照 ST 官方 [STM32F10x RM0008 参考手册](https://www.st.com/resource/en/reference_manual/cd00171190.pdf) 的 FLASH_ACR 寄存器章节，`0x40022000` 是 FLASH ACR，在这一兼容布局中 bit4 是 PRFTBE，bit2:0 是 LATENCY 字段。**如果在本函数之前 bit2 为 0**，经上述 `BIC #3; ORR #2` 后 LATENCY[2:0] 为 `010`，对应 2 个等待周期；若 bit2 此前被改变，这几条指令并没有独立保证 LATENCY 最终等于 `010`。由于 XL9951Q 数据手册不公开，寄存器语义及上电初态只能作为兼容族模型，不能当作芯片物理测量。

这段代码明显区别于应用主入口之后才使用的 `0x4002228C`，后者在合宙 AIR32 SDK 中被标注为 QSPI 解锁 / 重新锁定；**两个地址与两种用途不应混为一谈**。

## 4. 可以排除什么，不能排除什么

**在代码可见范围内已确认：**

- Reset veneer 先调用 RCC/Flash 访问控制初始化函数，再进入 ARM scatterload；两版行为结构一致；
- 早期时钟函数的两个 PC 相对寄存器基址是 `0x40021000`、`0x40022000`，并针对后一地址完成预取及延时配置；
- 可见的 Reset 包装函数还写了 VTOR `0xE000ED08`，值为 `0x08000000`；这个向量表设置并不是“外部 SPI NOR 的 XIP 映射”；
- 在上述两个限定函数内未找到独立的外置 NOR SPI/QSPI memory-mapped 初始化调用或 `0x4002228C` 文字池引用。

**不能声称已经排除：**

- XL9951Q 的掩膜 ROM 或厂商启动器在应用 Reset 入口之前已预先映射 Flash；
- 未公开的寄存器别名、内部 SRAM/Flash 配置或 OEM 私有功能；
- GT25Q16A 在应用运行时被用于语音、配置、资源数据或其他用途；
- CPU 实际芯片是否有 512 KiB 片内 Flash、真实晶圆厂及商业型号。

尤其要区分可见固件“**写入了某个控制寄存器**”与真实硬件“**接受并执行了该寄存器操作**”。此次只验证前者。

这也没有改变上一轮对 V2 scatterload 已消耗压缩字节范围 `0x08061A54..0x08062AEA` 的结果：若是直接线性程序空间映射，至少需要 **395 KiB 的 CPU 可读窗口**。

## 5. 实现及回归

新增 `tools/xl9951q_pre_scatterload_flash_acr.py` 和 `tests/test_xl9951q_pre_scatterload_flash_acr.py`：在原厂二进制数据上验证 Reset→main 路径、BL 目标、完整 168 字节函数、两个文字池、Flash ACR 指令序列、VTOR 写入。负面测试会修改 Flash literal、实际 STR 指令、VTOR literal 及 V1/V2 不同字节以确保回归检测可捕获偏差。

```sh
python -m pip install "capstone==5.0.6"
python tools/xl9951q_pre_scatterload_flash_acr.py --json
python -m unittest discover -s tests -v
```

CI 将证据报告保存为 `xl9951q-reset-flash-acr.json`，与此前 `xl9951q-pre-scatterload-flash-evidence.json` 分开，避免将已知上电前 Flash 时序配置和未证实的外部 Flash 映射混为一谈。

研究顺序上，下一步可专门分析**厂商 Bootloader/固件升级协议自身**是否含有存储类型识别、Flash 页大小及擦除算法信息。它可能限制可见 Flash 空间、OEM 兼容型号和恢复方式，但在没有厂家 ROM 的情况下仍无法从原厂应用固件唯一恢复晶圆来源。
