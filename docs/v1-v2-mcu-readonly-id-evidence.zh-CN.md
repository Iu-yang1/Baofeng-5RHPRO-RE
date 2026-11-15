# UV-5RH Pro：AIR32 / AT32 / 其他 STM32F1 兼容 MCU 的只读身份鉴别

日期：2026-11-15。依据合宙《从 SXX32F103 移植》官方文档、雅特力 AT32F403A/407 手册与 AN0023、Arm/ST 的 Cortex 内核手册，并对仓库原厂 V1.1.04 / V2.0.09 做了离线字面量引用核对。**这不是实机寄存器读回，也没有进行任何 SWD、JTAG、ISP 或 Flash 操作。**

## 1. 四组电子身份的精确定义

| 数据 | 读取方式和宽度 | 官方解释 | 区分能力 |
| --- | --- | --- | --- |
| AIR32 UID0 | CPU 地址 `0x1FFFF7E8`，32-bit | 合宙公开 AIR32 型号模式（后 4 bit 为通配位） | **可增强 AIR32 兼容体系证据**，但不证明芯片生产者、Flash 实际容量 |
| Flash F_SIZE | CPU 地址 `0x1FFFF7E0`，**16-bit** | ST/Artery F_SIZE 的低 16 位，单位 KiB | 可检查软件申报容量与原厂高 Flash 地址是否矛盾，不直接判厂家 |
| ARM CPUID | CPU 地址 `0xE000ED00`，32-bit | PARTNO: `0xC23` Cortex-M3，`0xC24` Cortex-M4 | 用来与候选芯片公开内核型号交叉比对，不包含 MCU 品牌 |
| SW-DP DPIDR | **SWD Debug Port** 寄存器读取，不是 CPU `mem32` 地址 | 常见 `0x2BA01477` 指向 Arm 调试端口组件 | 确定 DP 类型/通信，**不是 MCU 制造商或芯片型号** |
| Artery DEBUG_IDCODE | CPU 地址 `0xE0042000`，32-bit | AT32F403A/407 官方 PID 型号表 | 完整 32 位 PID 与 Project ID 一致时可高可信定位公开型号 |
| Artery Project ID | CPU 地址 `0x1FFFF7F3`，**8-bit** | UID[95:88]，AT32F403A=`0x07`、AT32F407/407A=`0x08` | 与 DEBUG_IDCODE 结合比单独 UID0 更有鉴别力 |

**修正早期表述：**“`0x1FFFF7E8` 的最高字节不能作任何型号 ID”只对特定厂商的布局成立。AT32 的 Series ID 在 UID[95:88]（`0x1FFFF7F3`）；**合宙明确将 UID[31:0] 的高位模式用于 AIR32F103 型号判别**。因此原厂固件比较 UID0[31:24] 与 `0x1A/0x1B/0x1C` 具有实质信息；**但被比较的实机值完全未知**，0x1B/0x1C 在合宙公开表内尚没有可证的型号对照。

### AIR32 官方 UID0 型号模式

| UID0 格式（X=末位任意十六进制数） | 合宙对应型号 |
| --- | --- |
| `0x1A5A5BBX` | AIR32F103CBT6 |
| `0x1A5A5CCX` | AIR32F103CCT6 |
| `0x1A6A5CDX` | AIR32F103RPT6 |
| `0x1A8A6DDX` | AIR32F103VET6 |
| `0x1A8A6EDX` | AIR32F103VGT6 |
| `0x1A9A6DDX` | AIR32F103ZET6 |

参见 [合宙官方迁移指南](https://wiki.luatos.com/chips/air32f103/switchFromSxx.html)、[AIR32F103 用户手册](https://c.vue2.cn/attachment/20230907152950811_Air32F103xx_User_Manual_CN-%E5%B8%A6%E7%9B%AE%E5%BD%95%E4%B9%A6%E7%AD%BE.pdf)。

### AT32F403A / AT32F407 典型 PID（均为 LQFP64）

| DEBUG_IDCODE | Project ID | 型号 | 公开 Flash |
| --- | --- | --- | --- |
| `0x700502CE` | `0x07` | AT32F403ARET7 | 512 KiB |
| `0x70050345` | `0x07` | AT32F403ARGT7 | 1024 KiB |
| `0x700502D2` | `0x08` | AT32F407RET7 | 512 KiB |
| `0x7005034C` | `0x08` | AT32F407RGT7 | 1024 KiB |

以上四条来自 [AT32F403A/407 官方参考手册 V2.02，第 486 页 DEBUG_IDCODE 完整型号表](https://static.chipdip.ru/lib/639/DOC046639644.pdf)。[雅特力 AN0023，第 23 页](https://cdn.promelec.ru/upload/items/2022/10/03/AT32F403A%26AT32F407_Get_started_guide_EN_V1.0.1.pdf) 同时确认 `0x1FFFF7F3` Project ID 和 `0xE0042000` PID 的组合识别法。四个 PID 是**正向识别列表**，不等于没有命中就能排除整个雅特力家族。

## 2. 当前原厂固件能够证明什么

现有 `tools/v2_mcu_identity_xrefs.py` 对 V1/V2 原厂 XOR 解码镜像分别扫描 Thumb PC 相对 `LDR` 字面量引用。测试中必须通过：

1. 两版 `0x080012A2` 都有指向 `0x1FFFF7E8` 的 Thumb 字面量加载候选；对应 `0x080012A4` 从该地址加载 UID0 并比较 `0x1A`、`0x1B`、`0x1C`；
2. 两版并无 `0xE0042000` 和 `0x1FFFF7F3` 的**对齐原始字面量**；目前不能证明原厂程序以这种直接方法查询 AT32 PID / Project ID；
### V1/V2 本轮 CI 实测的直接字面量引用计数

| 识别用地址 | V1.1.04 对齐文字池数 / Thumb LDR 候选 | V2.0.09 对齐文字池数 / Thumb LDR 候选 |
| --- | --- | --- |
| `0x1FFFF7E8` UID0 | **1 / 1**（`0x080012A2`） | **1 / 1**（`0x080012A2`） |
| `0x1FFFF7E0` F_SIZE | 0 / 0 | 0 / 0 |
| `0xE000ED00` ARM CPUID | 0 / 0 | 0 / 0 |
| `0xE0042000` DEBUG_IDCODE | 0 / 0 | 0 / 0 |
| `0x1FFFF7F3` AT32 Project ID | 0 / 0 | 0 / 0 |
| `0x1FFFF7EC`、`0x1FFFF7F0` UID 中高字 | 各 0 / 0 | 各 0 / 0 |

该证据来自只读离线脚本，并非实机寄存器值。无法据此证明不存在寄存器组合地址、跨函数参数、间接指针或系统 ROM 内访问。

3. 软件不能通过把 `0xE000ED00` 或 `0x1FFFF7E0` 作为常量写进报告，推导任何实机 CPUID / F_SIZE 数值；若无直接字面量，仍可能有其他地址构造或 ROM 内部代码；
4. `0x08061A54` 是原厂 scatterload 已验证的高地址读取位置，`0x08061A54-0x08000000=0x61A54`，从 0x08000000 起要求至少 391 KiB 的连续可读程序窗口。**这不单独证明内部 Flash 就是 512 KiB**：需另外排除别名和映射机制。

工具不会保存或公开来自设备的完整 96-bit 唯一 UID。仓库中固件固有的 `0x1FFFF7E8` 是**地址**，并非从实机读取出的序列号。

## 3. 两类候选的交叉证据

| 假设 | 更有利证据 | 仍待解释 |
| --- | --- | --- |
| **AIR32/MH32 软件同源系列、OEM 定制版** | UID0 0x1A 模式检测和特有 ROM `0x1FFFD00C` 回调、三级系统键、`0x4002228C` 解锁与恢复序列完全吻合官方 AIR32 SDK | 标准 AIR32F103RPT6 公开只有 **256 KiB Flash**，不直接满足程序高地址；厂商/定制容量无实物证据 |
| **标准 AT32F403A/407** | LQFP64、512 KiB/1024 KiB 内部 Flash、至少 96 KiB SRAM、M4F；官方给出可检测的 PID/Project ID | AIR32 专用隐藏寄存器/ROM 接口无公开 AT32 同语义证据；原厂未直接引用 AT32 PID 常量 |
| **其他 STM32F1 兼容 MCU（GD/HK/APM 等）** | 存在满足程序空间和 SRAM 条件的商业型号，部分是 Cortex-M3 | 尚无明确的供应商 UID/ROM 魔数对照，不能凭容量直接确认 |

CPUID 可能提供强排除条件：`0xC23` 与公开 AT32F403A/407 的 Cortex-M4F 不一致；`0xC24` 与公开 AIR32F103 的 Cortex-M3 不一致。**单独的 CPUID 却不应被解释为“ST 芯片”或“AT 芯片”**。

## 4. 用户未来获取只读读回时的核对顺序

连接 SWD 后先在调试器日志查看 SW-DP IDCODE/DPIDR（这是 **DP 级**访问，不应使用 `mem32 0x2BA01477`）。若读写保护不允许，则如实记录状态，不对保护位操作。

获得芯片 AP 内存访问权限后，仅使用以下只读命令作为参考（具体格式以调试器为准，如 J-Link Commander）：

```text
mem32 0xE000ED00 1     ; ARM CPUID
mem16 0x1FFFF7E0 1     ; F_SIZE, 单位 KiB
mem32 0xE0042000 1     ; MCU DEBUG_IDCODE，不是 DPIDR
mem8  0x1FFFF7F3 1     ; Artery Project ID（如果适用）
```

可选的 `mem32 0x1FFFF7E8 1` 可能返回唯一 ID 的一部分，**无需公开完整值**。要检查 AIR32 公开模式，可仅保留匹配型号，不上传原值。部分芯片具有调试读保护/特殊 ROM 行为；地址无法访问时停止该项，不尝试解锁或解除保护。**禁止执行任何写保护设置、擦除或刷写命令**。

### 离线解析命令（只是示例，未读取实机）

```sh
python tools/mcu_readonly_id_evidence.py --cpuid 0x410FC241 \
  --flash-size-halfword 0x0200 \
  --debug-id 0x700502CE --project-byte 0x07 --dpidr 0x2BA01477
```

解析器提供条件性候选及不一致提示；如果额外提供 `--uid-first-word`，**不会在 JSON 里回显完整 UID0 数值**。具体的芯片 UID 不应上传公开 CI 日志。

## 2026-11-15：进一步补充真实读取指令的控制流证据

参见 [UID/CPUID/F_SIZE/PID 指令级读取审计](v1-v2-mcu-id-cfg-reads.zh-CN.md)：V1/V2 经跨基本块 Thumb 数据流扫描，均检测到 7 个身份地址附近的 PC 相对字面量候选，但**仅 1 个可解析为身份寄存器读取指令**，即原厂 ROM 辅助函数中 `0x080012A4 LDR R6,[R0]` 读取 `0x1FFFF7E8` 的 UID0。其余六个候选属于 ARM SCB 的 `VTOR(0xE000ED08)`、`AIRCR(0xE000ED0C)`、`SCR(0xE000ED10)`，**不是 ARM CPUID**。本轮未找到其他四组 ID 的静态读指令，但算法并不覆盖全部间接地址与 ROM 路径，不能据此认定实机型号。

## 5. 验收和未解决问题

测试验证 6 个 AIR32 UID 模式及末位通配符、公开 AT32 PID、CPUID M3/M4、Flash 报告值与 391 KiB 窗口约束、DPIDR（Arm 组件而非厂家）、互相矛盾的证据和原厂 V1/V2 字面量引用。CI 只运行原厂静态扫描与人工构造的示例数值，绝不连接调试器。

**尚无实机 CPUID、F_SIZE、DEBUG_IDCODE、Project ID、DPIDR 或 UID 的任何读回**，不能宣布物理芯片身份已确定。下个研究动作应优先获取这些只读标识，或用全镜像数据流进一步追踪间接生成的识别地址；不因缺失实机测试而停止已经可离线验证的软件分析。
