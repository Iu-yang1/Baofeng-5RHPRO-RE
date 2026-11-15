# UV-5RH Pro V2.0.09 主板芯片丝印清单（用户现场读取）

记录日期：2026-11-15。对象：BAOFENG UV-5RH Pro，用户设备菜单报告“固件 v2_0_09、软件 v1_1_04”。

**证据类型：用户提供的人工抄录丝印（可能存在 0/O、1/I/L、8/B、A/8 等误读）。尚未获得照片、芯片封装引脚数、PCB 修订号或实机调试读取。任何候选型号均不得直接用于生成 MCU PAC、链接脚本和硬件驱动引脚表。**

## 一、原样丝印与器件识别

| 用户原样丝印（不要更改） | 当前识别 | 证据等级 | 具体后续确认 |
| --- | --- | --- | --- |
| `FD6818 CS4055XA` | **FD6818** 双向模拟通信射频收发 IC；`CS4055XA` 未验证是否批次/制造代码 | 高：器件主型号明确 | 确认 RFIC 外观与 `REG 0x00` 只读 ID；不要默认 FD6818B/BK4829 寄存器兼容 |
| `S16A-UGL I` | **未知**。不能确认是否 MCU、Flash、驱动或其他功能器件 | 未识别 | 芯片实拍、封装、各边引脚数、Pin 1、晶振/SWD/存储器走线关系 |
| `XL9951Q 2404CJW` | **未知**。后段可能为日期/批次标记，但未经厂商编码规则验证 | 未识别 | 芯片实拍、封装和丝印、附近元件及 PCB 位置 |
| `ATGM336H` | **中科微 ATGM336H GNSS 系列**，子型号可能为 5N 或 6N，不能单凭主型号判断代际与接口默认配置 | 高：系列型号明确 | 读取屏蔽模块完整侧面/表面版本，UART NMEA 原始数据、上电电压、PPS |
| `HTL7G06S011P ETRE0057 2433-JY`（2 片） | **HOLTO HTL7G06S011P** 离散 VHF/UHF RF LDMOS，标称 11 W 饱和功率测试条件；**不是整机承诺输出功率** | 高：主料号匹配 | 分别沿输出低通/带通滤波器确定 VHF/UHF 分工、PA bias 与前级控制；不要把 2433-JY 直接认成硬件版本号 |
| `5807M TN550` | 高概率为 **RDA5807M** FM 广播接收 IC（与 FD6818 的双向通信收发链路不同） | 较高 | 核对 10 脚封装，`SCLK/SDIO` 总线、晶振/时钟及广播天线连接 |
| `TDA2B22 DAWV40` | 低至中等可信的**音频功放**候选：可能存在 `8/B` 误读，需核对 `TDA2822A` / `TDA2822M`；不能宣称已确定 | 中低 | 先查封装 8/16 脚与扬声器输出走线，再与厂商引脚表比对；原字样不替换 |
| `3PEAK LM29048` | 高概率为 **3PEAK LM2904A** 双运算放大器（`A/8` 易混淆），LM2904B 亦仅作为需要验证的字符变体 | 中等 | 观察丝印最后字符，8 脚封装；测量输入、输出到麦克风/AF/PA 检波电路的连接 |

## 二、已核对的器件资料

1. **FD6818 Programming Guide**（非 V2 专用原厂芯片采购记录）：https://www.glaver.org/blog/UV-17/FD6818.pdf
2. **HTL7G06S011P Rev.1.8**，7.2 V 漏极、1.8–600 MHz，测试点 136–174 与 400–470 MHz 额定 11 W 饱和输出：https://file01.andesource.com/dkpdf/HTL7G06S011P_Product_datasheet_rev1.8.pdf
3. **ATGM336H-5N 用户手册**（AT6558，具体子型号/默认波特率依变体）：https://www.tinytronics.nl/product_files/002176_ATGM336H.pdf
4. **ATGM336H-6N 用户手册**（AT6668，部分变体 115200 bps）：https://datasheet.lcsc.com/lcsc/2401121833_ZHONGKEWEI-ATGM336H-6N-74_C5804601.pdf
5. **RDA5807M datasheet**，FM 广播调谐器，SCLK/SDIO 串行控制：https://datasheet.lcsc.com/lcsc/1810010217_RDA-Microelectronics-RDA5807M_C82537.pdf
6. **3PEAK LM2904A 官方型号页**：https://www.3peak.com/high-voltage-op-amps/lm2904a
7. **3PEAK LM2904A/LM2902A 数据手册**：https://static.3peak.com/res/doc/ds/Datasheet_LM2904A-LM2902A.pdf
8. **ST TDA2822M（8 脚）**：https://www.st.com/content/ccc/resource/technical/document/datasheet/9e/18/f7/cd/2e/b8/43/62/CD00000134.pdf/files/CD00000134.pdf/jcr%3Acontent/translations/en.CD00000134.pdf
9. **ST TDA2822（16 脚）**：https://www.st.com/resource/en/datasheet/tda2822.pdf
10. **早期 Pro 拆机参考**，该例中的器件识别与用户 V2 板不应混淆：https://github.com/amoxu/Baofeng-UV-5RM-5RH-RE/issues/10

## 三、对固件开发的直接影响

- **FD6818**：RFIC 识别明显前进一步。后续以该寄存器族对照 `RF state`、`PLL`、`RSSI`、`CTCSS/DCS`，但校准参数、RF 前端、实际 GPIO 仍是 V2 专有工作。
- **两颗 HTL7G06S011P**：射频前端较可能有分立 VHF/UHF PA 链路。软件应将 `TX path`、`PA bias` 和功率档位校准分别建模，不能把芯片 11 W Psat 当作整机稳定发射功率。
- **ATGM336H**：可建立对 GNSS `NMEA` 的协议兼容驱动接口；具体 UART 引脚、波特率、PPS 与子型号需要追踪固件/实机。这条线索**替代早期外部拆机帖子中“可能为 Wintec”这一不适用于用户板卡的假设**。
- **RDA5807M**：可建立独立 FM 广播服务及 I2C-like 两线总线接口；不得混入 FD6818 的业务 RF 控制器。
- **TDA / 3PEAK**：暂按音频功放与模拟小信号调理候选研究；不支持直接推断音频输入、扬声器开关、PTT 或 AFSK 注入 GPIO。
- **主 MCU**：`S16A-UGL I`、`XL9951Q` 未获得可靠型号匹配。两者可能是完整料号、OEM 内部标记或批次/封装代号，**不能仅凭猜测选定 MCU**。此前 V2 反汇编显示 ARMv7-M 兼容 Thumb-2 指令以及 F1/AT32F403A 风格寄存器布局，但仍是代码线索而不是丝印识别结果。

## 四、下轮最有价值的信息

优先拍摄：主板正反面全貌、`S16A-UGL I` 和 `XL9951Q 2404CJW` 的**正面垂直近照**，包含完整封装边缘、引脚和 Pin 1；标注芯片位于主板哪一侧及附近晶振。其次拍摄 `TDA2B22` 与 `3PEAK LM29048`，并数脚（8 脚、16 脚等）。这样通常可以识别是否存在 48/64/100 引脚 MCU，与 8 脚音频、Flash、稳压器区分。

如果可接受非破坏性测量，优先查最大 MCU 附近的 SWD test pads、串口 UART、外部 SPI Flash，以及 RFIC 控制三线；电台上电测量前应确认地线和 3.3 V 逻辑电平。没有连接图或器件型号前，不进行 Flash 擦写、读保护解除或盲目 GPIO 试探。

## 五、结论

**目前明确的不是“MCU 已确定”，而是主要业务外围器件已获得多项可靠型号依据。** 后续 MCU 判断仍需封装照片/厂商设备 ID 与 V2.0.09 原厂镜像寄存器指纹交叉验证。所有抄录字符串保留原样，以便纠错追踪。
