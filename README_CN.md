# ASUS BIOS Theme Patcher

`patch_asus_theme.py` 用于把一份华硕 BIOS 中的界面主题迁移到另一份华硕 BIOS 中。修改时会以目标 BIOS 为底子，只替换主题相关的内容，其余的硬件初始化代码、AGESA、微码等都会原封不动地保留下来。

整个脚本实际上只处理以下三个部分，其他地方完全不作改动：

| 内容 | GUID | 处理方式 |
| --- | --- | --- |
| AMITSE 界面属性与颜色 | `B1DA0ADF-4F77-4070-A88E-BFFE1C60529A` | 解析代码与主题表，仅安全迁移匹配的颜色属性 |
| 启动 Logo | `7BB28B99-61BB-11D5-9A5D-0090273FC14D` | 按 GUID 完整替换原始数据块 (Raw section) |
| 主题素材 | `CC5840D2-D8EA-459E-BAF4-349AC710EBBE` | 按 GUID 完整替换原始数据块 (Raw section) |

> [!WARNING]
> 修改华硕 `.CAP` 固件会导致官方的 Capsule 签名失效！生成成功仅代表文件结构修改正确，实际刷入时主板的安全校验机制不一定会直接接受它（在 X870E-E 上测试 USB FlashBack 可以直接刷入）。刷写前请务必备份好原厂 SPI 固件并准备好可靠的编程器恢复方案。

## 适用范围

本脚本适用于结构相近的华硕 AMI/AMITSE BIOS（例如同一平台或相关型号之间的主题迁移）。

它不是通用的 BIOS 修改工具，遇到以下情况时会主动报错并停止，不会强行盲改：
- 非华硕 BIOS；
- 主题系统被大幅重写过的版本；
- 无法被 UEFIExtract/UEFIReplace 正常处理的固件。

## 环境要求

- Python 3.10 或更高版本；
- `UEFIExtract` 和 `UEFIReplace`（Windows 版本的程序已包含在仓库中，在仓库目录下运行无需额外指定）。

## 快速使用

运行命令时，第一个参数是主题来源，第二个参数是作为修改底子的目标 BIOS：

```
source_bios = 提供颜色、Logo 和主题素材的来源 BIOS
target_bios = 作为修改底子的目标 BIOS（保留其原本的所有平台功能）
```

建议按照以下步骤进行操作：

### 1. 仅分析（检查匹配率）
```
python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET.CAP" --analyze
```
该模式仅提取并分析两边 BIOS 的主题表 and 匹配率，输出统计结果，**不会生成或修改任何文件**。你可以通过它确认两边的结构是否足够接近。

### 2. 试运行 (Dry run)
```
python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET.CAP" --dry-run
```
计算完整的补丁数据并统计颜色记录，但同样**不会写出文件**。

### 3. 正式生成主题 BIOS
```
python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET.CAP" -o "ASUS_TARGET_MIKU.CAP"
```
如果不指定 `-o` 参数，默认会输出为 `ASUS_TARGET_patched.CAP`。

---

## 示例：从 X870E-H-MIKU-EDITION 2103 迁移到 X870E-E 2103

```
python patch_asus_theme.py `
  "ROG-STRIX-X870E-H-GAMING-WIFI7-S-HATSUNE-MIKU-EDITION-ASUS-2103.CAP" `
  "ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-2103.CAP"
```
验证样本的理想分析输出如下：
```
Source theme tables: 1560, records=15237
Target theme tables: 1560, records=15237
Exact table matches: 1560/1560 (100.00%)
Patched color records: 1464
```

---

## 命令行参数说明

| 选项 | 说明 |
| --- | --- |
| `source_bios` | 主题来源 BIOS 路径 |
| `target_bios` | 作为修改底子的目标 BIOS 路径 |
| `-o`, `--output` | 输出的 BIOS 文件路径 |
| `--uefiextract PATH` | 显式指定 UEFIExtract 的程序路径 |
| `--uefireplace PATH` | 显式指定 UEFIReplace 的程序路径 |
| `--analyze` | 仅分析并打印未匹配的主题表，不写文件 |
| `--dry-run` | 计算补丁并统计，不写文件 |
| `--verbose` | 详细模式，打印具体匹配的表和每一条修改的颜色 |
| `--show-tool-output` | 不过滤 UEFIExtract/UEFIReplace 的原始输出日志 |
| `--min-block-coverage N` | 最低表匹配率门槛，默认 `0.70` |
| `--color-key KEY` | 将额外的 4 字节属性视为颜色（高级选项，可重复使用） |
| `--loose` | 放宽 ThemeRecord payload 尾部零填充的校验规则（高级选项） |

> [!NOTE]
> **专家选项注意事项**
> - `--color-key` 只接受两边固件代码都定义为 4 字节 payload 的属性，主要用于处理某些已确认但没有被 `type 4` 标记的特殊颜色 key，切勿用于强制复制未知的布局或几何属性。
> - `--loose` 只放宽 payload 尾部填充规则，不会绕过 PE、代码签名或表结构匹配，除非已经分析过目标版本，否则不建议使用它来强行提高匹配数量。
> - 降低 `--min-block-coverage` 只会放宽最终的安全匹配门槛，低匹配率通常意味着来源和目标版本差异过大，应先通过分析确认原因，而不是继续降低阈值。

---

## 实现原理

### 1. 从特征码恢复属性类型表
脚本在 AMITSE PE 模块的 `.text` 段内搜索稳定的机器码特征：
```
48 8D 47 04 39 18
```
对应的底层汇编逻辑为：
```
lea rax, [rdi + 4]
cmp dword ptr [rax], ebx
```
函数随后会读取 `ThemeRecord` 的 Key 并将其归一化，在类型表中获取对应的属性类型（`0..11`），再通过一项包含 12 个分支的 dispatch table 进入相应的转换路径。脚本通过解析邻近指令动态定位类型表和分派表的 RVA，从而规避了对固定文件偏移的依赖。

### 2. 属性类型与 Payload 长度分派
不同属性类型对应的有效 Payload 长度映射如下：

| 属性类型 | 有效长度 | 说明 |
| --- | ---: | --- |
| `0`, `1`, `2`, `3`, `4` | 4 字节 | **Type 4** 为主题颜色 Key（使用 `AARRGGBB` 格式） |
| `5` | 16 字节 | 几何/布局等属性 |
| `6` | 1 字节 | 布尔/单字节标志 |
| `7` | 16 字节 | 其它复合属性 |
| `8` | 8 字节 | 双字/长整数属性 |
| `9`, `10` | 2 字节 | 短整数属性 |
| `11` | 16 字节 | 特殊类型（允许扫描，但不作为颜色修改） |

脚本依据从代码中动态恢复的类型表，精准筛选出所有 `Type 4` 的记录进行迁移，不依赖任何硬编码的颜色值或盲目猜测。

### 3. 颜色记录的小端序表示说明
AMITSE/Skia 内部使用标准的 `AARRGGBB` 整数格式来管理颜色。在 x86 架构的小端序内存中，4 字节的颜色值显示为倒序：
```
BB GG RR AA
```
因此，在详细日志或修改提示中输出的 `CE E2 13 CC` 对应的实际通道为：
- **A** (Alpha) = `CC`
- **R** (Red) = `13`
- **G** (Green) = `E2`
- **B** (Blue) = `CE`

输出的 `Patched color records` 是被成功替换的 ThemeRecord 数量，而不是实际变化的字节总数。

### 4. ThemeRecord 结构与表边界判定
AMITSE 的主题记录在内存中以 `0x18` 字节的大小对齐，其 C 语言结构体定义如下：
```
struct ThemeRecord {
    uint32_t Group;
    uint32_t Key;
    uint8_t  Payload[16];
};
```
一张完整的主题表在 `.data` 节中具有如下边界结构：
```
ThemeRecord records[] = {
    {same_group, key_a, payload_a},
    {same_group, key_b, payload_b},
    // ...
    {same_group, 0, {0}}, // 终止项
};
```
扫描器通过严格匹配同 `Group` 且 `Key=0`、Payload 全零的终止项来准确划分各主题表边界，避免相邻表被错误合并。

### 5. 严格的表级匹配与安全写入
- **对齐与签名**：来源与目标表首先通过全局 Key 序列进行对齐，再根据 `(Group, complete key sequence)` 签名进行匹配。
- **局部覆盖**：只有在两边主题表精确匹配且局部索引一致时，脚本才会将来源记录的颜色覆盖到目标的 `Payload[0:4]` 中。Group ID、Key ID 以及表终止项均保持目标原值，绝不强行进行高风险的偏移拷贝。

---

## 生成后验证

为了安全起见，建议在刷写前执行以下验证：

1. 记录来源、目标以及生成文件的 SHA-256 哈希值；
2. 以生成的 BIOS 作为目标，再次运行分析命令：
   ```
   python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET_MIKU.CAP" --analyze
   ```
   如果迁移完全成功，此时输出的 `Patched color records` 应当为 `0`。

## 常见问题

### 为什么刷写时提示 Capsule 签名错误？
华硕官方固件带有私钥签名，脚本修改内容后 Capsule 签名必然失效。请使用支持忽略签名的刷写方式（如主板自带的 USB FlashBack 或编程器）。

### 为什么匹配率不是 100%？
不同型号或版本的 BIOS 可能会增删部分菜单控件。对于结构无法对齐的主题表，脚本会选择安全忽略并保持目标 BIOS 默认的样式来保证安全。

### 可以直接修改备份出来的 `.rom` 或 `.bin` 文件吗？
不可以。直接从主板 Dump 出来的 SPI 完整备份包含了 Capsule 卷之外的数据。脚本为了安全，对此类文件仅允许执行 `--analyze` 或 `--dry-run`，拒绝执行正式的 GUID 替换写入。

## 免责声明

修改和刷写主板 BIOS 存在极高的风险，可能导致设备无法启动、数据丢失、保修失效或硬件损坏。本项目及脚本仅用于生成修改后的固件文件，不对刷写结果及任何硬件损伤承担责任。所有操作风险由使用者自行承担。