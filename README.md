# ASUS BIOS Theme Patcher

[简体中文](README_CN.md)

`patch_asus_theme.py` is used to migrate an interface theme from one ASUS BIOS to another. The modification uses the target BIOS as the base, replacing only theme-related content. The remaining hardware initialization code, AGESA, microcode, etc., will be kept completely intact.

The script actually processes only the following three parts, leaving other areas completely untouched:

| Content | GUID | Processing Method |
| --- | --- | --- |
| AMITSE interface attributes and colors | `B1DA0ADF-4F77-4070-A88E-BFFE1C60529A` | Parses code and theme tables, safely migrating only matching color attributes |
| Boot Logo | `7BB28B99-61BB-11D5-9A5D-0090273FC14D` | Completely replaces the raw data block (Raw section) by GUID |
| Theme Assets | `CC5840D2-D8EA-459E-BAF4-349AC710EBBE` | Completely replaces the raw data block (Raw section) by GUID |

> [!WARNING]
> Modifying ASUS `.CAP` firmware will invalidate the official Capsule signature! Successful generation only indicates that the file structure was modified correctly. The motherboard's security verification mechanism may not directly accept it during actual flashing (tested USB FlashBack on X870E-E can be flashed directly). Before flashing, please make sure to back up the original factory SPI firmware and prepare a reliable programmer recovery solution.

## Scope of Application

This script is suitable for ASUS AMI/AMITSE BIOSes with similar structures (e.g., theme migration between the same platform or related models).

It is not a general-purpose BIOS modification tool. In the following cases, it will actively report an error and stop, rather than forcing a blind modification:
- Non-ASUS BIOS;
- Versions where the theme system has been heavily rewritten;
- Firmware that cannot be processed normally by UEFIExtract/UEFIReplace.

## Requirements

- Python 3.10 or higher;
- `UEFIExtract` and `UEFIReplace` (Windows executables are already included in the repository; running them in the repository directory requires no additional path specification).

## Quick Start

When running the command, the first argument is the theme source, and the second argument is the target BIOS used as the base for modification:

```
source_bios = The source BIOS providing colors, Logo, and theme assets
target_bios = The target BIOS acting as the base for modification (retaining all its original platform functionalities)
```

It is recommended to follow these steps:

### 1. Analysis Only (Check Match Rate)
```
python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET.CAP" --analyze
```
This mode only extracts and analyzes the theme tables and match rates of both BIOSes, outputting the statistical results. **It will not generate or modify any files.** You can use it to confirm whether the structures of both sides are close enough.

### 2. Dry Run
```
python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET.CAP" --dry-run
```
Calculates the complete patch data and counts color records, but **will not write any files** either.

### 3. Formally Generate Themed BIOS
```
python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET.CAP" -o "ASUS_TARGET_MIKU.CAP"
```
If the `-o` parameter is not specified, it will output as `ASUS_TARGET_patched.CAP` by default.

---

## Example: Migrating from X870E-H-MIKU-EDITION 2103 to X870E-E 2103

```
python patch_asus_theme.py `
  "ROG-STRIX-X870E-H-GAMING-WIFI7-S-HATSUNE-MIKU-EDITION-ASUS-2103.CAP" `
  "ROG-STRIX-X870E-E-GAMING-WIFI-ASUS-2103.CAP"
```
The ideal analysis output for the verification sample is as follows:
```
Source theme tables: 1560, records=15237
Target theme tables: 1560, records=15237
Exact table matches: 1560/1560 (100.00%)
Patched color records: 1464
```

---

## Command Line Arguments

| Option | Description |
| --- | --- |
| `source_bios` | Path to the theme source BIOS |
| `target_bios` | Path to the target BIOS used as the modification base |
| `-o`, `--output` | Path to the output BIOS file |
| `--uefiextract PATH` | Explicitly specify the path to the UEFIExtract executable |
| `--uefireplace PATH` | Explicitly specify the path to the UEFIReplace executable |
| `--analyze` | Only analyze and print unmatched theme tables, no files written |
| `--dry-run` | Calculate patches and gather statistics, no files written |
| `--verbose` | Verbose mode, printing specific matching tables and each modified color |
| `--show-tool-output` | Do not filter raw output logs from UEFIExtract/UEFIReplace |
| `--min-block-coverage N` | Minimum table match rate threshold, default is `0.70` |
| `--color-key KEY` | Treat an additional 4-byte attribute as a color (advanced option, reusable) |
| `--loose` | Relax the validation rules for trailing zero-padding in ThemeRecord payloads (advanced option) |

> [!NOTE]
> **Notes on Expert Options**
> - `--color-key` only accepts attributes defined as 4-byte payloads in both firmwares' code. It is mainly used to handle certain confirmed special color keys not marked with `type 4`. Do not use it to force copying unknown layouts or geometric attributes.
> - `--loose` only relaxes the payload trailing padding rules. It will not bypass PE, code signing, or table structure matching. Unless you have analyzed the target version, using it to force an increase in match count is not recommended.
> - Lowering `--min-block-coverage` only relaxes the final safety match threshold. A low match rate usually implies that the difference between the source and target versions is too large; the cause should be confirmed through analysis first, rather than continuing to lower the threshold.

---

## Implementation Principles

### 1. Attribute Type Table Recovery from Signature
The script searches for stable machine code signatures within the `.text` section of the AMITSE PE module:
```
48 8D 47 04 39 18
```
The corresponding underlying assembly logic is:
```
lea rax, [rdi + 4]
cmp dword ptr [rax], ebx
```
The function then reads the Key of the `ThemeRecord`, normalizes it, retrieves the corresponding attribute type (`0..11`) in the type table, and enters the corresponding conversion path through a dispatch table containing 12 branches. By parsing adjacent instructions, the script dynamically locates the RVA of the type table and dispatch table, thereby avoiding reliance on fixed file offsets.

### 2. Attribute Type and Payload Length Dispatch
The mapping of effective payload lengths corresponding to different attribute types is as follows:

| Attribute Type | Effective Length | Description |
| --- | ---: | --- |
| `0`, `1`, `2`, `3`, `4` | 4 bytes | **Type 4** is the theme color Key (using `AARRGGBB` format) |
| `5` | 16 bytes | Geometry/layout and other attributes |
| `6` | 1 byte | Boolean/single-byte flags |
| `7` | 16 bytes | Other composite attributes |
| `8` | 8 bytes | Double-word/long integer attributes |
| `9`, `10` | 2 bytes | Short integer attributes |
| `11` | 16 bytes | Special types (allows scanning, but not modified as colors) |

Based on the type table dynamically recovered from the code, the script accurately filters out all `Type 4` records for migration, without relying on any hardcoded color values or blind guessing.

### 3. Explanation of Little-Endian Representation for Color Records
AMITSE/Skia internally uses the standard `AARRGGBB` integer format to manage colors. In the little-endian memory of the x86 architecture, the 4-byte color value appears in reverse order:
```
BB GG RR AA
```
Therefore, `CE E2 13 CC` outputted in detailed logs or modification prompts corresponds to the actual channels:
- **A** (Alpha) = `CC`
- **R** (Red) = `13`
- **G** (Green) = `E2`
- **B** (Blue) = `CE`

The `Patched color records` in the output refers to the number of successfully replaced `ThemeRecord`s, not the total number of actually changed bytes.

### 4. ThemeRecord Structure and Table Boundary Determination
AMITSE theme records are aligned in memory with a size of `0x18` bytes. Its C-language structure definition is as follows:
```
struct ThemeRecord {
    uint32_t Group;
    uint32_t Key;
    uint8_t  Payload[16];
};
```
A complete theme table has the following boundary structure in the `.data` section:
```
ThemeRecord records[] = {
    {same_group, key_a, payload_a},
    {same_group, key_b, payload_b},
    // ...
    {same_group, 0, {0}}, // Termination item
};
```
The scanner precisely divides the boundaries of each theme table by strictly matching the termination item that shares the same `Group`, has `Key=0`, and a completely zeroed-out Payload, preventing adjacent tables from being incorrectly merged.

### 5. Strict Table-Level Matching and Safe Writing
- **Alignment and Signature**: Source and target tables are first aligned via the global Key sequence, and then matched based on the `(Group, complete key sequence)` signature.
- **Partial Overwrite**: The script overwrites the color of the source record into the target's `Payload[0:4]` only when the theme tables on both sides match exactly and their local indices are identical. Group IDs, Key IDs, and table termination items all retain their original target values, and high-risk offset copying is absolutely never forced.

---

## Post-Generation Verification

For safety reasons, it is recommended to perform the following verifications before flashing:

1. Record the SHA-256 hash values of the source, target, and generated files;
2. Run the analysis command again, using the generated BIOS as the target:
   ```
   python patch_asus_theme.py "MIKU_SOURCE.CAP" "ASUS_TARGET_MIKU.CAP" --analyze
   ```
   If the migration is completely successful, the outputted `Patched color records` should be `0` at this time.

## FAQ

### Why does it prompt a Capsule signature error during flashing?
Official ASUS firmware carries a private key signature. After the script modifies the content, the Capsule signature will inevitably become invalid. Please use a flashing method that supports ignoring the signature (such as the motherboard's built-in USB FlashBack or a programmer).

### Why is the match rate not 100%?
BIOS versions across different models or updates may add or remove certain menu controls. For theme tables whose structures cannot be aligned, the script chooses to safely ignore them and maintain the target BIOS's default style to ensure safety.

### Can I directly modify a dumped `.rom` or `.bin` file?
No. A full SPI backup dumped directly from the motherboard contains data outside the Capsule volume. For safety, the script only allows executing `--analyze` or `--dry-run` on such files, and refuses to execute formal GUID replacement writes.

## Disclaimer

Modifying and flashing a motherboard BIOS carries extremely high risks, which may lead to unbootable devices, data loss, voided warranties, or hardware damage. This project and script are only intended for generating modified firmware files and assume no responsibility for flashing outcomes or any hardware damage. All operational risks are borne solely by the user.
```