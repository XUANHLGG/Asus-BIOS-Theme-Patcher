#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import difflib
import shutil
import struct
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path


RECORD_SIZE = 0x18
PAYLOAD_SIZE = 0x10

# Number of meaningful bytes copied by the property converter for each type.
# Type 11 is a special case in the converter; accepting its full union here is
# necessary for locating table boundaries, but type 11 is never patched.
PROPERTY_PAYLOAD_LENGTHS = {
    0: 4,
    1: 4,
    2: 4,
    3: 4,
    4: 4,
    5: 16,
    6: 1,
    7: 16,
    8: 8,
    9: 2,
    10: 2,
    11: 16,
}

PROPERTY_CONVERTER_SIGNATURE = b"\x48\x8D\x47\x04\x39\x18"

AMITSE_FILE_GUID = "B1DA0ADF-4F77-4070-A88E-BFFE1C60529A"
LOGO_FILE_GUID = "7BB28B99-61BB-11D5-9A5D-0090273FC14D"
THEME_RAW_FILE_GUID = "CC5840D2-D8EA-459E-BAF4-349AC710EBBE"

SECTION_TYPE_PE32 = "10"
SECTION_TYPE_RAW = "19"

TOOL_NOISE_PREFIXES = (
    "FfsParser::parseCapsule: Aptio capsule signature may become invalid",
    "FfsParser::parseSections: non-UEFI data found in sections area",
    "FfsParser::performSecondPass: the last VTF appears inside compressed item",
    "parseImageFile: Aptio capsule signature may become invalid",
    "parseBios: one of volumes inside overlaps the end of data",
    "parseSection: GUID defined section with unknown processing method",
    "parseSection: GUID defined section can not be processed",
)
TOOL_NOISE_LINES = {"File replaced"}


def parse_int(value: str) -> int:
    """Parse decimal or 0x-prefixed key values accepted by --color-key."""
    return int(value, 0)


def is_tool_noise(line: str) -> bool:
    stripped = line.strip()
    return stripped in TOOL_NOISE_LINES or stripped.startswith(TOOL_NOISE_PREFIXES)


def print_tool_stream(output: str | None, show_tool_output: bool) -> None:
    if not output:
        return
    for line in output.splitlines():
        if show_tool_output or not is_tool_noise(line):
            print(line)


def run_cmd(cmd, check=True, capture_output=True, show_tool_output=False):
    result = subprocess.run(
        [str(x) for x in cmd],
        check=False,
        text=True,
        capture_output=capture_output,
    )
    # Never filter a failed command: its full output is needed for diagnosis.
    show_all = show_tool_output or result.returncode != 0
    print_tool_stream(result.stdout, show_all)
    print_tool_stream(result.stderr, show_all)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


def find_tool(explicit: str | None, name: str) -> str:
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        raise SystemExit(f"Tool not found: {explicit}")

    found = shutil.which(name)
    if found:
        return found

    for candidate_name in (name, name + ".exe"):
        candidate = Path.cwd() / candidate_name
        if candidate.is_file():
            return str(candidate)

    raise SystemExit(f"Tool not found: {name}. Put it in PATH or pass it explicitly.")


def u32le(b: bytes) -> int:
    return struct.unpack("<I", b)[0]


def i32le(b: bytes) -> int:
    return struct.unpack("<i", b)[0]


def fmt_u32(x: int) -> str:
    return f"0x{x:08X}"


def fmt_key(x: int) -> str:
    if x == 1000:
        return "1000(0x000003E8)"
    return f"0x{x:08X}"


def fmt_bytes4(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


def parse_pe_sections(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("AMITSE body is not a PE image (missing MZ header)")
    pe_off = u32le(data[0x3C:0x40])
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ValueError("AMITSE body has an invalid PE header")

    section_count = struct.unpack_from("<H", data, pe_off + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    section_table = pe_off + 24 + optional_size
    if section_table + section_count * 40 > len(data):
        raise ValueError("AMITSE PE section table is truncated")

    sections = []
    for index in range(section_count):
        off = section_table + index * 40
        name = data[off : off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, off + 8
        )
        if raw_offset + raw_size > len(data):
            raise ValueError(f"AMITSE PE section {name!r} is truncated")
        sections.append(
            {
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
            }
        )
    return sections


def get_pe_section(sections, name: str):
    matches = [section for section in sections if section["name"] == name]
    if len(matches) != 1:
        raise ValueError(f"AMITSE PE must contain exactly one {name} section")
    return matches[0]


def rva_to_offset(sections, rva: int) -> int:
    for section in sections:
        relative = rva - section["rva"]
        if 0 <= relative < section["raw_size"]:
            return section["raw_offset"] + relative
    raise ValueError(f"RVA 0x{rva:X} is not backed by a raw PE section")


def offset_to_rva(section, offset: int) -> int:
    return section["rva"] + offset - section["raw_offset"]


def find_runtime_function_start(data: bytes, sections, code_rva: int):
    """Use the PE exception directory to find an x64 function's true start."""
    pe_off = u32le(data[0x3C:0x40])
    optional_off = pe_off + 24
    optional_magic = struct.unpack_from("<H", data, optional_off)[0]
    if optional_magic != 0x20B:
        return None

    directory_count = u32le(data[optional_off + 108 : optional_off + 112])
    if directory_count <= 3:
        return None
    exception_rva, exception_size = struct.unpack_from(
        "<II", data, optional_off + 112 + 3 * 8
    )
    if not exception_rva or exception_size < 12:
        return None
    try:
        exception_off = rva_to_offset(sections, exception_rva)
    except ValueError:
        return None

    entry_count = exception_size // 12
    for index in range(entry_count):
        off = exception_off + index * 12
        if off + 12 > len(data):
            break
        begin_rva, end_rva, _ = struct.unpack_from("<III", data, off)
        if begin_rva <= code_rva < end_rva:
            return begin_rva
    return None


def find_nearby_function_prologue(data: bytes, text_section, code_offset: int):
    """Fallback for firmware that carries unwind data but omits its directory."""
    search_start = max(text_section["raw_offset"], code_offset - 0x100)
    suffix = b"\x55\x56\x57\x41\x56\x41\x57"
    for off in range(code_offset - 12, search_start - 1, -1):
        if data[off : off + 4] != b"\x48\x89\x5C\x24":
            continue
        if data[off + 5 : off + 12] == suffix:
            return offset_to_rva(text_section, off)
    return None


def analyze_property_converter(data: bytes):
    """Recover the property type map from the converter's machine code."""
    sections = parse_pe_sections(data)
    text_section = get_pe_section(sections, ".text")
    text_start = text_section["raw_offset"]
    text_end = text_start + text_section["raw_size"]

    candidates = []
    search_at = text_start
    while True:
        signature_off = data.find(PROPERTY_CONVERTER_SIGNATURE, search_at, text_end)
        if signature_off < 0:
            break
        search_at = signature_off + 1

        key_op = data.find(b"\x8B\x10\x8D\x82", signature_off + 6, signature_off + 48)
        if key_op < 0 or key_op + 13 > text_end or data[key_op + 8] != 0x3D:
            continue
        key_adjust = i32le(data[key_op + 4 : key_op + 8])
        max_index = u32le(data[key_op + 9 : key_op + 13])
        if key_adjust >= 0 or not 0x20 <= max_index <= 0x10000:
            continue

        window_end = min(text_end, key_op + 96)
        image_base_op = data.find(b"\x4C\x8D\x0D", key_op + 13, window_end)
        map_op = data.find(b"\x41\x0F\xB6\x84\x01", key_op + 13, window_end)
        dispatch_op = data.find(b"\x41\x8B\x8C\x81", key_op + 13, window_end)
        if min(image_base_op, map_op, dispatch_op) < 0:
            continue

        image_base_rva = offset_to_rva(text_section, image_base_op + 7) + i32le(
            data[image_base_op + 3 : image_base_op + 7]
        )
        map_rva = image_base_rva + u32le(data[map_op + 5 : map_op + 9])
        dispatch_rva = image_base_rva + u32le(data[dispatch_op + 4 : dispatch_op + 8])
        try:
            map_off = rva_to_offset(sections, map_rva)
            dispatch_off = rva_to_offset(sections, dispatch_rva)
        except ValueError:
            continue

        map_length = max_index + 1
        if map_off + map_length > len(data):
            continue
        type_bytes = data[map_off : map_off + map_length]
        if any(
            property_type not in PROPERTY_PAYLOAD_LENGTHS
            for property_type in type_bytes
        ):
            continue

        first_key = -key_adjust
        property_types = {
            first_key + index: property_type
            for index, property_type in enumerate(type_bytes)
        }
        signature_rva = offset_to_rva(text_section, signature_off)
        function_rva = find_runtime_function_start(data, sections, signature_rva)
        if function_rva is None:
            function_rva = find_nearby_function_prologue(
                data, text_section, signature_off
            )
        candidates.append(
            {
                "sections": sections,
                "signature_offset": signature_off,
                "signature_rva": signature_rva,
                "function_rva": function_rva,
                "type_map_offset": map_off,
                "type_map_rva": map_rva,
                "dispatch_offset": dispatch_off,
                "dispatch_rva": dispatch_rva,
                "first_key": first_key,
                "last_key": first_key + max_index,
                "property_types": property_types,
            }
        )

    if len(candidates) != 1:
        raise ValueError(
            "Expected one AMITSE property converter signature, "
            f"found {len(candidates)}"
        )
    return candidates[0]


def payload_matches_type(payload: bytes, property_type: int, strict: bool) -> bool:
    meaningful_length = PROPERTY_PAYLOAD_LENGTHS[property_type]
    return not strict or payload[meaningful_length:] == b"\0" * (
        PAYLOAD_SIZE - meaningful_length
    )


def parse_typed_record(data: bytes, off: int, property_types, strict: bool):
    if off < 0 or off + RECORD_SIZE > len(data):
        return None
    group, key = struct.unpack_from("<II", data, off)
    if group in {0, 0xFFFFFFFF} or key in {0, 0xFFFFFFFF}:
        return None
    property_type = property_types.get(key)
    if property_type is None:
        return None
    payload = data[off + 8 : off + RECORD_SIZE]
    if not payload_matches_type(payload, property_type, strict):
        return None
    return {
        "offset": off,
        "group": group,
        "key": key,
        "type": property_type,
        "payload": payload,
        "value": payload[:4],
    }


def scan_theme_tables(data: bytes, analysis, strict: bool = True):
    """Locate individually terminated ThemeRecord arrays inside PE .data."""
    data_section = get_pe_section(analysis["sections"], ".data")
    start = data_section["raw_offset"]
    end = start + data_section["raw_size"]
    property_types = analysis["property_types"]
    zero_payload = b"\0" * PAYLOAD_SIZE
    tables = []
    off = start

    while off + 2 * RECORD_SIZE <= end:
        first = parse_typed_record(data, off, property_types, strict)
        if first is None:
            off += 1
            continue

        group = first["group"]
        records = []
        cursor = off
        found_terminator = False
        while cursor + RECORD_SIZE <= end:
            record_group, key = struct.unpack_from("<II", data, cursor)
            if record_group != group:
                break
            if key == 0:
                if records and data[cursor + 8 : cursor + RECORD_SIZE] == zero_payload:
                    found_terminator = True
                break
            record = parse_typed_record(data, cursor, property_types, strict)
            if record is None:
                break
            records.append(record)
            cursor += RECORD_SIZE

        if not found_terminator:
            off += 1
            continue

        tables.append(
            {
                "index": len(tables),
                "start": off,
                "end": cursor + RECORD_SIZE,
                "terminator_offset": cursor,
                "group": group,
                "records": records,
                "key_signature": tuple(record["key"] for record in records),
            }
        )
        off = cursor + RECORD_SIZE

    return tables


def pair_theme_tables(source_tables, target_tables):
    """Match exact table shapes, then recover uniquely moved tables."""
    source_shapes = [table["key_signature"] for table in source_tables]
    target_shapes = [table["key_signature"] for table in target_tables]
    matcher = difflib.SequenceMatcher(
        None, source_shapes, target_shapes, autojunk=False
    )
    pairs = []
    matched_source = set()
    matched_target = set()

    for (
        tag,
        source_start,
        source_end,
        target_start,
        target_end,
    ) in matcher.get_opcodes():
        if tag != "equal":
            continue
        for source_index, target_index in zip(
            range(source_start, source_end), range(target_start, target_end)
        ):
            pairs.append(
                (source_tables[source_index], target_tables[target_index], "ordered")
            )
            matched_source.add(source_index)
            matched_target.add(target_index)

    source_unique = defaultdict(list)
    target_unique = defaultdict(list)
    for index, table in enumerate(source_tables):
        if index not in matched_source:
            source_unique[(table["group"], table["key_signature"])].append(table)
    for index, table in enumerate(target_tables):
        if index not in matched_target:
            target_unique[(table["group"], table["key_signature"])].append(table)

    recovered = 0
    for signature, source_matches in source_unique.items():
        target_matches = target_unique.get(signature, [])
        # A signature can occur in repeated UI variants.  It is still
        # deterministic when both sides contain the same number: preserve the
        # occurrence order within that exact (Group, key sequence) bucket.
        if not source_matches or len(source_matches) != len(target_matches):
            continue
        for source_table, target_table in zip(source_matches, target_matches):
            if (
                source_table["index"] in matched_source
                or target_table["index"] in matched_target
            ):
                continue
            pairs.append((source_table, target_table, "signature-moved"))
            matched_source.add(source_table["index"])
            matched_target.add(target_table["index"])
            recovered += 1

    pairs.sort(key=lambda pair: pair[1]["index"])
    return {
        "pairs": pairs,
        "ordered_count": len(pairs) - recovered,
        "recovered_count": recovered,
        "unmatched_source": [
            table for table in source_tables if table["index"] not in matched_source
        ],
        "unmatched_target": [
            table for table in target_tables if table["index"] not in matched_target
        ],
        "opcodes": matcher.get_opcodes(),
    }


def patch_theme_values(
    source_data: bytes,
    target_data: bytes,
    strict: bool = True,
    color_keys=None,
):
    source_analysis = analyze_property_converter(source_data)
    target_analysis = analyze_property_converter(target_data)
    source_tables = scan_theme_tables(source_data, source_analysis, strict=strict)
    target_tables = scan_theme_tables(target_data, target_analysis, strict=strict)
    table_match = pair_theme_tables(source_tables, target_tables)
    explicit_color_keys = set(color_keys or ())
    invalid_color_keys = set()
    for key in explicit_color_keys:
        source_type = source_analysis["property_types"].get(key)
        target_type = target_analysis["property_types"].get(key)
        if (
            source_type not in PROPERTY_PAYLOAD_LENGTHS
            or target_type not in PROPERTY_PAYLOAD_LENGTHS
            or PROPERTY_PAYLOAD_LENGTHS[source_type] != 4
            or PROPERTY_PAYLOAD_LENGTHS[target_type] != 4
        ):
            invalid_color_keys.add(key)
    explicit_color_keys -= invalid_color_keys

    patched = bytearray(target_data)
    changes = []
    changed_tables = []
    for source_table, target_table, match_mode in table_match["pairs"]:
        table_changes = 0
        for local_index, (source_record, target_record) in enumerate(
            zip(source_table["records"], target_table["records"])
        ):
            key = source_record["key"]
            if key != target_record["key"]:
                raise AssertionError("matched table key signatures diverged")
            is_code_color = source_record["type"] == target_record["type"] == 4
            is_four_byte_property = (
                PROPERTY_PAYLOAD_LENGTHS[source_record["type"]]
                == PROPERTY_PAYLOAD_LENGTHS[target_record["type"]]
                == 4
            )
            is_explicit_color = key in explicit_color_keys and is_four_byte_property
            if not (is_code_color or is_explicit_color):
                continue

            old_value = target_record["value"]
            new_value = source_record["value"]
            if old_value == new_value:
                continue

            value_off = target_record["offset"] + 8
            patched[value_off : value_off + 4] = new_value
            changes.append(
                {
                    "group": target_record["group"],
                    "key": key,
                    "offset": value_off,
                    "old_value": old_value,
                    "new_value": new_value,
                    "source_offset": source_record["offset"] + 8,
                    "source_group": source_record["group"],
                    "source_table_index": source_table["index"],
                    "target_table_index": target_table["index"],
                    "source_table_start": source_table["start"],
                    "target_table_start": target_table["start"],
                    "local_index": local_index,
                    "match_mode": match_mode,
                    "explicit_override": is_explicit_color and not is_code_color,
                }
            )
            table_changes += 1

        if table_changes:
            changed_tables.append(
                {
                    "source_table_index": source_table["index"],
                    "target_table_index": target_table["index"],
                    "source_table_start": source_table["start"],
                    "target_table_start": target_table["start"],
                    "record_count": len(source_table["records"]),
                    "match_mode": match_mode,
                    "changes": table_changes,
                }
            )

    return {
        "patched_data": bytes(patched),
        "changes": changes,
        "changed_tables": changed_tables,
        "source_analysis": source_analysis,
        "target_analysis": target_analysis,
        "source_tables": source_tables,
        "target_tables": target_tables,
        "table_match": table_match,
        "invalid_color_keys": sorted(invalid_color_keys),
    }


def extract_guid_body(
    uefiextract: str,
    bios_path: Path,
    guid: str,
    section_type: str,
    out_file: Path,
    show_tool_output: bool = False,
):
    out_dir = out_file.with_suffix(out_file.suffix + ".dir")

    if out_dir.exists():
        if out_dir.is_dir():
            shutil.rmtree(out_dir)
        else:
            out_dir.unlink()

    if out_file.exists():
        if out_file.is_dir():
            shutil.rmtree(out_file)
        else:
            out_file.unlink()

    run_cmd(
        [
            uefiextract,
            bios_path,
            guid,
            "-o",
            out_dir,
            "-m",
            "body",
            "-t",
            section_type,
        ],
        show_tool_output=show_tool_output,
    )

    body_file = out_dir / "body.bin"
    if not body_file.is_file():
        raise FileNotFoundError(f"Failed to extract body.bin: {body_file}")

    shutil.copy2(body_file, out_file)


def replace_node(
    uefireplace: str,
    bios_in: Path,
    bios_out: Path,
    guid: str,
    section_type: str,
    replacement_file: Path,
    show_tool_output: bool = False,
):
    cmd = [
        uefireplace,
        bios_in,
        guid,
        section_type,
        replacement_file.resolve(),
        "-o",
        bios_out,
    ]
    try:
        run_cmd(cmd, show_tool_output=show_tool_output)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"UEFIReplace failed for GUID {guid} (exit {exc.returncode}). "
            "The target image may not be a supported UEFI image."
        ) from exc

    if not bios_out.is_file():
        raise SystemExit(f"UEFIReplace reported success but did not create: {bios_out}")


def color_keys(analysis):
    return sorted(
        key
        for key, property_type in analysis["property_types"].items()
        if property_type == 4
    )


def print_converter_analysis(label, analysis):
    keys = color_keys(analysis)
    function_rva = analysis["function_rva"]
    function_text = "not found" if function_rva is None else f"0x{function_rva:X}"
    print(f"[+] {label} property converter:")
    print(
        f"    function={function_text}, "
        f"signature=0x{analysis['signature_rva']:X}, "
        f"dispatch=0x{analysis['dispatch_rva']:X}, "
        f"type_map=0x{analysis['type_map_rva']:X}"
    )
    print(
        f"    key_range=0x{analysis['first_key']:X}-0x{analysis['last_key']:X}, "
        f"type-4 keys ({len(keys)}): " + " ".join(f"{key:X}" for key in keys)
    )


def print_table_line(prefix, table):
    keys = " ".join(f"{key:X}" for key in table["key_signature"])
    print(
        f"    {prefix}[{table['index']:04d}] off=0x{table['start']:X} "
        f"group=0x{table['group']:X} records={len(table['records'])} keys={keys}"
    )


def print_analysis(result, show_unmatched=False):
    source_tables = result["source_tables"]
    target_tables = result["target_tables"]
    table_match = result["table_match"]
    matched_count = len(table_match["pairs"])
    denominator = min(len(source_tables), len(target_tables))
    coverage = matched_count / denominator if denominator else 0.0

    print_converter_analysis("Source", result["source_analysis"])
    print_converter_analysis("Target", result["target_analysis"])
    print(
        f"[+] Source theme tables: {len(source_tables)}, "
        f"records={sum(len(table['records']) for table in source_tables)}"
    )
    print(
        f"[+] Target theme tables: {len(target_tables)}, "
        f"records={sum(len(table['records']) for table in target_tables)}"
    )
    print(
        f"[+] Exact table matches: {matched_count}/{denominator} ({coverage:.2%}); "
        f"ordered={table_match['ordered_count']}, "
        f"signature-moved={table_match['recovered_count']}"
    )
    print(
        f"[+] Unmatched tables: source={len(table_match['unmatched_source'])}, "
        f"target={len(table_match['unmatched_target'])}"
    )

    if show_unmatched and table_match["unmatched_source"]:
        print("[+] Unmatched source tables (left unchanged):")
        for table in table_match["unmatched_source"]:
            print_table_line("S", table)
    if show_unmatched and table_match["unmatched_target"]:
        print("[+] Unmatched target tables (left unchanged):")
        for table in table_match["unmatched_target"]:
            print_table_line("T", table)

    return coverage


def print_summary(result):
    changes = result["changes"]
    print(f"[+] Patched color records: {len(changes)}")
    print(f"[+] Changed theme tables: {len(result['changed_tables'])}")

    override_count = sum(change["explicit_override"] for change in changes)
    if override_count:
        print(f"[!] Explicit --color-key overrides patched: {override_count}")
    if result["invalid_color_keys"]:
        keys = " ".join(fmt_key(key) for key in result["invalid_color_keys"])
        print(f"[!] Ignored --color-key values that are not 4-byte properties: {keys}")

    transition_counter = Counter(
        (change["old_value"], change["new_value"]) for change in changes
    )
    if transition_counter:
        print("[+] Patched color transitions (old -> new):")
        for (old_value, new_value), count in sorted(
            transition_counter.items(),
            key=lambda item: (-item[1], item[0][0], item[0][1]),
        ):
            print(f"    {fmt_bytes4(old_value)} -> {fmt_bytes4(new_value)} x {count}")


def print_verbose(result):
    changes = result["changes"]
    key_counter = Counter(ch["key"] for ch in changes)
    if key_counter:
        print()
        print("[+] Key patch counts:")
        for key, cnt in sorted(key_counter.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"    {fmt_key(key)} x {cnt}")

    print()
    print("[+] Changed table summaries:")
    for i, table in enumerate(result["changed_tables"], 1):
        print(
            f"    [{i:03d}] "
            f"src_table={table['source_table_index']}@0x{table['source_table_start']:X} "
            f"tgt_table={table['target_table_index']}@0x{table['target_table_start']:X} "
            f"records={table['record_count']} mode={table['match_mode']} "
            f"changes={table['changes']}"
        )

    print()
    print("[+] Patched records:")
    for i, ch in enumerate(changes, 1):
        print(
            f"[{i:03d}] "
            f"group={fmt_u32(ch['group'])} "
            f"key={fmt_key(ch['key'])} "
            f"offset=0x{ch['offset']:X} "
            f"{fmt_bytes4(ch['old_value'])} -> {fmt_bytes4(ch['new_value'])} "
            f"(source_value_off=0x{ch['source_offset']:X}, "
            f"tables={ch['source_table_index']}->{ch['target_table_index']}, "
            f"mode={ch['match_mode']})"
        )


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Migrate AMITSE colors, logo, and theme resources from a source "
            "ASUS BIOS into a target ASUS BIOS."
        )
    )
    ap.add_argument("source_bios", type=Path, help="Source BIOS image")
    ap.add_argument("target_bios", type=Path, help="Target BIOS image")
    ap.add_argument("-o", "--output", type=Path, help="Output BIOS path")
    ap.add_argument("--uefiextract", help="Path to UEFIExtract")
    ap.add_argument("--uefireplace", help="Path to UEFIReplace")
    ap.add_argument(
        "--loose", action="store_true", help="Relax ThemeRec tail validation"
    )
    ap.add_argument(
        "--color-key",
        action="append",
        type=parse_int,
        default=[],
        help=(
            "Explicitly treat an additional 4-byte property key as color "
            "(decimal or 0x-prefixed); may be repeated"
        ),
    )
    ap.add_argument(
        "--min-block-coverage",
        type=float,
        default=0.70,
        help="Refuse to patch when aligned table coverage is below this ratio (default: 0.70)",
    )
    ap.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze code/types/tables and report unmatched tables; do not write BIOS",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Extract and calculate the patch, but do not write a BIOS image",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed table and per-record patch logs",
    )
    ap.add_argument(
        "--show-tool-output",
        action="store_true",
        help="Show unfiltered UEFIExtract/UEFIReplace output",
    )
    args = ap.parse_args()

    source_bios = args.source_bios
    target_bios = args.target_bios

    if not source_bios.is_file():
        raise SystemExit(f"Source BIOS not found: {source_bios}")
    if not target_bios.is_file():
        raise SystemExit(f"Target BIOS not found: {target_bios}")

    if not 0.0 <= args.min_block_coverage <= 1.0:
        raise SystemExit("--min-block-coverage must be between 0 and 1")

    if (
        not args.dry_run
        and not args.analyze
        and target_bios.suffix.lower() in {".rom", ".bin"}
    ):
        raise SystemExit(
            "Refusing full GUID replacement on a raw SPI dump (.rom/.bin). "
            "Use --dry-run for analysis and use a vendor .CAP or a format-aware "
            "UEFI editor for the final image."
        )

    uefiextract = find_tool(args.uefiextract, "UEFIExtract")
    uefireplace = None
    if not args.dry_run and not args.analyze:
        uefireplace = find_tool(args.uefireplace, "UEFIReplace")

    out_bios = args.output
    if out_bios is None:
        out_bios = target_bios.with_name(
            target_bios.stem + "_patched" + target_bios.suffix
        )

    strict = not args.loose

    with tempfile.TemporaryDirectory(prefix="bios_theme_patch_") as td:
        work = Path(td)

        source_amitse = work / "source_amitse_pe32.bin"
        target_amitse = work / "target_amitse_pe32.bin"
        source_logo = work / "source_logo_raw.bin"
        source_theme = work / "source_theme_raw.bin"
        patched_amitse = work / "patched_amitse_pe32.bin"

        extract_guid_body(
            uefiextract,
            source_bios,
            AMITSE_FILE_GUID,
            SECTION_TYPE_PE32,
            source_amitse,
            show_tool_output=args.show_tool_output,
        )

        extract_guid_body(
            uefiextract,
            target_bios,
            AMITSE_FILE_GUID,
            SECTION_TYPE_PE32,
            target_amitse,
            show_tool_output=args.show_tool_output,
        )

        source_amitse_data = source_amitse.read_bytes()
        target_amitse_data = target_amitse.read_bytes()

        try:
            result = patch_theme_values(
                source_amitse_data,
                target_amitse_data,
                strict=strict,
                color_keys=args.color_key,
            )
        except ValueError as exc:
            raise SystemExit(f"AMITSE analysis failed: {exc}") from exc

        coverage = print_analysis(result, show_unmatched=args.analyze)
        print_summary(result)
        if args.verbose:
            print_verbose(result)

        if args.analyze:
            print("[+] Analysis complete; no files were written.")
            return

        if coverage < args.min_block_coverage:
            raise SystemExit(
                "AMITSE table alignment coverage is too low; refusing to write a BIOS. "
                "Use a closer-version source or inspect the unmatched blocks."
            )

        if not result["changes"]:
            raise SystemExit("No compatible color records were matched in AMITSE.")

        if args.dry_run:
            print("[+] Dry run complete; no BIOS image was written.")
            return

        patched_amitse.write_bytes(result["patched_data"])

        extract_guid_body(
            uefiextract,
            source_bios,
            LOGO_FILE_GUID,
            SECTION_TYPE_RAW,
            source_logo,
            show_tool_output=args.show_tool_output,
        )

        extract_guid_body(
            uefiextract,
            source_bios,
            THEME_RAW_FILE_GUID,
            SECTION_TYPE_RAW,
            source_theme,
            show_tool_output=args.show_tool_output,
        )

        if out_bios.suffix.lower() == ".cap":
            print(
                "[!] UEFIReplace may invalidate the ASUS capsule signature; "
                "verify with your board's recovery/programming path before flashing."
            )

        step1 = work / "step1_amitse.bin"
        step2 = work / "step2_logo.bin"
        step3 = out_bios

        replace_node(
            uefireplace,
            target_bios,
            step1,
            AMITSE_FILE_GUID,
            SECTION_TYPE_PE32,
            patched_amitse,
            show_tool_output=args.show_tool_output,
        )

        replace_node(
            uefireplace,
            step1,
            step2,
            LOGO_FILE_GUID,
            SECTION_TYPE_RAW,
            source_logo,
            show_tool_output=args.show_tool_output,
        )

        replace_node(
            uefireplace,
            step2,
            step3,
            THEME_RAW_FILE_GUID,
            SECTION_TYPE_RAW,
            source_theme,
            show_tool_output=args.show_tool_output,
        )

        print(f"[+] Wrote: {step3}")


if __name__ == "__main__":
    main()
