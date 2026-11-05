"""Split one library's memory in a captured process into segments.

Usage:
    python -I tools/lib_segments.py <session_dir> <libname>

<libname> is a file name (libar-pal.so) or a device path. The library's mappings
come from <session_dir>/evidence/<pid>_smaps.txt. Each mapping is one segment,
labelled by its permissions:
  code            r-x   executable text
  read_only_data  r--   .rodata, .eh_frame, read-only relocations
  data            rw-   .data, .got, and the file-backed part of .bss (written by the library)
  bss_anon        the zero-fill .bss that follows the library's rw mapping, named [anon:.bss]

The process's other anonymous memory (heap, allocators, thread stacks) is reported
separately as process context. smaps cannot attribute a heap allocation to a
library, so heap is not split by library.

Writes <session_dir>/<libname>_segments.csv, one row per mapping.
"""

import argparse
import csv
import json
import pathlib
import re
import sys

HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S{4}) ([0-9a-f]+) \S+ \S+\s*(.*)$")
FIELD = re.compile(r"^(Size|Rss|Pss|Private_Clean|Private_Dirty|Shared_Clean|Shared_Dirty|SwapPss):\s+(\d+) kB")
CSV_COLUMNS = [
    "library_path", "segment", "start", "end", "perms", "offset_hex",
    "size_kb", "rss_kb", "pss_kb", "private_kb", "private_dirty_kb", "swap_pss_kb",
]


def parse_mappings(text: str) -> list[dict]:
    mappings: list[dict] = []
    for line in text.splitlines():
        header = HEADER.match(line)
        if header:
            mappings.append({
                "start": int(header.group(1), 16),
                "end": int(header.group(2), 16),
                "perms": header.group(3),
                "offset": header.group(4),
                "path": header.group(5).strip(),
                "fields": {},
            })
            continue
        field = FIELD.match(line)
        if field and mappings:
            mappings[-1]["fields"][field.group(1)] = int(field.group(2))
    return mappings


def segment_of(perms: str) -> str:
    if perms.startswith("r-x"):
        return "code"
    if perms.startswith("r--"):
        return "read_only_data"
    if perms.startswith("rw"):
        return "data"
    return "other"


def row(library_path: str, mapping: dict, segment: str) -> dict:
    f = mapping["fields"]
    return {
        "library_path": library_path,
        "segment": segment,
        "start": f"{mapping['start']:x}",
        "end": f"{mapping['end']:x}",
        "perms": mapping["perms"],
        "offset_hex": mapping["offset"],
        "size_kb": f.get("Size", 0),
        "rss_kb": f.get("Rss", 0),
        "pss_kb": f.get("Pss", 0),
        "private_kb": f.get("Private_Clean", 0) + f.get("Private_Dirty", 0),
        "private_dirty_kb": f.get("Private_Dirty", 0),
        "swap_pss_kb": f.get("SwapPss", 0),
    }


def is_target(path: str, libname: str) -> bool:
    if libname.startswith("/"):
        return path == libname
    return path.rsplit("/", 1)[-1] == libname and path.startswith("/")


def heap_kind(path: str) -> str | None:
    if path == "[heap]":
        return "native_heap_brk"
    if path.startswith("[anon:scudo"):
        return "scudo_allocator"
    if path == "":
        return "anonymous_mmap"
    if path.startswith("[anon:") and not path.startswith("[anon:.bss"):
        return "named_anon"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("session_dir", type=pathlib.Path)
    parser.add_argument("libname")
    args = parser.parse_args()

    session = args.session_dir.resolve()
    manifest = json.loads((session / "evidence" / "manifest.json").read_text(encoding="utf-8"))
    pid = manifest["pid"]
    smaps = (session / "evidence" / f"{pid}_smaps.txt").read_text(encoding="utf-8", errors="replace")
    mappings = parse_mappings(smaps)

    rows: list[dict] = []
    owners = sorted({m["path"] for m in mappings if is_target(m["path"], args.libname)})
    if not owners:
        print(f"error: {args.libname} is not mapped by pid {pid}", file=sys.stderr)
        return 1
    for index, mapping in enumerate(mappings):
        if mapping["path"] not in owners:
            continue
        segment = segment_of(mapping["perms"])
        rows.append(row(mapping["path"], mapping, segment))
        following = mappings[index + 1] if index + 1 < len(mappings) else None
        if segment == "data" and following is not None and following["path"].startswith("[anon:.bss"):
            rows.append(row(mapping["path"], following, "bss_anon"))

    heap: dict[str, dict[str, int]] = {}
    for mapping in mappings:
        kind = heap_kind(mapping["path"])
        if kind is None:
            continue
        bucket = heap.setdefault(kind, {"mappings": 0, "rss_kb": 0, "pss_kb": 0, "private_dirty_kb": 0})
        bucket["mappings"] += 1
        bucket["rss_kb"] += mapping["fields"].get("Rss", 0)
        bucket["pss_kb"] += mapping["fields"].get("Pss", 0)
        bucket["private_dirty_kb"] += mapping["fields"].get("Private_Dirty", 0)

    summary: dict[str, dict[str, int]] = {}
    for item in rows:
        bucket = summary.setdefault(item["segment"], {"mappings": 0, "rss_kb": 0, "pss_kb": 0, "private_dirty_kb": 0})
        bucket["mappings"] += 1
        bucket["rss_kb"] += item["rss_kb"]
        bucket["pss_kb"] += item["pss_kb"]
        bucket["private_dirty_kb"] += item["private_dirty_kb"]

    library_name = owners[0].rsplit("/", 1)[-1]
    print(f"pid {pid}: {args.libname} mapped from {', '.join(owners)}")
    print(f"{'segment':<16} {'maps':>5} {'RSS kB':>8} {'PSS kB':>8} {'private dirty kB':>17}")
    for segment in ["code", "read_only_data", "data", "bss_anon"]:
        if segment in summary:
            s = summary[segment]
            print(f"{segment:<16} {s['mappings']:>5} {s['rss_kb']:>8} {s['pss_kb']:>8} {s['private_dirty_kb']:>17}")
    total_rss = sum(s["rss_kb"] for s in summary.values())
    total_pss = sum(s["pss_kb"] for s in summary.values())
    print(f"{'library total':<16} {'':>5} {total_rss:>8} {total_pss:>8}")

    print()
    print("process context (not attributable to this library):")
    for kind in sorted(heap):
        h = heap[kind]
        print(f"  {kind:<18} {h['mappings']:>5} maps  RSS {h['rss_kb']:>7} kB  PSS {h['pss_kb']:>7} kB")

    out = session / f"{library_name}_segments.csv"
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
