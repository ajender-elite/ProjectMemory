"""Rank a captured process's shared libraries by RSS or PSS, in descending order.

Usage:
    python -I tools/lib_memory_rank.py <session_dir> [--sort pss|rss] [--top N] [--json]

Reads <session_dir>/evidence/<pid>_smaps.txt directly. Each file-backed mapping is
attributed to its path, and the Rss, Pss, Private and Shared fields are summed per
file. Anonymous mappings are excluded from the library list but included in the
process totals, which are printed for comparison.

--json also writes <session_dir>/<pid>_lib_memory_rank.json.
"""

import argparse
import json
import pathlib
import re
import sys

HEADER = re.compile(r"^[0-9a-f]+-[0-9a-f]+ \S{4} \S+ \S+ \S+\s+(.*)$")
FIELD = re.compile(r"^(Rss|Pss|SwapPss|Private_Clean|Private_Dirty|Shared_Clean|Shared_Dirty):\s+(\d+) kB")


def rank(smaps_text: str) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    per_file: dict[str, dict[str, int]] = {}
    totals = {"rss": 0, "pss": 0}
    current: str | None = None
    for line in smaps_text.splitlines():
        header = HEADER.match(line)
        if header:
            path = header.group(1).strip()
            current = path if path.startswith("/") else None
            continue
        field = FIELD.match(line)
        if not field:
            continue
        key, value = field.group(1), int(field.group(2))
        if key == "Rss":
            totals["rss"] += value
        elif key == "Pss":
            totals["pss"] += value
        if current is None:
            continue
        bucket = per_file.setdefault(
            current,
            {"rss_kb": 0, "pss_kb": 0, "private_kb": 0, "shared_kb": 0, "swap_pss_kb": 0},
        )
        if key == "Rss":
            bucket["rss_kb"] += value
        elif key == "Pss":
            bucket["pss_kb"] += value
        elif key == "SwapPss":
            bucket["swap_pss_kb"] += value
        elif key in ("Private_Clean", "Private_Dirty"):
            bucket["private_kb"] += value
        elif key in ("Shared_Clean", "Shared_Dirty"):
            bucket["shared_kb"] += value
    return per_file, totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("session_dir", type=pathlib.Path)
    parser.add_argument("--sort", choices=["pss", "rss"], default="pss")
    parser.add_argument("--top", type=int, default=0, help="show only the first N rows (0 = all)")
    parser.add_argument("--json", action="store_true", help="also write the ranking as JSON")
    args = parser.parse_args()

    session = args.session_dir.resolve()
    manifest = json.loads((session / "evidence" / "manifest.json").read_text(encoding="utf-8"))
    pid = manifest["pid"]
    smaps = (session / "evidence" / f"{pid}_smaps.txt").read_text(encoding="utf-8", errors="replace")

    per_file, totals = rank(smaps)
    libraries = {path: values for path, values in per_file.items() if ".so" in path.rsplit("/", 1)[-1]}
    key = f"{args.sort}_kb"
    ordered = sorted(libraries.items(), key=lambda item: item[1][key], reverse=True)
    if args.top:
        ordered = ordered[: args.top]

    sum_lib_rss = sum(v["rss_kb"] for v in libraries.values())
    sum_lib_pss = sum(v["pss_kb"] for v in libraries.values())
    print(f"pid {pid}: {len(libraries)} shared libraries, sorted by {args.sort.upper()} (descending)")
    print(f"{'RSS kB':>8} {'PSS kB':>8} {'USS kB':>8} {'SwapPSS':>8}  library")
    for path, values in ordered:
        uss = values["private_kb"]
        print(f"{values['rss_kb']:>8} {values['pss_kb']:>8} {uss:>8} {values['swap_pss_kb']:>8}  {path}")
    print(f"{'-' * 40}")
    print(f"libraries total: RSS {sum_lib_rss} kB, PSS {sum_lib_pss} kB")
    print(f"process total (all mappings): RSS {totals['rss']} kB, PSS {totals['pss']} kB")

    if args.json:
        result = {
            "pid": pid,
            "sort": args.sort,
            "libraries": [{"path": path, **values} for path, values in ordered],
            "library_total": {"rss_kb": sum_lib_rss, "pss_kb": sum_lib_pss},
            "process_total": totals,
        }
        out = session / f"{pid}_lib_memory_rank.json"
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
