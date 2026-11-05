"""List every process on a device that maps a given shared library.

Usage:
    python -I tools/lib_sharing.py <adb_serial> <libname> [session_dir]

<libname> is a file name such as libhidlbase.so, or a full device path. When a
name matches more than one path (for example /system and /vendor copies), each
path is listed separately.

One read-only grep over /proc/[0-9]*/maps finds the mappings, and one read of
/proc/<pid>/comm names each process. Reading other processes' maps needs root on
a userdebug device (adb root). Without root, only processes the shell user can
read are listed.

If session_dir is given, the result is also written to
<session_dir>/<libname>_sharing.csv, one row per process mapping the library.
"""

import csv
import pathlib
import re
import shlex
import subprocess
import sys


def adb(serial: str, command: str) -> str:
    proc = subprocess.run(
        ["adb", "-s", serial, "shell", command],
        capture_output=True,
        timeout=120,
    )
    return proc.stdout.decode("utf-8", "replace")


def main() -> int:
    serial = sys.argv[1]
    libname = sys.argv[2]
    session_dir = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else None
    base = libname.rsplit("/", 1)[-1]
    exact_path = libname if libname.startswith("/") else None

    text = adb(serial, f"grep -H -F {shlex.quote(base)} /proc/[0-9]*/maps 2>/dev/null")

    paths: dict[str, set[int]] = {}
    for line in text.splitlines():
        m = re.match(r"^/proc/(\d+)/maps:(.*)$", line)
        if not m:
            continue
        mapped = m.group(2).split()[-1] if m.group(2).split() else ""
        if exact_path is not None:
            if mapped != exact_path:
                continue
        elif not mapped.endswith("/" + base):
            continue
        paths.setdefault(mapped, set()).add(int(m.group(1)))

    all_pids = sorted({pid for pids in paths.values() for pid in pids})
    names: dict[int, str] = {}
    if all_pids:
        out = adb(serial, "; ".join(f"echo {pid} $(cat /proc/{pid}/comm 2>/dev/null)" for pid in all_pids))
        for line in out.splitlines():
            parts = line.split(maxsplit=1)
            if parts and parts[0].isdigit():
                names[int(parts[0])] = parts[1] if len(parts) > 1 else ""

    result = {
        "library": base,
        "paths": {
            path: [{"pid": pid, "name": names.get(pid, "")} for pid in sorted(pids)]
            for path, pids in sorted(paths.items())
        },
        "processes": len(all_pids),
        "scan": "grep -F over /proc/[0-9]*/maps, names from /proc/<pid>/comm",
    }

    if not paths:
        print(f"{base}: not mapped by any readable process")
    for path, entries in result["paths"].items():
        print(f"{path}: {len(entries)} processes")
        for entry in entries:
            print(f"  {entry['pid']:>6}  {entry['name']}")

    if session_dir is not None:
        out_file = session_dir / f"{base}_sharing.csv"
        with out_file.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["library", "path", "pid", "process_name"])
            writer.writeheader()
            for path, entries in result["paths"].items():
                for entry in entries:
                    writer.writerow({
                        "library": base,
                        "path": path,
                        "pid": entry["pid"],
                        "process_name": entry["name"],
                    })
        print(f"wrote {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
