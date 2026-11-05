"""Classify every open file descriptor of a captured process, name it, and report its memory.

Usage:
    python -I tools/fd_report.py <session_dir>

Reads the session's evidence: fd list, fd_<n>_link (the target), fdinfo_<n>
(offset, flags, mount id), the process's smaps, and its socket tables.

For each descriptor:
  class         regular_file, memfd, dmabuf, ashmem, socket, pipe, eventfd, epoll,
                binder, device, procfs, sysfs, anon_inode, other
  path          the full target path, for files and devices. Empty otherwise.
  name          the readable name: file basename, memfd name, unix socket path,
                tcp/udp address pair, or anon_inode name. This is the string to
                search for in the codebase.
  access        read, write, read_write (from the open flags)
  mapped_*      RSS, PSS and USS of the process's mappings of that same target,
                from smaps. Descriptors that are never mapped show 0.

Process-wide dmabuf totals come from dmabuf_pss, dmabuf_rss and dmabuf_rss_hwm.
These are printed as raw values because the evidence doesn't state their unit.

Writes <session_dir>/<pid>_fd_report.csv and prints a summary by class.
"""

import csv
import json
import pathlib
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

from lib_memory_rank import rank  # noqa: E402

CSV_COLUMNS = [
    "fd", "class", "name", "path", "target", "access", "pos", "flags_octal", "mnt_id",
    "mapped_rss_kb", "mapped_pss_kb", "mapped_uss_kb", "note",
]
ACCESS = {0: "read", 1: "write", 2: "read_write"}


def classify(target: str) -> str:
    if target.startswith("socket:"):
        return "socket"
    if target.startswith("pipe:"):
        return "pipe"
    if target.startswith("anon_inode:"):
        inner = target[len("anon_inode:"):]
        for name, kind in (("eventfd", "eventfd"), ("eventpoll", "epoll"), ("dmabuf", "dmabuf"),
                           ("ashmem", "ashmem")):
            if name in inner:
                return kind
        return "anon_inode"
    if target.startswith("/memfd:"):
        return "memfd"
    if target.startswith("/dev/ashmem"):
        return "ashmem"
    if target.startswith("/dev/binder"):
        return "binder"
    if target.startswith("/dev/"):
        return "device"
    if target.startswith("/proc/"):
        return "procfs"
    if target.startswith("/sys/"):
        return "sysfs"
    if target.startswith("/dmabuf"):
        return "dmabuf"
    if target.startswith("/"):
        return "regular_file"
    return "other"


def parse_fdinfo(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def socket_tables(evidence: pathlib.Path, pid: int) -> dict[int, str]:
    """Map socket inode to a readable name, from the captured net tables."""
    names: dict[int, str] = {}
    unix = evidence / f"{pid}_net_unix.txt"
    if unix.exists():
        for line in unix.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 7 and parts[6].isdigit():
                names[int(parts[6])] = f"unix {parts[7]}" if len(parts) > 7 else "unix (unnamed)"
    for table in ("tcp", "tcp6", "udp", "udp6"):
        path = evidence / f"{pid}_net_{table}.txt"
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 10 and parts[9].isdigit():
                names[int(parts[9])] = f"{table} {parts[1]} -> {parts[2]}"
    return names


def name_of(target: str, kind: str, sockets: dict[int, str]) -> tuple[str, str]:
    """Return (name, path). The path is set only for file-like targets."""
    if kind == "memfd":
        return target[len("/memfd:"):].replace(" (deleted)", ""), target
    if kind in ("regular_file", "device", "binder", "ashmem", "procfs", "sysfs", "dmabuf"):
        return target.rsplit("/", 1)[-1] or target, target
    if kind == "socket":
        inode = target[len("socket:["):-1] if target.startswith("socket:[") else ""
        return sockets.get(int(inode), f"socket inode {inode}") if inode.isdigit() else target, ""
    if kind == "pipe":
        return target, ""
    if kind in ("eventfd", "epoll", "anon_inode"):
        return target[len("anon_inode:"):].strip("[]") or target, ""
    return target, ""


def mapped_for(target: str, per_file: dict[str, dict[str, int]]) -> dict[str, int]:
    return per_file.get(target, {"rss_kb": 0, "pss_kb": 0, "uss_kb": 0})


def read_optional(path: pathlib.Path) -> str | None:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else None


def main() -> int:
    session = pathlib.Path(sys.argv[1]).resolve()
    evidence = session / "evidence"
    pid = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))["pid"]

    fd_list = read_optional(evidence / f"{pid}_fd_list.txt")
    if fd_list is None:
        print(f"error: no fd list for pid {pid} in this session", file=sys.stderr)
        return 1
    smaps = read_optional(evidence / f"{pid}_smaps.txt") or ""
    per_file, _ = rank(smaps)
    sockets = socket_tables(evidence, pid)

    rows = []
    for token in fd_list.split():
        if not token.isdigit():
            continue
        link = read_optional(evidence / f"{pid}_fd_{token}_link.txt")
        target = (link or "").strip()
        info = parse_fdinfo(read_optional(evidence / f"{pid}_fdinfo_{token}.txt") or "")
        flags = int(info["flags"], 8) if "flags" in info else None
        access = ACCESS.get(flags & 3, "unknown") if flags is not None else "unknown"
        kind = classify(target)
        name, path = name_of(target, kind, sockets)
        mapped = mapped_for(target, per_file)
        rows.append({
            "fd": int(token),
            "class": kind,
            "name": name,
            "path": path,
            "target": target,
            "access": access,
            "pos": info.get("pos", ""),
            "flags_octal": info.get("flags", ""),
            "mnt_id": info.get("mnt_id", ""),
            "mapped_rss_kb": mapped["rss_kb"],
            "mapped_pss_kb": mapped["pss_kb"],
            "mapped_uss_kb": mapped["uss_kb"],
            "note": "" if target else "no readlink evidence",
        })
    rows.sort(key=lambda r: r["fd"])

    out = session / f"{pid}_fd_report.csv"
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    by_class: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = by_class.setdefault(row["class"], {"count": 0, "rss": 0, "pss": 0})
        bucket["count"] += 1
        bucket["rss"] += row["mapped_rss_kb"]
        bucket["pss"] += row["mapped_pss_kb"]

    print(f"pid {pid}: {len(rows)} open file descriptors")
    print(f"{'fd':>4} {'class':<14} {'mapped PSS kB':>13}  name")
    for row in rows:
        print(f"{row['fd']:>4} {row['class']:<14} {row['mapped_pss_kb']:>13}  {row['name']}")
    print()
    print(f"{'class':<16} {'fds':>5} {'mapped RSS kB':>14} {'mapped PSS kB':>14}")
    for name in sorted(by_class, key=lambda n: -by_class[n]["count"]):
        b = by_class[name]
        print(f"{name:<16} {b['count']:>5} {b['rss']:>14} {b['pss']:>14}")
    for name in ("dmabuf_pss", "dmabuf_rss", "dmabuf_rss_hwm"):
        value = read_optional(evidence / f"{pid}_{name}.txt")
        if value is not None:
            print(f"process {name} (raw value): {value.strip()}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
