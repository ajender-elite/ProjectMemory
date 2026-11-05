"""Report every thread of a captured process: identity, state, CPU, scheduling and wait point.

Usage:
    python -I tools/thread_report.py <session_dir>

Reads the session's evidence: per-thread stat, status, comm, wchan and schedstat
(captured by capture_evidence.py), and the process stat for totals. For each
thread:
  tid, name        from comm (the kernel's thread name, up to 15 characters)
  state            from stat, with its label (R, S, D, ...)
  utime_ms, stime_ms   CPU time in the user and kernel modes
  cpu_pct          this thread's share of the process's CPU time
  run_ms, wait_ms  scheduler time from schedstat: running, and runnable-but-waiting
  nice, priority   scheduling values from stat
  last_cpu         the CPU the thread last ran on (stat field 39)
  vol_ctx, nonvol_ctx   voluntary and involuntary context switches (status)
  wchan            the kernel function the thread sleeps in, if any

Times use CLK_TCK = 100, the same assumption as AndroidProcessAnalyzer.py.
Writes <session_dir>/<pid>_thread_report.csv and prints a summary, sorted by CPU.
"""

import csv
import json
import pathlib
import re
import sys

CLK_TCK = 100
STATE_LABELS = {
    "R": "running", "S": "sleeping", "D": "disk sleep", "T": "stopped", "t": "tracing stop",
    "W": "paging", "X": "dead", "Z": "zombie", "P": "parked", "I": "idle",
}
CSV_COLUMNS = [
    "tid", "name", "state", "state_label", "utime_ms", "stime_ms", "cpu_ms", "cpu_pct",
    "run_ms", "wait_ms", "nice", "priority", "last_cpu", "vol_ctx", "nonvol_ctx", "wchan",
    "stack_tls_start", "stack_tls_end", "stack_tls_size_kb", "stack_tls_rss_kb", "stack_tls_pss_kb",
]
STACK_TLS_HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) \S{4} \S+ \S+ \S+\s+\[anon:stack_and_tls:([^\]]+)\]\s*$")
SMAPS_FIELD = re.compile(r"^(Size|Rss|Pss):\s+(\d+) kB")


def stack_tls_by_tid(smaps_text: str, pid: int) -> dict[int, dict[str, object]]:
    """Map each thread to its [anon:stack_and_tls:<tid>] mapping: range, size, RSS and PSS.

    bionic places a thread's TLS block at the top of its stack mapping, and smaps
    does not separate the two, so this is one figure for stack plus TLS. The main
    thread's mapping is named "main" and belongs to the process id.
    """
    result: dict[int, dict[str, object]] = {}
    current: dict[str, object] | None = None
    for line in smaps_text.splitlines():
        header = STACK_TLS_HEADER.match(line)
        if header:
            label = header.group(3)
            tid = pid if label == "main" else int(label) if label.isdigit() else None
            current = None
            if tid is not None:
                current = {"start": header.group(1), "end": header.group(2), "tid": tid,
                           "size_kb": 0, "rss_kb": 0, "pss_kb": 0}
                result[tid] = current
            continue
        if line[:1] in "0123456789abcdef" and " " in line and "-" in line.split()[0]:
            current = None
            continue
        field = SMAPS_FIELD.match(line)
        if field and current is not None:
            key = {"Size": "size_kb", "Rss": "rss_kb", "Pss": "pss_kb"}[field.group(1)]
            current[key] = int(field.group(2))
    return result


def read(path: pathlib.Path) -> str | None:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else None


def parse_stat(text: str) -> dict[str, str]:
    """Fields after the parenthesised comm, keyed by their name in proc(5)."""
    after = text[text.rindex(")") + 1 :].split()
    names = {
        "state": 0, "priority": 15, "nice": 16, "utime": 11, "stime": 12,
        "processor": 36,
    }
    return {key: after[index] for key, index in names.items() if index < len(after)}


def parse_status(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields


def stack_tls_columns(info: dict[str, object] | None) -> dict[str, object]:
    if info is None:
        return {"stack_tls_start": "", "stack_tls_end": "", "stack_tls_size_kb": "",
                "stack_tls_rss_kb": "", "stack_tls_pss_kb": ""}
    return {
        "stack_tls_start": info["start"],
        "stack_tls_end": info["end"],
        "stack_tls_size_kb": info["size_kb"],
        "stack_tls_rss_kb": info["rss_kb"],
        "stack_tls_pss_kb": info["pss_kb"],
    }


def main() -> int:
    session = pathlib.Path(sys.argv[1]).resolve()
    evidence = session / "evidence"
    pid = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))["pid"]

    task_list = read(evidence / f"{pid}_task_list.txt")
    if task_list is None:
        print(f"error: no thread list for pid {pid} in this session", file=sys.stderr)
        return 1

    process_stat = read(evidence / f"{pid}_stat_start.txt") or ""
    process_fields = parse_stat(process_stat) if process_stat else {}
    process_ticks = (
        int(process_fields.get("utime", 0)) + int(process_fields.get("stime", 0))
    ) if process_fields else 0

    tls = stack_tls_by_tid(read(evidence / f"{pid}_smaps.txt") or "", pid)

    rows = []
    for token in task_list.split():
        if not token.isdigit():
            continue
        tid = int(token)
        base = f"{pid}_task_{tid}"
        stat_text = read(evidence / f"{base}_stat.txt")
        if stat_text is None or ")" not in stat_text:
            continue
        fields = parse_stat(stat_text)
        status = parse_status(read(evidence / f"{base}_status.txt") or "")
        comm = (read(evidence / f"{base}_comm.txt") or "").strip()
        wchan = (read(evidence / f"{base}_wchan.txt") or "").strip()
        schedstat = (read(evidence / f"{base}_schedstat.txt") or "").split()

        utime = int(fields.get("utime", 0))
        stime = int(fields.get("stime", 0))
        cpu_ticks = utime + stime
        state = fields.get("state", "?")
        run_ns = int(schedstat[0]) if len(schedstat) > 0 and schedstat[0].isdigit() else None
        wait_ns = int(schedstat[1]) if len(schedstat) > 1 and schedstat[1].isdigit() else None
        rows.append({
            "tid": tid,
            "name": comm,
            "state": state,
            "state_label": STATE_LABELS.get(state, "unknown"),
            "utime_ms": round(utime * 1000 / CLK_TCK, 1),
            "stime_ms": round(stime * 1000 / CLK_TCK, 1),
            "cpu_ms": round(cpu_ticks * 1000 / CLK_TCK, 1),
            "cpu_pct": round(100 * cpu_ticks / process_ticks, 2) if process_ticks else "",
            "run_ms": round(run_ns / 1e6, 1) if run_ns is not None else "",
            "wait_ms": round(wait_ns / 1e6, 1) if wait_ns is not None else "",
            "nice": fields.get("nice", ""),
            "priority": fields.get("priority", ""),
            "last_cpu": fields.get("processor", ""),
            "vol_ctx": status.get("voluntary_ctxt_switches", ""),
            "nonvol_ctx": status.get("nonvoluntary_ctxt_switches", ""),
            "wchan": wchan,
            **stack_tls_columns(tls.get(tid)),
        })

    rows.sort(key=lambda r: r["cpu_ms"], reverse=True)
    out = session / f"{pid}_thread_report.csv"
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"pid {pid}: {len(rows)} threads, sorted by CPU time")
    print(f"{'tid':>6} {'name':<16} {'state':<12} {'cpu ms':>9} {'cpu %':>6} {'wait ms':>9} {'nice':>5} {'cpu':>4} {'vol':>6} {'nonvol':>7}  wchan")
    for r in rows:
        print(f"{r['tid']:>6} {r['name']:<16} {r['state_label']:<12} {r['cpu_ms']:>9} "
              f"{str(r['cpu_pct']):>6} {str(r['wait_ms']):>9} {r['nice']:>5} {r['last_cpu']:>4} "
              f"{r['vol_ctx']:>6} {r['nonvol_ctx']:>7}  {r['wchan']}")
    total_cpu = sum(r["cpu_ms"] for r in rows)
    print(f"total thread CPU: {round(total_cpu, 1)} ms")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
