"""Capture raw /proc snapshots for one Android process over adb.

Usage:
    python -I tools/capture_evidence.py <adb_serial> <pid> <output_root> [session_id]

Creates <output_root>/<session_id>/evidence/ (session_id defaults to a new UUID)
and writes each command's stdout byte-for-byte there, plus manifest.json. The
manifest records the command, exit code, byte count and SHA-256 of every file,
so later steps use exactly what the device returned. An existing session is
never overwritten.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import uuid

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from session_metadata import metadata_block  # noqa: E402


def repo_commit() -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("serial")
    parser.add_argument("pid", type=int)
    parser.add_argument("output_root", type=pathlib.Path)
    parser.add_argument("session_id", nargs="?", default=None)
    parser.add_argument("--scenario", default=None, help="what the device was doing, e.g. 'idle' or 'playback'")
    args = parser.parse_args()
    serial, pid, output_root = args.serial, args.pid, args.output_root
    session_id = args.session_id or str(uuid.uuid4())
    session_dir = output_root / session_id
    if session_dir.exists():
        print(f"error: {session_dir} already exists; choose another session_id", file=sys.stderr)
        return 1
    evidence_dir = session_dir / "evidence"
    evidence_dir.mkdir(parents=True)
    entries: list[dict] = []

    def capture(command: str, name: str) -> bytes:
        proc = subprocess.run(
            ["adb", "-s", serial, "shell", command],
            capture_output=True,
            timeout=60,
        )
        (evidence_dir / name).write_bytes(proc.stdout)
        entry = {
            "command": command,
            "file": name,
            "exit_code": proc.returncode,
            "bytes": len(proc.stdout),
            "sha256": hashlib.sha256(proc.stdout).hexdigest(),
        }
        if proc.returncode != 0:
            entry["stderr"] = proc.stderr.decode("utf-8", "replace").strip()
        entries.append(entry)
        return proc.stdout

    p = f"/proc/{pid}"
    # Commands are the exact strings AndroidProcessAnalyzer.py sends to adb.
    stat_start = capture(f"cat {p}/stat", f"{pid}_stat_start.txt").decode("utf-8", "replace")
    process_name = stat_start[stat_start.index("(") + 1 : stat_start.rindex(")")] if ")" in stat_start else None
    capture(f"cat {p}/status", f"{pid}_status.txt")
    capture(f"cat {p}/cmdline", f"{pid}_cmdline.txt")
    capture(f"readlink {p}/exe", f"{pid}_exe_link.txt")
    capture(f"readlink {p}/cwd", f"{pid}_cwd_link.txt")
    capture(f"cat {p}/smaps", f"{pid}_smaps.txt")
    capture(f"cat {p}/limits", f"{pid}_limits.txt")
    capture(f"cat {p}/oom_score", f"{pid}_oom_score.txt")
    capture(f"cat {p}/oom_score_adj", f"{pid}_oom_score_adj.txt")
    capture(f"cat {p}/io", f"{pid}_io.txt")
    capture(f"cat {p}/cgroup", f"{pid}_cgroup.txt")
    capture(f"cat {p}/attr/current", f"{pid}_attr_current.txt")
    capture(f"dumpsys meminfo {pid}", f"{pid}_dumpsys_meminfo.txt")
    capture(f"cat /dev/binderfs/binder_logs/proc/{pid}", f"{pid}_binder_log.txt")

    task_out = capture(f"ls {p}/task", f"{pid}_task_list.txt").decode("utf-8", "replace")
    for token in task_out.split():
        if token.isdigit():
            capture(f"cat {p}/task/{token}/stat", f"{pid}_task_{token}_stat.txt")

    fd_out = capture(f"ls {p}/fd", f"{pid}_fd_list.txt").decode("utf-8", "replace")
    for token in fd_out.split():
        if token.isdigit():
            capture(f"readlink {p}/fd/{token}", f"{pid}_fd_{token}_link.txt")

    # Captured again at the end: if starttime changes, the process restarted mid-capture.
    capture(f"cat {p}/stat", f"{pid}_stat_end.txt")

    manifest = {
        "session_id": session_id,
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "adb_serial": serial,
        "pid": pid,
        "analyzer_repo_commit": repo_commit(),
        "metadata": metadata_block(serial, pid, process_name, args.scenario, "capture"),
        "entries": entries,
    }
    (evidence_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    failed = sum(1 for e in entries if e["exit_code"] != 0)
    print(f"captured {len(entries)} commands ({failed} nonzero) into {session_dir}")
    print(f"next: python -I tools/build_dump.py {session_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
