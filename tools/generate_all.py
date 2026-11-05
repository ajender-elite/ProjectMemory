"""Run every tool for one process: capture, dump, memory ranking, and per-library reports.

Usage:
    python -I tools/generate_all.py <adb_serial> <pid> <output_root> [session_id]

Steps, in order:
  1. capture_evidence.py   raw /proc evidence into <output_root>/<session>/evidence/
  2. build_dump.py         <pid>_pid_analyze_dump.json (report + evidence)
  3. lib_memory_rank.py    <pid>_lib_memory_rank.csv (all file-backed mappings)
  4. for each shared library the process maps:
       lib_segments.py     <lib>_segments.csv
       lib_deps.py         <device path with / as _>_deps.json (one per path)
       lib_sharing.py      <lib>_sharing.csv

Each step runs the existing tool as a separate process with python -I. A failure
in one library's step is recorded and the run continues. The summary is written to
<session>/generate_all_summary.csv.
"""

import argparse
import csv
import pathlib
import re
import subprocess
import sys
import uuid

TOOLS = pathlib.Path(__file__).resolve().parent
PYTHON = sys.executable


def run(*args: str) -> tuple[int, str]:
    proc = subprocess.run([PYTHON, "-I", *args], capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("serial")
    parser.add_argument("pid")
    parser.add_argument("output_root", type=pathlib.Path)
    parser.add_argument("session_id", nargs="?", default=None)
    parser.add_argument("--scenario", default=None, help="what the device was doing, recorded in the session metadata")
    args = parser.parse_args()
    serial, pid, output_root = args.serial, args.pid, args.output_root
    session_id = args.session_id or str(uuid.uuid4())
    session = output_root / session_id
    rows: list[dict[str, str]] = []

    def record(step: str, target: str, code: int, detail: str) -> None:
        rows.append({"step": step, "target": target, "status": "ok" if code == 0 else "failed",
                     "detail": detail.splitlines()[-1] if detail else ""})
        print(f"[{'ok' if code == 0 else 'FAILED'}] {step} {target}")

    capture_args = [str(TOOLS / "capture_evidence.py"), serial, pid, str(output_root), session_id]
    if args.scenario is not None:
        capture_args += ["--scenario", args.scenario]
    code, out = run(*capture_args)
    record("capture", pid, code, out)
    if code != 0:
        print(out)
        return 1

    code, out = run(str(TOOLS / "build_dump.py"), str(session))
    record("dump", pid, code, out)

    code, out = run(str(TOOLS / "lib_memory_rank.py"), str(session), "--sort", "pss")
    record("memory_rank", pid, code, out)

    smaps = (session / "evidence" / f"{pid}_smaps.txt").read_text(encoding="utf-8", errors="replace")
    libraries: list[str] = []
    for line in smaps.splitlines():
        m = re.match(r"^[0-9a-f]+-[0-9a-f]+ \S{4} \S+ \S+ \S+\s+(/\S+\.so[\w.-]*)\s*$", line)
        if m and m.group(1) not in libraries:
            libraries.append(m.group(1))
    print(f"{len(libraries)} shared libraries mapped by pid {pid}")

    for path in libraries:
        name = path.rsplit("/", 1)[-1]
        code, out = run(str(TOOLS / "lib_segments.py"), str(session), name)
        record("segments", name, code, out)
        code, out = run(str(TOOLS / "lib_deps.py"), str(session), path)
        record("deps", name, code, out)
        code, out = run(str(TOOLS / "lib_sharing.py"), serial, name, str(session))
        record("sharing", name, code, out)

    summary = session / "generate_all_summary.csv"
    with summary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["step", "target", "status", "detail"])
        writer.writeheader()
        writer.writerows(rows)

    failed = sum(1 for r in rows if r["status"] != "ok")
    print(f"session {session}: {len(rows)} steps, {failed} failed; summary in {summary}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
