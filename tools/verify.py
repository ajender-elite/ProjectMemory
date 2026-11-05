"""Verify an output directory. Exit 0 only if every check passes.

Usage:
    python -I tools/verify.py <output_dir>

Expects <output_dir>/evidence/ (raw files and manifest.json) and
<output_dir>/<pid>_pid_analyze_dump.json. The verbose file is checked if present.

Checks:
  1. Integrity: every evidence file matches its manifest SHA-256 and size.
  2. Reproducibility: replaying the evidence reproduces the dump
     (generated_at_utc excluded).
  3. Schema: the dump validates against schemas/analyzer-report.schema.json.
  4. Independent cross-checks: values recomputed from raw files with plain
     regex code, not the analyzer's parsers.
  5. Verbose file (if present): validates, and its embedded hashes match disk.
"""

import hashlib
import json
import pathlib
import re
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))

import jsonschema  # noqa: E402

import replay_report  # noqa: E402

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))


def main() -> int:
    output_dir = pathlib.Path(sys.argv[1]).resolve()
    evidence_dir = output_dir / "evidence"
    manifest = json.loads((evidence_dir / "manifest.json").read_text(encoding="utf-8"))
    entries = manifest["entries"]
    pid = manifest["pid"]
    dump_file = output_dir / f"{pid}_pid_analyze_dump.json"
    report = json.loads(dump_file.read_text(encoding="utf-8"))
    schema = json.loads(
        (REPO / "schemas" / "analyzer-report.schema.json").read_text(encoding="utf-8")
    )

    # 1. Integrity
    bad = []
    for e in entries:
        data = (evidence_dir / e["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != e["sha256"] or len(data) != e["bytes"]:
            bad.append(e["file"])
    check("evidence files match manifest SHA-256 and size", not bad,
          ", ".join(bad) or f"{len(entries)} files")

    # 2. Reproducibility
    def without_timestamp(doc: dict) -> dict:
        doc = json.loads(json.dumps(doc, default=str))
        doc["report"].pop("generated_at_utc", None)
        return doc

    fresh = replay_report.replay(output_dir)
    check("replay reproduces the dump", without_timestamp(fresh) == without_timestamp(report))

    # 3. Schema
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(report),
        key=lambda err: list(err.path),
    )
    detail = "; ".join(
        f"{'/'.join(str(p) for p in err.path)}: {err.message}" for err in errors[:3]
    )
    check("dump validates against analyzer-report schema", not errors, detail)

    # 4. Independent cross-checks (no analyzer code)
    by_command: dict[str, dict] = {}
    for e in entries:
        by_command.setdefault(e["command"], e)

    def raw(command: str) -> str:
        return (evidence_dir / by_command[command]["file"]).read_bytes().decode("utf-8", "replace")

    p = f"/proc/{pid}"
    smaps = raw(f"cat {p}/smaps")
    sums = {k: 0 for k in ("Rss", "Pss", "SwapPss", "Private_Clean", "Private_Dirty")}
    for line in smaps.splitlines():
        m = re.match(r"^(Rss|Pss|SwapPss|Private_Clean|Private_Dirty):\s+(\d+) kB", line)
        if m:
            sums[m.group(1)] += int(m.group(2))
    mem_totals = (report.get("memory") or {}).get("totals") or {}

    check("memory.rss_kb equals raw smaps Rss sum",
          mem_totals.get("rss_kb") == sums["Rss"],
          f"report {mem_totals.get('rss_kb')} vs raw {sums['Rss']}")
    check("memory.pss_kb equals raw smaps Pss sum",
          mem_totals.get("pss_kb") == sums["Pss"],
          f"report {mem_totals.get('pss_kb')} vs raw {sums['Pss']}")
    check("memory.uss_kb equals raw Private_Clean + Private_Dirty",
          mem_totals.get("uss_kb") == sums["Private_Clean"] + sums["Private_Dirty"],
          f"report {mem_totals.get('uss_kb')} vs raw {sums['Private_Clean'] + sums['Private_Dirty']}")
    check("memory.swap_pss_kb equals raw smaps SwapPss sum",
          mem_totals.get("swap_pss_kb") == sums["SwapPss"],
          f"report {mem_totals.get('swap_pss_kb')} vs raw {sums['SwapPss']}")

    dumpsys = raw(f"dumpsys meminfo {pid}")
    m = re.search(r"^\s*TOTAL\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", dumpsys, re.M)
    if m:
        dump_pss, dump_rss = int(m.group(1)), int(m.group(5))
        check("dumpsys TOTAL PSS equals raw Pss + SwapPss",
              dump_pss == sums["Pss"] + sums["SwapPss"],
              f"dumpsys {dump_pss} vs raw {sums['Pss'] + sums['SwapPss']}")
        check("dumpsys TOTAL RSS equals raw Rss",
              dump_rss == sums["Rss"], f"dumpsys {dump_rss} vs raw {sums['Rss']}")
    else:
        check("dumpsys TOTAL line present", False, "no TOTAL row found")

    stat_start = raw(f"cat {p}/stat")
    stat_end = (evidence_dir / next(e["file"] for e in entries if e["command"] == f"cat {p}/stat" and e["file"].endswith("stat_end.txt"))).read_bytes().decode("utf-8", "replace")

    def comm_and_starttime(stat: str) -> tuple[str, str]:
        comm = stat[stat.index("(") + 1 : stat.rindex(")")]
        fields = stat[stat.rindex(")") + 1 :].split()
        return comm, fields[19]  # starttime is field 22; fields[0] is field 3

    comm_s, start_s = comm_and_starttime(stat_start)
    comm_e, start_e = comm_and_starttime(stat_end)
    check("process unchanged during capture (comm and starttime)",
          (comm_s, start_s) == (comm_e, start_e),
          f"start {comm_s}/{start_s} vs end {comm_e}/{start_e}")
    identity = report.get("identity") or {}
    check("identity.name equals raw stat comm", identity.get("name") == comm_s,
          f"report {identity.get('name')} vs raw {comm_s}")

    oom = raw(f"cat {p}/oom_score").strip()
    adj = raw(f"cat {p}/oom_score_adj").strip()
    limits = report.get("limits_and_oom") or {}
    check("oom_score equals raw oom_score file", str(limits.get("oom_score")) == oom,
          f"report {limits.get('oom_score')} vs raw {oom}")
    check("oom_score_adj equals raw oom_score_adj file", str(limits.get("oom_score_adj")) == adj,
          f"report {limits.get('oom_score_adj')} vs raw {adj}")

    selinux_raw = raw(f"cat {p}/attr/current").replace("\x00", "").strip()
    security = report.get("security") or {}
    check("selinux_context equals raw attr/current", security.get("selinux_context") == selinux_raw,
          f"report {security.get('selinux_context')} vs raw {selinux_raw}")

    cap_hex = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", raw(f"cat {p}/status"), re.M)
    if cap_hex:
        bits = bin(int(cap_hex.group(1), 16)).count("1")
        check("capabilities_effective count equals set bits in raw CapEff",
              len(security.get("capabilities_effective") or []) == bits,
              f"report {len(security.get('capabilities_effective') or [])} vs raw {bits} bits")

    io_text = raw(f"cat {p}/io")
    rchar = re.search(r"^rchar:\s*(\d+)", io_text, re.M)
    check("io.rchar equals raw io file",
          rchar is not None and (report.get("io") or {}).get("rchar") == int(rchar.group(1)),
          f"report {(report.get('io') or {}).get('rchar')} vs raw {rchar.group(1) if rchar else None}")

    tids = [t for t in raw(f"ls {p}/task").split() if t.isdigit()]
    threads_total = ((report.get("threads") or {}).get("summary") or {}).get("total")
    check("thread count equals raw task directory", threads_total == len(tids),
          f"report {threads_total} vs raw {len(tids)}")

    fds = [t for t in raw(f"ls {p}/fd").split() if t.isdigit()]
    fd_total = ((report.get("file_descriptors") or {}).get("summary") or {}).get("total")
    check("fd count equals raw fd directory", fd_total == len(fds),
          f"report {fd_total} vs raw {len(fds)}")

    # 5. Verbose file, if present
    verbose_path = output_dir / f"{pid}_pid_analyze_verbose.json"
    if verbose_path.exists():
        verbose = json.loads(verbose_path.read_text(encoding="utf-8"))
        vschema = json.loads(
            (REPO / "schemas" / "analyzer-verbose.schema.json").read_text(encoding="utf-8")
        )
        verrors = sorted(
            jsonschema.Draft202012Validator(vschema).iter_errors(verbose),
            key=lambda err: list(err.path),
        )
        vdetail = "; ".join(
            f"{'/'.join(str(p) for p in err.path)}: {err.message}" for err in verrors[:3]
        )
        check("verbose file validates against verbose schema", not verrors, vdetail)
        mismatched = [
            item["file"]
            for item in verbose["evidence"]
            if hashlib.sha256((evidence_dir / item["file"]).read_bytes()).hexdigest()
            != item["sha256"]
        ]
        check("verbose file evidence hashes match files on disk", not mismatched,
              ", ".join(mismatched) or f"{len(verbose['evidence'])} items")
        check("verbose file embeds the same report as the dump",
              verbose["report"] == report)

    width = max(len(name) for name, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        failed += 0 if ok else 1
        suffix = f"  ({detail})" if detail else ""
        print(f"[{status}] {name.ljust(width)}{suffix}")
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
