"""Rebuild <pid>_pid_analyze_dump.json from captured evidence, with no device access.

Usage:
    python -I tools/replay_report.py <output_dir>

Reads <output_dir>/evidence/manifest.json and the raw files beside it, runs the
analyzer from this repository, and writes <output_dir>/<pid>_pid_analyze_dump.json.
"""

import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]

# Same section set as the live run. environment is excluded: it can hold secrets.
SECTIONS = [
    "identity",
    "memory",
    "dependencies",
    "threads",
    "file_descriptors",
    "cpu",
    "io",
    "limits_and_oom",
    "security",
    "binder",
    "android_meminfo",
    "cgroups_namespaces",
]


class ReplayAdb:
    """Stands in for AdbClient: answers shell() from captured evidence files."""

    def __init__(self, evidence_dir: pathlib.Path, entries: list[dict], normalize):
        self.evidence_dir = evidence_dir
        self.normalize = normalize
        self.serial = None
        self.timeout = 30
        self.by_command: dict[str, dict] = {}
        for entry in entries:
            # stat is captured twice (start and end). The analyzer used the first
            # capture live, so the first one is kept.
            self.by_command.setdefault(entry["command"], entry)

    def shell(self, script: str) -> str:
        entry = self.by_command.get(script)
        if entry is None:
            raise RuntimeError(f"no evidence captured for: {script}")
        if entry["exit_code"] != 0:
            # Same failure path as AdbClient.shell().
            raise RuntimeError(f"adb shell failed: {entry.get('stderr', '')}")
        raw = (self.evidence_dir / entry["file"]).read_bytes()
        return self.normalize(raw.decode("utf-8", "replace"))


def load_manifest(output_dir: pathlib.Path) -> dict:
    path = output_dir / "evidence" / "manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


def replay(output_dir: pathlib.Path) -> dict:
    sys.path.insert(0, str(REPO))
    import AndroidProcessAnalyzer as analyzer

    manifest = load_manifest(output_dir)
    client = ReplayAdb(
        output_dir / "evidence",
        manifest["entries"],
        analyzer.AdbClient._normalize_text,
    )
    ctx = analyzer.Context(
        adb_client=client,
        serial=None,
        pid=manifest["pid"],
        access_level=analyzer.AccessLevel(),
        sections=set(SECTIONS),
        elf_cache_dir=None,
        sample_duration=None,
        sample_interval=None,
        no_cross_process=False,
        no_deps=False,
        include_env=False,
        clk_tck=100,
        max_list=100,
        top_n=5,
        sort_by="pss",
    )
    result = analyzer.Orchestrator(ctx).collect_all()
    return analyzer.build_report(result)


def dump_path(output_dir: pathlib.Path, pid: int) -> pathlib.Path:
    return output_dir / f"{pid}_pid_analyze_dump.json"


def main() -> int:
    output_dir = pathlib.Path(sys.argv[1]).resolve()
    pid = load_manifest(output_dir)["pid"]
    report = replay(output_dir)
    out = dump_path(output_dir, pid)
    out.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
