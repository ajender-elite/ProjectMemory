"""Write <session>/<pid>_pid_analyze_dump.json: the full report plus every evidence file.

Usage:
    python -I tools/build_dump.py <session_dir>

The report is rebuilt from the evidence with the analyzer in this repository.
Each evidence item keeps its exact command, exit code, byte count and SHA-256,
and its content decoded as UTF-8 (invalid bytes replaced).
"""

import hashlib
import json
import pathlib
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import replay_report  # noqa: E402


def build_dump(session_dir: pathlib.Path) -> dict:
    manifest = json.loads((session_dir / "evidence" / "manifest.json").read_text(encoding="utf-8"))
    evidence_dir = session_dir / "evidence"

    items = []
    for entry in manifest["entries"]:
        raw = (evidence_dir / entry["file"]).read_bytes()
        item = {
            "command": entry["command"],
            "file": entry["file"],
            "exit_code": entry["exit_code"],
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "content": raw.decode("utf-8", "replace"),
            "content_encoding": "utf-8 (invalid bytes replaced)",
        }
        if "stderr" in entry:
            item["stderr"] = entry["stderr"]
        items.append(item)

    return {
        "schema_version": "3.0-dump",
        "session_id": manifest.get("session_id", session_dir.name),
        "pid": manifest["pid"],
        "adb_serial": manifest["adb_serial"],
        "captured_utc": manifest["captured_utc"],
        "analyzer_repo_commit": manifest.get("analyzer_repo_commit"),
        "report": replay_report.replay(session_dir),
        "evidence": items,
    }


def main() -> int:
    session_dir = pathlib.Path(sys.argv[1]).resolve()
    dump = build_dump(session_dir)
    out = session_dir / f"{dump['pid']}_pid_analyze_dump.json"
    out.write_text(json.dumps(dump, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(dump['evidence'])} evidence items)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
