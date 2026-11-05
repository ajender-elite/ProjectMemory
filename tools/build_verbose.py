"""Build <pid>_pid_analyze_verbose.json: the dump plus every evidence file, inline.

Usage:
    python -I tools/build_verbose.py <output_dir>

Each evidence item keeps the exact command, exit code, byte count and SHA-256
from the manifest, plus its content decoded as UTF-8 (invalid bytes replaced).
"""

import hashlib
import json
import pathlib
import sys


def main() -> int:
    output_dir = pathlib.Path(sys.argv[1]).resolve()
    evidence_dir = output_dir / "evidence"
    manifest = json.loads((evidence_dir / "manifest.json").read_text(encoding="utf-8"))
    pid = manifest["pid"]
    report = json.loads(
        (output_dir / f"{pid}_pid_analyze_dump.json").read_text(encoding="utf-8")
    )

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

    verbose = {
        "schema_version": "3.0-verbose",
        "pid": pid,
        "adb_serial": manifest["adb_serial"],
        "captured_utc": manifest["captured_utc"],
        "analyzer_repo_commit": manifest.get("analyzer_repo_commit"),
        "report": report,
        "evidence": items,
    }
    out = output_dir / f"{pid}_pid_analyze_verbose.json"
    out.write_text(json.dumps(verbose, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(items)} evidence items)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
