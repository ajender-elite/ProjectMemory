"""Device, process and scenario metadata for a capture session.

collect(serial) reads build and device properties over adb. The result is stored
in the manifest's "metadata" block, which build_dump.py copies into the dump.

Usage (to annotate an existing session):
    python -I tools/session_metadata.py <adb_serial> <session_dir> [--scenario TEXT] [--backfill]

--backfill marks the block as read from the device after capture, not at capture
time. Use it only for sessions captured before metadata existed.
"""

import argparse
import datetime
import json
import pathlib
import subprocess
import sys

PROPERTIES = {
    "build_fingerprint": "ro.build.fingerprint",
    "android_release": "ro.build.version.release",
    "sdk_level": "ro.build.version.sdk",
    "build_id": "ro.build.id",
    "build_type": "ro.build.type",
    "product_model": "ro.product.model",
    "product_device": "ro.product.device",
    "hardware": "ro.hardware",
}


def collect(serial: str) -> dict[str, str]:
    command = "; ".join(f"echo {key}=$(getprop {prop})" for key, prop in PROPERTIES.items())
    proc = subprocess.run(["adb", "-s", serial, "shell", command], capture_output=True, text=True, timeout=60)
    values: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in PROPERTIES:
            values[key] = value.strip()
    missing = [key for key in PROPERTIES if key not in values]
    if missing:
        raise RuntimeError(f"could not read device properties: {', '.join(missing)}")
    return values


def metadata_block(serial: str, pid: int, process_name: str | None, scenario: str | None, source: str) -> dict:
    return {
        "pid": pid,
        "adb_serial": serial,
        "collected_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "scenario": scenario,
        "process_name": process_name,
        "device": collect(serial),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("serial")
    parser.add_argument("session_dir", type=pathlib.Path)
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--backfill", action="store_true")
    args = parser.parse_args()

    manifest_path = args.session_dir.resolve() / "evidence" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    process_name = None
    stat_file = manifest_path.parent / f"{manifest['pid']}_stat_start.txt"
    if stat_file.exists():
        stat = stat_file.read_text(encoding="utf-8", errors="replace")
        if "(" in stat and ")" in stat:
            process_name = stat[stat.index("(") + 1 : stat.rindex(")")]

    previous = manifest.get("metadata", {})
    scenario = args.scenario if args.scenario is not None else previous.get("scenario")
    source = "backfilled" if args.backfill else "capture"
    manifest["metadata"] = metadata_block(args.serial, manifest["pid"], process_name, scenario, source)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"metadata for pid {manifest['pid']}: fingerprint {manifest['metadata']['device']['build_fingerprint']}, "
          f"scenario {scenario!r}, source {source}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
