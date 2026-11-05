"""Find a shared library's dependencies and dependents on a device, including dlopen-loaded ones.

Usage:
    python -I tools/lib_deps.py <session_dir> <libname>

<libname> is a file name such as libaudiocorehal.qti.so, or a device path.

Two kinds of edge are used:
  static  - DT_NEEDED entries, read from the ELF headers.
  runtime - dlopen. These never appear in DT_NEEDED. They are found from the
            process's memory map: a mapped library that no static path from the
            executable reaches was loaded at runtime. The tool then searches the
            mapped binaries for its file name. That is a hint, not proof: the
            name may be built at run time, or only appear as data.

Dependencies: the DT_NEEDED closure of <libname>, pulled from the device on demand.
Dependents:   libraries that list <libname> in DT_NEEDED (direct and transitive),
              and mapped binaries whose bytes mention its name (dlopen hints).
              The search is bounded to the process's mapped set. It is not a
              scan of the whole device.

Files pulled from the device are cached under <session_dir>/libs/. Output goes to
<session_dir>/<device path with / replaced by _>_deps.json, so copies of one name from /system and /vendor get separate files.

Name resolution uses the search path below, not full linker namespace rules.
Names that cannot be found are listed under "unresolved".
"""

import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from AndroidProcessAnalyzer import ElfReader  # noqa: E402

SEARCH_DIRS = [
    "/vendor/lib64",
    "/system/lib64",
    "/apex/com.android.runtime/lib64/bionic",
]


class Device:
    def __init__(self, serial: str, cache_dir: pathlib.Path) -> None:
        self.serial = serial
        self.cache_dir = cache_dir
        self._listings: dict[str, set[str]] = {}
        self._elf = ElfReader()

    def _adb(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["adb", "-s", self.serial, *args], capture_output=True, timeout=120)

    def listing(self, directory: str) -> set[str]:
        if directory not in self._listings:
            proc = self._adb("shell", f"ls {directory}")
            names = set(proc.stdout.decode("utf-8", "replace").split()) if proc.returncode == 0 else set()
            self._listings[directory] = names
        return self._listings[directory]

    def local_copy(self, device_path: str) -> pathlib.Path:
        local = self.cache_dir / device_path.lstrip("/")
        if not local.exists():
            local.parent.mkdir(parents=True, exist_ok=True)
            proc = self._adb("pull", device_path, str(local))
            if proc.returncode != 0:
                raise RuntimeError(f"adb pull failed for {device_path}: {proc.stderr.decode('utf-8', 'replace')}")
        return local

    def elf_info(self, device_path: str) -> tuple[str | None, list[str]]:
        result = self._elf.read(self.local_copy(device_path).read_bytes())
        if not result.ok:
            return None, []
        return result.soname, result.needed


def resolve(name: str, parent_dir: str, device: Device) -> str | None:
    for directory in [parent_dir, *SEARCH_DIRS]:
        if name in device.listing(directory):
            return f"{directory}/{name}"
    return None


def session_inputs(session_dir: pathlib.Path) -> tuple[str | None, list[str]]:
    """Return (executable, mapped shared libraries) for the captured pid."""
    evidence = session_dir / "evidence"
    manifest = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    pid = manifest["pid"]
    exe = None
    exe_file = evidence / f"{pid}_exe_link.txt"
    if exe_file.exists():
        candidate = exe_file.read_text(encoding="utf-8", errors="replace").strip()
        exe = candidate if candidate.startswith("/") else None
    smaps = (evidence / f"{pid}_smaps.txt").read_text(encoding="utf-8", errors="replace")
    libs: list[str] = []
    for line in smaps.splitlines():
        m = re.match(r"^[0-9a-f]+-[0-9a-f]+ \S{4} \S+ \S+ \S+\s+(/\S+\.so[\w.-]*)\s*$", line)
        if m and m.group(1) not in libs:
            libs.append(m.group(1))
    return exe, libs


def forward_closure(start: str, device: Device) -> tuple[dict[str, dict], list[str]]:
    nodes: dict[str, dict] = {}
    unresolved: list[str] = []
    queue = [start]
    while queue:
        path = queue.pop(0)
        if path in nodes:
            continue
        _, needed = device.elf_info(path)
        parent = path.rsplit("/", 1)[0]
        resolved = {name: resolve(name, parent, device) for name in needed}
        for name, target in resolved.items():
            if target is None:
                unresolved.append(f"{name} (needed by {path})")
            elif target not in nodes:
                queue.append(target)
        nodes[path] = {"needed": needed, "resolved": resolved}
    return nodes, unresolved


def main() -> int:
    session_dir = pathlib.Path(sys.argv[1]).resolve()
    libname = sys.argv[2]
    manifest = json.loads((session_dir / "evidence" / "manifest.json").read_text(encoding="utf-8"))
    device = Device(manifest["adb_serial"], session_dir / "libs")

    exe, mapped = session_inputs(session_dir)
    candidates = ([exe] if exe else []) + mapped
    target_path = next((p for p in mapped if p == libname or p.rsplit("/", 1)[1] == libname), None)
    if target_path is None:
        target_path = next((f"{d}/{libname}" for d in SEARCH_DIRS if libname in device.listing(d)), None)
    if target_path is None:
        print(f"error: {libname} not found in the process's mapped libraries or the search path", file=sys.stderr)
        return 1
    target_name = target_path.rsplit("/", 1)[1]
    target_soname, _ = device.elf_info(target_path)

    # Static reach: what the executable pulls in through DT_NEEDED.
    static_nodes, _ = forward_closure(exe, device) if exe else ({}, [])
    static_reach = set(static_nodes)

    # Bytes of every candidate, read once, for dlopen name hints.
    blobs = {p: device.local_copy(p).read_bytes() for p in candidates}

    def mentions(path: str, name: str) -> bool:
        return name.encode("utf-8") in blobs[path]

    infos = {p: device.elf_info(p) for p in candidates}

    # A runtime root is a mapped library that is not statically reachable and that no
    # other mapped library lists in DT_NEEDED. Such a library was dlopen-ed (or its
    # name was found at run time). A library that some mapped library needs is
    # explained by that parent, so it is not a root.
    needed_by_mapped: dict[str, list[str]] = {}
    for parent, (_, needed) in infos.items():
        for name in needed:
            needed_by_mapped.setdefault(name, []).append(parent)
    runtime_roots = []
    for path in mapped:
        if path in static_reach:
            continue
        names = {path.rsplit("/", 1)[1], infos[path][0]} - {None}
        if not any(name in needed_by_mapped for name in names):
            runtime_roots.append(path)

    root_hints = []
    for root in runtime_roots:
        loaders = [p for p in candidates if p != root and mentions(p, root.rsplit("/", 1)[1])]
        root_hints.append({"path": root, "loader_hints": loaders})

    # DT_NEEDED dependents within the mapped set, transitively.
    direct = sorted(
        p for p, (_, needed) in infos.items()
        if p != target_path and ({target_name, target_soname} & set(needed))
    )
    transitive: set[str] = set(direct)
    frontier = list(direct)
    while frontier:
        current = frontier.pop()
        names = {current.rsplit("/", 1)[1], infos[current][0]} - {None}
        for p, (_, needed) in infos.items():
            if p == target_path or p in transitive:
                continue
            if names & set(needed):
                transitive.add(p)
                frontier.append(p)

    dlopen_hints = sorted(p for p in candidates if p != target_path and mentions(p, target_name))

    deps, unresolved = forward_closure(target_path, device)
    result = {
        "library": target_path,
        "soname": target_soname,
        "loaded_by_executable_statically": target_path in static_reach,
        "dependencies": {
            "closure": sorted(p for p in deps if p != target_path),
            "direct": deps[target_path]["resolved"],
            "unresolved": unresolved,
        },
        "dependents": {
            "scope": f"executable and {len(mapped)} shared libraries mapped by pid {manifest['pid']}",
            "static_direct": direct,
            "static_transitive": sorted(transitive - set(direct)),
            "runtime_hints": dlopen_hints,
        },
        "runtime_loaded": {
            "method": "mapped but not reachable from the executable through DT_NEEDED",
            "roots": root_hints,
        },
        "notes": [
            "Dependency names are resolved with the search path in this tool, not full linker namespace rules.",
            "runtime_hints are file-name matches in mapped binaries. A name built at run time will not match.",
        ],
    }
    out = session_dir / f"{target_path.lstrip('/').replace('/', '_')}_deps.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(target_path)
    print(f"  loaded statically (DT_NEEDED from executable): {result['loaded_by_executable_statically']}")
    print("dependencies (direct):")
    for name, path in result["dependencies"]["direct"].items():
        print(f"  {name} -> {path or 'UNRESOLVED'}")
    print(f"dependencies (closure): {len(result['dependencies']['closure'])} libraries")
    print(f"dependents (static, direct): {len(direct)}")
    for path in direct:
        print(f"  {path}")
    print(f"dependents (runtime hints): {len(dlopen_hints)}")
    for path in dlopen_hints:
        print(f"  {path}")
    print(f"runtime-loaded roots (dlopen, not reachable statically): {len(runtime_roots)}")
    for hint in root_hints:
        loaders = ", ".join(pathlib.PurePosixPath(p).name for p in hint["loader_hints"]) or "no hint"
        print(f"  {hint['path']}  <- {loaders}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
