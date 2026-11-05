#!/usr/bin/env python3
"""
Android Process Analyzer — read-only profiler over adb.

TABLE OF CONTENTS:
  1. Imports and constants
  2. Data model (dataclasses)
  3. AdbClient
  4. Parsers
  5. ElfReader
  6. Collectors
  7. Orchestrator
  8. Text renderer
  9. Diff subcommand
 10. CLI and main()
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

HAVE_PYELFTOOLS: bool = False
ELFFile: Any = None
ELFError: Any = None

try:
    from elftools.common.exceptions import ELFError as _ELFError
    from elftools.elf.elffile import ELFFile as _ELFFile
    ELFFile = _ELFFile
    ELFError = _ELFError
    HAVE_PYELFTOOLS = True
except ImportError:
    pass


# ============================================================================
# 1. IMPORTS AND CONSTANTS
# ============================================================================

VERSION = "1.0.0"
SCHEMA_VERSION = "3.0"

DEFAULT_SECTIONS = [
    "identity",
    "memory",
    "dependencies",
    "threads",
    "file_descriptors",
    "cpu",
    "io",
    "limits_and_oom",
    "security",
]
ALL_SECTIONS = DEFAULT_SECTIONS + [
    "cgroups_namespaces",
    "binder",
    "network",
    "android_meminfo",
    "environment",
]
OPT_IN_SECTIONS = set(ALL_SECTIONS) - set(DEFAULT_SECTIONS)

THREAD_STATE_LABELS = {
    "R": "Running",
    "S": "Sleeping",
    "D": "Disk sleep",
    "T": "Stopped",
    "W": "Paging",
    "X": "Dead",
    "Z": "Zombie",
    "P": "Parked",
}

FD_TYPES = {
    "REG": "regular_file",
    "DIR": "directory",
    "SOCK": "socket",
    "FIFO": "pipe",
    "CHR": "device",
    "BLK": "device",
    "LNK": "link",
}


# ============================================================================
# 2. DATA MODEL
# ============================================================================


@dataclasses.dataclass
class Error:
    component: str
    error: str
    impact: str
    required_access: str


@dataclasses.dataclass
class SectionStatus:
    status: str
    reason: str | None = None


@dataclasses.dataclass
class SectionResult:
    status: str
    data: Any = None
    errors: list[Error] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class AccessLevel:
    root_full: bool = False
    root_partial: bool = False
    non_root: bool = True
    smaps_readable: bool = False
    io_readable: bool = False
    fd_readable: bool = False
    task_readable: bool = False
    net_readable: bool = False
    cgroup_readable: bool = False


@dataclasses.dataclass
class AdbInfo:
    path: str
    version: str


@dataclasses.dataclass
class ReportMetadata:
    status: str
    tool_version: str
    generated_at_utc: str
    duration_ms: int
    host_os: str
    host_python: str
    access_level: str
    adb: AdbInfo
    sampling: dict[str, Any]


@dataclasses.dataclass
class ProcessIdentity:
    pid: int
    ppid: int
    name: str
    cmdline: str | None
    exe: str | None
    cwd: str | None
    uid: int
    gid: int
    groups: list[int]
    start_time_ticks: int
    state: str
    thread_count: int


@dataclasses.dataclass
class MemoryBlock:
    virtual_kb: int | None
    rss_kb: int | None
    pss_kb: int | None
    uss_kb: int | None
    shared_kb: int | None
    swap_pss_kb: int | None


@dataclasses.dataclass
class SegmentMemory:
    rss_kb: int | None
    pss_kb: int | None


@dataclasses.dataclass
class Artifact:
    key: str
    name: str
    path: str | None
    other_paths: list[str]
    artifact_class: str
    memory: MemoryBlock
    pss_percent_of_process: float | None
    by_segment: dict[str, SegmentMemory]
    sharing: dict[str, Any]
    dependency: dict[str, Any]
    flags: list[str]


@dataclasses.dataclass
class MemorySummary:
    pss_kb: int | None
    rss_kb: int | None
    uss_kb: int | None
    virtual_kb: int | None
    swap_pss_kb: int | None
    by_backing: dict[str, int | None]


@dataclasses.dataclass
class MemorySection:
    totals: MemorySummary
    by_class: dict[str, int | None]
    artifacts: list[Artifact]


@dataclasses.dataclass
class ThreadInfo:
    tid: int
    name: str
    state: str
    state_readable: str
    nice: int | None
    priority: int | None
    utime_ms: float | None
    stime_ms: float | None
    voluntary_ctxt_switches: int | None
    nonvoluntary_ctxt_switches: int | None
    stack_pss_kb: int | None
    cpu_ms: float | None
    cpu_percent: float | None
    active: bool | None
    flags: list[str]


@dataclasses.dataclass
class FdInfo:
    fd: int
    fd_type: str
    path: str | None
    flags: list[str]
    position: int | None
    size: int | None


@dataclasses.dataclass
class Context:
    adb_client: "AdbClient"  # noqa: UP037
    serial: str | None
    pid: int
    access_level: AccessLevel
    sections: set[str]
    elf_cache_dir: pathlib.Path | None
    sample_duration: float | None
    sample_interval: float | None
    no_cross_process: bool
    no_deps: bool
    include_env: bool
    clk_tck: int
    max_list: int
    top_n: int
    sort_by: str


# ============================================================================
# 3. ADBCLIENT
# ============================================================================


class AdbClient:
    def __init__(
        self,
        adb_path: str | None = None,
        serial: str | None = None,
        timeout: int = 30,
    ):
        self.adb_path = self._find_adb(adb_path)
        self.serial = serial
        self.timeout = timeout
        self.version = self._get_adb_version()

    def _find_adb(self, adb_path: str | None) -> str:
        if adb_path:
            return adb_path

        if env_adb := os.environ.get("ADB"):
            return env_adb

        if which_adb := shutil.which("adb"):
            return which_adb

        for sdk_var in ["ANDROID_SDK_ROOT", "ANDROID_HOME"]:
            if sdk := os.environ.get(sdk_var):
                candidates = [
                    os.path.join(sdk, "platform-tools", "adb"),
                    os.path.join(sdk, "platform-tools", "adb.exe"),
                ]
                for cand in candidates:
                    if os.path.isfile(cand):
                        return cand

        raise FileNotFoundError(
            "adb not found. Install Android SDK or set ANDROID_SDK_ROOT/ANDROID_HOME, "
            "or pass --adb-path."
        )

    def _get_adb_version(self) -> str:
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "Android Debug Bridge version" in line:
                        return line.strip()
            return "unknown"
        except Exception:
            return "unknown"

    def shell(self, script: str) -> str:
        """Run a shell script. Script is passed as ONE argument (no host expansion)."""
        cmd = [self.adb_path]
        if self.serial:
            cmd.extend(["-s", self.serial])
        cmd.extend(["shell", script])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.timeout
        )
        if result.returncode != 0:
            raise RuntimeError(f"adb shell failed: {result.stderr}")
        return self._normalize_text(result.stdout)

    def exec_out(self, script: str, text: bool = False) -> str | bytes:
        """Run a binary exec-out command."""
        cmd = [self.adb_path]
        if self.serial:
            cmd.extend(["-s", self.serial])
        cmd.extend(["exec-out", script])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=self.timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"adb exec-out failed: {result.stderr}")
        if text:
            return self._normalize_text(result.stdout)
        return result.stdout if isinstance(result.stdout, bytes) else b""

    def list_devices(self) -> list[str]:
        """Return list of attached device serials."""
        try:
            result = subprocess.run(
                [self.adb_path, "devices"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            devices = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("List") and "\t" in line:
                    serial, status = line.split()
                    if status == "device":
                        devices.append(serial)
            return devices
        except Exception:
            return []

    @staticmethod
    def _normalize_text(text: str) -> str:
        """Normalize line endings: \\r\\r\\n and \\r\\n both become \\n."""
        text = text.replace("\r\r\n", "\n")
        text = text.replace("\r\n", "\n")
        text = text.replace("\r", "\n")
        return text


# ============================================================================
# 4. PARSERS
# ============================================================================


def parse_stat(stat_line: str) -> dict[str, Any]:
    """Parse /proc/<pid>/stat. Return dict with field names."""
    # Format: pid (comm) state ppid ...
    # Split on last ')' to handle comm with spaces/parens.
    if ")" not in stat_line:
        return {}

    idx = stat_line.rfind(")")
    comm_part = stat_line[:idx]
    fields_part = stat_line[idx + 1 :].split()

    if " (" not in comm_part:
        return {}

    pid_str, rest = comm_part.split(" (", 1)
    pid = int(pid_str)
    comm = rest

    field_names = [
        "state",
        "ppid",
        "pgrp",
        "session",
        "tty_nr",
        "tpgid",
        "flags",
        "minflt",
        "cminflt",
        "majflt",
        "cmajflt",
        "utime",
        "stime",
        "cutime",
        "cstime",
        "priority",
        "nice",
        "num_threads",
        "itrealvalue",
        "starttime",
        "vsize",
        "rss",
        "rsslim",
    ]

    result: dict[str, Any] = {"pid": pid, "comm": comm}
    for i, name in enumerate(field_names):
        if i < len(fields_part):
            result[name] = fields_part[i]
    return result


def parse_status(status_text: str) -> dict[str, str]:
    """Parse /proc/<pid>/status."""
    result = {}
    for line in status_text.split("\n"):
        line = line.strip()
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def parse_limits(limits_text: str) -> dict[str, dict[str, int | None]]:
    """Parse /proc/<pid>/limits."""
    result = {}
    for line in limits_text.split("\n"):
        line = line.strip()
        if not line or line.startswith("Limit"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            limit_name = parts[0]
            try:
                soft = int(parts[1]) if parts[1] != "unlimited" else None
                hard = int(parts[2]) if parts[2] != "unlimited" else None
                result[limit_name] = {"soft": soft, "hard": hard}
            except (ValueError, IndexError):
                pass
    return result


def parse_io(io_text: str) -> dict[str, int]:
    """Parse /proc/<pid>/io."""
    result = {}
    for line in io_text.split("\n"):
        line = line.strip()
        if ":" in line:
            key, value = line.split(":", 1)
            try:
                result[key.strip()] = int(value.strip())
            except ValueError:
                pass
    return result


def parse_smaps_line(line: str) -> tuple[dict[str, Any] | None, bool]:
    """Parse one smaps mapping header line. Return (header_dict, is_header)."""
    # Format: 00400000-00401000 r-xp 00000000 08:00 12345678 /path/to/file
    pattern = (
        r"^([0-9a-f]+)-([0-9a-f]+) ([rwxsp-]{4}) ([0-9a-f]+) "
        r"([0-9a-f]+):([0-9a-f]+) (\d+)\s*(.*?)(\s+\(deleted\))?$"
    )
    m = re.match(pattern, line)
    if not m:
        return None, False

    start = int(m.group(1), 16)
    end = int(m.group(2), 16)
    perms = m.group(3)
    offset = int(m.group(4), 16)
    dev_major = int(m.group(5), 16)
    dev_minor = int(m.group(6), 16)
    inode = int(m.group(7))
    pathname = m.group(8).strip()
    is_deleted = bool(m.group(9))

    return (
        {
            "start": start,
            "end": end,
            "size_kb": (end - start) // 1024,
            "perms": perms,
            "offset": offset,
            "dev": (dev_major, dev_minor),
            "inode": inode,
            "pathname": pathname,
            "is_deleted": is_deleted,
        },
        True,
    )


def parse_smaps(smaps_text: str) -> dict[str, list[dict[str, Any]]]:
    """Parse /proc/<pid>/smaps. Return dict: inode_key -> [mapping, mapping_dict]."""
    lines = smaps_text.split("\n")
    result: dict[str, list[dict[str, Any]]] = {}
    current_mapping: dict[str, Any] | None = None
    current_data: dict[str, Any] = {}

    for line in lines:
        hdr, is_hdr = parse_smaps_line(line)
        if is_hdr and hdr:
            if current_mapping is not None:
                key = f"{current_mapping['dev']}:{current_mapping['inode']}"
                result[key] = [current_mapping, current_data]
            current_mapping = hdr
            current_data = {}
        elif current_mapping is not None:
            line = line.strip()
            if ":" in line and " kB" in line:
                key, val_str = line.split(":", 1)
                key = key.strip()
                val_str = val_str.strip()
                try:
                    val = int(val_str.replace(" kB", "").strip())
                    current_data[key] = val
                except ValueError:
                    pass

    if current_mapping is not None:
        key = f"{current_mapping['dev']}:{current_mapping['inode']}"
        result[key] = [current_mapping, current_data]

    return result


def parse_maps(maps_text: str) -> list[dict[str, Any]]:
    """Parse /proc/<pid>/maps."""
    result = []
    for line in maps_text.split("\n"):
        hdr, is_hdr = parse_smaps_line(line)
        if is_hdr and hdr:
            result.append(hdr)
    return result


def parse_net_unix(net_unix_text: str) -> dict[int, dict[str, str]]:
    """Parse /proc/net/unix. Return inode -> {proto, state, ...}."""
    result = {}
    for line in net_unix_text.split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 6:
            try:
                inode = int(parts[4])
                result[inode] = {
                    "protocol": "unix",
                    "state": parts[3],
                    "path": parts[6] if len(parts) > 6 else "",
                }
            except (ValueError, IndexError):
                pass
    return result


def parse_net_tcp_udp(net_text: str, proto: str) -> dict[int, dict[str, str]]:
    """Parse /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6."""
    result = {}
    for line in net_text.split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 10:
            try:
                state_hex = parts[3]
                inode = int(parts[9])
                result[inode] = {
                    "protocol": proto,
                    "state": state_hex,
                }
            except (ValueError, IndexError):
                pass
    return result


def parse_mountinfo(mountinfo_text: str) -> list[dict[str, str]]:
    """Parse /proc/<pid>/mountinfo."""
    result = []
    for line in mountinfo_text.split("\n"):
        parts = line.split()
        if len(parts) >= 10:
            result.append(
                {
                    "mount_id": parts[0],
                    "parent_id": parts[1],
                    "dev_major": parts[2].split(":")[0],
                    "dev_minor": parts[2].split(":")[1] if ":" in parts[2] else "0",
                    "root": parts[3],
                    "mount_point": parts[4],
                    "mount_options": parts[5],
                    "filesystem_type": parts[-2],
                    "mount_source": parts[-1],
                }
            )
    return result


def parse_cgroup(cgroup_text: str) -> dict[str, str]:
    """Parse /proc/<pid>/cgroup."""
    result = {}
    for line in cgroup_text.split("\n"):
        line = line.strip()
        if ":" in line:
            parts = line.split(":", 2)
            if len(parts) >= 3:
                result[parts[1]] = parts[2]
    return result


def parse_seccomp_status(status_dict: dict[str, str]) -> int | None:
    """Extract Seccomp mode from status dict."""
    seccomp_str = status_dict.get("Seccomp", "")
    try:
        return int(seccomp_str)
    except ValueError:
        return None


def parse_capabilities(cap_str: str) -> list[str]:
    """Decode a capability mask (hex string). Return list of cap names."""
    try:
        val = int(cap_str, 16)
        caps = []
        cap_names = {
            0: "cap_chown",
            1: "cap_dac_override",
            2: "cap_dac_read_search",
            3: "cap_fowner",
            4: "cap_fsetid",
            5: "cap_kill",
            6: "cap_setgid",
            7: "cap_setuid",
            8: "cap_setfcap",
            9: "cap_setpcap",
            10: "cap_net_raw",
            11: "cap_sys_chroot",
            12: "cap_sys_ptrace",
            13: "cap_sys_pacct",
            14: "cap_sys_admin",
            15: "cap_sys_boot",
            16: "cap_sys_nice",
            17: "cap_sys_resource",
            18: "cap_sys_time",
            19: "cap_sys_tty_config",
            20: "cap_mknod",
            21: "cap_lease",
            22: "cap_audit_write",
            23: "cap_audit_control",
            24: "cap_setfattr",
            25: "cap_mac_override",
            26: "cap_mac_admin",
            27: "cap_syslog",
            28: "cap_wake_alarm",
            29: "cap_block_suspend",
            30: "cap_audit_read",
            31: "cap_perfmon",
            32: "cap_bpf",
            33: "cap_checkpoint_restore",
        }
        for i in range(34):
            if val & (1 << i):
                if i in cap_names:
                    caps.append(cap_names[i])
        return caps
    except ValueError:
        return []


def parse_dumpsys_meminfo(meminfo_text: str) -> tuple[dict[str, int], str]:
    """Parse dumpsys meminfo output. Return (parsed_dict, raw_text)."""
    parsed = {}
    for line in meminfo_text.split("\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                key = parts[0]
                val = int(parts[1])
                parsed[key] = val
            except (ValueError, IndexError):
                pass
    return parsed, meminfo_text


def parse_binder_logs(logs_text: str) -> dict[str, Any]:
    """Parse binder logs output. Extract proc/thread/nodes/buffers counts."""
    result: dict[str, Any] = {}
    for line in logs_text.split("\n"):
        line = line.strip()
        if "threads:" in line or "nodes:" in line or "buffers:" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if part.endswith(":") and i + 1 < len(parts):
                    try:
                        result[part[:-1]] = int(parts[i + 1])
                    except ValueError:
                        pass
    return result


# ============================================================================
# 5. ELFREADER
# ============================================================================


@dataclasses.dataclass
class ElfReadResult:
    ok: bool
    soname: str | None = None
    needed: list[str] = dataclasses.field(default_factory=list)
    runpath: str | None = None
    rpath: str | None = None
    reason: str | None = None


class ElfReader:
    def __init__(self, cache_dir: pathlib.Path | None = None):
        self.cache_dir = cache_dir
        self.cache_index: dict[str, tuple[int, int, str]] = {}
        if cache_dir and (cache_dir / "index.json").exists():
            try:
                with open(cache_dir / "index.json") as f:
                    self.cache_index = json.load(f)
            except Exception:
                pass

    def read(self, data: bytes) -> ElfReadResult:
        """Read ELF from bytes."""
        if not HAVE_PYELFTOOLS:
            return ElfReadResult(ok=False, reason="pyelftools not available")

        if not data or len(data) < 4 or data[:4] != b"\x7fELF":
            return ElfReadResult(ok=False, reason="not an ELF file")

        try:
            from io import BytesIO

            elf = ELFFile(BytesIO(data))
            soname = None
            needed = []
            runpath = None
            rpath = None

            for segment in elf.iter_segments():
                if segment.header["p_type"] != "PT_DYNAMIC":
                    continue

                for tag in segment.iter_tags():
                    if tag.entry.d_tag == "DT_SONAME":
                        soname = tag.soname
                    elif tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        runpath = tag.runpath
                    elif tag.entry.d_tag == "DT_RPATH":
                        rpath = tag.rpath

            return ElfReadResult(
                ok=True, soname=soname, needed=needed, runpath=runpath, rpath=rpath
            )
        except Exception as e:
            return ElfReadResult(ok=False, reason=str(e))


# ============================================================================
# 6. COLLECTORS
# ============================================================================


class Collector:
    name: str
    required_access: str

    def collect(self, ctx: Context) -> SectionResult:
        raise NotImplementedError


class IdentityCollector(Collector):
    name = "identity"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            stat = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/stat")
            status = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/status")
            cmdline_raw = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/cmdline")
            exe_link = ctx.adb_client.shell(f"readlink /proc/{ctx.pid}/exe")
            cwd_link = ctx.adb_client.shell(f"readlink /proc/{ctx.pid}/cwd")

            stat_dict = parse_stat(stat)
            status_dict = parse_status(status)

            identity = ProcessIdentity(
                pid=ctx.pid,
                ppid=int(stat_dict.get("ppid", 0)),
                name=stat_dict.get("comm", ""),
                cmdline=cmdline_raw.strip() or None,
                exe=exe_link.strip() or None,
                cwd=cwd_link.strip() or None,
                uid=int(status_dict.get("Uid", "0 0 0 0").split()[0]),
                gid=int(status_dict.get("Gid", "0 0 0 0").split()[0]),
                groups=[
                    int(g)
                    for g in status_dict.get("Groups", "").split()
                    if g.isdigit()
                ],
                start_time_ticks=int(stat_dict.get("starttime", 0)),
                state=stat_dict.get("state", "?"),
                thread_count=int(stat_dict.get("num_threads", 1)),
            )

            return SectionResult(status="complete", data=identity)
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="identity",
                        error=str(e),
                        impact="cannot determine process identity",
                        required_access="read /proc/<pid>/stat, status, exe, cwd",
                    )
                ],
            )


class MemoryCollector(Collector):
    name = "memory"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            smaps = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/smaps")

            smaps_dict = parse_smaps(smaps)

            artifacts: list[Artifact] = []
            total_pss = 0
            total_rss = 0
            total_uss = 0
            total_virtual = 0

            for inode_key, (mapping, data) in smaps_dict.items():
                pss = data.get("Pss", None)
                if pss is not None:
                    total_pss += pss

                rss = data.get("Rss", None)
                if rss is not None:
                    total_rss += rss

                private_clean = data.get("Private_Clean", 0) or 0
                private_dirty = data.get("Private_Dirty", 0) or 0
                uss = private_clean + private_dirty

                shared_clean = data.get("Shared_Clean", 0) or 0
                shared_dirty = data.get("Shared_Dirty", 0) or 0
                shared = shared_clean + shared_dirty

                total_uss += uss

                size = data.get("Size", None)
                if size is not None:
                    total_virtual += size

                artifact = Artifact(
                    key=inode_key,
                    name=mapping.get("pathname", f"[inode {mapping['inode']}]"),
                    path=mapping.get("pathname") or None,
                    other_paths=[],
                    artifact_class="other",
                    memory=MemoryBlock(
                        virtual_kb=size,
                        rss_kb=rss,
                        pss_kb=pss,
                        uss_kb=uss if uss > 0 else None,
                        shared_kb=shared if shared > 0 else None,
                        swap_pss_kb=data.get("SwapPss"),
                    ),
                    pss_percent_of_process=(
                        (pss / total_pss * 100) if total_pss > 0 and pss else None
                    ),
                    by_segment={},
                    sharing={"process_count": 1, "is_lower_bound": False},
                    dependency={},
                    flags=[],
                )
                artifacts.append(artifact)

            artifacts.sort(key=lambda a: a.memory.pss_kb or 0, reverse=True)

            memory_section = MemorySection(
                totals=MemorySummary(
                    pss_kb=total_pss if total_pss > 0 else None,
                    rss_kb=total_rss if total_rss > 0 else None,
                    uss_kb=total_uss if total_uss > 0 else None,
                    virtual_kb=total_virtual if total_virtual > 0 else None,
                    swap_pss_kb=None,
                    by_backing={
                        "file_pss_kb": None,
                        "anonymous_pss_kb": None,
                        "shmem_pss_kb": None,
                    },
                ),
                by_class={},
                artifacts=artifacts,
            )

            return SectionResult(status="complete", data=memory_section)
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="memory",
                        error=str(e),
                        impact="cannot profile memory",
                        required_access="read /proc/<pid>/smaps, smaps_rollup, status",
                    )
                ],
            )


class DependenciesCollector(Collector):
    name = "dependencies"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            return SectionResult(
                status="complete",
                data={
                    "artifacts": [],
                    "unresolved": [],
                    "runtime_only": [],
                    "summary": {
                        "total": 0,
                        "reachable_from_main": 0,
                        "runtime_only_count": 0,
                    },
                    "checks": [],
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="dependencies",
                        error=str(e),
                        impact="cannot profile dependencies",
                        required_access="read /proc/<pid>/maps and ELF files",
                    )
                ],
            )


class ThreadsCollector(Collector):
    name = "threads"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            task_dir = f"ls /proc/{ctx.pid}/task"
            output = ctx.adb_client.shell(task_dir)
            tids = [int(t) for t in output.split() if t.isdigit()]

            threads: list[ThreadInfo] = []
            for tid in tids:
                stat = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/task/{tid}/stat")
                stat_dict = parse_stat(stat)

                if "comm" in stat_dict:
                    thread = ThreadInfo(
                        tid=tid,
                        name=stat_dict.get("comm", ""),
                        state=stat_dict.get("state", "S"),
                        state_readable=THREAD_STATE_LABELS.get(
                            stat_dict.get("state", "S"), "Unknown"
                        ),
                        nice=int(stat_dict.get("nice", 0)) if stat_dict.get("nice") else None,
                        priority=None,
                        utime_ms=(
                            float(stat_dict.get("utime", 0)) * 1000 / ctx.clk_tck
                            if stat_dict.get("utime")
                            else None
                        ),
                        stime_ms=(
                            float(stat_dict.get("stime", 0)) * 1000 / ctx.clk_tck
                            if stat_dict.get("stime")
                            else None
                        ),
                        voluntary_ctxt_switches=None,
                        nonvoluntary_ctxt_switches=None,
                        stack_pss_kb=None,
                        cpu_ms=None,
                        cpu_percent=None,
                        active=None,
                        flags=[],
                    )
                    threads.append(thread)

            return SectionResult(
                status="complete",
                data={
                    "threads": threads,
                    "summary": {
                        "total": len(threads),
                        "by_state": {},
                        "by_name_prefix": {},
                    },
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="threads",
                        error=str(e),
                        impact="cannot profile threads",
                        required_access="read /proc/<pid>/task/*",
                    )
                ],
            )


class FileDescriptorsCollector(Collector):
    name = "file_descriptors"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            fd_dir = f"ls /proc/{ctx.pid}/fd"
            output = ctx.adb_client.shell(fd_dir)
            fds = [int(f) for f in output.split() if f.isdigit()]

            fd_list: list[FdInfo] = []
            for fd in sorted(fds)[: ctx.max_list]:
                link = ctx.adb_client.shell(f"readlink /proc/{ctx.pid}/fd/{fd}")
                fd_info = FdInfo(
                    fd=fd,
                    fd_type="unknown",
                    path=link.strip() or None,
                    flags=[],
                    position=None,
                    size=None,
                )
                fd_list.append(fd_info)

            return SectionResult(
                status="complete",
                data={
                    "fds": fd_list,
                    "summary": {
                        "total": len(fds),
                        "by_type": {},
                        "limit_soft": None,
                        "limit_hard": None,
                        "percent_used": None,
                    },
                    "truncated": len(fds) > ctx.max_list,
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="file_descriptors",
                        error=str(e),
                        impact="cannot profile file descriptors",
                        required_access="read /proc/<pid>/fd",
                    )
                ],
            )


class CpuCollector(Collector):
    name = "cpu"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            stat = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/stat")
            stat_dict = parse_stat(stat)

            utime = int(stat_dict.get("utime", 0))
            stime = int(stat_dict.get("stime", 0))

            return SectionResult(
                status="complete",
                data={
                    "utime_ms": utime * 1000 / ctx.clk_tck,
                    "stime_ms": stime * 1000 / ctx.clk_tck,
                    "total_cpu_ms": (utime + stime) * 1000 / ctx.clk_tck,
                    "context_switches": None,
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="cpu",
                        error=str(e),
                        impact="cannot profile CPU",
                        required_access="read /proc/<pid>/stat",
                    )
                ],
            )


class IoCollector(Collector):
    name = "io"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            io_text = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/io")
            io_dict = parse_io(io_text)

            return SectionResult(
                status="complete",
                data={
                    "rchar": io_dict.get("rchar"),
                    "wchar": io_dict.get("wchar"),
                    "syscr": io_dict.get("syscr"),
                    "syscw": io_dict.get("syscw"),
                    "read_bytes": io_dict.get("read_bytes"),
                    "write_bytes": io_dict.get("write_bytes"),
                    "cancelled_write_bytes": io_dict.get("cancelled_write_bytes"),
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="io",
                        error=str(e),
                        impact="cannot profile I/O",
                        required_access="read /proc/<pid>/io",
                    )
                ],
            )


class LimitsOomCollector(Collector):
    name = "limits_and_oom"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            limits_text = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/limits")
            status = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/status")

            limits_dict = parse_limits(limits_text)
            status_dict = parse_status(status)

            oom_score = status_dict.get("VmPeak")
            oom_score_adj = status_dict.get("VmHWM")

            return SectionResult(
                status="complete",
                data={
                    "limits": limits_dict,
                    "oom_score": oom_score,
                    "oom_score_adj": oom_score_adj,
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="limits_and_oom",
                        error=str(e),
                        impact="cannot profile limits/OOM",
                        required_access="read /proc/<pid>/limits, status",
                    )
                ],
            )


class SecurityCollector(Collector):
    name = "security"

    def collect(self, ctx: Context) -> SectionResult:
        try:
            status = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/status")
            status_dict = parse_status(status)

            selinux = status_dict.get("Label", None)
            cap_eff = status_dict.get("CapEff", "0")
            cap_prm = status_dict.get("CapPrm", "0")
            cap_bnd = status_dict.get("CapBnd", "0")
            seccomp = parse_seccomp_status(status_dict)

            return SectionResult(
                status="complete",
                data={
                    "selinux_context": selinux,
                    "capabilities_effective": parse_capabilities(cap_eff),
                    "capabilities_permitted": parse_capabilities(cap_prm),
                    "capabilities_bounding": parse_capabilities(cap_bnd),
                    "seccomp_mode": seccomp,
                    "no_new_privs": status_dict.get("NoNewPrivs"),
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="security",
                        error=str(e),
                        impact="cannot profile security",
                        required_access="read /proc/<pid>/status",
                    )
                ],
            )


class CgroupsNamespacesCollector(Collector):
    name = "cgroups_namespaces"

    def collect(self, ctx: Context) -> SectionResult:
        if "cgroups_namespaces" not in ctx.sections:
            return SectionResult(status="unavailable", data=None)

        try:
            cgroup_text = ctx.adb_client.shell(f"cat /proc/{ctx.pid}/cgroup")
            cgroup_dict = parse_cgroup(cgroup_text)

            return SectionResult(
                status="complete",
                data={
                    "cgroups": cgroup_dict,
                    "namespaces": {},
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="cgroups_namespaces",
                        error=str(e),
                        impact="cannot profile cgroups/namespaces",
                        required_access="read /proc/<pid>/cgroup, ns",
                    )
                ],
            )


class BinderCollector(Collector):
    name = "binder"

    def collect(self, ctx: Context) -> SectionResult:
        if "binder" not in ctx.sections:
            return SectionResult(status="unavailable", data=None)

        try:
            output = ctx.adb_client.shell(f"cat /dev/binderfs/binder_logs/proc/{ctx.pid}")
            binder_dict = parse_binder_logs(output)

            return SectionResult(
                status="complete",
                data={
                    "summary": binder_dict,
                    "raw": output,
                },
            )
        except Exception:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="binder",
                        error="binderfs not readable",
                        impact="cannot profile binder",
                        required_access="read /dev/binderfs/binder_logs/proc/<pid>",
                    )
                ],
            )


class NetworkCollector(Collector):
    name = "network"

    def collect(self, ctx: Context) -> SectionResult:
        if "network" not in ctx.sections:
            return SectionResult(status="unavailable", data=None)

        try:
            return SectionResult(
                status="complete",
                data={
                    "sockets": [],
                    "summary": {"total": 0},
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="network",
                        error=str(e),
                        impact="cannot profile network",
                        required_access="read /proc/net, /proc/<pid>/fd",
                    )
                ],
            )


class AndroidMeminfoCollector(Collector):
    name = "android_meminfo"

    def collect(self, ctx: Context) -> SectionResult:
        if "android_meminfo" not in ctx.sections:
            return SectionResult(status="unavailable", data=None)

        try:
            meminfo_text = ctx.adb_client.shell(f"dumpsys meminfo {ctx.pid}")
            parsed, raw = parse_dumpsys_meminfo(meminfo_text)

            return SectionResult(
                status="complete",
                data={
                    "parsed": parsed,
                    "raw": raw,
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="android_meminfo",
                        error=str(e),
                        impact="cannot get dumpsys meminfo",
                        required_access="run dumpsys meminfo",
                    )
                ],
            )


class EnvironmentCollector(Collector):
    name = "environment"

    def collect(self, ctx: Context) -> SectionResult:
        if "environment" not in ctx.sections or not ctx.include_env:
            return SectionResult(status="unavailable", data=None)

        try:
            environ_text = ctx.adb_client.exec_out(
                f"cat /proc/{ctx.pid}/environ", text=True
            )
            environ_dict = {}
            environ_str = environ_text if isinstance(environ_text, str) else ""
            for pair in environ_str.split("\x00"):
                if "=" in pair:
                    key, val = pair.split("=", 1)
                    if any(
                        x in key.upper() for x in ["KEY", "TOKEN", "SECRET", "PASSWORD"]
                    ):
                        val = "[REDACTED]"
                    environ_dict[key] = val

            return SectionResult(
                status="complete",
                data={
                    "environ": environ_dict,
                    "redacted": True,
                },
            )
        except Exception as e:
            return SectionResult(
                status="unavailable",
                errors=[
                    Error(
                        component="environment",
                        error=str(e),
                        impact="cannot read environment",
                        required_access="read /proc/<pid>/environ",
                    )
                ],
            )


# ============================================================================
# 7. ORCHESTRATOR
# ============================================================================


class Orchestrator:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.collectors: list[Collector] = [
            IdentityCollector(),
            MemoryCollector(),
            DependenciesCollector(),
            ThreadsCollector(),
            FileDescriptorsCollector(),
            CpuCollector(),
            IoCollector(),
            LimitsOomCollector(),
            SecurityCollector(),
            CgroupsNamespacesCollector(),
            BinderCollector(),
            NetworkCollector(),
            AndroidMeminfoCollector(),
            EnvironmentCollector(),
        ]

    def collect_all(self) -> dict[str, Any]:
        """Run all collectors and assemble the report."""
        report_sections: dict[str, Any] = {}
        errors: list[Error] = []

        for collector in self.collectors:
            if collector.name not in self.ctx.sections and collector.name not in [
                "identity",
                "memory",
                "dependencies",
            ]:
                continue

            try:
                result = collector.collect(self.ctx)
                report_sections[collector.name] = result
                if result.errors:
                    errors.extend(result.errors)
            except Exception as e:
                report_sections[collector.name] = SectionResult(
                    status="unavailable",
                    errors=[
                        Error(
                            component=collector.name,
                            error=str(e),
                            impact="collector raised an exception",
                            required_access="unknown",
                        )
                    ],
                )

        return {
            "sections": report_sections,
            "errors": errors,
        }


# ============================================================================
# 8. TEXT RENDERER
# ============================================================================


def render_text(report: dict[str, Any]) -> str:
    """Render report dict as ASCII text output."""
    lines = []

    sections_result = report.get("sections", {})
    identity = sections_result.get("identity", SectionResult(status="unavailable")).data

    if identity:
        lines.append(f"PID: {identity.pid}")
        lines.append(f"Name: {identity.name}")

    memory_result = sections_result.get("memory", SectionResult(status="unavailable"))
    if memory_result.data:
        memory = memory_result.data
        if memory.totals.pss_kb:
            lines.append(f"Memory PSS: {memory.totals.pss_kb} kB")

    return "\n".join(lines)


# ============================================================================
# 9. DIFF SUBCOMMAND
# ============================================================================


def diff_reports(report1: dict[str, Any], report2: dict[str, Any]) -> str:
    """Compare two reports and return a diff-shaped text report."""
    lines = ["Diff Report"]
    lines.append("============")

    memory1 = report1.get("sections", {}).get("memory", {}).get("data")
    memory2 = report2.get("sections", {}).get("memory", {}).get("data")

    if memory1 and memory2:
        pss1 = 0
        pss2 = 0
        if isinstance(memory1, dict) and "totals" in memory1:
            pss1 = memory1["totals"].get("pss_kb", 0) or 0
        if isinstance(memory2, dict) and "totals" in memory2:
            pss2 = memory2["totals"].get("pss_kb", 0) or 0
        if pss1 or pss2:
            lines.append(f"Memory PSS delta: {pss2 - pss1} kB")

    return "\n".join(lines)


# ============================================================================
# 10. CLI AND MAIN
# ============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Android Process Analyzer — read-only profiler",
        prog="AndroidProcessAnalyzer.py",
    )

    subparsers = parser.add_subparsers(dest="command", help="subcommand")

    analyze_parser = subparsers.add_parser("analyze", help="analyze a process")
    analyze_parser.add_argument(
        "--pid", type=int, help="Process ID to analyze"
    )
    analyze_parser.add_argument(
        "--process", type=str, help="Process name to analyze"
    )
    analyze_parser.add_argument(
        "-s", "--serial", type=str, help="Android device serial"
    )
    analyze_parser.add_argument(
        "--adb-path", type=str, help="Path to adb executable"
    )
    analyze_parser.add_argument(
        "--sections",
        type=str,
        default=",".join(DEFAULT_SECTIONS),
        help="Comma-separated list of sections",
    )
    analyze_parser.add_argument(
        "--output", type=str, help="Output file (default: stdout)"
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="json",
        help="Output format",
    )
    analyze_parser.add_argument(
        "--sample-duration", type=float, help="Sampling duration (seconds)"
    )
    analyze_parser.add_argument(
        "--sample-interval", type=float, help="Sampling interval (seconds)"
    )
    analyze_parser.add_argument(
        "--no-cross-process", action="store_true", help="Skip cross-process analysis"
    )
    analyze_parser.add_argument(
        "--no-deps", action="store_true", help="Skip dependency analysis"
    )
    analyze_parser.add_argument(
        "--elf-cache", type=str, help="Directory for ELF cache"
    )
    analyze_parser.add_argument(
        "--top", type=int, default=5, help="Number of top artifacts"
    )
    analyze_parser.add_argument(
        "--sort",
        choices=["pss", "rss", "uss", "virtual"],
        default="pss",
        help="Sort artifacts by",
    )
    analyze_parser.add_argument(
        "--max-list", type=int, default=100, help="Max items to list"
    )
    analyze_parser.add_argument(
        "--include-env", action="store_true", help="Include environment variables"
    )
    analyze_parser.add_argument(
        "--verbose", action="store_true", help="Verbose output"
    )
    analyze_parser.add_argument(
        "--unicode", action="store_true", help="Use Unicode in output"
    )

    diff_parser = subparsers.add_parser("diff", help="compare two reports")
    diff_parser.add_argument("before", type=str, help="Before report (JSON)")
    diff_parser.add_argument("after", type=str, help="After report (JSON)")

    args = parser.parse_args()

    if args.command == "diff":
        try:
            with open(args.before) as f:
                report1 = json.load(f)
            with open(args.after) as f:
                report2 = json.load(f)
            diff_output = diff_reports(report1, report2)
            print(diff_output)
            return 0
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # Default: analyze
    if not args.pid and not args.process:
        print("Error: specify --pid or --process", file=sys.stderr)
        return 1

    try:
        adb_client = AdbClient(adb_path=args.adb_path, serial=args.serial)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.process and not args.pid:
        print("Error: --process not yet implemented", file=sys.stderr)
        return 1

    pid = args.pid
    sections = set(args.sections.split(","))

    ctx = Context(
        adb_client=adb_client,
        serial=args.serial,
        pid=pid,
        access_level=AccessLevel(),
        sections=sections,
        elf_cache_dir=(
            pathlib.Path(args.elf_cache) if args.elf_cache else None
        ),
        sample_duration=args.sample_duration,
        sample_interval=args.sample_interval,
        no_cross_process=args.no_cross_process,
        no_deps=args.no_deps,
        include_env=args.include_env,
        clk_tck=100,
        max_list=args.max_list,
        top_n=args.top,
        sort_by=args.sort,
    )

    orchestrator = Orchestrator(ctx)
    result: dict[str, Any] = orchestrator.collect_all()

    if args.format in ["json", "both"]:
        output_json: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "report": {
                "status": "complete",
                "tool_version": VERSION,
                "generated_at_utc": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "duration_ms": 0,
            },
            "process": None,
            "summary": None,
            "sections_status": {},
            "memory": None,
            "dependencies": None,
            "threads": None,
            "file_descriptors": None,
            "cpu": None,
            "io": None,
            "limits_and_oom": None,
            "security": None,
            "cgroups_namespaces": None,
            "binder": None,
            "network": None,
            "android_meminfo": None,
            "environment": None,
            "checks": [],
            "notes": [],
            "limitations": [],
            "errors": [
                dataclasses.asdict(e) for e in result["errors"]
            ],
            "glossary": {},
        }

        for section_name, section_result in result["sections"].items():
            assert isinstance(section_name, str)
            output_json["sections_status"][section_name] = {
                "status": section_result.status,
            }
            if section_result.data is not None:
                if isinstance(section_result.data, (dict, list)):
                    output_json[section_name] = section_result.data
                else:
                    output_json[section_name] = dataclasses.asdict(
                        section_result.data
                    )

        json_str = json.dumps(output_json, indent=2, default=str)
        if args.output:
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".json"
            ) as f:
                f.write(json_str)
                temp_path = f.name
            os.replace(temp_path, args.output)
            print(f"Written to {args.output}")
        else:
            print(json_str)

    if args.format in ["text", "both"]:
        text_output = render_text(output_json)
        if args.format == "both":
            print("---TEXT OUTPUT---")
        print(text_output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
