# Android Process Analyzer

A read-only profiler for Android processes that extracts memory, dependencies, threads, file descriptors, CPU, I/O, and other system information via `adb` without modifying the device.

## Features

- **Memory profiling**: per-artifact PSS, RSS, USS, and swap PSS from `/proc/[pid]/smaps`, grouped by file
- **Thread profiling**: scheduling state and CPU time per thread
- **File descriptors**: count and type, with path resolution for the first 100
- **Limits, OOM, and security**: rlimits, OOM score, SELinux context, capabilities, seccomp
- **Device evidence capture**: records every raw `/proc` file the analysis reads, with SHA-256 hashes, and rebuilds the report from those files alone (see [Device Evidence](#device-evidence))
- **No device modifications**: read-only; never writes to `/proc`, sends signals, or uses ptrace

Not yet implemented (the code either returns a placeholder or ignores the option): ELF dependency analysis, cross-process sharing (`sharing.process_count` is always 1), sampling mode (`--sample-*` flags are accepted and ignored), and `--process` name lookup.

## Setup

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate  # or . .venv/bin/activate on POSIX
pip install -r requirements-dev.txt
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
# If you get an execution policy error, run:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
pip install -r requirements-dev.txt
```

Activation-free forms (works on all platforms):
```bash
.venv/bin/python    # Linux/macOS
.venv\Scripts\python.exe  # Windows
```

### adb

Android Debug Bridge (adb) is required on the host. Install via your OS package manager:

**Linux**:
```bash
sudo apt-get install adb  # Debian/Ubuntu
```

**macOS** (via Homebrew):
```bash
brew install android-platform-tools
```

**Windows**: Download from [Android SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools).
Set `ANDROID_SDK_ROOT` or `ANDROID_HOME` environment variable, or pass `--adb-path /path/to/adb.exe`.

**Note**: On Windows 10/11, USB drivers for your device may be required. See [OEM USB Drivers](https://developer.android.com/studio/run/oem-usb).

## Usage

### Analyze a Process

```bash
python AndroidProcessAnalyzer.py analyze --pid 1234
```

Output defaults to JSON to stdout. To save:
```bash
python AndroidProcessAnalyzer.py analyze --pid 1234 --output report.json
```

### Select Sections

By default, analyze identity, memory, dependencies, threads, file_descriptors, cpu, io, limits_and_oom, and security.

Opt-in sections (network, binder, cgroups_namespaces, android_meminfo, environment) require explicit selection:
```bash
python AndroidProcessAnalyzer.py analyze --pid 1234 --sections memory,dependencies,network
```

### Sampling Mode (not yet implemented)

The `--sample-duration` and `--sample-interval` flags are accepted but have no effect yet.

### Text Output

```bash
python AndroidProcessAnalyzer.py analyze --pid 1234 --format text
python AndroidProcessAnalyzer.py analyze --pid 1234 --format both  # JSON + text
```

### Sort and Filter

```bash
python AndroidProcessAnalyzer.py analyze --pid 1234 --sort pss --top 10 --max-list 50
```

### Diff Two Reports

```bash
python AndroidProcessAnalyzer.py diff before.json after.json
```

Compare memory, threads, file descriptors, and I/O between two snapshots.

## Device Evidence

Use this workflow to keep a complete, verifiable record of one process. It needs a device reachable over `adb`.

### 1. Capture raw files

```bash
python -I tools/capture_evidence.py <adb-serial> <pid> output [session_id]
```

Each run creates `output/<session_id>/`. `session_id` defaults to a new UUID, and an existing session is never overwritten. Each command's output is saved byte for byte as `output/<session_id>/evidence/<pid>_<name>`, and `manifest.json` in the same folder records each command, its exit code, byte count, and SHA-256. The manifest also records the analyzer's git commit. Captured commands are the same strings the analyzer sends, plus `dumpsys meminfo`, a binder log read, and a start and end `stat` read. Comparing the two `stat` reads detects a process restart during capture.

### 2. Rebuild the report from the evidence

```bash
python -I tools/replay_report.py output/<session_id>
```

This runs the analyzer from this repository against the saved files, with no device, and writes `output/<session_id>/<pid>_pid_analyze_dump.json`.

### 3. Build the verbose capture

```bash
python -I tools/build_verbose.py output/<session_id>
```

This writes `output/<session_id>/<pid>_pid_analyze_verbose.json`: the dump plus every evidence file inline, each with its command, exit code, byte count, and SHA-256. Schema: `schemas/analyzer-verbose.schema.json`.

### 4. Verify

```bash
python -I tools/verify.py output/<session_id>
```

Exit code 0 means every check passed. The dump, the verbose file if present, and the evidence are all checked.

Checks include hash integrity, reproducibility, schema validation, and independent recomputation of memory totals, OOM values, SELinux, capability count, thread and fd counts, and I/O from the raw files. Exit code 0 means all checks passed.

### Output layout

```
output/
  <session_id>/                    one folder per capture session
    <pid>_pid_analyze_dump.json      analyzer report
    <pid>_pid_analyze_verbose.json   report + every evidence file inline (optional)
    evidence/
      manifest.json                  command, exit code, size, SHA-256 per file
      <pid>_*.txt                    raw adb output, byte for byte
```

Each session is self-contained, so you can compare runs by listing their folders. `output/` holds raw device data, so it is git-ignored. Keep it out of commits and shared repositories.

## Schemas

- `schemas/analyzer-report.schema.json`: the `report.json` format (schema_version 3.0). Generated by `tools/gen_schema.py`; do not edit by hand. Collected sections are objects, and `null` only when `sections_status` is `unavailable`. Unknown fields are rejected.
- `schemas/analyzer-verbose.schema.json`: the `verbose.json` format, hand-maintained.

### Full Help

```bash
python AndroidProcessAnalyzer.py --help
python AndroidProcessAnalyzer.py analyze --pid 1 --help
```

## Understanding the Report

### Memory Metrics

- **Virtual (VmSize)**: total address space mapped (file-backed or anonymous). Not resident.
- **RSS (Resident Set Size)**: pages currently in physical RAM.
- **PSS (Proportional Set Size)**: RSS adjusted for sharing: each shared page is divided by the number of sharers. **Use this for total memory cost of a process.**
- **USS (Unique Set Size)**: Private_Clean + Private_Dirty; memory used only by this process.

Example: if a shared library is mapped in two processes, RSS counts it twice, but PSS divides by 2.

### Sampling vs. Non-Sampling

- **Without sampling** (`--sample-duration` not set): all CPU and I/O values are cumulative since process start; threads show current state only.
- **With sampling** (`--sample-duration N --sample-interval M`): values show deltas over the window; threads marked "active" had CPU ticks in that window.

### Sections

- **identity**: PID, name, cmdline, UID/GID, start time.
- **memory** (core): per-artifact breakdown of PSS, RSS, USS, with by_segment splits for file-backed.
- **dependencies** (core): not implemented. Always returns an empty placeholder.
- **threads**: per-thread CPU, state, context switches, stack attribution (heuristic).
- **file_descriptors**: open FD count/type, socket resolution, RLIMIT_NOFILE usage.
- **cpu**: cumulative utime, stime; with sampling, per-thread active/idle.
- **io**: rchar, wchar, read_bytes, write_bytes, etc.; rates with sampling.
- **limits_and_oom**: RLIMIT_* soft/hard, OOM score.
- **security**: SELinux context, capabilities, Seccomp mode, NoNewPrivs.
- **cgroups_namespaces** (opt-in): raw cgroup paths and namespace IDs.
- **binder** (opt-in): binder thread/node/ref counts from /dev/binderfs or debugfs.
- **network** (opt-in): not implemented. Always returns an empty placeholder.
- **android_meminfo** (opt-in): parsed `dumpsys meminfo <pid>` output.
- **environment** (opt-in): process environment variables (secrets redacted with `--include-env`).

## Development

### Run Tests

```bash
.venv/bin/python -m pytest -q
```

### Type Check

```bash
.venv/bin/python -m mypy --strict AndroidProcessAnalyzer.py
```

### Lint

```bash
.venv/bin/python -m ruff check --select E,F,I,UP,B AndroidProcessAnalyzer.py
```

## Known Limitations

### Verification Status

Tested on one device: a Qualcomm `userdebug` build reached over TCP (`adb connect`), from Windows 11, against the audio HAL process `audiohalservice.qti`. Collection covered identity, memory, threads, fds, cpu, io, limits, security, binder, and `dumpsys meminfo`. The verifier independently recomputes memory totals, the `dumpsys` TOTAL row, OOM values, SELinux label, capability count, I/O `rchar`, and thread and fd counts from the raw files. Binder and `dumpsys` detail sections are collected but not cross-checked. See [Device Evidence](#device-evidence).

Still **not verified**:

- **exec-out binary integrity**: reading deleted files via `/proc/<pid>/map_files/`.
- **SELinux/AppArmor across devices**: context reading tested on one device only.
- **Binder logs**: `/dev/binderfs/binder_logs/proc/<pid>` layouts vary by Android version.
- **dumpsys meminfo**: parser is defensive, but output format changes between versions.
- **All-PID scan**: cross-process sharing is not implemented, so this path is untested.
- **Real ELF files**: pyelftools was validated on toy binaries only.
- **PowerShell setup steps**: described but not executed on Windows.

### Device Requirements

- `adb` must be in PATH, or set `ADB` env var or `--adb-path`.
- Device must be reachable: `adb devices`.
- Reading `smaps`, `fd`, `io`, and binder logs requires root. The `shell` user gets `Permission denied` for these. On a `userdebug` build, `adb root` grants it. Run `adb unroot` when you're done.
- Process must exist during collection; exits mid-collection set status to "limited".
- PID reuse detected via `/proc/<pid>/stat` starttime; status becomes "invalid" if PID reused.
- Some `/proc` files may be unreadable depending on SELinux policy or UID (recorded in errors[]).

### Assumptions

- CLK_TCK from `getconf CLK_TCK` on device, fallback to 100 (recorded as assumption in limitations[]).
- Smaps fields with no value on older kernels are null, not 0.
- Anonymous mapping attribution to threads is heuristic (named `[anon:stack_and_tls:<tid>]`); may be absent.
- Soname resolution searches only mapped libraries, not the filesystem (Android namespace-aware).

## See Also

- `/proc` documentation: [proc(5) man page](https://man7.org/linux/man-pages/man5/proc.5.html)
- Android memory: [Memory Analysis](https://developer.android.com/studio/profile/memory-profiler)
- ELF format: [Oracle ELF Spec](https://docs.oracle.com/cd/E23824_01/pdf/819-0690.pdf)
