# Android Process Analyzer

A read-only profiler for Android processes that extracts memory, dependencies, threads, file descriptors, CPU, I/O, and other system information via `adb` without modifying the device.

## Features

- **Memory profiling**: detailed per-artifact PSS, RSS, USS analysis from `/proc/[pid]/smaps`
- **Dependency analysis**: extracts ELF dependencies and tracks shared library reachability
- **Thread profiling**: CPU usage, scheduling state, context switches per thread
- **File descriptors**: classification, socket resolution, open limit tracking
- **Cross-process sharing**: identifies which other processes share libraries
- **Sampling mode**: tracks CPU and I/O deltas over time
- **No device modifications**: purely read-only; never writes to `/proc`, sends signals, or uses ptrace

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
python AndroidProcessAnalyzer.py --pid 1234
```

Output defaults to JSON to stdout. To save:
```bash
python AndroidProcessAnalyzer.py --pid 1234 --output report.json
```

### Select Sections

By default, analyze identity, memory, dependencies, threads, file_descriptors, cpu, io, limits_and_oom, and security.

Opt-in sections (network, binder, cgroups_namespaces, android_meminfo, environment) require explicit selection:
```bash
python AndroidProcessAnalyzer.py --pid 1234 --sections memory,dependencies,network
```

### Sampling Mode

Track CPU and I/O changes over time:
```bash
python AndroidProcessAnalyzer.py --pid 1234 --sample-duration 5 --sample-interval 0.5
```

### Text Output

```bash
python AndroidProcessAnalyzer.py --pid 1234 --format text
python AndroidProcessAnalyzer.py --pid 1234 --format both  # JSON + text
```

### Sort and Filter

```bash
python AndroidProcessAnalyzer.py --pid 1234 --sort pss --top 10 --max-list 50
```

### Diff Two Reports

```bash
python AndroidProcessAnalyzer.py diff before.json after.json
```

Compare memory, threads, file descriptors, and I/O between two snapshots.

### Full Help

```bash
python AndroidProcessAnalyzer.py --help
python AndroidProcessAnalyzer.py --pid 1 --help
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
- **dependencies** (core): ELF dependency tree, soname resolution, closure analysis, cross-process sharing.
- **threads**: per-thread CPU, state, context switches, stack attribution (heuristic).
- **file_descriptors**: open FD count/type, socket resolution, RLIMIT_NOFILE usage.
- **cpu**: cumulative utime, stime; with sampling, per-thread active/idle.
- **io**: rchar, wchar, read_bytes, write_bytes, etc.; rates with sampling.
- **limits_and_oom**: RLIMIT_* soft/hard, OOM score.
- **security**: SELinux context, capabilities, Seccomp mode, NoNewPrivs.
- **cgroups_namespaces** (opt-in): raw cgroup paths and namespace IDs.
- **binder** (opt-in): binder thread/node/ref counts from /dev/binderfs or debugfs.
- **network** (opt-in): sockets owned by the process.
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

### No Real Android Device Available

The following behaviors are **not verified** in this build (developed on Linux with fixtures only):

- **adb.exe** on Windows: all adb invocations assume Unix paths; binary detection not tested.
- **exec-out binary integrity**: reading deleted files via `/proc/<pid>/map_files/` not tested.
- **SELinux/AppArmor**: context reading and capability decoding are fixtures-only.
- **Binder logs**: `/dev/binderfs/binder_logs/proc/<pid>` and debugfs layouts vary by Android version.
- **dumpsys meminfo**: parser is defensive but output format changes; fallback to raw text.
- **All-PID scan**: cross-process sharing enumeration with `ls /proc/[0-9]*/maps` not tested on real device.
- **Real ELF files**: ELF reading via pyelftools validated on toy binaries only; Android use cases (APEX, namespaces) untested.
- **PowerShell setup steps**: described but not executed on Windows.

### Device Requirements

- `adb` must be in PATH, or set `ADB` env var or `--adb-path`.
- Device must be reachable: `adb devices`.
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
