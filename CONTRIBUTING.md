# Contributing to Android Process Analyzer

Thanks for your interest in contributing! This guide will help you set up your development environment and understand our code standards.

## Quick Start

### 1. Clone and Set Up

```bash
git clone git@github.com:ajender-elite/ProjectMemory.git
cd ProjectMemory
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
pip install -r requirements-dev.txt
```

### 2. Run Tests Before Any Changes

```bash
python -m pytest -v                    # Run all tests
python -m ruff check .                 # Lint
python -m mypy --strict .              # Type check
```

All must pass before opening a PR.

## Code Standards

### Type Hints (Mandatory)

Every function must have type hints. We use `mypy --strict`.

```python
# ✅ Good
def parse_smaps(smaps_text: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Parse /proc/<pid>/smaps into one (mapping, data) pair per mapping."""
    ...

# ❌ Bad
def parse_smaps(smaps_text):  # Missing return type
    ...
```

**Modern Python 3.9+ style**:
- Use `dict[str, int]` not `Dict[str, int]`
- Use `str | None` not `Optional[str]`
- Use `list[str]` not `List[str]`
- All functions in module scope must have full signatures

### Naming Conventions

- **Classes**: `CapitalCase` (e.g., `MemoryCollector`, `AdbClient`)
- **Functions**: `snake_case` (e.g., `parse_smaps`, `collect_all`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_SECTIONS`, `THREAD_STATE_LABELS`)
- **Private helpers**: prefix with `_` (e.g., `_normalize_text`, `_find_adb`)
- **Avoid single-letter vars** except in loops: `for i, item in enumerate(...)` is OK

### Imports

```python
# Order: stdlib, third-party, local (blank lines between)
import dataclasses
import json
from typing import Any

import pytest

from AndroidProcessAnalyzer import parse_smaps
```

Run `ruff check --select I` to auto-fix import order.

### Docstrings

Keep them **short and focused**. Code is self-documenting; only explain **why**, not **what**.

```python
# ✅ Good: explains the quirk
def parse_stat(stat_line: str) -> dict[str, Any]:
    """Parse /proc/<pid>/stat. Split on last ')' so comm with parens works."""
    ...

# ❌ Bad: repeats what the code says
def parse_stat(stat_line: str) -> dict[str, Any]:
    """This function parses a stat line by extracting fields."""
    ...
```

**No multi-line docstrings or comments.** If you need more than one line, it's probably a design problem.

### No Comments Needed

The code should be clear enough. If you're about to write a comment, rename a variable or refactor instead.

```python
# ❌ Don't do this
for line in smaps_text.split("\n"):
    # Skip header lines
    if line.startswith("Limit"):
        continue

# ✅ Do this
for line in smaps_text.split("\n"):
    if is_header_line(line):
        continue
```

## Modularity & Architecture

### Adding a New Section

If you want to add a new data collector (e.g., `gpu_memory`):

1. **Create a collector class**:
   ```python
   class GpuMemoryCollector(Collector):
       name = "gpu_memory"
   
       def collect(self, ctx: Context) -> SectionResult:
           try:
               # Your logic here
               return SectionResult(status="complete", data={...})
           except Exception as e:
               return SectionResult(
                   status="unavailable",
                   errors=[Error(
                       component="gpu_memory",
                       error=str(e),
                       impact="cannot profile GPU memory",
                       required_access="...",
                   )]
               )
   ```

2. **Add to orchestrator**:
   ```python
   self.collectors = [
       IdentityCollector(),
       MemoryCollector(),
       # ... existing ones ...
       GpuMemoryCollector(),  # <- Add here
   ]
   ```

3. **Update ALL_SECTIONS**:
   ```python
   ALL_SECTIONS = [
       # ... existing ...
       "gpu_memory",  # <- Add here if opt-in
   ]
   ```

4. **Add tests**:
   ```python
   class TestGpuMemory:
       def test_gpu_parsing(self) -> None:
           gpu_text = "..."  # fixture
           result = parse_gpu_output(gpu_text)
           assert result["total_kb"] == 1024
   ```

5. **Run full test suite** to ensure isolation (other collectors still work if yours fails).

### Modifying Parsers

Parsers are **pure functions**. Never call I/O from a parser.

```python
# ✅ Good: takes text, returns structured data
def parse_io(io_text: str) -> dict[str, int]:
    result = {}
    for line in io_text.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = int(value.strip())
    return result

# ❌ Bad: calls adb (should be in collector, not parser)
def parse_io() -> dict[str, int]:
    io_text = adb_client.shell("cat /proc/1/io")  # WRONG
    ...
```

### Testing Patterns

**Unit test a parser with fixtures, not mocks**:

```python
# ✅ Good: test with real data format
def test_smaps_with_spaces_in_path(self) -> None:
    smaps_text = """00400000-00401000 r-xp ... /path with spaces/file.so
Size:                  4 kB
Pss:                   2 kB
"""
    result = parse_smaps(smaps_text)
    mapping, _ = result[0]
    assert mapping["pathname"] == "/path with spaces/file.so"

# ❌ Bad: mock the parser (defeats the purpose)
def test_smaps(self) -> None:
    with patch('parse_smaps') as mock_parse:
        mock_parse.return_value = {"fake": "data"}
        ...
```

**Test collector failure isolation**:

```python
def test_collector_exception_isolation(self) -> None:
    # If one collector crashes, others keep running
    # (Already covered implicitly; add explicit test if adding new collector)
    pass
```

## Testing Checklist

Before opening a PR, ensure:

- [ ] **pytest passes**: `python -m pytest -q`
- [ ] **ruff passes**: `python -m ruff check .`
- [ ] **mypy passes**: `python -m mypy --strict .`
- [ ] **No new warnings**: check stderr for anything you added
- [ ] **Existing tests still pass**: no regressions
- [ ] **New code has tests**: aim for 80%+ coverage on new code
- [ ] **Line length ≤ 100**: `ruff` will catch this

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive names: `feature/binder-logs-parsing`, `fix/smaps-edge-case`, `docs/update-readme`.

### 2. Make Changes

- Edit `AndroidProcessAnalyzer.py` or `tests/test_android_process_analyzer.py`
- Run tests frequently: `python -m pytest tests/test_android_process_analyzer.py -k your_test -v`
- Use a linter: `python -m ruff check --fix` to auto-fix many issues

### 3. Commit Often

```bash
git add AndroidProcessAnalyzer.py
git commit -m "component: short description

Detailed explanation of why this change is needed, what it does,
and any caveats.

Co-Authored-By: Your Name <your.email@example.com>"
```

**Commit message style**:
- First line: `component: subject` (under 70 chars)
- Blank line
- Detailed body (wrapped at 70 chars)
- Blank line
- Co-author line if you worked with others

### 4. Push and Open PR

```bash
git push -u origin feature/your-feature-name
```

Open a PR on GitHub with:
- Title: same as commit subject
- Description: explain what changed and why
- Link to any relevant issues: "Fixes #123"

### 5. Code Review

- Respond to feedback
- Push new commits (don't force-push unless asked)
- CI must pass (ruff + mypy + pytest)

## Common Development Tasks

### Add Support for a New `/proc` File

Example: adding `/proc/<pid>/auxv` parsing

1. **Write a parser** (pure function):
   ```python
   def parse_auxv(auxv_bytes: bytes) -> dict[str, int]:
       """Parse ELF auxiliary vector."""
       result = {}
       # implementation
       return result
   ```

2. **Write tests**:
   ```python
   def test_auxv_parsing(self) -> None:
       auxv_bytes = b"\x21\x00\x00\x00..."  # real auxv data
       result = parse_auxv(auxv_bytes)
       assert result["AT_PAGESZ"] == 4096
   ```

3. **Add to a collector**:
   ```python
   class IdentityCollector(Collector):
       def collect(self, ctx: Context) -> SectionResult:
           # existing code
           auxv = ctx.adb_client.exec_out(f"cat /proc/{ctx.pid}/auxv", text=False)
           auxv_dict = parse_auxv(auxv)
           # add to result
   ```

### Debug a Failing Test

```bash
# Run with verbose output
python -m pytest tests/test_android_process_analyzer.py::TestSmapsParsing::test_smaps_with_spaces_in_path -vv

# Drop into pdb on failure
python -m pytest --pdb tests/test_android_process_analyzer.py

# Print stdout/stderr
python -m pytest -s tests/test_android_process_analyzer.py
```

### Test Against a Real Device

Use the evidence workflow in the README. It checks the analyzer's output against the raw files it read:

```bash
adb devices
python -I tools/capture_evidence.py <serial> <pid> output
python -I tools/build_dump.py output/<session_id>
python -I tools/verify.py output/<session_id>
```

For quick spot checks, compare raw files directly:

```bash
adb shell cat /proc/1234/smaps | head -20
```

If verification fails, check:
- Field indices in parsers (Android version variations)
- Newline normalization (CRLF vs LF)
- Unicode encoding (non-ASCII in paths)
- Permissions: `smaps`, `fd`, `io`, and binder logs need root (`adb root` on `userdebug`)

### Changing the Report Schema

`schemas/analyzer-report.schema.json` is generated. Do not edit it by hand.

1. Change the section definitions in `tools/gen_schema.py`.
2. Regenerate: `python -I tools/gen_schema.py schemas/analyzer-report.schema.json`
3. Rebuild an existing session's dump (`tools/build_dump.py output/<session_id>`) and run `tools/verify.py output/<session_id>`. Both the dump and its report must validate.
4. If the dump's structure changes, update `schemas/analyzer-dump.schema.json`. It is hand-maintained.

Schema changes follow the rule in the FAQ: add fields, don't remove them.

### Evidence Bundles

`output/` contains raw device data and is git-ignored. Never commit it, and don't paste its contents into issues or PRs. Scripts that read captured or downloaded content should run with `python -I`, which ignores the current directory and `PYTHONPATH`.

### Library Dependency Tool

`tools/lib_deps.py` reads ELF headers from a session's cached libraries, pulling them from the device on demand. Run it with `python -I tools/lib_deps.py output/<session_id> <libname>`.

Rules when changing it:

- **Static and runtime edges stay separate.** `DT_NEEDED` edges are facts. A `dlopen` edge is inferred, so it is always reported as a hint, never as a dependency.
- **Stay within the mapped set.** The tool answers "what does this process load", not "what in the device could load this". Widening the search means pulling the whole device, which is a different and much heavier mode.
- **Reuse the analyzer's ELF reader.** `ElfReader` is in `AndroidProcessAnalyzer.py`. Don't add a second ELF parser.
- **Keep unresolved names visible.** Anything the search path can't resolve goes under `unresolved`. Don't drop it silently.

To test a change, run the tool against an existing session and check that the runtime roots include the HAL modules the process actually loads. Also check that a library which appears in `DT_NEEDED` is never listed as a runtime root.

### Profile Performance

```bash
python -m cProfile -s cumtime AndroidProcessAnalyzer.py analyze --pid 1
```

Most time is adb I/O, not parsing. Parsers should be sub-millisecond.

## Debugging Tips

### adb Connection Issues

```bash
# Check if device is connected
adb devices

# Get device info
adb shell getprop ro.build.version.release  # Android version

# Test adb path discovery
python -c "from AndroidProcessAnalyzer import AdbClient; print(AdbClient().adb_path)"
```

### Parser Debugging

```python
# Add print to understand parsing
import sys

def parse_smaps(smaps_text: str) -> dict[str, list[dict[str, Any]]]:
    for line in smaps_text.split("\n")[:5]:  # First 5 lines
        print(f"DEBUG: {line!r}", file=sys.stderr)
    # ...
```

### Type Errors

If mypy is strict:

```bash
# Show all errors
python -m mypy --strict AndroidProcessAnalyzer.py

# Type check one section
python -m mypy --strict --no-error-summary AndroidProcessAnalyzer.py | grep "parse_smaps"

# Disable a specific check if truly needed (rare)
some_value: Any = complex_operation()  # type: ignore[assignment]
```

But first ask: can I fix the type instead of ignoring?

## Performance Expectations

Target metrics (no real adb, fixtures only):

- **Test suite**: < 1 second (currently about 0.3s for 54 tests)
- **Type check**: < 10 seconds (currently < 5s)
- **Linting**: < 5 seconds (currently < 1s)
- **Single parse**: < 1ms (e.g., smaps with 1000 mappings)
- **Full collection** (with real device): 5-30s depending on process complexity

If you add code that makes tests slow, investigate:

```bash
python -m pytest --durations=10  # 10 slowest tests
```

## FAQ

**Q: Should I add comments to explain complex logic?**
A: No. Rename variables, extract functions, or refactor instead. If logic is so complex it needs explanation, it's usually wrong.

**Q: Can I use an external library?**
A: Only if essential and discussed first. We want to keep dependencies minimal (pyelftools only for ELF reading).

**Q: What if my test fails on Windows but passes on Linux?**
A: Check for path separators (`\` vs `/`), line endings (CRLF vs LF), and subprocess differences. Tests should run identically on all platforms.

**Q: How do I handle errors in a collector?**
A: Never crash. Return `SectionResult(status="unavailable", errors=[Error(...)])`. Other collectors keep running.

**Q: Should I worry about backwards compatibility?**
A: Yes for JSON schema (add fields, don't remove). No for internal APIs (this is a single tool, not a library).

**Q: Can I refactor the single file into multiple modules?**
A: Yes, when it exceeds 2000 lines significantly. For now, keep it together for deployment simplicity.

## Getting Help

- **Questions?** Open a GitHub issue with `[question]` tag
- **Bug report?** Include: OS, Python version, adb version, exact command, error output
- **Feature request?** Describe the use case, why it matters, how you'd use it
- **Code review help?** Tag maintainers in your PR

---

**Happy coding!** We appreciate contributions that follow these standards. They keep the codebase maintainable and make the tool usable for years to come.
