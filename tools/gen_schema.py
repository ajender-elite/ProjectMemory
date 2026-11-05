"""Generate schemas/analyzer-report.schema.json for schema_version 3.0.

Every field the analyzer emits is required. Sections must be an object when
collected and null only when their sections_status is "unavailable".
Unknown fields are rejected at every object level.
"""

import json
import pathlib
import sys

OUT = pathlib.Path(sys.argv[1])

SECTIONS = [
    "identity", "memory", "dependencies", "threads", "file_descriptors", "cpu",
    "io", "limits_and_oom", "security", "binder", "android_meminfo",
    "cgroups_namespaces",
]
NULLABLE_SECTIONS_ALWAYS_NULL = ["process", "summary", "network", "environment"]


def obj(required, properties, additional=False):
    return {
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": additional,
    }


INT = {"type": "integer"}
NUM = {"type": "number"}
STR = {"type": "string"}
NINT = {"type": ["integer", "null"]}
NNUM = {"type": ["number", "null"]}
NSTR = {"type": ["string", "null"]}
STRS = {"type": "array", "items": STR}
ANY_OBJ = {"type": "object"}

DEFS = {
    "limit": obj(["soft", "hard"], {"soft": NINT, "hard": NINT}),
    "error": obj(
        ["component", "error", "impact", "required_access"],
        {"component": STR, "error": STR, "impact": STR, "required_access": STR},
    ),
    "memoryBlock": obj(
        ["virtual_kb", "rss_kb", "pss_kb", "uss_kb", "shared_kb", "swap_pss_kb"],
        {"virtual_kb": NINT, "rss_kb": NINT, "pss_kb": NINT, "uss_kb": NINT,
         "shared_kb": NINT, "swap_pss_kb": NINT},
    ),
    "memorySummary": obj(
        ["pss_kb", "rss_kb", "uss_kb", "virtual_kb", "swap_pss_kb", "by_backing"],
        {"pss_kb": NINT, "rss_kb": NINT, "uss_kb": NINT, "virtual_kb": NINT,
         "swap_pss_kb": NINT, "by_backing": ANY_OBJ},
    ),
    "artifact": obj(
        ["key", "name", "path", "other_paths", "artifact_class", "memory",
         "pss_percent_of_process", "by_segment", "sharing", "dependency", "flags"],
        {
            "key": STR, "name": STR, "path": NSTR,
            "other_paths": STRS, "artifact_class": STR,
            "memory": {"$ref": "#/$defs/memoryBlock"},
            "pss_percent_of_process": NNUM,
            "by_segment": ANY_OBJ,
            "sharing": obj(["process_count", "is_lower_bound"],
                           {"process_count": INT, "is_lower_bound": {"type": "boolean"}}),
            "dependency": ANY_OBJ,
            "flags": STRS,
        },
    ),
    "thread": obj(
        ["tid", "name", "state", "state_readable", "nice", "priority", "utime_ms",
         "stime_ms", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
         "stack_pss_kb", "cpu_ms", "cpu_percent", "active", "flags"],
        {
            "tid": INT, "name": STR, "state": STR, "state_readable": STR,
            "nice": NINT, "priority": NINT, "utime_ms": NNUM, "stime_ms": NNUM,
            "voluntary_ctxt_switches": NINT, "nonvoluntary_ctxt_switches": NINT,
            "stack_pss_kb": NINT, "cpu_ms": NNUM, "cpu_percent": NNUM,
            "active": {"type": ["boolean", "null"]}, "flags": STRS,
        },
    ),
    "fd": obj(
        ["fd", "fd_type", "path", "flags", "position", "size"],
        {"fd": INT, "fd_type": STR, "path": NSTR, "flags": STRS,
         "position": NINT, "size": NINT},
    ),
}

SECTION_DEFS = {
    "identity": obj(
        ["pid", "ppid", "name", "cmdline", "exe", "cwd", "uid", "gid", "groups",
         "start_time_ticks", "state", "thread_count"],
        {"pid": INT, "ppid": INT, "name": STR, "cmdline": NSTR, "exe": NSTR,
         "cwd": NSTR, "uid": INT, "gid": INT,
         "groups": {"type": "array", "items": INT},
         "start_time_ticks": INT, "state": STR, "thread_count": INT},
    ),
    "memory": obj(
        ["totals", "by_class", "artifacts"],
        {"totals": {"$ref": "#/$defs/memorySummary"},
         "by_class": ANY_OBJ,
         "artifacts": {"type": "array", "items": {"$ref": "#/$defs/artifact"}}},
    ),
    "dependencies": obj(
        ["artifacts", "unresolved", "runtime_only", "summary", "checks"],
        {"artifacts": {"type": "array"}, "unresolved": {"type": "array"},
         "runtime_only": {"type": "array"},
         "summary": obj(["total", "reachable_from_main", "runtime_only_count"],
                        {"total": INT, "reachable_from_main": INT,
                         "runtime_only_count": INT}),
         "checks": {"type": "array"}},
    ),
    "threads": obj(
        ["threads", "summary"],
        {"threads": {"type": "array", "items": {"$ref": "#/$defs/thread"}},
         "summary": obj(["total", "by_state", "by_name_prefix"],
                        {"total": INT, "by_state": ANY_OBJ, "by_name_prefix": ANY_OBJ})},
    ),
    "file_descriptors": obj(
        ["fds", "summary", "truncated"],
        {"fds": {"type": "array", "items": {"$ref": "#/$defs/fd"}},
         "summary": obj(["total", "by_type", "limit_soft", "limit_hard", "percent_used"],
                        {"total": INT, "by_type": ANY_OBJ, "limit_soft": NINT,
                         "limit_hard": NINT, "percent_used": NNUM}),
         "truncated": {"type": "boolean"}},
    ),
    "cpu": obj(
        ["utime_ms", "stime_ms", "total_cpu_ms", "context_switches"],
        {"utime_ms": NUM, "stime_ms": NUM, "total_cpu_ms": NUM,
         "context_switches": NINT},
    ),
    "io": obj(
        ["rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes",
         "cancelled_write_bytes"],
        {k: NINT for k in ["rchar", "wchar", "syscr", "syscw", "read_bytes",
                           "write_bytes", "cancelled_write_bytes"]},
    ),
    "limits_and_oom": obj(
        ["limits", "oom_score", "oom_score_adj"],
        {"limits": {"type": "object", "additionalProperties": {"$ref": "#/$defs/limit"}},
         "oom_score": NINT, "oom_score_adj": NINT},
    ),
    "security": obj(
        ["selinux_context", "capabilities_effective", "capabilities_permitted",
         "capabilities_bounding", "seccomp_mode", "no_new_privs"],
        {"selinux_context": NSTR, "capabilities_effective": STRS,
         "capabilities_permitted": STRS, "capabilities_bounding": STRS,
         "seccomp_mode": NINT, "no_new_privs": NSTR},
    ),
    "binder": obj(["summary", "raw"], {"summary": ANY_OBJ, "raw": STR}),
    "android_meminfo": obj(["parsed", "raw"], {"parsed": ANY_OBJ, "raw": STR}),
    "cgroups_namespaces": obj(["cgroups", "namespaces"],
                              {"cgroups": ANY_OBJ, "namespaces": ANY_OBJ}),
}

for name, body in DEFS.items():
    DEFS[name] = body
DEFS.update({f"sec_{k}": v for k, v in SECTION_DEFS.items()})

properties: dict = {
    "schema_version": {"const": "3.0"},
    "report": obj(
        ["status", "tool_version", "generated_at_utc", "duration_ms"],
        {"status": STR, "tool_version": STR,
         "generated_at_utc": {"type": "string", "format": "date-time"},
         "duration_ms": INT},
    ),
    "sections_status": obj(
        SECTIONS,
        {name: obj(["status"], {"status": {"enum": ["complete", "unavailable"]}})
         for name in SECTIONS},
    ),
    "errors": {"type": "array", "items": {"$ref": "#/$defs/error"}},
    "checks": {"type": "array"},
    "notes": {"type": "array"},
    "limitations": {"type": "array"},
    "glossary": ANY_OBJ,
}
for name in NULLABLE_SECTIONS_ALWAYS_NULL:
    properties[name] = {"type": "null"}
for name in SECTIONS:
    # Typed as object here; the allOf rules below allow null only when unavailable.
    properties[name] = {"type": ["object", "null"]}

all_of = []
for name in SECTIONS:
    unavailable = {
        "properties": {"sections_status": {
            "required": [name],
            "properties": {name: {"required": ["status"],
                                  "properties": {"status": {"const": "unavailable"}}}},
        }},
        "required": ["sections_status"],
    }
    all_of.append({
        "if": unavailable,
        "then": {"properties": {name: {"type": "null"}}},
        "else": {"properties": {name: {"$ref": f"#/$defs/sec_{name}"}}},
    })

schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Android Process Analyzer report (schema_version 3.0)",
    "description": (
        "Output of `AndroidProcessAnalyzer.py analyze --format json` with the full "
        "section set. A collected section is an object; it is null only when its "
        "sections_status is \"unavailable\". Unknown fields are rejected. "
        "Generated by gen_schema.py; do not edit by hand."
    ),
    "type": "object",
    "required": ["schema_version", "report", "sections_status", "errors",
                 "process", "summary", "network", "environment", "checks", "notes",
                 "limitations", "glossary"] + SECTIONS,
    "additionalProperties": False,
    "properties": properties,
    "allOf": all_of,
    "$defs": {**DEFS, **{f"sec_{k}": v for k, v in SECTION_DEFS.items()}},
}

OUT.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
print(f"wrote {OUT}")
