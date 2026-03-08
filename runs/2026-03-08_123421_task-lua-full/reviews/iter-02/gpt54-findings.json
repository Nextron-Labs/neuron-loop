[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "main / banner and summary stdout writes",
    "title": "Normal execution writes to stdout, which breaks the hardened stderr-only error/reporting convention",
    "description": "The script prints the banner with `print_banner()` and always prints the final run summary with `io.write(...)` to stdout. In the hardened sibling collectors, operational/errors are routed consistently away from stdout so stdout can remain machine-consumable or unused. Here, even `--quiet` does not suppress the banner or summary, and any caller that expects silent success or reserved stdout will receive unsolicited output.",
    "impact": "Automation that wraps the collector may misparse stdout, especially on embedded systems where scripts are chained together. This is also a parity gap versus the hardened collectors' behavior.",
    "suggestion": "Suppress banner/summary unless explicitly requested, or route them through `log_msg()`/stderr. At minimum, honor `--quiet` for banner and summary output.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "main / progress option handling",
    "title": "Progress reporting flags are parsed but never implemented",
    "description": "The script accepts `--progress` and `--no-progress`, and `config.progress` is documented as supporting TTY auto-detection, but no code ever uses this setting. This is a direct parity gap with the hardened collectors, which provide progress reporting with TTY auto-detection.",
    "impact": "Users relying on consistent CLI behavior across collectors will get silently ignored options. This is especially problematic in operational tooling where progress visibility is expected for long scans.",
    "suggestion": "Either implement progress reporting and TTY auto-detection, or remove the options. A minimal fix is to detect TTY via `test -t 2` and emit periodic progress updates to stderr when enabled.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "upload_with_nc / HTTPS endpoint handling",
    "title": "Netcat backend cannot perform HTTPS but is still selected for SSL mode",
    "description": "When `config.ssl` is true and only `nc` is available, `detect_upload_tool()` still selects `nc` and merely logs a warning. `upload_with_nc()` then strips `https://` and sends a plain HTTP request over the target port, typically 443. This is not TLS and will fail against real HTTPS servers; worse, it may send sensitive sample data unencrypted to a listener if the endpoint is misconfigured or intercepted.",
    "impact": "Uploads fail reliably in SSL mode on systems with only netcat, or data may be transmitted without TLS despite the user explicitly requesting `--ssl`.",
    "suggestion": "Do not allow `nc` when `config.ssl` is true. Treat this as fatal during tool detection unless a TLS-capable tool is available. Example: `if config.ssl and tool == 'nc' then die('HTTPS requires curl or wget; nc is not TLS-capable') end`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "send_collection_marker / upload tool fallback logic",
    "title": "Collection markers may be skipped when BusyBox wget is the detected backend",
    "description": "If `config.upload_tool` is `busybox-wget`, `send_collection_marker()` does not enter the fallback detection block because `tool ~= ''`, but it also does not have a branch that executes until the later `elseif tool == 'wget' or tool == 'busybox-wget'`. That part is fine only if `config.upload_tool` was already set. However, in paths where marker sending happens before upload tool detection or where detection is deferred/changed, the fallback only checks for `curl` and generic `wget`, not BusyBox wget classification. This creates inconsistent behavior and makes marker delivery dependent on call order.",
    "impact": "Begin/end markers can be omitted on minimal BusyBox systems in edge flows, reducing server-side visibility and breaking collection lifecycle tracking.",
    "suggestion": "Make marker sending use the same centralized tool detection/classification logic as file uploads, or call `detect_upload_tool()` before any marker attempt and remove ad-hoc fallback probing.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "mktemp / os.tmpname fallback path creation",
    "title": "Temporary file fallback is race-prone and can clobber attacker-chosen paths",
    "description": "When `mktemp` is unavailable, the code falls back to `os.tmpname()` and then separately opens the returned path, explicitly noting the race. On multi-user systems or writable shared `/tmp`, this can be exploited with symlinks or pre-created files. The later `/tmp/thunderstorm.<time><rand>` fallback has the same TOCTOU issue because it also uses predictable naming plus non-exclusive open.",
    "impact": "An attacker on the same device could influence temp file contents, cause uploads to use attacker-controlled data, or overwrite arbitrary files writable by the collector process.",
    "suggestion": "Prefer requiring `mktemp` when available and fail closed if no safe temp creation primitive exists. If a fallback is unavoidable, create temp files via a shell `umask 077; mktemp` invocation only, and abort if that fails rather than using predictable names.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "build_find_command / use of `-mtime -%d`",
    "title": "Max-age filtering is off by up to almost one day",
    "description": "The script uses `find ... -mtime -N`, which matches files modified less than N*24 hours ago, not 'within the last N calendar days' and not an exact day threshold. For example, `--max-age 14` excludes files that are 14 days and a few minutes old, which may surprise users expecting inclusive behavior. This is a correctness issue in file selection semantics.",
    "impact": "Suspicious files near the age threshold may be skipped unexpectedly, reducing collection coverage.",
    "suggestion": "Document the exact semantics clearly or switch to a more precise comparison using `-mtime`/`-mmin` as intended. If parity with other collectors expects inclusive day behavior, adjust the expression accordingly.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F7",
    "severity": "MEDIUM",
    "location": "scan_directory / `handle:close()` result ignored",
    "title": "Find command failures are silently ignored, so partial scan failures do not affect exit code",
    "description": "The script reads file paths from `io.popen(cmd)` and then calls `handle:close()` without checking its return status. If `find` encounters an execution error beyond stderr suppression, or exits non-zero due to environmental issues, the collector still treats the directory scan as successful unless zero files were seen. This conflicts with the hardened requirement that partial failures be tracked and reflected in exit code 1.",
    "impact": "Real scan failures can be hidden, causing false clean exits even though some directories were not scanned correctly.",
    "suggestion": "Capture and evaluate the close status from `io.popen` where available, and increment a scan-failure counter that contributes to exit code 1. Also avoid blanket `2>/dev/null` if you need to distinguish permission noise from real command failure.",
    "false_positive_risk": "low"
  },
  {
    "id": "F8",
    "severity": "MEDIUM",
    "location": "parse_proc_mounts / mountpoint parsing from `/proc/mounts`",
    "title": "Escaped mountpoints from `/proc/mounts` are not unescaped before exclusion matching",
    "description": "Mountpoints in `/proc/mounts` encode spaces and some characters using backslash escapes such as `\\040`. The code stores the raw encoded mountpoint string in `dynamic_excludes` and later compares it against real filesystem paths in `find -path`. For mountpoints containing spaces or escaped characters, the exclusion will not match the actual path tree.",
    "impact": "Network/special filesystems mounted on paths with spaces or escaped characters may be scanned unintentionally, causing hangs, permission issues, or collection from excluded storage.",
    "suggestion": "Unescape `/proc/mounts` mountpoints before storing them, at least for common octal escapes like `\\040`, `\\011`, `\\012`, and `\\134`.",
    "false_positive_risk": "low"
  }
]