[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "build_find_command / age filter construction",
    "title": "Files exactly at max-age boundary are incorrectly excluded",
    "description": "The code claims to use minute-granularity filtering so files exactly at the configured age limit are included, but it builds the command with `-mmin -%d`. In `find`, `-mmin -N` means strictly less than N minutes old, so a file exactly N minutes old is still excluded. This contradicts the stated hardening goal and can skip borderline files that should be collected.",
    "impact": "Suspicious files that are exactly at the retention threshold can be silently missed, reducing collection coverage and making behavior inconsistent with the other hardened collectors.",
    "suggestion": "Adjust the predicate to include the boundary explicitly, e.g. use a range such as `-mmin -<N+1>` if acceptable for BusyBox/GNU portability, or switch to a shell-side timestamp comparison approach that includes equality. At minimum, fix the comment because the current implementation does not provide the promised behavior.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "send_collection_marker / nc branch",
    "title": "nc marker transport treats successful HTTP responses as failures",
    "description": "Unlike `upload_with_nc`, the `send_collection_marker` nc path checks `exec_ok(nc_cmd)` and logs failure if netcat exits non-zero. On BusyBox/OpenBSD netcat variants, a non-zero exit can still occur even when a complete HTTP response was received. The file upload nc backend already avoids trusting the exit code and validates the response body instead, but the marker path does not. This can cause begin/end markers to be reported as failed even when the server accepted them.",
    "impact": "Collection tracking becomes unreliable on nc-only systems: begin markers may be retried unnecessarily, scan IDs may be lost, and end markers may be skipped or misreported.",
    "suggestion": "Mirror the logic used in `upload_with_nc`: ignore the raw `nc` exit status, read the response file, validate the HTTP status line/body, and only then decide success/failure.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "send_collection_marker / tool fallback selection",
    "title": "BusyBox wget fallback is bypassed for collection markers",
    "description": "When `config.upload_tool` is empty, marker sending falls back by probing `curl`, then any `wget`, then `nc`. If only BusyBox wget is installed, this path sets `tool = \"wget\"` and executes the GNU wget code path. Earlier in the script, upload tool detection distinguishes GNU wget from BusyBox wget because behavior differs materially. The marker fallback ignores that distinction, so marker delivery may use unsupported or incompatible wget options on minimal systems.",
    "impact": "On embedded targets with only BusyBox wget available, begin/end markers can fail even though the script otherwise supports BusyBox wget as a last-resort transport.",
    "suggestion": "Reuse `detect_upload_tool()` or at least apply the same `wget_is_busybox()` check in the fallback path so `tool` becomes `busybox-wget` when appropriate.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "MEDIUM",
    "location": "main / begin marker retry sleep",
    "title": "Retry sleep command is shell-invoked without availability check",
    "description": "The script relies on `os.execute(\"sleep 2\")` for begin-marker retry and backoff delays. On most BusyBox systems this exists, but the code treats these sleeps as unconditional and never checks whether the command is available or succeeded. This is inconsistent with the otherwise defensive runtime probing approach used for `timeout` and upload tools.",
    "impact": "On stripped-down environments or unusual PATH setups, retry timing silently degrades and can cause immediate retry storms or inconsistent behavior.",
    "suggestion": "Probe `sleep` once or tolerate failure explicitly, e.g. wrap it in a helper that ignores absence but logs at debug level. If portability is a concern, document the dependency clearly.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "main / signal handling parity gap",
    "title": "Interrupted collection marker is not implemented despite stated hardening baseline",
    "description": "The prompt states the other collectors send an `interrupted` collection marker with stats on SIGINT/SIGTERM. This Lua script only documents a shell-wrapper workaround in comments and does not provide an actual wrapper or integrated mechanism to emit the marker on interruption. Given Lua 5.1 limitations this is understandable, but it is still a real parity gap versus the hardened baseline.",
    "impact": "Operational visibility is reduced: aborted scans appear as missing end markers rather than explicit interruptions, which complicates server-side tracking and incident response workflows.",
    "suggestion": "Ship a companion POSIX shell wrapper alongside the Lua script that traps INT/TERM, forwards termination to the Lua process, and sends the `interrupted` marker with current stats. If that is out of scope, document this as an explicit unsupported feature rather than implying parity.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "scan_directory / handle:close result ignored",
    "title": "find command failures after partial output are not detected",
    "description": "The code reads `find` output via `io.popen(...):lines()` and always calls `handle:close()`, but it ignores the close result. If `find` encounters an execution error after emitting some paths, or exits non-zero for another reason, the scan continues as if successful. The surrounding `pcall` only catches Lua iteration errors, not the subprocess exit status.",
    "impact": "Directory scans can be partially incomplete without affecting counters or exit code, leading to silent under-collection and false confidence in successful runs.",
    "suggestion": "Capture and evaluate the return value from `handle:close()` (or use a helper similar to `exec_ok` for popen-backed commands) and increment failure state / log a warning when `find` exits non-zero.",
    "false_positive_risk": "low"
  }
]