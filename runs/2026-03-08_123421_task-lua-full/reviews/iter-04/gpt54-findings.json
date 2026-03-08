[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "scan_directory / duplicated block around the >>>REPLACE marker",
    "title": "Script contains unresolved patch markers and duplicated code, making it syntactically invalid",
    "description": "The file still includes literal `>>>REPLACE` markers and replacement notes such as `(move randomseed to top of main)`. These are not Lua comments and will cause a parse error before execution. In addition, the surrounding code is duplicated in `scan_directory`, so the checked-in file is not runnable as-is.",
    "impact": "The collector will fail to start at all on target systems, resulting in no scanning, no uploads, and no collection markers.",
    "suggestion": "Remove the patch markers and keep only the intended final code. Ensure `scan_directory` contains a single progress-detection block and that `main()` contains only valid Lua statements. Run `lua -p thunderstorm-collector.lua` or equivalent syntax validation before release.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "mktemp / fallback branch using io.open(path, \"wb\")",
    "title": "Temporary-file fallback is vulnerable to symlink clobbering and races",
    "description": "When `mktemp` is unavailable, the code generates `/tmp/thunderstorm.<suffix>` and creates it with `io.open(..., \"wb\")`. On multi-user or adversarial systems, an attacker can pre-create that path as a symlink to another file. Opening with `wb` follows symlinks and truncates the target. The random suffix reduces predictability but does not provide atomic creation or symlink protection.",
    "impact": "This can overwrite arbitrary writable files, corrupt logs/configuration, or redirect request/response temp files in unsafe ways. `/tmp` is explicitly attacker-controlled on many systems.",
    "suggestion": "Do not implement a non-atomic temp-file fallback with plain `io.open`. Prefer requiring a real `mktemp` utility, or create a private temp directory with restrictive permissions and use shell `mktemp` inside it. If no safe primitive exists in pure Lua 5.1, fail closed with a fatal error instead of creating insecure temp files.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "scan_directory / after handle:close()",
    "title": "Find command failures are silently ignored, so partial scans can exit as clean",
    "description": "The code reads `find` output via `io.popen(cmd)` and then calls `handle:close()`, but it never inspects the close status. `find` commonly exits non-zero on traversal errors, I/O errors, or permission problems even when some paths were emitted. The comment explicitly says partial results are treated as valid, but the hardened behavior requested for the other collectors is to reflect partial failures in the exit code. As written, a directory scan can miss files due to runtime errors and still return exit code 0 if uploads succeeded.",
    "impact": "Operators may believe the collection completed cleanly when it actually skipped parts of the filesystem. This weakens incident response and parity with the hardened collectors' exit-code contract.",
    "suggestion": "Capture and evaluate the `find` exit status. If it is non-zero, log to stderr and increment a partial-failure counter so the process exits 1. If BusyBox/Lua version differences make `popen():close()` status awkward, redirect `find` exit code to a temp file or wrap the command in `sh -c 'find ...; echo $? >status'`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "MEDIUM",
    "location": "send_collection_marker / scan_id extraction",
    "title": "Fallback scan_id parser can return escaped JSON fragments instead of the real value",
    "description": "The strict pattern only accepts `[A-Za-z0-9_%.%-]+`. If the server returns a valid JSON string containing any escaped character, the fallback pattern `\"scan_id\"%s*:%s*\"([^\"]*)\"` stops at the first embedded escaped quote sequence and returns the raw escaped fragment rather than the decoded string. That malformed value is then appended to the upload endpoint as `scan_id=...`.",
    "impact": "Uploads may be associated with the wrong scan or rejected entirely if the server ever changes scan_id format. This is a correctness bug in marker-to-upload correlation.",
    "suggestion": "Either constrain the server contract and reject non-simple scan IDs explicitly, or implement minimal JSON string parsing for this field that honors backslash escapes before using the value.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "send_collection_marker / tool fallback logic",
    "title": "Begin/end markers are skipped when only nc is available and upload tool was not pre-detected",
    "description": "Inside `send_collection_marker`, if `config.upload_tool` is empty, the fallback detection checks only `curl` and `wget`; it does not consider `nc`. Today `main()` usually calls `detect_upload_tool()` first in non-dry-run mode, but this function is written as a general fallback and will incorrectly skip marker sending in any path where the upload tool was not pre-populated and only `nc` exists.",
    "impact": "Collection markers can be lost on minimal systems that rely on `nc`, breaking scan lifecycle tracking and parity with the other collectors.",
    "suggestion": "Reuse `detect_upload_tool()` or mirror its full logic, including `nc` selection for non-SSL URLs. Avoid maintaining a second, incomplete tool-detection path.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "main / end-marker send result ignored",
    "title": "End marker delivery failures do not affect exit status",
    "description": "The script sends the final `end` collection marker but ignores whether it succeeded. The hardened behavior described for the other collectors emphasizes partial-failure reporting. If all file uploads succeed but the end marker fails, the script still exits 0, even though the server-side collection state is incomplete.",
    "impact": "Operational tooling may treat the run as fully successful while the Thunderstorm server never receives completion metadata or final stats.",
    "suggestion": "Have `send_collection_marker` return success separately from `scan_id`, and treat begin/end marker failures as partial failures that produce exit code 1 (unless you intentionally document a different contract).",
    "false_positive_risk": "medium"
  }
]