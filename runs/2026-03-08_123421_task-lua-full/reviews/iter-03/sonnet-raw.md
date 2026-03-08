```json
[
  {
    "id": "F1",
    "severity": "CRITICAL",
    "location": "scan_directory / for file_path in handle:lines() loop",
    "title": "Malformed script: `>>>REPLACE` marker left in production code",
    "description": "The source file contains a literal `>>>REPLACE` token followed by a duplicated block of code (the progress-detection and pcall-wrapped scan loop appears twice). The `>>>REPLACE` line is not valid Lua and will cause a syntax error, making the entire script fail to load. The code between the first `for file_path in handle:lines() do` and the `>>>REPLACE` marker is an incomplete, unclosed loop body.",
    "impact": "The script cannot be executed at all — `lua thunderstorm-collector.lua` will immediately abort with a syntax error. Complete loss of functionality.",
    "suggestion": "Remove the first (incomplete) copy of the loop and the `>>>REPLACE` marker, keeping only the pcall-wrapped version that follows it. The final scan_directory function should contain exactly one progress-detection block and one pcall-wrapped loop.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "CRITICAL",
    "location": "shell_quote / all upload functions",
    "title": "shell_quote does not protect against filenames starting with a dash being interpreted as options",
    "description": "shell_quote wraps the string in single quotes, which correctly handles most special characters. However, when the quoted value is passed as a positional argument to tools like `nc`, a filename like `-e /bin/sh` stored in a path such as `/tmp/-e /bin/sh` would be single-quoted correctly. The real risk is in `upload_with_nc` where `shell_quote(host)` and `shell_quote(port)` are passed directly as arguments to `nc`. If the server hostname parsed from the URL were attacker-controlled and began with `-`, it could inject nc options. More critically, `shell_quote(req_file)` and `shell_quote(resp_file)` use mktemp paths that are under attacker influence via symlink attacks (see F3), but the option-injection risk exists for the host/port fields derived from config.",
    "impact": "If the server field is set to a value starting with `-` (e.g., via a config injection), nc/curl/wget could receive unintended flags. Low likelihood in normal use but a hardening gap.",
    "suggestion": "Prepend `--` before positional arguments where the tool supports it, or validate that `config.server` does not start with `-` in `validate_config()`.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "mktemp / build_multipart_body / upload_with_nc / submit_file",
    "title": "TOCTOU race on temp file fallback path; symlink attack possible",
    "description": "When `mktemp` (the system binary) is unavailable, the code falls back to `os.tmpname()` and then opens the returned path. `os.tmpname()` in Lua 5.1 calls C `tmpnam()`, which is documented as unsafe due to the race between name generation and file creation. An attacker with write access to `/tmp` can create a symlink at the returned path between `os.tmpname()` and `io.open()`, causing the script to write multipart body data (including file contents) to an attacker-chosen destination. The secondary fallback (`/tmp/thunderstorm.<time><random>`) is also predictable because `os.time()` has 1-second granularity and `math.random` is seeded with `os.time()` — the seed is set in `main()` after `mktemp` may already be called during `send_collection_marker` for the begin marker.",
    "impact": "On a shared system, an attacker could redirect file upload bodies (containing potentially sensitive scanned files) to arbitrary paths, or cause the script to overwrite files.",
    "suggestion": "Always prefer the `mktemp` binary. If unavailable, use `/dev/urandom` via `io.open('/dev/urandom','rb'):read(8)` to generate an unpredictable suffix. Also call `math.randomseed` before the first `mktemp()` call (move it before `send_collection_marker`).",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "build_multipart_body",
    "title": "Boundary collision: file content containing the boundary string causes malformed multipart body",
    "description": "The multipart boundary is generated as `----ThunderstormBoundary` + two 9-digit random numbers. If the binary content of the uploaded file happens to contain this exact byte sequence preceded by `\\r\\n--`, the HTTP server will interpret it as a premature boundary, truncating the file data and potentially causing the server to parse a malformed request. The boundary is not checked against the file content before use.",
    "impact": "Malware samples (which may contain arbitrary byte sequences) could trigger this. The server would receive a truncated or malformed file, defeating the purpose of the scanner. This is a correctness issue for binary files.",
    "suggestion": "After generating the boundary, read the file once to verify the boundary does not appear in it, regenerating if necessary. Alternatively, use a cryptographically derived boundary (e.g., hex-encode bytes from `/dev/urandom`). Since the file is already being streamed to a temp file, a pre-scan pass is feasible.",
    "false_positive_risk": "low"
  },
  {
    "id": "F5",
    "severity": "HIGH",
    "location": "upload_with_nc / send_collection_marker",
    "title": "nc upload silently succeeds even on connection failure when resp is empty",
    "description": "In `upload_with_nc`, if `nc` fails to connect (e.g., server unreachable), it exits non-zero but the script ignores the exit code (`exec_ok(cmd)` result is discarded). The response file will be empty, and the check `if not resp or resp == ''` returns `false` — correctly. However, if nc connects but the server closes the connection before sending a response (e.g., TLS mismatch, server crash mid-transfer), `resp` will also be empty and the function returns `false`. The issue is that the nc exit code is never checked, so a partial upload (nc connected, sent data, server closed without responding) is indistinguishable from a clean failure. More importantly, `exec_ok(cmd)` return value is thrown away — this is intentional per the comment, but means retry logic in `submit_file` will always retry even when nc itself reports success (exit 0) with an empty body.",
    "impact": "Files may be retried unnecessarily (wasting bandwidth on embedded systems) or silently dropped when nc exits non-zero due to the server closing the connection after receiving the full upload (which is valid HTTP/1.0 behavior).",
    "suggestion": "Capture nc's exit code: `local nc_ok = exec_ok(cmd)`. If `nc_ok` is false AND resp is empty, treat as connection failure. If `nc_ok` is true but resp is empty, log a warning about missing response but consider it a potential success (or retry once).",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "HIGH",
    "location": "submit_file / temp file cleanup loop",
    "title": "Temp file list truncation uses table.remove in reverse but leaves gaps if upload functions add non-contiguous entries",
    "description": "After each upload attempt, `submit_file` removes temp files created during that attempt by iterating `temp_files` from `#temp_files` down to `temps_before + 1` using `table.remove`. This is correct for a simple stack. However, `build_multipart_body` calls `mktemp()` which appends to `temp_files`, and the upload functions (curl, wget, nc) also call `mktemp()` for resp_file and err_file. If an upload function returns early (e.g., `build_multipart_body` returns nil and the function returns false before creating resp_file), `temps_before` was captured before the attempt, so the cleanup loop correctly removes whatever was added. This part is actually correct. The real bug is: `send_collection_marker` also calls `mktemp()` and adds to `temp_files`, but never cleans up those entries — it relies on `cleanup_temp_files()` at the end of `main()`. If the script is killed (SIGKILL) or crashes, those temp files leak. This is a minor resource leak but on embedded systems with limited `/tmp` space it matters.",
    "impact": "Temp file accumulation in `/tmp` on embedded systems with small RAM-backed tmpfs. Each collection run with many files could leave dozens of temp files if the process is interrupted.",
    "suggestion": "In `send_collection_marker`, track the temp_files index before the call and clean up immediately after, similar to the pattern in `submit_file`. Or use a dedicated cleanup wrapper.",
    "false_positive_risk": "low"
  },
  {
    "id": "F7",
    "severity": "HIGH",
    "location": "sanitize_filename",
    "title": "sanitize_filename uses a Lua pattern class that does not correctly escape backslash",
    "description": "The pattern `'[\"\\\\;]'` in Lua source is the string `[\"%\\;]` at runtime (Lua string escaping: `\\\\` → `\\`). In a Lua character class `[...]`, `%\\` means literal `%` followed by `\\` — but `%` inside `[]` is not a magic character in Lua patterns, so this matches `%`, `\\`, `\"`, and `;`. The intent was to match `\"`, `\\`, and `;`. The accidental inclusion of `%` is harmless for the sanitization purpose, but the backslash IS correctly matched here (since `\\` inside `[]` is just a literal backslash in Lua patterns). So the backslash replacement works. However, the function is used to sanitize the filename in the Content-Disposition header. The header value is placed inside double quotes: `filename=\"%s\"`. If `sanitize_filename` replaces `\"` with `_` but a filename contains `\\\"` (backslash then quote), the backslash is replaced with `_` and the quote is replaced with `_`, so the output is safe. This is actually correct but the pattern comment is misleading. The real issue: `sanitize_filename` is NOT applied to the boundary string or to the endpoint URL — only to the filename in the Content-Disposition header.",
    "impact": "Low direct impact since the pattern works correctly by accident, but the misleading pattern could cause future maintainers to break it.",
    "suggestion": "Rewrite the pattern clearly: `s:gsub('[\"\\\\;%%]', '_')` if `%` should be included, or `s:gsub('[\"\\\\;]', '_')` if not. Add a comment explaining why each character is excluded.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F8",
    "severity": "HIGH",
    "location": "build_find_command",
    "title": "find -mtime -N semantics: -mtime -0 matches no files, and -mtime -1 only matches files modified in the last 24 hours, not 'today'",
    "description": "The find command uses `-mtime -N` where N is `config.max_age`. The `find -mtime -N` predicate matches files modified less than N*24 hours ago. With `max_age=14`, this correctly finds files modified in the last 14 days. However, the validation in `validate_config` warns about `max_age=0` but allows it through (the warning says it matches nothing, which is correct). More importantly, `max_age=1` matches files modified less than 24 hours ago — not 'today' as users might expect. This is documented behavior of find, but there's no warning for `max_age=1`. This is a minor UX issue. The more significant issue: if `config.max_age` is very large (e.g., 36500 for 100 years), the find command will scan all files, which could be millions of files on a system, causing memory exhaustion in the popen pipe buffer or extremely long runtime.",
    "impact": "Unexpectedly large scans if max_age is set to a very high value. No upper bound validation.",
    "suggestion": "Add an upper bound check in `validate_config`: `if config.max_age > 3650 then log_msg('warn', 'max-age > 3650 days; this will scan very old files') end`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F9",
    "severity": "HIGH",
    "location": "upload_with_wget / upload_with_busybox_wget",
    "title": "wget --post-file with multipart body: Content-Length header may be wrong if body_len is nil",
    "description": "In `upload_with_wget`, `body_len` comes from `build_multipart_body` as the third return value. `build_multipart_body` returns `nil, nil, nil` on failure, and the caller checks `if not boundary then return false end`. However, `body_len` is computed as `total_body` which counts bytes written. If the source file is empty (0 bytes), `body_len` will equal `#preamble + #epilogue`, which is correct. The issue is that `body_len` counts Lua string lengths in bytes, which is correct for binary data. BUT: on systems where `io.seek('end')` returns a size that differs from the actual bytes read (e.g., due to text-mode translation on non-Linux systems), the Content-Length could be wrong. Since the target is Linux/embedded, this is low risk. The actual bug: `body_len` is the size of the multipart body written to the temp file, but wget's `--post-file` will send the actual file size regardless of the Content-Length header. If they differ (shouldn't happen on Linux), the server may reject the request. This is not a real bug on the target platform.",
    "impact": "Minimal on Linux targets. Potential issue if ported to non-Linux.",
    "suggestion": "After writing the temp file, verify its size matches body_len using `file_size_kb` or a seek, and log a warning if they differ.",
    "false_positive_risk": "high"
  },
  {
    "id": "F10",
    "severity": "MEDIUM",
    "location": "parse_proc_mounts",
    "title": "Octal escape decoding in /proc/mounts is incomplete and order-dependent",
    "description": "The function decodes `\\040` (space), `\\011` (tab), `\\012` (newline), and `\\134` (backslash) from mountpoint paths. However, it applies them sequentially with `gsub`, and the backslash replacement (`\\134` → `\\`) is applied last. If a mountpoint contains `\\134040` (escaped backslash followed by escaped space), the sequence would be: `\\134040` → after `\\040` substitution: `\\134 ` (backslash-134-space) — wait, `\\040` matches the literal 4-character sequence `\040`, not `\\134040`. Actually the gsub patterns use literal strings (4th arg `true` is not passed, so they're patterns). `\\040` as a Lua pattern matches `\` then `0` then `4` then `0`. This is correct for the literal text in /proc/mounts. The order issue: `\\134` should be decoded FIRST (before other backslash sequences), otherwise `\\134040` would be decoded as `\\134` + `040` → `\040` (a literal backslash-zero-four-zero) rather than `\ ` (backslash-space). The current code decodes `\\040` first, which means `\\134040` → `\134 ` (wrong) instead of `\ ` (correct).",
    "impact": "Mountpoints with backslashes followed by spaces (rare but valid) would not be correctly excluded, potentially causing the scanner to traverse network or special filesystems.",
    "suggestion": "Decode `\\134` (backslash) FIRST, then decode the other sequences: move the `mp:gsub('\\\\134', '\\\\')` line before the other gsub calls.",
    "false_positive_risk": "low"
  },
  {
    "id": "F11",
    "severity": "MEDIUM",
    "location": "detect_upload_tool / wget_is_busybox",
    "title": "wget_is_busybox() is called twice: once during detection and potentially again in send_collection_marker",
    "description": "In `detect_upload_tool`, `wget_is_busybox()` is called when wget is found. In `send_collection_marker`, if `config.upload_tool` is empty (which shouldn't happen after detection but is a fallback), `wget_is_busybox()` is called again. Each call spawns a subprocess (`io.popen`). On embedded systems, subprocess spawning is expensive. More importantly, `wget_is_busybox()` is not memoized — if called multiple times it re-executes `wget --version` each time. This is wasteful but not a correctness bug.",
    "impact": "Minor performance issue on embedded systems. Not a correctness bug.",
    "suggestion": "Memoize the result of `wget_is_busybox()` similar to `_check_mktemp()`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F12",
    "severity": "MEDIUM",
    "location": "send_collection_marker",
    "title": "scan_id extracted from JSON response using a fragile pattern that can be fooled by nested JSON",
    "description": "The scan_id is extracted with `resp:match('\"scan_id\"%s*:%s*\"([^\"]+)\"')`. This pattern will match the first occurrence of `\"scan_id\":\"...\"` in the response. If the response JSON contains a nested object or array where a string value contains `\"scan_id\":\"fake\"`, the pattern would match the wrong value. Additionally, if the scan_id itself contains escaped quotes (valid JSON: `\"scan_id\":\"abc\\\"def\"`), the pattern `[^\"]+` would stop at the escaped quote, returning a truncated ID. While Thunderstorm server responses are likely well-controlled, this is a robustness issue.",
    "impact": "Wrong scan_id could cause the end marker to be associated with the wrong scan on the server, breaking scan tracking.",
    "suggestion": "Use a more specific pattern that anchors to the beginning of the JSON object, or validate that the extracted ID matches an expected format (alphanumeric/UUID). At minimum, document the assumption that scan_ids don't contain escaped quotes.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F13",
    "severity": "MEDIUM",
    "location": "main / math.randomseed",
    "title": "math.randomseed called after mktemp() is first used, so early temp files use uninitialized RNG",
    "description": "`math.randomseed(os.time() + ...)` is called in `main()` after `validate_config()`, `detect_source_name()`, and before `parse_proc_mounts()`. However, `send_collection_marker` (the begin marker) is called after `detect_upload_tool()` which is after the seed call — so that's fine. BUT: `mktemp()` is called from `build_multipart_body` which is called from upload functions. The seed IS set before any uploads. However, if `_check_mktemp()` fails and the fallback path is used, `math.random(10000,99999)` is called. In Lua 5.1, the default RNG state before `randomseed` is implementation-defined but typically produces the same sequence on every run. The seed IS set before uploads, so this is actually fine for the upload path. The issue is if `mktemp()` is called before `math.randomseed` — checking the code flow: `parse_args` → `validate_config` → `detect_source_name` → `parse_proc_mounts` → `detect_upload_tool` → `math.randomseed` → `send_collection_marker` (which calls `mktemp`). So the seed IS set before the first `mktemp` call that uses `math.random`. This finding is lower severity than initially assessed.",
    "impact": "Low — the seed is set before mktemp is first called in practice.",
    "suggestion": "Move `math.randomseed` to the very top of `main()` before any function calls, as a defensive measure.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F14",
    "severity": "MEDIUM",
    "location": "upload_with_curl",
    "title": "curl error output captured from err_file but only logged at debug level, hiding upload failures",
    "description": "When curl fails, the error message from stderr (captured in `err_file`) is logged at `debug` level: `log_msg('debug', 'curl error: ' .. ...)`. This means that unless `--debug` is enabled, curl errors (e.g., 'Connection refused', 'SSL certificate problem') are silently swallowed. The caller (`submit_file`) logs a generic 'Upload failed' warning, but the specific curl error is lost in non-debug mode.",
    "impact": "Operators cannot diagnose upload failures without re-running with `--debug`. In production on embedded systems where re-running may not be easy, this makes troubleshooting very difficult.",
    "suggestion": "Log curl errors at `warn` level (not `debug`) so they appear in normal operation. The specific error message is valuable for diagnosis.",
    "false_positive_risk": "low"
  },
  {
    "id": "F15",
    "severity": "MEDIUM",
    "location": "build_find_command",
    "title": "find prune expression uses -path which matches on the full path, but the pattern P/* may not prune correctly on all find implementations",
    "description": "The prune expression uses `-path /proc -o -path /proc/*`. On GNU find, `-path /proc/*` correctly matches any path under `/proc`. On BusyBox find, `-path` behavior with wildcards may differ — specifically, BusyBox find's `-path` uses `fnmatch()` which should work correctly. However, the expression structure `\\( -path P -o -path P/* -o -path Q -o -path Q/* ... \\) -prune -o -type f -print` has a subtle issue: the `-prune` action only prevents descending into matched directories, but if `find` is given a start path that IS one of the excluded paths (e.g., `find /proc ...`), the prune won't help because find has already entered it. This is handled by the `test -d` check before scanning, but if a scan_dir is `/` (root), the prune expressions need to work correctly. The `-path P/*` pattern requires the path to contain a `/` after P, which means the directory P itself is matched by `-path P` (without the slash). This is correct.",
    "impact": "On some BusyBox versions, the wildcard in `-path P/*` might not work as expected, causing excluded directories to be scanned.",
    "suggestion": "Add a test with BusyBox find to verify prune behavior. As a fallback, consider using `-name` based exclusions for known special directories, or add a runtime check of the find version.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F16",
    "severity": "MEDIUM",
    "location": "upload_with_nc",
    "title": "HTTP/1.1 request without proper chunked encoding or guaranteed Content-Length may cause server to hang",
    "description": "The nc upload sends an HTTP/1.1 request with `Connection: close` and a `Content-Length` header. This should work correctly. However, if `body_len` (the Content-Length) is computed incorrectly (e.g., due to the boundary collision scenario in F4 where the body is truncated), the server will wait for more data than is sent, causing a timeout. Additionally, HTTP/1.1 with `Connection: close` requires the server to close the connection after the response, which nc handles via `-w 10` timeout. If the server is slow to respond (e.g., scanning a large file), the 10-second timeout may cause nc to close the connection before reading the full response, resulting in a false failure.",
    "impact": "Large file uploads via nc may be incorrectly reported as failed even when the server received the file successfully, causing unnecessary retries.",
    "suggestion": "Increase the nc timeout (`-w`) based on file size, or use HTTP/1.0 instead of HTTP/1.1 (which has simpler connection semantics). Consider using `Connection: close` with HTTP/1.0 to avoid keep-alive complications.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F17",
    "severity": "LOW",
    "location": "log_msg",
    "title": "syslog via os.execute('logger ...') is called synchronously and blocks the scan loop",
    "description": "When `config.log_to_syslog` is true, every non-debug log message spawns a shell process via `os.execute`. The comment notes that debug messages are skipped to avoid this overhead. However, info-level messages (logged for every submitted file in debug mode, and for errors/warnings) still spawn a shell. On embedded systems with slow process creation, this can significantly slow down the scan loop.",
    "impact": "Performance degradation on embedded systems when syslog is enabled. Not a correctness issue.",
    "suggestion": "Batch syslog messages or use a pipe to a persistent logger process. Alternatively, document that syslog should only be enabled when performance is not critical.",
    "false_positive_risk": "low"
  },
  {
    "id": "F18",
    "severity": "LOW",
    "location": "is_cloud_path",
    "title": "Cloud path detection uses case-insensitive matching but path:lower() is called on every file",
    "description": "For every file processed, `is_cloud_path` calls `path:lower()` and then iterates through all cloud directory names. On embedded systems scanning millions of files, this creates unnecessary string allocations. This is a minor performance issue.",
    "impact": "Minor memory pressure and GC overhead on embedded systems with millions of files.",
    "suggestion": "Pre-compute lowercased versions of CLOUD_DIR_NAMES at startup. The `path:lower()` call per file is unavoidable but the name comparisons could be optimized.",
    "false_positive_risk": "low"
  },
  {
    "id": "F19",
    "severity": "LOW",
    "location": "validate_config",
    "title": "validate_config does not validate that scan directories exist or are accessible",
    "description": "The validation checks server, port, ca_cert, max_age, max_size_kb, retries, and source, but does not check whether the configured scan directories exist. Non-existent directories are handled gracefully in `scan_directory` with a warning, but a typo in a directory path would silently result in no files being scanned with exit code 0 (if no other failures occur).",
    "impact": "Silent no-op if all scan directories are mistyped. Exit code 0 would be misleading.",
    "suggestion": "In `validate_config`, warn (not die) if a configured scan directory does not exist: `if not exec_ok('test -d ' .. shell_quote(dir)) then log_msg('warn', 'Scan directory does not exist: ' .. dir) end`.",
    "false_positive_risk": "low"
  }
]
```