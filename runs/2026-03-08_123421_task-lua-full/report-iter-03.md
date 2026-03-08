# Neuron-Loop Report — Iteration 3
Generated: 2026-03-08 12:45:36

## Tests: ❌ FAIL
```
=== TEST 1: Lua 5.1 syntax check ===
luac: /test/collector.lua:967: unexpected symbol near '>'
  ❌ FAIL: Syntax errors detected

=== TEST 2: Help flag (-h) ===
  ❌ FAIL: Help text only contains 0/15 expected flags

=== TEST 3: Banner output (dry-run mode) ===
  ❌ FAIL: Banner missing or incorrect
  ❌ FAIL: Banner missing version

=== TEST 4: Unknown flag error ===
  ❌ FAIL: Unknown flag silently ignored
  ✅ PASS: Non-zero exit code on unknown flag

=== TEST 5: Dry-run mode ===
  ❌ FAIL: Dry-run mode not acknowledged
  ❌ FAIL: No files discovered in dry-run
  Output snippet:
    lua: /test/collector.lua:967: unexpected symbol near '>'

=== TEST 6: File size filtering ===
  ❌ FAIL: Large file not filtered (or not logged)
  Output snippet:

=== TEST 7: Integration test (stub server upload) ===
  ✅ PASS: Stub server running on port 18080
  Collector output:
    lua: /test/collector.lua:967: unexpected symbol near '>'
  ❌ FAIL: No files received by stub server
  ❌ FAIL: Summary line missing
  ❌ FAIL: Source parameter not found in server log

=== TEST 8: Lua 5.1 keyword compatibility ===
  ✅ PASS: No Lua 5.1 incompatible keywords found

========================================
  RESULTS: 3 passed, 11 failed, 8 tests
========================================
```

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 7 | T1 |
| sonnet | 18 | T1 |

## Triaged: 25 to fix, 0 skipped (from 25 raw findings, 25 unique)

### 🔧 1. [CRITICAL] Malformed script: `>>>REPLACE` marker left in production code
- **Location:** scan_directory / for file_path in handle:lines() loop
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The source file contains a literal `>>>REPLACE` token followed by a duplicated block of code (the progress-detection and pcall-wrapped scan loop appears twice). The `>>>REPLACE` line is not valid Lua and will cause a syntax error, making the entire script fail to load. The code between the first `for file_path in handle:lines() do` and the `>>>REPLACE` marker is an incomplete, unclosed loop body.
- **Fix:** Remove the first (incomplete) copy of the loop and the `>>>REPLACE` marker, keeping only the pcall-wrapped version that follows it. The final scan_directory function should contain exactly one progress-detection block and one pcall-wrapped loop.

### 🔧 2. [CRITICAL] shell_quote does not protect against filenames starting with a dash being interpreted as options
- **Location:** shell_quote / all upload functions
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** shell_quote wraps the string in single quotes, which correctly handles most special characters. However, when the quoted value is passed as a positional argument to tools like `nc`, a filename like `-e /bin/sh` stored in a path such as `/tmp/-e /bin/sh` would be single-quoted correctly. The real risk is in `upload_with_nc` where `shell_quote(host)` and `shell_quote(port)` are passed directly as arguments to `nc`. If the server hostname parsed from the URL were attacker-controlled and began with 
- **Fix:** Prepend `--` before positional arguments where the tool supports it, or validate that `config.server` does not start with `-` in `validate_config()`.

### 🔧 3. [HIGH] Patched block leaves a stray `for` and breaks the function syntactically
- **Location:** scan_directory / replaced loop body
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The file shows an original `for file_path in handle:lines() do` immediately followed by a replacement block that introduces another `for file_path in handle:lines() do` inside a `pcall`. If applied literally, the outer loop is never closed and the function becomes invalid Lua. This is not just a merge artifact concern: the target file as presented is not executable.
- **Fix:** Remove the original loop header entirely and keep only the wrapped version. The function should contain exactly one iteration over `handle:lines()`, e.g. `local ok, scan_err = pcall(function() for file_path in handle:lines() do ... end end)`.

### 🔧 4. [HIGH] Missing space before `-H` corrupts curl command when no CA cert is used
- **Location:** send_collection_marker / curl command construction
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The curl marker upload command is built with `"... %s%s-H %s ..."`. When `ca_cert_flag` is empty, this expands to something like `curl ... -k -H ...`, which works only if `insecure` ends with a space. But when `config.insecure` is false and `ca_cert_flag` is empty, it becomes `curl ... <respfile> -H ...` only because the previous placeholder may or may not provide spacing; the formatting is fragile and can produce malformed concatenation such as `--cacert 'x'-H` when flags are changed. This diff
- **Fix:** Build the command with explicit spaces between every optional segment, e.g. `"curl -sS --fail -o %s %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null"` and let empty flags collapse harmlessly.

### 🔧 5. [HIGH] No `nc` implementation for collection markers causes marker loss on minimal systems
- **Location:** send_collection_marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script supports `nc` for file uploads, but `send_collection_marker` only implements curl and wget paths. On systems where `detect_upload_tool()` selected `nc` (a stated supported environment on BusyBox/OpenWrt), begin/end markers are silently skipped because `tool == "nc"` is never handled and the function just returns an empty string.
- **Fix:** Add an `nc` JSON POST path similar to `upload_with_nc`, or explicitly document and surface this as a warning/error when `config.upload_tool == "nc"` so operators know markers are unavailable.

### 🔧 6. [HIGH] TOCTOU race on temp file fallback path; symlink attack possible
- **Location:** mktemp / build_multipart_body / upload_with_nc / submit_file
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When `mktemp` (the system binary) is unavailable, the code falls back to `os.tmpname()` and then opens the returned path. `os.tmpname()` in Lua 5.1 calls C `tmpnam()`, which is documented as unsafe due to the race between name generation and file creation. An attacker with write access to `/tmp` can create a symlink at the returned path between `os.tmpname()` and `io.open()`, causing the script to write multipart body data (including file contents) to an attacker-chosen destination. The secondar
- **Fix:** Always prefer the `mktemp` binary. If unavailable, use `/dev/urandom` via `io.open('/dev/urandom','rb'):read(8)` to generate an unpredictable suffix. Also call `math.randomseed` before the first `mktemp()` call (move it before `send_collection_marker`).

### 🔧 7. [HIGH] Boundary collision: file content containing the boundary string causes malformed multipart body
- **Location:** build_multipart_body
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The multipart boundary is generated as `----ThunderstormBoundary` + two 9-digit random numbers. If the binary content of the uploaded file happens to contain this exact byte sequence preceded by `\r\n--`, the HTTP server will interpret it as a premature boundary, truncating the file data and potentially causing the server to parse a malformed request. The boundary is not checked against the file content before use.
- **Fix:** After generating the boundary, read the file once to verify the boundary does not appear in it, regenerating if necessary. Alternatively, use a cryptographically derived boundary (e.g., hex-encode bytes from `/dev/urandom`). Since the file is already being streamed to a temp file, a pre-scan pass is feasible.

### 🔧 8. [HIGH] nc upload silently succeeds even on connection failure when resp is empty
- **Location:** upload_with_nc / send_collection_marker
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In `upload_with_nc`, if `nc` fails to connect (e.g., server unreachable), it exits non-zero but the script ignores the exit code (`exec_ok(cmd)` result is discarded). The response file will be empty, and the check `if not resp or resp == ''` returns `false` — correctly. However, if nc connects but the server closes the connection before sending a response (e.g., TLS mismatch, server crash mid-transfer), `resp` will also be empty and the function returns `false`. The issue is that the nc exit cod
- **Fix:** Capture nc's exit code: `local nc_ok = exec_ok(cmd)`. If `nc_ok` is false AND resp is empty, treat as connection failure. If `nc_ok` is true but resp is empty, log a warning about missing response but consider it a potential success (or retry once).

### 🔧 9. [HIGH] Temp file list truncation uses table.remove in reverse but leaves gaps if upload functions add non-contiguous entries
- **Location:** submit_file / temp file cleanup loop
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** After each upload attempt, `submit_file` removes temp files created during that attempt by iterating `temp_files` from `#temp_files` down to `temps_before + 1` using `table.remove`. This is correct for a simple stack. However, `build_multipart_body` calls `mktemp()` which appends to `temp_files`, and the upload functions (curl, wget, nc) also call `mktemp()` for resp_file and err_file. If an upload function returns early (e.g., `build_multipart_body` returns nil and the function returns false be
- **Fix:** In `send_collection_marker`, track the temp_files index before the call and clean up immediately after, similar to the pattern in `submit_file`. Or use a dedicated cleanup wrapper.

### 🔧 10. [HIGH] sanitize_filename uses a Lua pattern class that does not correctly escape backslash
- **Location:** sanitize_filename
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The pattern `'["\\;]'` in Lua source is the string `["%\;]` at runtime (Lua string escaping: `\\` → `\`). In a Lua character class `[...]`, `%\` means literal `%` followed by `\` — but `%` inside `[]` is not a magic character in Lua patterns, so this matches `%`, `\`, `"`, and `;`. The intent was to match `"`, `\`, and `;`. The accidental inclusion of `%` is harmless for the sanitization purpose, but the backslash IS correctly matched here (since `\` inside `[]` is just a literal backslash in Lu
- **Fix:** Rewrite the pattern clearly: `s:gsub('["\\;%%]', '_')` if `%` should be included, or `s:gsub('["\\;]', '_')` if not. Add a comment explaining why each character is excluded.

### 🔧 11. [HIGH] find -mtime -N semantics: -mtime -0 matches no files, and -mtime -1 only matches files modified in the last 24 hours, not 'today'
- **Location:** build_find_command
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command uses `-mtime -N` where N is `config.max_age`. The `find -mtime -N` predicate matches files modified less than N*24 hours ago. With `max_age=14`, this correctly finds files modified in the last 14 days. However, the validation in `validate_config` warns about `max_age=0` but allows it through (the warning says it matches nothing, which is correct). More importantly, `max_age=1` matches files modified less than 24 hours ago — not 'today' as users might expect. This is documented b
- **Fix:** Add an upper bound check in `validate_config`: `if config.max_age > 3650 then log_msg('warn', 'max-age > 3650 days; this will scan very old files') end`.

### 🔧 12. [HIGH] wget --post-file with multipart body: Content-Length header may be wrong if body_len is nil
- **Location:** upload_with_wget / upload_with_busybox_wget
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In `upload_with_wget`, `body_len` comes from `build_multipart_body` as the third return value. `build_multipart_body` returns `nil, nil, nil` on failure, and the caller checks `if not boundary then return false end`. However, `body_len` is computed as `total_body` which counts bytes written. If the source file is empty (0 bytes), `body_len` will equal `#preamble + #epilogue`, which is correct. The issue is that `body_len` counts Lua string lengths in bytes, which is correct for binary data. BUT:
- **Fix:** After writing the temp file, verify its size matches body_len using `file_size_kb` or a seek, and log a warning if they differ.

### 🔧 13. [MEDIUM] Marker upload success is inferred only from response body, not transport status
- **Location:** send_collection_marker / response parsing
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** For both curl and wget marker uploads, the code ignores the return value of `exec_ok(cmd)` and proceeds to parse the response file. If the command fails or writes no response, the function just returns an empty string without logging why. This makes begin/end marker failures opaque and undermines the retry logic.
- **Fix:** Check `exec_ok(cmd)` and log stderr or at least a warning on failure before returning `""`. For curl, capture stderr to a temp file as done in `upload_with_curl`.

### 🔧 14. [MEDIUM] `--max-age 0` is accepted even though the generated `find -mtime -0` matches nothing
- **Location:** build_find_command / validate_config
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script warns that `max-age=0` will match no files, but still accepts it. The surrounding context says the other collectors were hardened for correctness and consistent behavior; silently running a scan that can never submit anything is a correctness trap rather than a useful mode.
- **Fix:** Reject `max-age == 0` in `validate_config()` with a fatal error, or translate it to a meaningful behavior such as `-mtime 0`/`-mmin` semantics if that is intended.

### 🔧 15. [MEDIUM] Fallback temp-file creation is race-prone and may overwrite attacker-chosen files
- **Location:** mktemp
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When `mktemp` is unavailable, the function falls back to `os.tmpname()` and then to a predictable `/tmp/thunderstorm.<time><random>` path opened with `io.open(..., "wb")`. On multi-user systems or compromised devices, this is vulnerable to symlink races because Lua's standard library cannot request exclusive creation. The comment acknowledges TOCTOU risk, but the code still uses these files for request bodies and responses.
- **Fix:** Prefer failing closed when no safe temp-file mechanism exists, or invoke a shell helper that performs atomic creation (`umask 077; mktemp`) and abort if unavailable. At minimum, set restrictive permissions and avoid predictable fallback names.

### 🔧 16. [MEDIUM] No practical interrupted-marker support despite hardened collector requirement
- **Location:** main / signal handling limitation
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script explicitly states that Lua 5.1 lacks native signal handling and suggests a shell wrapper, but no wrapper is provided and the example trap runs `--dry-run`, which would not send an `interrupted` marker at all. The prompt states the other collectors send an `interrupted` collection marker with stats on SIGINT/SIGTERM and notes that Lua should use a shell-wrapper approach or clearly note the limitation. The current note is misleading because the sample wrapper does not achieve the stated
- **Fix:** Either provide a real wrapper script that traps signals and posts an `interrupted` marker using the same transport tools, or remove the incorrect example and clearly document that interrupted markers are unsupported in pure Lua mode.

### 🔧 17. [MEDIUM] wget_is_busybox() is called twice: once during detection and potentially again in send_collection_marker
- **Location:** detect_upload_tool / wget_is_busybox
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In `detect_upload_tool`, `wget_is_busybox()` is called when wget is found. In `send_collection_marker`, if `config.upload_tool` is empty (which shouldn't happen after detection but is a fallback), `wget_is_busybox()` is called again. Each call spawns a subprocess (`io.popen`). On embedded systems, subprocess spawning is expensive. More importantly, `wget_is_busybox()` is not memoized — if called multiple times it re-executes `wget --version` each time. This is wasteful but not a correctness bug.
- **Fix:** Memoize the result of `wget_is_busybox()` similar to `_check_mktemp()`.

### 🔧 18. [MEDIUM] scan_id extracted from JSON response using a fragile pattern that can be fooled by nested JSON
- **Location:** send_collection_marker
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The scan_id is extracted with `resp:match('"scan_id"%s*:%s*"([^"]+)"')`. This pattern will match the first occurrence of `"scan_id":"..."` in the response. If the response JSON contains a nested object or array where a string value contains `"scan_id":"fake"`, the pattern would match the wrong value. Additionally, if the scan_id itself contains escaped quotes (valid JSON: `"scan_id":"abc\"def"`), the pattern `[^"]+` would stop at the escaped quote, returning a truncated ID. While Thunderstorm se
- **Fix:** Use a more specific pattern that anchors to the beginning of the JSON object, or validate that the extracted ID matches an expected format (alphanumeric/UUID). At minimum, document the assumption that scan_ids don't contain escaped quotes.

### 🔧 19. [MEDIUM] math.randomseed called after mktemp() is first used, so early temp files use uninitialized RNG
- **Location:** main / math.randomseed
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `math.randomseed(os.time() + ...)` is called in `main()` after `validate_config()`, `detect_source_name()`, and before `parse_proc_mounts()`. However, `send_collection_marker` (the begin marker) is called after `detect_upload_tool()` which is after the seed call — so that's fine. BUT: `mktemp()` is called from `build_multipart_body` which is called from upload functions. The seed IS set before any uploads. However, if `_check_mktemp()` fails and the fallback path is used, `math.random(10000,9999
- **Fix:** Move `math.randomseed` to the very top of `main()` before any function calls, as a defensive measure.

### 🔧 20. [MEDIUM] curl error output captured from err_file but only logged at debug level, hiding upload failures
- **Location:** upload_with_curl
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When curl fails, the error message from stderr (captured in `err_file`) is logged at `debug` level: `log_msg('debug', 'curl error: ' .. ...)`. This means that unless `--debug` is enabled, curl errors (e.g., 'Connection refused', 'SSL certificate problem') are silently swallowed. The caller (`submit_file`) logs a generic 'Upload failed' warning, but the specific curl error is lost in non-debug mode.
- **Fix:** Log curl errors at `warn` level (not `debug`) so they appear in normal operation. The specific error message is valuable for diagnosis.

### 🔧 21. [MEDIUM] find prune expression uses -path which matches on the full path, but the pattern P/* may not prune correctly on all find implementations
- **Location:** build_find_command
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The prune expression uses `-path /proc -o -path /proc/*`. On GNU find, `-path /proc/*` correctly matches any path under `/proc`. On BusyBox find, `-path` behavior with wildcards may differ — specifically, BusyBox find's `-path` uses `fnmatch()` which should work correctly. However, the expression structure `\( -path P -o -path P/* -o -path Q -o -path Q/* ... \) -prune -o -type f -print` has a subtle issue: the `-prune` action only prevents descending into matched directories, but if `find` is gi
- **Fix:** Add a test with BusyBox find to verify prune behavior. As a fallback, consider using `-name` based exclusions for known special directories, or add a runtime check of the find version.

### 🔧 22. [MEDIUM] HTTP/1.1 request without proper chunked encoding or guaranteed Content-Length may cause server to hang
- **Location:** upload_with_nc
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc upload sends an HTTP/1.1 request with `Connection: close` and a `Content-Length` header. This should work correctly. However, if `body_len` (the Content-Length) is computed incorrectly (e.g., due to the boundary collision scenario in F4 where the body is truncated), the server will wait for more data than is sent, causing a timeout. Additionally, HTTP/1.1 with `Connection: close` requires the server to close the connection after the response, which nc handles via `-w 10` timeout. If the s
- **Fix:** Increase the nc timeout (`-w`) based on file size, or use HTTP/1.0 instead of HTTP/1.1 (which has simpler connection semantics). Consider using `Connection: close` with HTTP/1.0 to avoid keep-alive complications.

### 🔧 23. [LOW] syslog via os.execute('logger ...') is called synchronously and blocks the scan loop
- **Location:** log_msg
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When `config.log_to_syslog` is true, every non-debug log message spawns a shell process via `os.execute`. The comment notes that debug messages are skipped to avoid this overhead. However, info-level messages (logged for every submitted file in debug mode, and for errors/warnings) still spawn a shell. On embedded systems with slow process creation, this can significantly slow down the scan loop.
- **Fix:** Batch syslog messages or use a pipe to a persistent logger process. Alternatively, document that syslog should only be enabled when performance is not critical.

### 🔧 24. [LOW] Cloud path detection uses case-insensitive matching but path:lower() is called on every file
- **Location:** is_cloud_path
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** For every file processed, `is_cloud_path` calls `path:lower()` and then iterates through all cloud directory names. On embedded systems scanning millions of files, this creates unnecessary string allocations. This is a minor performance issue.
- **Fix:** Pre-compute lowercased versions of CLOUD_DIR_NAMES at startup. The `path:lower()` call per file is unavoidable but the name comparisons could be optimized.

### 🔧 25. [LOW] validate_config does not validate that scan directories exist or are accessible
- **Location:** validate_config
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The validation checks server, port, ca_cert, max_age, max_size_kb, retries, and source, but does not check whether the configured scan directories exist. Non-existent directories are handled gracefully in `scan_directory` with a warning, but a typo in a directory path would silently result in no files being scanned with exit code 0 (if no other failures occur).
- **Fix:** In `validate_config`, warn (not die) if a configured scan directory does not exist: `if not exec_ok('test -d ' .. shell_quote(dir)) then log_msg('warn', 'Scan directory does not exist: ' .. dir) end`.
