# Neuron-Loop Report — Iteration 2
Generated: 2026-03-08 12:05:36

## Tests: ❌ FAIL
```
=== TEST 1: Lua 5.1 syntax check ===
Error: statfs /home/neo/.openclaw/workspace/projects/thunderstorm-collector-lua/thunderstorm-collector.lua: no such file or directory
  ❌ FAIL: Syntax errors detected

=== TEST 2: Help flag (-h) ===
  ❌ FAIL: Help text only contains 1/15 expected flags

=== TEST 3: Banner output (dry-run mode) ===
  ✅ PASS: Banner contains Thunderstorm
  ❌ FAIL: Banner missing version

=== TEST 4: Unknown flag error ===
  ✅ PASS: Unknown flag produces error message
  ✅ PASS: Non-zero exit code on unknown flag

=== TEST 5: Dry-run mode ===
  ❌ FAIL: Dry-run mode not acknowledged
  ❌ FAIL: No files discovered in dry-run
  Output snippet:
    Error: statfs /home/neo/.openclaw/workspace/projects/thunderstorm-collector-lua/thunderstorm-collector.lua: no such file or directory

=== TEST 6: File size filtering ===
  ❌ FAIL: Large file not filtered (or not logged)
  Output snippet:

=== TEST 7: Integration test (stub server upload) ===
  ✅ PASS: Stub server running on port 18080
  Collector output:
    Error: statfs /home/neo/.openclaw/workspace/projects/thunderstorm-collector-lua/thunderstorm-collector.lua: no such file or directory
  ❌ FAIL: No files received by stub server
  ❌ FAIL: Summary line missing
  ❌ FAIL: Source parameter not found in server log

=== TEST 8: Lua 5.1 keyword compatibility ===
  ✅ PASS: No Lua 5.1 incompatible keywords found

========================================
  RESULTS: 5 passed, 9 failed, 8 tests
========================================

grep: /home/neo/.openclaw/workspace/projects/thunderstorm-collector-lua/thunderstorm-collector.lua: No such file or directory
grep: /home/neo/.openclaw/workspace/projects/thunderstorm-collector-lua/thunderstorm-collector.lua: No such file or directory
grep: /home/neo/.openclaw/workspace/projects/thunderstorm-collector-lua/thunderstorm-collector.lua: No such file or directory
```

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 7 | T1 |
| sonnet | 18 | T1 |

## Triaged: 25 to fix, 0 skipped (from 25 raw findings, 25 unique)

### 🔧 1. [CRITICAL] Malformed curl command breaks JSON marker delivery when TLS flags are empty
- **Location:** send_collection_marker / curl command construction
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The curl command for collection markers is built as `"curl -s -o %s %s-H 'Content-Type: application/json' ..."`. When `get_curl_tls_flags()` returns an empty string (the normal HTTP case, or HTTPS with default CA validation), the resulting command becomes `curl -s -o <file> -H 'Content-Type: application/json' ...` only if spacing is correct. Here the `-H` is concatenated directly to `%s`, so with an empty TLS flag string it becomes `... -o <file> -H ...`? Actually because `%s-H` is used, the com
- **Fix:** Do not rely on helper-returned trailing spaces. Build arguments with explicit separators, e.g. `"curl -s -o %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null"` and pass `tls_flags` without embedded trailing spaces, or append flags conditionally. Example: `local cmd = string.format("curl -s -o %s%s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null", shell_quote(resp_file), tls_flags ~= "" and (" " .. tls_flags) or "", shell_quote("Content-Type: application/json"), shell_quote(body_fil

### 🔧 2. [CRITICAL] Shell injection via filepath in curl -F argument
- **Location:** upload_with_curl / build around line 330-355
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In upload_with_curl, the form field is constructed as `shell_quote("file=@" .. filepath)`. shell_quote wraps the entire string in single quotes, but the value passed to curl's -F option is `file=@/path/to/file`. curl itself parses the -F value and interprets semicolons as field separators (e.g., `file=@/tmp/foo;type=text/html` changes the Content-Type). If filepath contains a semicolon, curl will interpret the part after it as additional form-data parameters. While shell injection is prevented b
- **Fix:** Use `--form-string` for the filename field and `--form` only for the file reference, or sanitize filepath to remove semicolons before embedding in -F. Better: use `curl -F 'file=@-' --data-binary @filepath` with a separate filename header, or pass the filepath via an environment variable and use a wrapper. At minimum, strip or reject filenames containing semicolons before constructing the curl command.

### 🔧 3. [CRITICAL] Multipart boundary not verified against file content — potential boundary collision
- **Location:** build_multipart_body / lines ~290-325
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The multipart boundary is generated as `ThunderstormBoundary<time><rand1><rand2>`. The boundary is never checked against the actual file content. If a binary file happens to contain the exact boundary string (e.g., `--ThunderstormBoundary...`), the server's MIME parser will split the body at that point, corrupting the upload and potentially causing the server to parse attacker-controlled file content as form metadata. math.random with os.time() seed is not cryptographically random and on embedde
- **Fix:** After generating the boundary, scan the file content (or at least the first/last few KB) for the boundary string and regenerate if found. Alternatively, use a longer random boundary (e.g., 32 hex chars from /dev/urandom: `head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' \n'`).

### 🔧 4. [CRITICAL] Incomplete sanitization — NUL bytes and other control characters not removed from filename
- **Location:** sanitize_filename / line ~115
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** sanitize_filename replaces `%z` (NUL byte in Lua patterns) along with `"`, `\`, and `;`. However, it does not remove other control characters (0x01-0x1F except \r and \n which are handled separately). More importantly, the `%z` in the character class `["\\;%z]` is a Lua pattern class for NUL, but inside `[]` in Lua patterns, `%z` matches the NUL character correctly only in some implementations. The real issue is that HTTP headers (Content-Disposition) containing control characters other than the
- **Fix:** Replace all bytes < 0x20 and 0x7F with underscores: `r = s:gsub('[%c]', '_')`. Also consider percent-encoding the filename in the Content-Disposition header instead of sanitizing.

### 🔧 5. [HIGH] Non-option positional arguments are silently ignored
- **Location:** parse_args / unknown-option handling
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The argument parser only errors on tokens starting with `-`. Any unexpected positional argument is ignored because there is no final `else` branch to reject it. For example, `lua thunderstorm-collector.lua /tmp --server x` will silently ignore `/tmp` instead of treating it as invalid input.
- **Fix:** Add a final `else` branch in `parse_args` that rejects unexpected positional arguments: `else die("Unexpected argument: " .. a .. " (use --help)") end`.

### 🔧 6. [HIGH] Max-age filter is off by almost a full day and mishandles `--max-age 0`
- **Location:** build_find_command / use of `-mtime -%d`
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script uses `find ... -mtime -N`, which matches files modified less than N*24 hours ago, not 'within the last N calendar days' as users typically expect. More importantly, `-mtime -0` is effectively unsatisfiable on standard `find`, so `--max-age 0` will scan nothing even though validation allows 0. This is a real behavioral bug, not just semantics.
- **Fix:** Either reject `--max-age 0` explicitly, or implement age filtering with `-mmin`/shell-side timestamp comparison. If keeping `find`, map days to minutes and use `-mmin -<minutes>` where supported, or document and enforce `max-age >= 1`.

### 🔧 7. [HIGH] curl upload sends filename as a separate form field instead of the file part filename
- **Location:** upload_with_curl / multipart form construction
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The curl path uses `-F 'file=@<path>' -F 'filename=<safe_name>'`. That creates two multipart fields: one file field named `file` and one text field named `filename`. It does not set the multipart filename parameter on the `file` part. The wget/nc implementations do set `Content-Disposition: ... name="file"; filename="..."`. If the server expects the uploaded file part's filename metadata, curl uploads will behave differently from wget/nc and may report the local basename or omit the intended san
- **Fix:** Use curl's `filename=` attribute on the same form part, while still avoiding injection by quoting safely: `-F 'file=@/path;filename=<safe_name>;type=application/octet-stream'`. If semicolon parsing concerns remain, validate/sanitize `safe_name` more strictly and keep the filename on the same part rather than as a separate field.

### 🔧 8. [HIGH] nc upload uses body_len from build_multipart_body but body is re-streamed — length mismatch if file changes
- **Location:** upload_with_nc / lines ~390-430
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** build_multipart_body computes body_len as `#header + fsize + #footer` where fsize is obtained by seeking to end of file. The actual body is then written to a temp file. In upload_with_nc, the Content-Length header uses body_len from build_multipart_body. However, the nc path re-reads the body_file (the temp file written by build_multipart_body) and appends it to the request. If the file was modified between the size measurement and the actual read (TOCTOU), or if the write to the temp file faile
- **Fix:** After writing the temp file in build_multipart_body, verify its actual size matches body_len. In upload_with_nc, use file_size_bytes(body_file) for the Content-Length rather than the pre-computed body_len.

### 🔧 9. [HIGH] Content-Length in nc marker request uses #body (Lua string length) which is correct for UTF-8 but the body is written to a file and re-read — inconsistency with file path
- **Location:** send_collection_marker / nc branch, lines ~490-515
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In the nc branch of send_collection_marker, the HTTP request is built with `Content-Length: #body` and then `req_f:write(body)` writes the body inline. This is actually correct for the marker case (body is a Lua string). However, the body was already written to body_file earlier, and the nc branch ignores body_file entirely — it re-embeds the body string directly in the request file. This means the body_file temp file is created but never used in the nc path, wasting a temp file slot. More impor
- **Fix:** In the nc branch of send_collection_marker, either use body_file consistently (read it and stream it) or document that body_file is only used by curl/wget branches and skip creating it for nc.

### 🔧 10. [HIGH] find prune logic is incorrect — files in excluded directories will still be printed
- **Location:** build_find_command / lines ~540-560
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command is constructed as: `find DIR \( -path P1 -prune -o -path P2 -prune \) -o -type f -mtime -N -print`. The issue is operator precedence: `-prune` has no `-print` action, so when a pruned directory is encountered, find evaluates the entire expression. The correct POSIX idiom requires `\( PRUNE_EXPR \) -o \( -type f -mtime -N -print \)`. In the current code, the structure is `\( prune1 -o prune2 \) -o -type f -mtime -N -print`. When a path matches a prune clause, `-prune` returns tru
- **Fix:** Use the more portable form: `find DIR \( -path P1 -o -path P2 \) -prune -o -type f -mtime -N -print`. This groups all prune paths together with a single `-prune` action, which is more reliably handled across find implementations.

### 🔧 11. [HIGH] wget --header with shell_quote may fail on some wget versions due to quoting of boundary value
- **Location:** upload_with_wget / lines ~360-385
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The wget command uses `--header=` with shell_quote around the entire header value including the boundary. The resulting shell command looks like: `wget ... --header='Content-Type: multipart/form-data; boundary=ThunderstormBoundaryXXX'`. While this is correct shell quoting, some versions of wget (particularly older BusyBox wget) parse `--header=VALUE` by splitting on the first colon to get the header name, and may not handle the single-quoted value correctly when the shell expands it. More critic
- **Fix:** This is documented as a known limitation for busybox-wget. For the standard wget path, add `--header='Content-Length: BODY_LEN'` explicitly since wget with --post-file may not set it. Use body_len from build_multipart_body.

### 🔧 12. [HIGH] io.popen handle not closed on error path — resource leak
- **Location:** scan_directory / lines ~580-640
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** scan_directory opens a popen handle and wraps the iteration in pcall. If pcall catches an error, `handle:close()` is called after the pcall block. However, if `handle:lines()` itself throws (which can happen if the popen'd process writes to a broken pipe), the pcall will catch it and execution jumps to after the pcall block where handle:close() is called. This part is actually correct. BUT: if `io.popen(cmd)` returns a handle but the find process immediately exits with an error (e.g., permission
- **Fix:** After handle:close(), check if files_scanned didn't increase and log a warning. Alternatively, redirect find's stderr to a temp file and check it after the scan.

### 🔧 13. [HIGH] scan_id appended to api_endpoint without JSON/URL escaping validation
- **Location:** main / scan_id append to api_endpoint, lines ~680-685
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The scan_id is extracted from the server response with `resp:match('"scan_id"%s*:%s*"([^"]+)"')`. This regex captures everything between quotes, which could include URL-special characters if the server returns an unexpected scan_id format. The scan_id is then passed through urlencode() before appending to the URL, which is correct. However, the scan_id is also passed to send_collection_marker as a raw string and embedded in JSON via json_escape(). If the server returns a scan_id containing chara
- **Fix:** Restrict the scan_id pattern to safe characters: `resp:match('"scan_id"%s*:%s*"([A-Za-z0-9_%-]+)"')` or limit length: capture up to 64 chars.

### 🔧 14. [MEDIUM] Boundary generation reseeds PRNG on every upload, increasing collision risk
- **Location:** build_multipart_body / boundary generation
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** Each call to `build_multipart_body` executes `math.randomseed(os.time())` and then draws two random numbers. Multiple uploads started within the same second will reuse the same seed and therefore generate identical boundaries. While multipart boundaries only need to avoid appearing in the body, repeated predictable boundaries reduce that safety margin and defeat the stated intent of generating a 'sufficiently random boundary'.
- **Fix:** Seed the PRNG once at startup, not per upload. Better, include monotonic uniqueness such as a counter plus time and temp path: `boundary = string.format("ThunderstormBoundary_%d_%d_%d", os.time(), os.clock()*1000000, upload_seq)`.

### 🔧 15. [MEDIUM] Normal stdout output violates hardened parity expectation that errors go to stderr and can pollute automation
- **Location:** main / banner and summary output to stdout
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script always prints the banner and final summary to stdout. The hardened sibling collectors were updated for cleaner automation behavior, and this script already routes logs to stderr. Emitting banner/summary on stdout makes machine consumption harder and differs from the rest of the toolchain.
- **Fix:** Suppress the banner by default in non-interactive mode, or send it to stderr. Likewise, send the summary to stderr unless an explicit `--json`/reporting mode is added.

### 🔧 16. [MEDIUM] Fatal-error path cannot include the real scan_id in interrupted marker
- **Location:** entry point pcall(main) / interrupted marker logic
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The top-level `pcall(main)` handler sends an `interrupted` marker with `scan_id = nil` because `scan_id` is local to `main` and never persisted globally. If a fatal Lua error occurs after a successful begin marker, the server cannot correlate the interrupted marker with the started collection.
- **Fix:** Store `scan_id` in a global/runtime state table once obtained, and reuse it in the top-level error handler: e.g. `runtime = { scan_id = "" }` and set `runtime.scan_id = scan_id` in `main`, then pass it to `send_collection_marker` on failure.

### 🔧 17. [MEDIUM] Temp files created in world-writable directories without restricted permissions
- **Location:** mktemp / lines ~130-140
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** mktemp() calls the shell `mktemp` command which by default creates files in /tmp with mode 0600 — this is safe. However, the fallback `os.tmpname()` returns a path (typically in /tmp) but does NOT create the file atomically with restricted permissions. The subsequent `io.open(path, 'wb')` creates the file, but between os.tmpname() returning the path and io.open() creating it, another process could create a symlink at that path pointing to a sensitive file, causing the collector to overwrite it (
- **Fix:** The mktemp shell command fallback is already the primary path and is safe. For the os.tmpname() fallback, add a check: after io.open(), verify the file is a regular file (not a symlink) using `test -f` and `test ! -L`. Or use `mktemp` with a fallback to a process-specific path like `/tmp/thunderstorm-$$-RANDOM`.

### 🔧 18. [MEDIUM] find -mtime uses integer days — files modified within the last 24h may be missed or double-counted at boundary
- **Location:** build_find_command / lines ~540-560
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command uses `-mtime -N` where N is config.max_age. POSIX find's -mtime counts in 24-hour periods rounded down, so `-mtime -14` finds files modified in the last 14*24=336 hours. This is standard behavior. However, if max_age is 0, the command becomes `-mtime -0` which on GNU find matches files modified in the last 0 days (i.e., nothing), while on some POSIX implementations `-mtime -0` matches files modified less than 24 hours ago. The validate_config() allows max_age >= 0, so max_age=0 
- **Fix:** Either reject max_age=0 in validate_config() with a clear error, or document this behavior. Alternatively, use `-mtime -1` as minimum or use `-newer` with a reference file for more precise time control.

### 🔧 19. [MEDIUM] wget version detection uses exec_capture which may fail silently — BusyBox wget may be used as GNU wget
- **Location:** detect_upload_tool / wget_is_busybox, lines ~240-270
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** wget_is_busybox() runs `wget --version 2>&1` and checks if the output contains 'busybox'. If exec_capture returns nil (popen failed) or the output doesn't contain 'busybox', it returns false, treating the wget as GNU wget. On some embedded systems, `wget --version` may not be supported (BusyBox wget may not implement --version) and returns an error or empty output, causing wget_is_busybox() to return false incorrectly. This means BusyBox wget would be used as if it were GNU wget, which has diffe
- **Fix:** Also check if `wget --version` returns a non-zero exit code or empty output as an indicator of BusyBox wget. Alternatively, check for 'GNU Wget' in the output (positive identification) rather than checking for 'busybox' (negative identification).

### 🔧 20. [MEDIUM] send_collection_marker ignores upload failures silently — begin/end markers may be lost without warning
- **Location:** send_collection_marker / lines ~455-530
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** send_collection_marker uses `os.execute(cmd)` for curl and wget paths (not exec_ok), so the return value is ignored. If the marker upload fails, the function returns "" (no scan_id extracted), and the caller logs a warning for the begin marker. But for the end marker, the return value of send_collection_marker is not checked at all in main(). Failed end markers are silently dropped.
- **Fix:** Use exec_ok() instead of os.execute() for the marker upload commands, and return a boolean success indicator in addition to the scan_id. Log a warning if the end marker fails.

### 🔧 21. [MEDIUM] Cloud path detection uses case-insensitive match but path separator check is case-sensitive
- **Location:** is_cloud_path / lines ~225-240
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** is_cloud_path() converts the path to lowercase with `path:lower()` and then checks for `"/" .. name .. "/"`. The CLOUD_DIR_NAMES entries are already lowercase. This is correct for the directory name matching. However, the check `lower:sub(-(#name + 1)) == "/" .. name` checks if the path ends with `/name`. This misses paths that end without a trailing slash AND where the directory is the last component without a slash prefix in the lowercased string (e.g., a path that IS exactly the cloud dir nam
- **Fix:** This is a very minor edge case. No change needed unless paths without leading slashes are expected.

### 🔧 22. [MEDIUM] scan_id appended to api_endpoint with separator logic that may produce double '?' if source is empty
- **Location:** main / lines ~700-710
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The api_endpoint is built as `base_url/api/endpoint?source=X` if source is non-empty, or `base_url/api/endpoint` if source is empty. Then scan_id is appended with: `local sep = "&"; if not api_endpoint:find("?") then sep = "?" end`. If source is empty, api_endpoint has no `?`, so sep becomes `?`. If source is non-empty, sep is `&`. This logic is correct. However, `api_endpoint:find("?")` — the `?` character in Lua patterns is a quantifier meaning 'zero or one of the previous'. So `find("?")` act
- **Fix:** Use `find("?", 1, true)` for plain string search (the third argument `true` disables pattern matching): `if not api_endpoint:find("?", 1, true) then sep = "?" end`.

### 🔧 23. [MEDIUM] Exponential backoff calculation is O(n) loop instead of direct formula
- **Location:** submit_file / exponential backoff, lines ~445-455
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The backoff delay is computed as: `local delay = 1; for _ = 2, attempt do delay = delay * 2 end`. For attempt=1, the loop runs 0 times (2 to 1 is empty), delay=1. For attempt=2, loop runs once, delay=2. For attempt=3, loop runs twice, delay=4. This gives delays of 1, 2, 4 seconds for attempts 1, 2, 3. The logic is correct but unnecessarily complex. More importantly, with default retries=3, the maximum total wait is 1+2=3 seconds (no sleep after the last attempt), which is reasonable. No bug here
- **Fix:** Replace with `local delay = math.pow(2, attempt - 1)` or in Lua 5.1: `local delay = 2 ^ (attempt - 1)`. Note: Lua 5.1 supports the `^` operator for exponentiation.

### 🔧 24. [LOW] Syslog logger command uses shell_quote for message but facility.priority is not validated
- **Location:** log_msg / syslog branch, lines ~165-172
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The syslog logger command is: `logger -p FACILITY.PRIORITY MESSAGE`. The facility comes from config.syslog_facility which is user-controlled via... actually it's not exposed via CLI args (no --syslog-facility option), so it uses the hardcoded default 'user'. The priority is derived from the level parameter which is controlled by the code itself. However, if someone adds a --syslog-facility option in the future, the facility value is concatenated directly into the shell command without shell_quot
- **Fix:** No immediate action needed. If --syslog-facility is added as a CLI option, validate it against known facility names.

### 🔧 25. [LOW] All globals are in global namespace — risk of accidental pollution in embedded Lua environments
- **Location:** global scope / lines ~30-60
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** VERSION, config, counters, EXCLUDE_PATHS, dynamic_excludes, etc. are all global variables. In Lua 5.1, globals are stored in the global environment table. On embedded systems running multiple Lua scripts or using Lua as an embedded scripting engine, global pollution can cause unexpected interactions. Additionally, the pcall(main) at the bottom references `config` and `counters` as globals in the error handler, which works but is fragile.
- **Fix:** Wrap the entire script in a `do ... end` block or use `local` for all module-level variables. At minimum, make VERSION, config, counters local to main() or a module table.
