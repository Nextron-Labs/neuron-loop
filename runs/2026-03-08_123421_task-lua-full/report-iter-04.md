# Neuron-Loop Report — Iteration 4
Generated: 2026-03-08 12:49:31

## Tests: ❌ FAIL
```
=== TEST 1: Lua 5.1 syntax check ===
luac: /test/collector.lua:1148: unexpected symbol near '>'
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
    lua: /test/collector.lua:1148: unexpected symbol near '>'

=== TEST 6: File size filtering ===
  ❌ FAIL: Large file not filtered (or not logged)
  Output snippet:

=== TEST 7: Integration test (stub server upload) ===
  ✅ PASS: Stub server running on port 18080
  Collector output:
    lua: /test/collector.lua:1148: unexpected symbol near '>'
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
| gpt54 | 6 | T1 |
| sonnet | 17 | T1 |

## Triaged: 23 to fix, 0 skipped (from 23 raw findings, 23 unique)

### 🔧 1. [CRITICAL] Duplicate code block causes scan_directory to never execute file processing
- **Location:** scan_directory / progress detection block (duplicated before pcall)
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The source file contains a literal '>>>REPLACE' marker and a duplicated block of code starting with 'local show_progress = config.progress'. The first copy of the block (before '>>>REPLACE') is never closed with a pcall/end, and the second copy (after '>>>REPLACE') contains the actual pcall with the file-processing loop. As written, the Lua parser will encounter the duplicate local declarations and the stray '>>>REPLACE' text, causing a syntax error that prevents the entire script from loading. 
- **Fix:** Remove the first (incomplete) copy of the show_progress/progress_counter block and the '>>>REPLACE' marker, keeping only the version inside the pcall. The function should read:

```lua
function scan_directory(dir, api_endpoint)
    if not exec_ok("test -d " .. shell_quote(dir)) then
        log_msg("warn", "Skipping non-directory path '" .. dir .. "'")
        return
    end
    log_msg("info", "Scanning '" .. dir .. "'")
    local cmd = build_find_command(dir)
    log_msg("debug", "find command

### 🔧 2. [CRITICAL] Second stray '>>>REPLACE' marker causes syntax error in main()
- **Location:** main / second '>>>REPLACE' marker
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** There is a second '>>>REPLACE\n(move randomseed to top of main)' comment block inserted in the middle of the main() function body, between the 'Record start time' block and the 'Send begin marker' block. This is not valid Lua syntax and will cause a parse error, preventing the script from running.
- **Fix:** Remove the '>>>REPLACE\n(move randomseed to top of main)' lines. The math.randomseed call is already correctly placed at the top of main(), so no code movement is needed—just delete the marker.

### 🔧 3. [HIGH] Script contains unresolved patch markers and duplicated code, making it syntactically invalid
- **Location:** scan_directory / duplicated block around the >>>REPLACE marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The file still includes literal `>>>REPLACE` markers and replacement notes such as `(move randomseed to top of main)`. These are not Lua comments and will cause a parse error before execution. In addition, the surrounding code is duplicated in `scan_directory`, so the checked-in file is not runnable as-is.
- **Fix:** Remove the patch markers and keep only the intended final code. Ensure `scan_directory` contains a single progress-detection block and that `main()` contains only valid Lua statements. Run `lua -p thunderstorm-collector.lua` or equivalent syntax validation before release.

### 🔧 4. [HIGH] Temporary-file fallback is vulnerable to symlink clobbering and races
- **Location:** mktemp / fallback branch using io.open(path, "wb")
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When `mktemp` is unavailable, the code generates `/tmp/thunderstorm.<suffix>` and creates it with `io.open(..., "wb")`. On multi-user or adversarial systems, an attacker can pre-create that path as a symlink to another file. Opening with `wb` follows symlinks and truncates the target. The random suffix reduces predictability but does not provide atomic creation or symlink protection.
- **Fix:** Do not implement a non-atomic temp-file fallback with plain `io.open`. Prefer requiring a real `mktemp` utility, or create a private temp directory with restrictive permissions and use shell `mktemp` inside it. If no safe primitive exists in pure Lua 5.1, fail closed with a fatal error instead of creating insecure temp files.

### 🔧 5. [HIGH] Find command failures are silently ignored, so partial scans can exit as clean
- **Location:** scan_directory / after handle:close()
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The code reads `find` output via `io.popen(cmd)` and then calls `handle:close()`, but it never inspects the close status. `find` commonly exits non-zero on traversal errors, I/O errors, or permission problems even when some paths were emitted. The comment explicitly says partial results are treated as valid, but the hardened behavior requested for the other collectors is to reflect partial failures in the exit code. As written, a directory scan can miss files due to runtime errors and still retu
- **Fix:** Capture and evaluate the `find` exit status. If it is non-zero, log to stderr and increment a partial-failure counter so the process exits 1. If BusyBox/Lua version differences make `popen():close()` status awkward, redirect `find` exit code to a temp file or wrap the command in `sh -c 'find ...; echo $? >status'`.

### 🔧 6. [HIGH] Boundary collision check misses the preamble and epilogue themselves
- **Location:** build_multipart_body / boundary collision check
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The collision check searches the file content for '\r\n--' .. candidate, but the actual boundary delimiter that appears at the very start of the body is '--' .. boundary (no leading \r\n). If the file begins with bytes that match '--<boundary>', the preamble delimiter will collide with file content and corrupt the multipart message. The check should also cover '--' .. candidate at position 1 (start of body) and '--' .. candidate .. '--' (epilogue).
- **Fix:** Also check for the plain '--' .. candidate pattern (without leading \r\n) to cover the opening delimiter:
```lua
local needle1 = "\r\n--" .. candidate
local needle2 = "--" .. candidate  -- covers opening delimiter
if search_buf:find(needle1, 1, true) or search_buf:find(needle2, 1, true) then
    collision = true
    break
end
```

### 🔧 7. [HIGH] nc upload silently succeeds on HTTP error responses that contain a 2xx line elsewhere
- **Location:** upload_with_nc / HTTP response check
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The response check uses `resp:match("HTTP/1%.%d 2%d%d")` which searches anywhere in the response body. A server that returns HTTP 400 with a JSON body containing the string 'HTTP/1.1 200' (e.g., in an error description or echoed request) would be incorrectly treated as a success. The status line must be anchored to the beginning of the response.
- **Fix:** Anchor the match to the start of the response:
```lua
if resp:match("^HTTP/1%.%d 2%d%d") then return true end
```

### 🔧 8. [HIGH] Temp file list truncation uses table.remove in reverse but leaves holes after partial removal
- **Location:** submit_file / temp file cleanup loop
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** After each upload attempt the code removes temp files created during that attempt and then truncates the `temp_files` table by calling `table.remove(temp_files, i)` in a reverse loop from `#temp_files` down to `temps_before + 1`. However, `temps_before` is captured once before the retry loop. On the second and subsequent attempts, new temp files are appended starting at index `temps_before + 1` again (since the list was truncated), so the cleanup is correct for the indices—but if `build_multipar
- **Fix:** Reset `temps_before` at the start of each retry iteration:
```lua
for attempt = 1, config.retries do
    local temps_before = #temp_files  -- capture inside loop
    local success = false
    -- ... upload ...
    -- cleanup
    for i = #temp_files, temps_before + 1, -1 do
        os.remove(temp_files[i])
        table.remove(temp_files, i)
    end
    if success then return true end
    -- ...
end
```

### 🔧 9. [HIGH] Missing -X POST flag in curl upload command causes GET request
- **Location:** upload_with_curl / cmd construction
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The curl command in `upload_with_curl` uses `--data-binary @file` which implicitly sets the method to POST in modern curl versions, but the explicit `-X POST` flag present in the collection marker curl command is absent here. Some older curl versions (common on embedded/OpenWrt systems) require the explicit flag when combined with `--fail --show-error`. More importantly, the format string has `%s%s%s` for insecure+ca_cert+endpoint but the endpoint is shell_quote'd as the third %s while the Conte
- **Fix:** Add `-X POST` explicitly:
```lua
local cmd = string.format(
    "curl -sS --fail --show-error -X POST %s%s" ..
    " --connect-timeout 30 --max-time 120" ..
    " -H %s --data-binary @%s -o %s 2>%s %s",
    insecure, ca_cert_flag,
    shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
    shell_quote(body_file),
    shell_quote(resp_file),
    shell_quote(err_file),
    shell_quote(endpoint)
)
```
Note also that the endpoint argument should come last in curl invocations.

### 🔧 10. [HIGH] find -mtime predicate semantics: -mtime -N finds files modified less than N*24h ago, not N days
- **Location:** build_find_command
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The command uses `-mtime -<max_age>` which on POSIX find means files modified less than max_age*24 hours ago (rounded down to whole days). With max_age=14 this finds files modified in the last 13-14 days depending on the current time of day. This is the standard behavior and matches the other collectors, so it is not a bug per se—but the validate_config check `max_age == 0` correctly rejects 0. However, the comment 'Max file age in days' in the config is slightly misleading since -mtime -1 finds
- **Fix:** This is acceptable behavior matching POSIX find semantics. Update the help text to say 'Max file age in days (uses find -mtime; -mtime -N finds files modified less than N×24h ago)'.

### 🔧 11. [HIGH] nc collection marker path uses #body (byte count) but body may contain multi-byte sequences
- **Location:** send_collection_marker / nc path
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The Content-Length header is set to `#body` where body is a Lua string. In Lua 5.1, `#` on a string returns the number of bytes, which is correct for Content-Length. However, `json_escape` can produce `\uXXXX` sequences for control characters, and the source name could contain UTF-8 multi-byte sequences that are passed through unescaped (json_escape only escapes control chars 0x00-0x1F, not high bytes). The byte count will still be correct since Lua strings are byte arrays. This is actually fine
- **Fix:** No code change needed; add a comment confirming that #body is byte-accurate in Lua 5.1.

### 🔧 12. [MEDIUM] Fallback scan_id parser can return escaped JSON fragments instead of the real value
- **Location:** send_collection_marker / scan_id extraction
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The strict pattern only accepts `[A-Za-z0-9_%.%-]+`. If the server returns a valid JSON string containing any escaped character, the fallback pattern `"scan_id"%s*:%s*"([^"]*)"` stops at the first embedded escaped quote sequence and returns the raw escaped fragment rather than the decoded string. That malformed value is then appended to the upload endpoint as `scan_id=...`.
- **Fix:** Either constrain the server contract and reject non-simple scan IDs explicitly, or implement minimal JSON string parsing for this field that honors backslash escapes before using the value.

### 🔧 13. [MEDIUM] Begin/end markers are skipped when only nc is available and upload tool was not pre-detected
- **Location:** send_collection_marker / tool fallback logic
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** Inside `send_collection_marker`, if `config.upload_tool` is empty, the fallback detection checks only `curl` and `wget`; it does not consider `nc`. Today `main()` usually calls `detect_upload_tool()` first in non-dry-run mode, but this function is written as a general fallback and will incorrectly skip marker sending in any path where the upload tool was not pre-populated and only `nc` exists.
- **Fix:** Reuse `detect_upload_tool()` or mirror its full logic, including `nc` selection for non-SSL URLs. Avoid maintaining a second, incomplete tool-detection path.

### 🔧 14. [MEDIUM] End marker delivery failures do not affect exit status
- **Location:** main / end-marker send result ignored
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script sends the final `end` collection marker but ignores whether it succeeded. The hardened behavior described for the other collectors emphasizes partial-failure reporting. If all file uploads succeed but the end marker fails, the script still exits 0, even though the server-side collection state is incomplete.
- **Fix:** Have `send_collection_marker` return success separately from `scan_id`, and treat begin/end marker failures as partial failures that produce exit code 1 (unless you intentionally document a different contract).

### 🔧 15. [MEDIUM] Pre-computed cloud pattern tables (_cloud_mid_patterns, _cloud_end_suffixes) are never used
- **Location:** is_cloud_path
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The function `_init_cloud_patterns()` populates `_cloud_mid_patterns` and `_cloud_end_suffixes` at module load time, but `is_cloud_path()` ignores these tables entirely and re-constructs the patterns inline by iterating `CLOUD_DIR_NAMES` and doing string concatenation on every call. The optimization is dead code.
- **Fix:** Either use the pre-computed tables in is_cloud_path:
```lua
function is_cloud_path(path)
    local lower = path:lower()
    for _, pat in ipairs(_cloud_mid_patterns) do
        if lower:find(pat, 1, true) then return true end
    end
    for _, suf in ipairs(_cloud_end_suffixes) do
        if lower:sub(-(#suf)) == suf then return true end
    end
    -- macOS check ...
    return false
end
```
or remove `_init_cloud_patterns` and the two tables if the optimization is not desired.

### 🔧 16. [MEDIUM] nc upload URL path parsing drops query string when path_rest is nil
- **Location:** upload_with_nc / URL parsing
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The path extraction uses `hostpath:match("^[^/]+/(.*)$")` which captures everything after the first slash. If the URL is `http://host:8080/api/checkAsync?source=foo`, path_rest will be `api/checkAsync?source=foo` and path_query will be `/api/checkAsync?source=foo`—this is correct. However, if the URL has no path component at all (e.g., `http://host:8080`), path_rest is nil and path_query becomes `/`, which would POST to the wrong endpoint. While the endpoint is always constructed with a path in 
- **Fix:** Add a guard:
```lua
local path_rest = hostpath:match("^[^/]+/(.*)$") or ""
local path_query = "/" .. path_rest
```
This is already done but the `or ""` should be verified to handle the no-path case correctly.

### 🔧 17. [MEDIUM] sanitize_filename does not handle DEL character (0x7F) correctly via %c pattern
- **Location:** sanitize_filename
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The code applies `r:gsub("%c", "_")` to replace control characters, then separately `r:gsub("\127", "_")` for DEL. In Lua 5.1, `%c` in patterns matches characters for which `isctype(c, ctype_cntrl)` is true. On most C libraries this includes 0x7F (DEL), making the second gsub redundant but harmless. However, on some minimal libc implementations (uClibc, musl) `%c` may not match 0x7F. The explicit second gsub is the correct defensive approach, but the comment says 'Replace all control characters 
- **Fix:** Combine into a single pattern or add a comment explaining the belt-and-suspenders approach. No functional change needed.

### 🔧 18. [MEDIUM] stats_json is concatenated into JSON body without validation, allowing injection
- **Location:** send_collection_marker / JSON body construction
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The stats_json parameter is appended directly into the JSON body: `body = body .. "," .. stats_json`. In main(), stats_json is constructed from integer counters via string.format, so the values are safe. However, the function signature accepts arbitrary strings, and if a caller passes a malformed or attacker-influenced stats_json, it would produce invalid or injected JSON. This is a defense-in-depth concern since all current callers are internal.
- **Fix:** Either document that stats_json must be a pre-validated JSON fragment, or validate that it contains only expected characters (digits, quotes, colons, braces, commas).

### 🔧 19. [MEDIUM] SSL + nc detection runs 'which nc' twice unnecessarily and logs misleading warning
- **Location:** detect_upload_tool
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When SSL is enabled and nc is the only available tool, the function first calls `exec_ok("which nc ...")` inside the nc block (skipping it with a debug log), then at the end calls `exec_ok("which nc ...")` again to emit a warning. This spawns two extra shell processes. More importantly, the final warning block is only reached if `has_wget` is false (since busybox-wget would have returned true), but the condition `if config.ssl and exec_ok("which nc ...")` is evaluated even when the function is a
- **Fix:** Track nc availability in a local variable:
```lua
local has_nc = exec_ok("which nc >/dev/null 2>&1")
if has_nc then
    if config.ssl then
        log_msg("debug", "nc skipped: does not support HTTPS")
    else
        config.upload_tool = "nc"
        return true
    end
end
-- ...
if config.ssl and has_nc then
    log_msg("warn", "nc is available but cannot be used for HTTPS")
end
```

### 🔧 20. [MEDIUM] total_body size calculation is incorrect: preamble length counted but file bytes not streamed to variable
- **Location:** build_multipart_body / total_body calculation
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The variable `total_body` is initialized to `#preamble` and incremented by `#chunk` for each chunk read from the source file, then incremented by `#epilogue`. This correctly computes the total byte count of the multipart body written to the temp file. The value is returned as `body_len` and used by wget's Content-Length header. However, `total_body` is computed correctly only if all chunks are read without error. If `src:read(chunk_size)` returns a partial chunk due to an I/O error mid-file, `to
- **Fix:** After writing the temp file, use `file_size_kb` or seek to determine the actual written size rather than computing it incrementally, or check for write errors:
```lua
local written, werr = out:write(chunk)
if not written then
    src:close(); out:close()
    return nil, nil, nil
end
```

### 🔧 21. [MEDIUM] Octal escape decoding in /proc/mounts is incomplete: only \040, \011, \012, \134 handled
- **Location:** parse_proc_mounts
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The /proc/mounts format encodes special characters as octal escapes (\NNN). The code handles space (\040), tab (\011), newline (\012), and backslash (\134). However, other characters can appear in mount points, such as \043 (#), \073 (;), or any other byte. If a mount point contains such characters, the exclusion path will not match the actual filesystem path returned by find, and files under that mount point will not be excluded.
- **Fix:** Use a general octal decoder:
```lua
mp = mp:gsub("\\(%d%d%d)", function(oct)
    return string.char(tonumber(oct, 8))
end)
```
This handles all octal escapes in a single pass.

### 🔧 22. [LOW] syslog logger command uses shell_quote for facility.priority but logger -p expects unquoted argument on some BusyBox versions
- **Location:** log_msg / syslog path
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The syslog call uses `shell_quote(config.syslog_facility .. "." .. prio)` which wraps the priority in single quotes. GNU logger and most implementations accept quoted arguments via the shell, but BusyBox logger on some versions passes the literal quoted string (including the quotes) as the priority, resulting in an invalid priority and the message being dropped or logged with default priority.
- **Fix:** Since syslog_facility and prio are controlled internal values (not user input that needs quoting), use them directly after validating they contain only safe characters:
```lua
local prio_arg = config.syslog_facility .. "." .. prio
-- prio_arg contains only [a-z0-9.] so no quoting needed
os.execute(string.format("logger -p %s %s 2>/dev/null",
    prio_arg, shell_quote("thunderstorm-collector: " .. clean)))
```

### 🔧 23. [LOW] scan_id appended to api_endpoint with incorrect separator detection
- **Location:** main / api_endpoint scan_id append
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The code checks `if not api_endpoint:find("?")` to decide whether to use '?' or '&' as the separator. `string.find` with a single-character argument treats '?' as a Lua pattern metacharacter (matches any character). This means the condition is always true (any string contains 'any character'), so '?' is always used as the separator even when the URL already has a query string (e.g., `?source=foo`), producing `?source=foo?scan_id=...` which is an invalid URL.
- **Fix:** Use the plain=true flag for find:
```lua
local sep = "&"
if not api_endpoint:find("?", 1, true) then sep = "?" end
api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
```
