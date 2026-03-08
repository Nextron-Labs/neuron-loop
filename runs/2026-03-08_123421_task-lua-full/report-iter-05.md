# Neuron-Loop Report — Iteration 5
Generated: 2026-03-08 12:54:28

## Tests: ❌ FAIL
```
=== TEST 1: Lua 5.1 syntax check ===
luac: /test/collector.lua:1: ')' expected near 'randomseed'
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
    lua: /test/collector.lua:1: ')' expected near 'randomseed'

=== TEST 6: File size filtering ===
  ❌ FAIL: Large file not filtered (or not logged)
  Output snippet:

=== TEST 7: Integration test (stub server upload) ===
  ✅ PASS: Stub server running on port 18080
  Collector output:
    lua: /test/collector.lua:1: ')' expected near 'randomseed'
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
| gpt54 | 4 | T1 |
| sonnet | 17 | T1 |

## Triaged: 21 to fix, 0 skipped (from 21 raw findings, 21 unique)

### 🔧 1. [CRITICAL] Dead code attempts to re-run find after output already consumed; find exit status never actually checked
- **Location:** scan_directory / find_status_file block after pcall
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** After the pcall loop consumes all find output via io.popen, the code creates a new `status_file` temp file and builds a `status_cmd` string but never executes it (no `exec_ok(status_cmd)` call). The comment even acknowledges this: 'We already ran the find via popen above'. The `status_file` is created via `mktemp()` (registered in `temp_files`) and then immediately removed with `os.remove(status_file)`, but the `table.remove` from `temp_files` never happens, leaving a dangling entry. More import
- **Fix:** Either (a) use the wrapped sh -c approach that was in the original REPLACE block (write find status to a temp file, read it after popen closes) or (b) accept that popen exit status is unavailable in Lua 5.1 and remove the dead status-checking code entirely. Remove the mktemp()/os.remove() pair for status_file since it serves no purpose. If find exit status matters, use: `local wrapped = string.format('sh -c \'%s; echo $? >%s\'', cmd, status_file)` and open that file after `handle:close()`.

### 🔧 2. [CRITICAL] shell_quote applied to nc host and port arguments breaks nc invocation on BusyBox
- **Location:** upload_with_nc / nc command construction
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc command is built as: `nc -w %d %s %s <%s >%s` where host and port are passed through `shell_quote()`, producing e.g. `nc -w 30 'hostname' '8080' <...`. BusyBox nc (the target platform) does not accept quoted tokens as separate arguments when the shell expands them — the shell does strip the quotes, so this is actually fine in a shell context. However the real bug is that `shell_quote(port)` where port is a string like `"80"` produces `'80'` which is valid. The actual critical issue is tha
- **Fix:** Cap nc_timeout to a reasonable maximum: `local nc_timeout = math.min(300, math.max(30, 30 + math.floor(body_len / 10240)))`. Also add a sanity check that body_len is reasonable before computing the timeout.

### 🔧 3. [HIGH] find exit status is no longer captured, so partial scan failures are silently ignored
- **Location:** scan_directory / wrapped find execution and handle close
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The hardened behavior requires failed scans to be reflected in the exit code. The current replacement removes the earlier wrapper that wrote find's exit status to a temp file and falls back to plain io.popen(cmd). As a result, permission errors, traversal failures, and other non-zero find exits are suppressed by `2>/dev/null` and never propagated into `counters.files_failed`. The later comment acknowledges this gap but does not actually detect it.
- **Fix:** Restore the wrapped execution that records find's exit status during the same run, then increment `files_failed` when the recorded status is non-zero. For example, keep the `sh -c 'find ...; echo $? >statusfile'` approach and read the status after `handle:close()`.

### 🔧 4. [HIGH] End marker failures are not counted when no scan_id was obtained
- **Location:** send_collection_marker / end marker failure handling
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script intends to treat end-marker send failures as partial failures, but it only increments `counters.files_failed` when `end_id == "" and scan_id ~= ""`. If the begin marker failed twice and `scan_id` is empty, the end marker may still fail, yet that failure is ignored for exit-code purposes. This is inconsistent with the stated hardening goal that marker failures should affect reliability reporting.
- **Fix:** Track marker send success explicitly instead of inferring it from returned scan_id. For example, make `send_collection_marker` return `(ok, scan_id)` and increment `files_failed` whenever the end marker POST fails, regardless of whether a scan_id exists.

### 🔧 5. [HIGH] Boundary collision check reads file twice: once for collision check, once for body writing — TOCTOU and double I/O cost
- **Location:** build_multipart_body / boundary collision check
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The function opens `filepath` once to check for boundary collisions, closes it, then opens it again to stream into the temp file. Between these two opens, the file content could change (TOCTOU). More practically, on embedded systems with slow flash storage, reading a 2 MB file twice doubles I/O cost and time. Additionally, if the file is deleted or becomes unreadable between the collision check and the body-writing open, `src` will be nil and the function returns `nil, nil, nil` silently — the c
- **Fix:** Open the file once, read it into the temp file, then scan the temp file for boundary collisions (or generate the boundary first using /dev/urandom which makes collisions astronomically unlikely and skip the collision check entirely — a 128-bit random boundary has collision probability of ~2^-128 per file byte). If the collision check is kept, do it in a single pass while writing to the temp file.

### 🔧 6. [HIGH] curl --data-binary @file sends the multipart body but Content-Length header is not set, relying on curl's chunked or server-determined length
- **Location:** upload_with_curl / cmd construction
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** Unlike the wget backend which explicitly sets `Content-Length`, the curl backend uses `--data-binary @file` without setting Content-Length. curl will set it automatically from the file size, which is correct. However, the `body_len` return value from `build_multipart_body` is computed as `#preamble + file_content_bytes + #epilogue` which is correct. The real issue: curl is invoked with `--fail --show-error` but the error output is captured to `err_file` via `2>err_file`. If curl fails with exit 
- **Fix:** Remove `--fail` and instead check the HTTP status code separately, or use `--fail-with-body` (curl 7.76+, not available on embedded systems). Alternative: remove `--fail`, always read resp_file, check for HTTP error status in the response, and log the reason. Or keep `--fail` but also log the resp_file content when exec_ok returns false.

### 🔧 7. [HIGH] The REPLACE block removes the find exit-status wrapper but the replacement code references the old `cmd` variable in dead status-checking code, creating confusion and a broken status check
- **Location:** scan_directory / wrapped_cmd (original) vs io.popen(cmd) (replacement)
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The original code used a `wrapped_cmd` with `sh -c` to capture find's exit status. The REPLACE block switches to plain `io.popen(cmd)`. Then after the pcall, the dead code block references `cmd` again in `status_cmd` but never runs it. The variable `find_status_file` from the original code is gone (replaced by `status_file` in the dead block). The net result is that the replacement code is internally inconsistent: it claims to check find exit status but doesn't, and the dead code references `cmd
- **Fix:** Remove the entire dead status-checking block (from `-- Note: find exits non-zero...` to `os.remove(status_file)`). Add a comment: `-- Note: io.popen() in Lua 5.1 does not expose the child exit status; find permission errors are not detectable. Use the sh wrapper for exit-status-aware operation.`

### 🔧 8. [HIGH] mktemp fallback uses exec_capture with sh -c mktemp, but if mktemp binary doesn't exist in sh's PATH either, die() is called — however the primary check already tried sh-accessible mktemp via exec_ok('which mktemp'), making the fallback redundant and the die() message misleading
- **Location:** mktemp / fallback path
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `_check_mktemp()` runs `which mktemp` to detect mktemp. If not found, `_has_mktemp = false`. Then `mktemp()` tries `exec_capture('mktemp /tmp/thunderstorm.XXXXXX')` (which will fail since mktemp isn't in PATH), gets empty result, then tries `exec_capture("sh -c 'mktemp /tmp/thunderstorm.XXXXXX 2>/dev/null'")` which will also fail for the same reason. Then `die()` is called with message about permissions. The die message says 'check permissions' but the real issue is mktemp not being installed. M
- **Fix:** Add a pure-Lua fallback in mktemp(): if both mktemp attempts fail, generate a path using `_urandom_suffix()` and create the file with `io.open()`. Accept the TOCTOU risk with a comment, or use a loop to find an unused name. Fix the die() message to say 'mktemp not found or /tmp not writable'.

### 🔧 9. [HIGH] nc response check anchors to start of string but HTTP/1.0 responses may have leading \r\n or server banners on some implementations
- **Location:** upload_with_nc / HTTP response parsing
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `resp:match("^HTTP/1%.%d 2%d%d")` anchors to the very start of the response. RFC 7230 requires the status line to be the first line, so this is correct for compliant servers. However, some embedded HTTP servers (lighttpd on OpenWrt, for example) may prepend a blank line or the response may have a BOM. More practically: the nc command reads the full response including headers and body into resp_file. If the server sends `HTTP/1.0 200 OK
...`, the match works. If the server sends `HTTP/1.1 200 OK
- **Fix:** Change the match to `resp:match('HTTP/1[%.%d]+ 2%d%d')` without the `^` anchor, or use `resp:find('HTTP/1%.%d 2%d%d')` to be more lenient about leading content.

### 🔧 10. [HIGH] find -mtime -N semantics: -mtime -14 finds files modified less than 14*24 hours ago, not 'within 14 days' as intended for max_age=14
- **Location:** build_find_command
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command uses `-mtime -%d` with `config.max_age`. POSIX `find -mtime -N` means 'modified less than N*24 hours ago'. For `max_age=14`, this finds files modified in the last 14 days, which is correct. However, `max_age=1` finds files modified in the last 24 hours (not 'today'). The validation rejects `max_age=0` with a correct message. This is actually correct behavior and matches the intent. The real issue: the find command uses `shell_quote(dir)` for the directory argument, which is corr
- **Fix:** No change needed. The -mtime semantics are correct.

### 🔧 11. [MEDIUM] nc backend misparses bracketed IPv6 endpoints
- **Location:** upload_with_nc / URL parsing
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The nc uploader extracts host and port using `hostport:match("^([^:]+)")` and `hostport:match(":(%d+)$")`. This works for IPv4/hostnames but fails for valid URLs like `http://[2001:db8::1]:8080/...`, where the host contains multiple colons and brackets. The parsed host becomes incorrect and the connection command is malformed.
- **Fix:** Add explicit parsing for bracketed IPv6 literals, e.g. detect `^%[(.-)%](?::(%d+))?$` before the hostname/IPv4 path, and pass the unbracketed address to `nc` while preserving the correct Host header.

### 🔧 12. [MEDIUM] Collection markers are silently skipped if no upload tool was detected earlier and only nc is available with HTTPS
- **Location:** send_collection_marker / tool selection
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When `config.upload_tool` is empty, marker sending performs ad-hoc tool detection. In the HTTPS + nc-only case it logs a debug message and leaves `tool` unset, causing the function to return `""` without a clear warning unless debug logging is enabled. This is especially relevant for begin markers before any uploads occur or in edge cases where detection state is not set.
- **Fix:** Emit a warning, not debug-only output, whenever marker delivery is impossible due to backend limitations. Better yet, return an explicit failure status and reason so callers can surface it consistently.

### 🔧 13. [MEDIUM] Temp file cleanup in submit_file uses table.remove in a reverse loop but removes from temp_files while iterating, which is correct — however body_file from build_multipart_body is registered in temp_files AND the cleanup loop removes it, but if build_multipart_body itself calls mktemp() for the output file, that file is also in temp_files and will be cleaned up by the loop — this is correct. The actual issue: if config.retries > 1 and the first attempt fails, the body_file temp is cleaned up, but on the next retry build_multipart_body re-reads the source file and creates a new temp. If the source file was deleted between retries (e.g., /tmp cleanup), build_multipart_body returns nil and submit_file returns false. This is correct behavior. However, the exponential backoff delay is computed incorrectly.
- **Location:** submit_file / temp file cleanup loop
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The exponential backoff loop: `local delay = 1; for _ = 2, attempt do delay = delay * 2 end`. For attempt=1 (first failure, sleeping before attempt 2): the loop runs from 2 to 1, which in Lua means zero iterations (since 2 > 1), so delay stays 1. For attempt=2: loop runs once (2 to 2), delay = 2. For attempt=3: loop runs twice (2 to 3), delay = 4. So delays are 1, 2, 4 seconds for attempts 1, 2, 3. This is correct exponential backoff. BUT: the sleep happens `if attempt < config.retries`, so for 
- **Fix:** No change needed for backoff. However, document that retries=1 means exactly one attempt (no retries), which may surprise users who expect retries=1 to mean 'retry once' (2 total attempts).

### 🔧 14. [MEDIUM] sanitize_filename uses Lua pattern %c which in Lua 5.1 matches bytes 0x01-0x1F but NOT 0x00 (NUL byte), leaving NUL bytes in Content-Disposition filename
- **Location:** sanitize_filename
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The comment says 'Replace all control characters (0x00-0x1F, 0x7F)'. The pattern `%c` in Lua 5.1 matches characters for which `iscntrl()` returns true, which typically includes 0x01-0x1F and 0x7F but behavior for 0x00 (NUL) is implementation-defined and often excluded because NUL terminates C strings. The separate `r:gsub("\127", "_")` handles 0x7F. But NUL bytes in filenames (rare but possible on Linux) would pass through into the Content-Disposition header, potentially truncating the header at
- **Fix:** Add explicit NUL handling: `r = r:gsub('%z', '_')` (Lua pattern `%z` matches NUL in Lua 5.1). Add this before or after the `%c` substitution.

### 🔧 15. [MEDIUM] scan_id regex allows dots and hyphens but the character class is anchored incorrectly for UUIDs with uppercase hex
- **Location:** send_collection_marker / scan_id extraction regex
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The regex `'"scan_id"%s*:%s*"([A-Za-z0-9_%.%-]+)"'` correctly allows alphanumeric, underscore, dot, and hyphen. UUID format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` uses only hex digits and hyphens, all covered. This is correct. However, the regex uses `%s*` between `scan_id` and `:` and between `:` and `"`, which handles pretty-printed JSON. The issue: if the server returns the scan_id embedded in a larger JSON object where the value contains a `+` or `/` (e.g., base64-encoded IDs), the regex won
- **Fix:** Log a debug message when the response contains `scan_id` but the regex doesn't match: `if resp:find('"scan_id"') and id == nil then log_msg('debug', 'scan_id present in response but format not recognized') end`. Consider widening the character class to `[A-Za-z0-9_%.%-%+%/%=]+` to cover base64.

### 🔧 16. [MEDIUM] parse_proc_mounts only decodes \040, \011, \012, \134 but /proc/mounts can encode any byte as \NNN octal
- **Location:** parse_proc_mounts
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The code handles the four most common octal escapes in /proc/mounts. However, /proc/mounts can encode any special character as `\NNN` octal. For example, a mountpoint with a tab character other than \011 won't occur (\011 IS tab), but mountpoints with characters like `#` (\043), `(` (\050), `)` (\051), or non-ASCII bytes in UTF-8 paths would be encoded as octal sequences that are not decoded. The undecoded path (e.g., `/mnt/my\040share` decoded to `/mnt/my share`) would be compared against file 
- **Fix:** Implement a general octal decoder: `mp = mp:gsub('\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end)`. Apply this after the specific substitutions or replace them all with this general approach.

### 🔧 17. [MEDIUM] wget --ca-certificate flag uses shell_quote but the = separator means the quoted value includes the = sign inside the quotes, which is wrong
- **Location:** upload_with_wget / ca_cert_flag
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `ca_cert_flag = "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "` produces `--ca-certificate='/path/to/cert.pem' `. The shell will see `--ca-certificate=` as one token and `'/path/to/cert.pem'` as a separate token. wget expects `--ca-certificate=/path/to/cert.pem` as a single argument. The shell_quote wraps only the path, not the `--ca-certificate=` prefix, so the argument is split incorrectly. Compare with the curl backend: `"--cacert " .. shell_quote(config.ca_cert)` which correctly p
- **Fix:** Change to: `ca_cert_flag = shell_quote("--ca-certificate=" .. config.ca_cert) .. " "` — quote the entire argument including the `=` and path. Or use: `"--ca-certificate " .. shell_quote(config.ca_cert) .. " "` if wget accepts space-separated form (it does for most options).

### 🔧 18. [MEDIUM] scan_id appended to api_endpoint with urlencode but api_endpoint may already have a query string with source parameter, and the separator logic is wrong
- **Location:** main / api_endpoint scan_id append
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The code: `local sep = "&"; if not api_endpoint:find("?") then sep = "?" end; api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)`. The `api_endpoint` is built as `base_url .. "/api/" .. endpoint_name .. query_source` where `query_source` is either `""` or `"?source=" .. urlencode(config.source)`. So if source is set, api_endpoint already has `?`, and `sep = "&"` is correct. If source is empty, `query_source = ""` and `sep = "?"` is correct. This logic is actually correct. How
- **Fix:** Change `api_endpoint:find("?")` to `api_endpoint:find("?", 1, true)` to use plain string matching. Same fix needed in any other place where literal `?` is searched in a URL.

### 🔧 19. [MEDIUM] syslog logger command uses shell_quote for the message but the facility.priority argument is also shell_quoted — however the format string concatenates them without proper quoting of the combined argument
- **Location:** log_msg / syslog path
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `os.execute(string.format("logger -p %s %s 2>/dev/null", shell_quote(config.syslog_facility .. "." .. prio), shell_quote("thunderstorm-collector: " .. clean)))`. This produces e.g. `logger -p 'user.info' 'thunderstorm-collector: message'`. This is correct — both arguments are properly shell-quoted. However, `clean` is derived from `message:gsub("[\r\n]", " ")` which removes newlines but not other shell-special characters. Since `shell_quote` wraps in single quotes and escapes embedded single quo
- **Fix:** No immediate fix needed. If syslog_facility becomes user-configurable in the future, validate it against an allowlist of valid syslog facility names.

### 🔧 20. [MEDIUM] total_body counter counts preamble bytes but file content bytes are counted as Lua string lengths which may differ from actual bytes written for binary files in text mode
- **Location:** build_multipart_body / total_body calculation
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The preamble and epilogue are written with `out:write()` and their lengths counted with `#preamble` and `#epilogue`. The source file is opened with `io.open(filepath, "rb")` (binary mode) and read in chunks — correct. But `total_body = total_body + #chunk` counts Lua string bytes, which for binary data is the actual byte count. The output file is opened with `io.open(tmp, "wb")` (binary mode). On Linux, binary and text mode are identical, so this is fine. The `total_body` value is used as `Conte
- **Fix:** No change needed for the target platform. Add a comment noting that binary mode is required for correct Content-Length calculation.

### 🔧 21. [LOW] detect_upload_tool calls 'which nc' twice: once to skip it for SSL, and once at the end to report a warning
- **Location:** detect_upload_tool
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When `config.ssl = true` and nc is the only available tool, the function: (1) checks `which nc` and skips it with a debug log, (2) `has_wget` is false (wget not found), so falls through to the final block, (3) checks `which nc` again to log a warning. This is two `exec_ok` calls (two shell forks) for the same check. Minor inefficiency.
- **Fix:** Cache the nc availability: `local has_nc = exec_ok('which nc >/dev/null 2>&1')` at the top of the function, then use `has_nc` throughout.
