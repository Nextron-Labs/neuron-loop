# Neuron-Loop Report — Iteration 2
Generated: 2026-03-08 12:41:31

## Tests: ✅ PASS

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 8 | T1 |
| sonnet | 19 | T1 |

## Triaged: 27 to fix, 0 skipped (from 27 raw findings, 27 unique)

### 🔧 1. [CRITICAL] nc upload reads entire file body into Lua memory before writing to request file
- **Location:** upload_with_nc / lines ~340-390
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In upload_with_nc, after building the multipart body in a temp file (which correctly streams in chunks), the code then does `req_f:write(body_f:read('*a'))` to append the body to the HTTP request file. This reads the entire file content into a single Lua string in memory. On embedded systems with 2-16 MB RAM and files up to 2000 KB, this can cause OOM or Lua memory errors, defeating the purpose of the chunked streaming in build_multipart_body.
- **Fix:** Stream the body file to the request file in chunks instead of reading all at once:
```lua
local chunk_size = 8192
while true do
    local chunk = body_f:read(chunk_size)
    if not chunk then break end
    req_f:write(chunk)
end
```

### 🔧 2. [CRITICAL] Content-Length in nc upload is computed from preamble+epilogue+chunk-counted bytes but preamble/epilogue byte counts may be wrong on systems where Lua counts characters not bytes
- **Location:** build_multipart_body / lines ~270-310
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** total_body is computed as `#preamble + sum(#chunk) + #epilogue`. In Lua 5.1, `#` on a string returns the number of bytes, which is correct for binary data. However, preamble and epilogue are constructed with string.format and contain CRLF sequences. The real issue is that body_len passed to upload_with_nc is the size of the multipart body written to body_file, but the nc backend then writes the HTTP headers PLUS the body into req_file and sends that. The Content-Length header value (body_len) is
- **Fix:** No change needed for Content-Length. However, ensure temp files created by mktemp() before a failure in build_multipart_body are still cleaned up (they are, via cleanup_temp_files at exit).

### 🔧 3. [CRITICAL] JSON body passed directly to curl -d via shell_quote — NUL bytes and very long source names could cause shell argument issues; more critically, body written to temp file for wget but passed as shell argument for curl
- **Location:** send_collection_marker / lines ~430-490
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** For curl, the JSON body is passed as `shell_quote(body)` directly on the command line via `-d`. If config.source or VERSION contains single quotes (which shell_quote handles by escaping), this is safe. However, the body could be large enough to hit ARG_MAX on some systems. More importantly, for wget the code correctly writes body to a temp file and uses --post-file, but for curl it passes the body as a command-line argument. This is inconsistent and could fail on systems with small ARG_MAX limit
- **Fix:** Write the JSON body to a temp file for curl too, and use `--data-binary @file` instead of `-d shell_quote(body)`:
```lua
local body_tmp = mktemp()
local bf = io.open(body_tmp, 'wb')
if bf then bf:write(body); bf:close() end
local cmd = string.format(
    'curl -sS --fail -o %s %s%s-H %s --max-time 10 --data-binary @%s %s 2>/dev/null',
    shell_quote(resp_file), insecure, ca_cert_flag,
    shell_quote('Content-Type: application/json'),
    shell_quote(body_tmp), shell_quote(url))
```

### 🔧 4. [HIGH] Normal execution writes to stdout, which breaks the hardened stderr-only error/reporting convention
- **Location:** main / banner and summary stdout writes
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script prints the banner with `print_banner()` and always prints the final run summary with `io.write(...)` to stdout. In the hardened sibling collectors, operational/errors are routed consistently away from stdout so stdout can remain machine-consumable or unused. Here, even `--quiet` does not suppress the banner or summary, and any caller that expects silent success or reserved stdout will receive unsolicited output.
- **Fix:** Suppress banner/summary unless explicitly requested, or route them through `log_msg()`/stderr. At minimum, honor `--quiet` for banner and summary output.

### 🔧 5. [HIGH] Progress reporting flags are parsed but never implemented
- **Location:** main / progress option handling
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script accepts `--progress` and `--no-progress`, and `config.progress` is documented as supporting TTY auto-detection, but no code ever uses this setting. This is a direct parity gap with the hardened collectors, which provide progress reporting with TTY auto-detection.
- **Fix:** Either implement progress reporting and TTY auto-detection, or remove the options. A minimal fix is to detect TTY via `test -t 2` and emit periodic progress updates to stderr when enabled.

### 🔧 6. [HIGH] Netcat backend cannot perform HTTPS but is still selected for SSL mode
- **Location:** upload_with_nc / HTTPS endpoint handling
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When `config.ssl` is true and only `nc` is available, `detect_upload_tool()` still selects `nc` and merely logs a warning. `upload_with_nc()` then strips `https://` and sends a plain HTTP request over the target port, typically 443. This is not TLS and will fail against real HTTPS servers; worse, it may send sensitive sample data unencrypted to a listener if the endpoint is misconfigured or intercepted.
- **Fix:** Do not allow `nc` when `config.ssl` is true. Treat this as fatal during tool detection unless a TLS-capable tool is available. Example: `if config.ssl and tool == 'nc' then die('HTTPS requires curl or wget; nc is not TLS-capable') end`.

### 🔧 7. [HIGH] Collection markers may be skipped when BusyBox wget is the detected backend
- **Location:** send_collection_marker / upload tool fallback logic
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** If `config.upload_tool` is `busybox-wget`, `send_collection_marker()` does not enter the fallback detection block because `tool ~= ''`, but it also does not have a branch that executes until the later `elseif tool == 'wget' or tool == 'busybox-wget'`. That part is fine only if `config.upload_tool` was already set. However, in paths where marker sending happens before upload tool detection or where detection is deferred/changed, the fallback only checks for `curl` and generic `wget`, not BusyBox 
- **Fix:** Make marker sending use the same centralized tool detection/classification logic as file uploads, or call `detect_upload_tool()` before any marker attempt and remove ad-hoc fallback probing.

### 🔧 8. [HIGH] find -mtime uses days but the semantics differ: -mtime -N means modified within N*24h, not N calendar days; also -mtime -0 would find nothing
- **Location:** build_find_command / lines ~530-560
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command uses `-mtime -N` where N is config.max_age. POSIX find's -mtime counts 24-hour periods, not calendar days. `-mtime -14` means files modified less than 14*24=336 hours ago. This is the intended behavior. However, if max_age=0, `-mtime -0` means files modified less than 0 hours ago, which matches nothing. The validate_config() check allows max_age >= 0, so max_age=0 is valid but would scan no files. This is a usability issue but not a crash.
- **Fix:** Either document that max_age=0 scans no files, or change the validation to require max_age >= 1, or use `-mtime -1` as minimum. Add a warning in validate_config:
```lua
if config.max_age == 0 then
    log_msg('warn', 'max-age=0 will match no files (find -mtime -0 matches nothing)')
end
```

### 🔧 9. [HIGH] nc response check uses HTTP/1.x pattern but nc may receive partial response or no response before connection closes
- **Location:** upload_with_nc / lines ~370-395
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc backend sends the request and reads the response with `nc -w 30`. The response is read into resp_file and then checked with `resp:match('HTTP/1%.%d 2%d%d')`. However, nc with -w 30 waits 30 seconds for data after the connection goes idle. On some servers that close the connection immediately after sending the response, nc may exit before reading the full response. More critically, if the server uses HTTP/1.1 keep-alive and doesn't close the connection, nc will wait the full 30 seconds. Th
- **Fix:** Add `Connection: close` to the request headers (already done - good). Also consider reducing the timeout or adding a note that nc is only suitable for small file sets. Verify the request already includes `Connection: close` (it does at line ~375). The main remaining issue is the 30s timeout per file. Consider using `-w 10` or making it configurable.

### 🔧 10. [HIGH] sanitize_filename does not escape all characters that are special in multipart Content-Disposition headers
- **Location:** sanitize_filename / lines ~95-101
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The filename in the Content-Disposition header is enclosed in double quotes: `filename="<safe_name>"`. sanitize_filename replaces `"`, `\`, `;`, `\r`, `\n` with underscores. However, it does not handle other control characters (0x00-0x1F, 0x7F) that could appear in filenames on Linux filesystems. A filename with embedded control characters (e.g., 0x01-0x1F) would be passed through unmodified into the Content-Disposition header, potentially corrupting the multipart boundary parsing on the server 
- **Fix:** Add control character sanitization to sanitize_filename:
```lua
function sanitize_filename(s)
    if not s then return '' end
    local r = s:gsub('["\\;]', '_')
    r = r:gsub('%c', '_')  -- replace all control chars including \r, \n, \t, etc.
    return r
end
```

### 🔧 11. [HIGH] Mount point paths with spaces or special characters in /proc/mounts are not handled correctly
- **Location:** parse_proc_mounts / lines ~490-510
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** /proc/mounts encodes spaces in paths as `\040` (octal escape). The pattern `(%S+)%s+(%S+)%s+(%S+)` correctly splits on whitespace, so a mount point with a space would be split incorrectly — the path would be truncated at the space. The captured mountpoint would be wrong, and the exclusion would not work for paths containing spaces.
- **Fix:** Decode \040 escape sequences from the captured mountpoint:
```lua
local _, mp, fstype = line:match('^(%S+)%s+(%S+)%s+(%S+)')
if mp then
    mp = mp:gsub('\\040', ' ')  -- decode octal-escaped spaces
    mp = mp:gsub('\\011', '\t') -- decode octal-escaped tabs
end
```

### 🔧 12. [HIGH] Fallback temp file path using os.time() + math.random is predictable and has TOCTOU race
- **Location:** mktemp / lines ~115-140
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When mktemp binary is unavailable, the code falls back to os.tmpname() and then potentially to `/tmp/thunderstorm.<time><random>`. The os.tmpname() fallback has a TOCTOU race (noted in comments). The secondary fallback uses os.time() (second granularity) + math.random(10000,99999). math.random in Lua 5.1 uses the C rand() function which may not be seeded properly (math.randomseed is not called in the script). Without seeding, math.random returns the same sequence on every run, making the temp fi
- **Fix:** Add math.randomseed(os.time()) at script startup (in main() before any mktemp calls). Also consider using os.clock() combined with os.time() for better entropy:
```lua
math.randomseed(os.time() + math.floor(os.clock() * 1000000))
```
Add this near the top of main() before any mktemp() calls.

### 🔧 13. [HIGH] io.popen handle for find command is not closed on early return paths
- **Location:** scan_directory / lines ~590-640
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In scan_directory, if the function returns early (e.g., due to exec_ok failing for the directory test), the handle from io.popen is properly not opened. However, within the file processing loop, there is no mechanism to close the handle if an unexpected error occurs during processing. More importantly, `handle:close()` is called after the loop, but if the loop body raises a Lua error (e.g., from a failed string operation on a malformed path), the handle would be leaked. In Lua 5.1, unclosed io.p
- **Fix:** Wrap the loop in pcall or use a local function with proper cleanup:
```lua
local ok, err = pcall(function()
    for file_path in handle:lines() do
        -- processing
    end
end)
handle:close()
if not ok then
    log_msg('error', 'Error during scan of ' .. dir .. ': ' .. tostring(err))
end
```

### 🔧 14. [HIGH] wget --post-file with multipart body does not set Content-Length header, relying on chunked transfer which BusyBox wget may not support
- **Location:** upload_with_wget / lines ~370-400
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** GNU wget with --post-file sends the file content as the POST body but does not automatically add a Content-Length header for the multipart body — it relies on the server accepting chunked transfer encoding or the connection being closed to signal end of body. BusyBox wget may not support chunked transfer encoding. Without Content-Length, some HTTP/1.0 servers or strict HTTP/1.1 servers may reject the request.
- **Fix:** Add an explicit Content-Length header to the wget command:
```lua
local cmd = string.format(
    'wget -q -O %s %s%s--header=%s --header=%s --post-file=%s %s 2>/dev/null',
    shell_quote(resp_file), insecure, ca_cert_flag,
    shell_quote('Content-Type: multipart/form-data; boundary=' .. boundary),
    shell_quote('Content-Length: ' .. tostring(body_len)),
    shell_quote(body_file), shell_quote(endpoint))
```

### 🔧 15. [MEDIUM] Temporary file fallback is race-prone and can clobber attacker-chosen paths
- **Location:** mktemp / os.tmpname fallback path creation
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When `mktemp` is unavailable, the code falls back to `os.tmpname()` and then separately opens the returned path, explicitly noting the race. On multi-user systems or writable shared `/tmp`, this can be exploited with symlinks or pre-created files. The later `/tmp/thunderstorm.<time><rand>` fallback has the same TOCTOU issue because it also uses predictable naming plus non-exclusive open.
- **Fix:** Prefer requiring `mktemp` when available and fail closed if no safe temp creation primitive exists. If a fallback is unavoidable, create temp files via a shell `umask 077; mktemp` invocation only, and abort if that fails rather than using predictable names.

### 🔧 16. [MEDIUM] Max-age filtering is off by up to almost one day
- **Location:** build_find_command / use of `-mtime -%d`
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script uses `find ... -mtime -N`, which matches files modified less than N*24 hours ago, not 'within the last N calendar days' and not an exact day threshold. For example, `--max-age 14` excludes files that are 14 days and a few minutes old, which may surprise users expecting inclusive behavior. This is a correctness issue in file selection semantics.
- **Fix:** Document the exact semantics clearly or switch to a more precise comparison using `-mtime`/`-mmin` as intended. If parity with other collectors expects inclusive day behavior, adjust the expression accordingly.

### 🔧 17. [MEDIUM] Find command failures are silently ignored, so partial scan failures do not affect exit code
- **Location:** scan_directory / `handle:close()` result ignored
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script reads file paths from `io.popen(cmd)` and then calls `handle:close()` without checking its return status. If `find` encounters an execution error beyond stderr suppression, or exits non-zero due to environmental issues, the collector still treats the directory scan as successful unless zero files were seen. This conflicts with the hardened requirement that partial failures be tracked and reflected in exit code 1.
- **Fix:** Capture and evaluate the close status from `io.popen` where available, and increment a scan-failure counter that contributes to exit code 1. Also avoid blanket `2>/dev/null` if you need to distinguish permission noise from real command failure.

### 🔧 18. [MEDIUM] Escaped mountpoints from `/proc/mounts` are not unescaped before exclusion matching
- **Location:** parse_proc_mounts / mountpoint parsing from `/proc/mounts`
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** Mountpoints in `/proc/mounts` encode spaces and some characters using backslash escapes such as `\040`. The code stores the raw encoded mountpoint string in `dynamic_excludes` and later compares it against real filesystem paths in `find -path`. For mountpoints containing spaces or escaped characters, the exclusion will not match the actual path tree.
- **Fix:** Unescape `/proc/mounts` mountpoints before storing them, at least for common octal escapes like `\040`, `\011`, `\012`, and `\134`.

### 🔧 19. [MEDIUM] Shell injection risk if scan directory paths contain shell metacharacters
- **Location:** build_find_command / lines ~530-560
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** scan_dirs entries are passed through shell_quote() in build_find_command, which correctly handles single quotes. However, the exclude paths in EXCLUDE_PATHS and dynamic_excludes are also passed through shell_quote(). The dynamic_excludes come from /proc/mounts mountpoint parsing. If a mountpoint contains a single quote (unusual but possible on some filesystems), shell_quote handles it correctly via the `'"'"'` escaping. This appears safe. However, the dir argument to scan_directory comes from co
- **Fix:** No change needed. The shell_quote implementation is correct.

### 🔧 20. [MEDIUM] scan_id extracted from server response is not validated before use in URL construction
- **Location:** send_collection_marker / lines ~430-490
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The scan_id is extracted from the server JSON response using `resp:match('"scan_id"%s*:%s*"([^"]+)"')`. This scan_id is then appended to the API endpoint URL via urlencode(). urlencode() properly percent-encodes all non-safe characters, so URL injection is prevented. However, the scan_id is also passed to send_collection_marker as a parameter and embedded in JSON via json_escape(). If the server returns a maliciously crafted scan_id with characters that survive json_escape (which it shouldn't — 
- **Fix:** Consider adding a length check on scan_id (e.g., reject if > 256 chars) as a defense-in-depth measure against unexpectedly large values from a compromised server.

### 🔧 21. [MEDIUM] Progress reporting feature is advertised in --help and config but never implemented
- **Location:** main / lines ~660-720
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The config has a `progress` field (nil=auto-detect TTY, true/false=forced), --progress and --no-progress CLI flags are parsed, but the progress reporting functionality is never actually implemented anywhere in the code. The scan_directory function never checks config.progress or outputs any progress indicators.
- **Fix:** Either implement basic progress reporting in scan_directory (e.g., print a dot or counter every N files when config.progress is true), or remove the --progress/--no-progress flags and config field, and remove them from --help output to avoid misleading users.

### 🔧 22. [MEDIUM] curl command missing --max-time / --connect-timeout flags for file uploads
- **Location:** upload_with_curl / lines ~320-360
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The curl command for file uploads does not include `--max-time` or `--connect-timeout` flags. The collection marker curl command correctly uses `--max-time 10`, but the file upload curl command has no timeout. On embedded systems with unstable network connections, a stalled upload could hang indefinitely, blocking the entire scan.
- **Fix:** Add appropriate timeouts to the upload curl command:
```lua
local cmd = string.format(
    'curl -sS --fail --show-error -X POST %s%s%s' ..
    ' --connect-timeout 30 --max-time 120' ..
    ' -H %s --data-binary @%s -o %s 2>%s',
    ...)
```
Consider making the timeout configurable.

### 🔧 23. [MEDIUM] Cloud path detection suffix check uses hardcoded length that may be wrong for some entries
- **Location:** is_cloud_path / lines ~500-515
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The suffix check `lower:sub(-(#name + 1)) == '/' .. name` correctly computes the length dynamically using `#name`. This is correct. However, the macOS cloud storage check `lower:sub(-20) == '/library/cloudstorage'` uses a hardcoded length of 20. The string '/library/cloudstorage' has 21 characters (including the leading slash), so `sub(-20)` would miss the leading slash and the comparison would fail for paths that end exactly with '/library/cloudstorage'. Let me count: /library/cloudstorage = 1+
- **Fix:** Fix the hardcoded length:
```lua
local cloud_suffix = '/library/cloudstorage'
if lower:sub(-(#cloud_suffix)) == cloud_suffix then return true end
```

### 🔧 24. [MEDIUM] Syslog logging via os.execute('logger ...') spawns a shell process for every log message
- **Location:** log_msg / lines ~175-205
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When syslog logging is enabled, every call to log_msg spawns a shell process via os.execute to run the logger command. In scan_directory, log_msg is called for every file (at debug level) and for every submission. With thousands of files, this spawns thousands of shell processes, which is extremely expensive on embedded systems with limited RAM and slow process creation.
- **Fix:** Batch syslog messages or use a pipe to a persistent logger process. At minimum, add a check to skip syslog for debug-level messages unless explicitly needed:
```lua
if config.log_to_syslog and level ~= 'debug' then
    -- spawn logger only for non-debug messages
end
```

### 🔧 25. [MEDIUM] Temp files created by build_multipart_body accumulate throughout the run and are only cleaned at exit
- **Location:** build_multipart_body / lines ~270-310
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** Each call to build_multipart_body creates two temp files (via mktemp): one for the multipart body. Each call to upload_with_curl/wget/nc creates additional temp files (resp_file, err_file, req_file). These are all tracked in temp_files[] and only cleaned up at exit via cleanup_temp_files(). For a scan of 10,000 files with 3 retries each, this could create 30,000-60,000 temp file entries in temp_files[] and the same number of actual files on disk simultaneously.
- **Fix:** Clean up temp files after each file submission attempt rather than accumulating them. Track temp files per-upload and clean them immediately after the upload attempt:
```lua
-- After submit_file() returns, clean up files created during that submission
-- Use a separate 'current_upload_temps' list that's cleared after each file
```
Alternatively, reuse temp file paths across uploads (create them once, reuse, delete at end).

### 🔧 26. [LOW] exec_capture does not check handle:close() return value for command exit status
- **Location:** exec_capture / lines ~155-160
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** io.popen returns a handle, and handle:close() in Lua 5.2+ returns the exit status of the command. In Lua 5.1, close() returns true/nil. The exec_capture function ignores the return value of handle:close(), so if the command fails (e.g., hostname -f returns non-zero), the output is still returned. This is intentional for exec_capture (we want the output regardless of exit code), but it means callers cannot distinguish between 'command succeeded with output' and 'command failed with partial output
- **Fix:** Document that exec_capture returns output regardless of exit code, and callers should validate the output content rather than relying on exit status.

### 🔧 27. [LOW] validate_config allows retries=0 via the > 0 check but the submit_file loop uses 1-based indexing so retries=1 means one attempt with no retries
- **Location:** validate_config / lines ~225-245
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** validate_config requires `config.retries > 0` (so minimum is 1). The submit_file loop is `for attempt = 1, config.retries do`, so retries=1 means exactly one attempt. The --help says 'Retry attempts per file (default: 3)' which implies retries=3 means 3 retries (4 total attempts), but the implementation means retries=3 means 3 total attempts (2 retries). The semantics are inconsistent with the help text.
- **Fix:** Either rename the parameter to 'attempts' and update help text, or change the loop to `for attempt = 1, config.retries + 1 do` to make retries mean the number of retry attempts after the first failure.
