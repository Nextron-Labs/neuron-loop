# Neuron-Loop Report — Iteration 1
Generated: 2026-03-08 12:13:32

## Tests: ✅ PASS

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 8 | T1 |
| sonnet | 22 | T1 |

## Triaged: 29 to fix, 0 skipped (from 30 raw findings, 29 unique)

### 🔧 1. [CRITICAL] Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures
- **Location:** die() / main()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine', 'some uploads failed', and 'fatal misconfiguration'.
- **Fix:** At the end of main(), use: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end. Change die() to os.exit(2) for fatal errors. Update parse_args unknown-option handler to also use os.exit(2).

### 🔧 2. [CRITICAL] Shell injection via filename in curl --form argument
- **Location:** upload_with_curl() / shell_quote()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** upload_with_curl builds the --form argument as: 'file=@<filepath>;filename="<safe_name>"'. The filepath is passed through shell_quote() which wraps in single quotes and escapes embedded single quotes. However, safe_name (from sanitize_filename) only strips backslash, double-quote, semicolon, CR, LF — it does NOT strip NUL bytes or other characters. More critically, the entire --form value is a single shell_quote() call containing both the @ path and the filename= part. If filepath itself contain
- **Fix:** For the filepath in the curl --form value, additionally validate that it contains no characters that could escape the shell_quote boundary. Consider using curl's --form-string for the filename part and a separate --form for the file reference.

### 🔧 3. [CRITICAL] Entire file loaded into Lua memory — catastrophic on embedded systems with large files
- **Location:** build_multipart_body()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file (max_size_kb default), this creates at least 3 copies of the file content in memory simultaneously: the raw content string, the parts table entry, and the body string from table.concat. On a 2–16 MB RAM embedded device, a 2 MB file would consume 6+ MB just for this operation, likely causing OOM.
- **Fix:** Write the multipart body directly to the temp file in chunks rather than building it in memory. Write the headers first, then copy the source file in chunks (e.g., 64KB at a time), then write the closing boundary. Calculate body_len separately using file_size_kb * 1024 + header/footer lengths.

### 🔧 4. [HIGH] Exit codes do not follow the documented collector contract
- **Location:** die / function body; parse_args unknown-option branch; main exit path
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script exits with `os.exit(1)` for fatal errors in `die()`, and also uses `os.exit(1)` for unknown CLI options. On successful completion it implicitly exits 0 even when some files failed to upload. The stated hardened behavior for the other collectors is `0=clean, 1=partial failure, 2=fatal error`, but this Lua collector does not implement that contract.
- **Fix:** Introduce explicit final exit status handling: use `os.exit(2)` for fatal errors in `die()` and argument/validation failures; after the scan, exit `1` if `counters.files_failed > 0`, otherwise `0`. Example: `local code = (counters.files_failed > 0) and 1 or 0; cleanup_temp_files(); if log_file_handle then log_file_handle:close() end; os.exit(code)`.

### 🔧 5. [HIGH] Missing required begin-marker retry on initial failure
- **Location:** main / begin marker send block
- **Models:** sonnet, gpt54 (2 models)
- **Action:** fix
- **Details:** The script sends the `begin` collection marker exactly once via `send_collection_marker(base_url, "begin", nil, nil)`. If that initial request fails transiently, no retry is attempted, despite the documented hardening requirement of a single retry after 2 seconds on initial failure.
- **Fix:** If the first begin marker returns an empty `scan_id`, sleep 2 seconds and retry once before proceeding. Example: `scan_id = send_collection_marker(...); if scan_id == "" then os.execute("sleep 2"); scan_id = send_collection_marker(...) end`.

### 🔧 6. [HIGH] Custom CA bundle support (`--ca-cert`) is missing
- **Location:** CLI parsing/help + upload_with_curl + upload_with_wget + send_collection_marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The hardened requirements explicitly include `--ca-cert PATH` for TLS validation with custom CA bundles, but the Lua collector neither parses this option nor passes a CA bundle to curl/wget. It only supports `--ssl` and `--insecure`.
- **Fix:** Add `config.ca_cert`, parse `--ca-cert <path>`, validate the file exists, and pass it to backends (`curl --cacert <path>`, `wget --ca-certificate=<path>` where supported). Reject incompatible combinations only where necessary.

### 🔧 7. [HIGH] No interruption handling or documented wrapper strategy for SIGINT/SIGTERM
- **Location:** main / collection lifecycle; entire script
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The requirements call out signal handling parity via a shell-wrapper approach because Lua 5.1 lacks native signal handling on these targets. This script has neither in-process handling nor any documented/implemented wrapper mechanism to send an `interrupted` collection marker with stats on SIGINT/SIGTERM.
- **Fix:** Implement the documented shell-wrapper approach: have a small POSIX shell launcher trap `INT`/`TERM`, invoke the Lua collector in a way that persists state/stats, and send an `interrupted` marker before exit. If that is intentionally unsupported, document the limitation explicitly in the script/help and release notes.

### 🔧 8. [HIGH] Multipart body construction reads entire file into memory and duplicates it
- **Location:** build_multipart_body / full function; upload_with_wget; upload_with_nc; upload_with_busybox_wget
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** For wget/nc uploads, `build_multipart_body()` reads the whole sample with `f:read("*a")`, concatenates it into a Lua table, then `table.concat`s the full multipart body, and finally writes that body to a temp file. This creates multiple in-memory copies of the sample plus headers. On 2–16 MB embedded devices, a file near the 2000 KB limit can consume several megabytes transiently.
- **Fix:** Stream multipart construction directly to the temp file instead of materializing the whole body in memory. Write headers, then copy the source file in chunks (e.g. 8–32 KB), then write the closing boundary. Compute `Content-Length` from file size plus header/footer lengths if needed.

### 🔧 9. [HIGH] Shell injection via --post-data with unquoted body containing special characters
- **Location:** send_collection_marker() / wget/busybox-wget branch
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In send_collection_marker(), the wget branch uses --post-data=<shell_quote(body)>. The body is a JSON string containing config.source which comes from hostname output or --source CLI argument. shell_quote() wraps in single quotes and escapes embedded single quotes. However, the wget command is built as a format string where --post-data=%s uses shell_quote(body). If body contains characters that interact with wget's own argument parsing (e.g., very long strings, or if shell_quote fails for some e
- **Fix:** Write the JSON body to a temp file and use --post-file= instead of --post-data= for the wget marker call, consistent with how upload_with_wget works.

### 🔧 10. [HIGH] find prune logic is incorrect — pruned paths are still printed
- **Location:** build_find_command()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command is built as: find <dir> -path X -prune -o -path Y -prune -o ... -o -type f -mtime -N -print. This is the correct POSIX pattern. However, the prune_str is constructed as: table.concat(prune_parts, ' -o ') .. ' -o '. Each prune_part is '-path X -prune'. The final command becomes: find dir -path X -prune -o -path Y -prune -o -type f -mtime -N -print. This is actually correct POSIX find syntax. BUT: if a pruned directory itself matches -type f (it won't, it's a dir), or if the prune
- **Fix:** Test the find prune behavior on BusyBox. Consider using '-path /proc -prune -o -path /proc/* -prune' for robustness, or use the pattern '-path "/proc*" -prune' to catch both the dir and its contents.

### 🔧 11. [HIGH] nc (netcat) upload reads entire response into memory and has no timeout on response reading
- **Location:** upload_with_nc()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** exec_capture() uses io.popen() to run the nc command and reads the entire response with handle:read('*a'). The nc command has -w 30 (30s write timeout) but the response reading in Lua has no timeout. If the server sends a partial response and keeps the connection open, io.popen read will block indefinitely. Additionally, exec_capture captures stdout of the pipeline 'cat file | nc ...', which is the server's HTTP response — this could be megabytes if the server misbehaves.
- **Fix:** Add a timeout wrapper: use 'timeout 35 sh -c "cat ... | nc -w 30 ..."' or redirect nc output to a temp file with a timeout, then read the temp file. Also limit response reading to first 4KB.

### 🔧 12. [HIGH] Missing --ca-cert option for custom CA bundle (parity gap with other 8 collectors)
- **Location:** main() — --ca-cert option missing
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 hardened collectors support --ca-cert PATH for TLS certificate validation with custom CA bundles. This script has no --ca-cert option. When --ssl is used on embedded systems that lack system CA stores, there is no way to provide a custom CA certificate, forcing users to use --insecure (-k) which disables all TLS validation.
- **Fix:** Add config.ca_cert = '' field, add --ca-cert <path> CLI option in parse_args(), and pass --cacert <path> to curl or --ca-certificate <path> to wget when config.ca_cert ~= ''.

### 🔧 13. [HIGH] Backslash escape pattern in gsub is incorrect — only strips backslash, not escaping it
- **Location:** sanitize_filename()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** sanitize_filename() uses: r = s:gsub('["\\;]', '_'). In a Lua character class, \\ is a single backslash. So the pattern '["\\;]' matches double-quote, backslash, and semicolon. This appears correct. However, the intent is to sanitize for use in a Content-Disposition header filename= value which is double-quoted. The function replaces these with underscore, which is safe. BUT: it does not handle forward slashes in the basename. Since filename is extracted as filepath:match('([^/]+)$'), it won't c
- **Fix:** Add NUL byte stripping: r = r:gsub('%z', '_') (Lua pattern %z matches NUL). Also consider stripping other control characters.

### 🔧 14. [HIGH] io.popen handle not closed on early return paths; resource leak
- **Location:** scan_directory() / io.popen()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In scan_directory(), if handle:lines() iteration is interrupted by an error in a called function (e.g., submit_file throws an uncaught error via pcall boundary), the popen handle is never closed. More practically: if the script is killed (SIGTERM), the popen handle leaks. In Lua 5.1 on embedded systems, unclosed popen handles can leave zombie find processes running.
- **Fix:** Wrap the iteration in a pcall or use a pattern that ensures handle:close() is always called: local ok, err = pcall(function() for file_path in handle:lines() do ... end end); handle:close(); if not ok then log_msg('error', err) end

### 🔧 15. [MEDIUM] Use of `os.tmpname()` is unsafe/unreliable on embedded Unix targets
- **Location:** mktemp / function body
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** `mktemp()` relies on `os.tmpname()` and then opens the returned path. On Unix-like systems this is prone to race conditions because the name generation and file creation are separate operations. On some minimal environments `os.tmpname()` may also return unusable paths or fail unexpectedly.
- **Fix:** Prefer invoking a shell `mktemp` utility when available (`mktemp /tmp/thunderstorm.XXXXXX`) and fall back carefully only if absent. If keeping a Lua fallback, create files under a fixed writable temp dir with randomized names and retry on collision.

### 🔧 16. [MEDIUM] Collection marker requests ignore command success and can silently fail
- **Location:** send_collection_marker / curl and wget command construction
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** Both curl and wget branches in `send_collection_marker()` call `os.execute(cmd)` but do not check whether the command succeeded. The function then attempts to parse `resp_file` if present and otherwise returns an empty string. This suppresses transport failures and makes begin/end marker delivery failures indistinguishable from a valid empty response.
- **Fix:** Use `exec_ok(cmd)` and log failures to stderr/log file. Return a success flag plus optional `scan_id`, e.g. `return false, ""` on transport failure and `return true, id or ""` on HTTP success.

### 🔧 17. [MEDIUM] Unconditional stdout output breaks quiet/non-interactive behavior parity
- **Location:** main / banner and summary output
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script always prints the ASCII banner and final summary to stdout, even when `--quiet` is set. The hardened behavior described for the other collectors includes TTY-aware progress control and routing errors to stderr; this collector still emits normal-status output unconditionally to stdout.
- **Fix:** Suppress banner/summary unless stdout is a TTY and quiet mode is off, or add explicit `--progress/--no-progress` parity and gate human-oriented output behind it. Keep errors on stderr.

### 🔧 18. [MEDIUM] json_escape %c pattern also matches \n, \r, \t which are already escaped above it
- **Location:** json_escape()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** json_escape() first replaces \n, \r, \t with their JSON escape sequences, then applies s:gsub('%c', ...) which matches ALL control characters including \n (0x0A), \r (0x0D), \t (0x09). Since gsub processes the string sequentially and the prior replacements have already converted these to multi-character escape sequences (e.g., \n becomes the two characters backslash+n), the %c pattern will NOT re-match them (backslash is 0x5C, not a control char; 'n' is 0x6E). So this is actually safe. However, 
- **Fix:** After the %c gsub, add: s = s:gsub('\x7f', '\\u007f'). Or rewrite json_escape to handle all cases in a single pass.

### 🔧 19. [MEDIUM] URL path extraction regex fails for URLs with no path component
- **Location:** upload_with_nc() — path_rest extraction
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In upload_with_nc(), path_rest is extracted with: hostpath:match('^[^/]+/(.*)$'). If the URL is 'http://host:8080' (no trailing slash, no path), hostpath is 'host:8080' and path_rest is nil, so path_query becomes '/'. But the actual endpoint always has '/api/checkAsync?...' so this shouldn't occur in practice. However, if config.server contains a slash (e.g., user error), hostpath parsing breaks entirely. The host extraction host = hostport:match('^([^:]+)') would also fail if hostport is nil.
- **Fix:** Add nil checks: if not hostport then log_msg('error', 'Invalid endpoint URL for nc'); return false end. Validate config.server doesn't contain slashes in validate_config().

### 🔧 20. [MEDIUM] wget_is_busybox() spawns a subprocess even when wget is not available
- **Location:** detect_upload_tool() / wget_is_busybox()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** detect_upload_tool() calls wget_is_busybox() only after confirming wget exists (has_wget is true), so this is actually fine. However, wget_is_busybox() uses exec_capture('wget --version 2>&1') which on some BusyBox systems causes wget to actually attempt a connection or print usage to stderr and exit non-zero. The 2>&1 redirect captures both, so the output check works. But on systems where 'wget --version' is not recognized (BusyBox wget may not support --version), it may print usage/error text 
- **Fix:** Also check if the output contains 'GNU Wget' to positively identify GNU wget, rather than relying solely on absence of 'busybox': if output:lower():find('gnu wget') then return false (it's GNU); elseif output:lower():find('busybox') then return true; else return true (assume busybox if unknown) end.

### 🔧 21. [MEDIUM] Syslog via os.execute('logger ...') called for every log message — severe performance issue
- **Location:** main() — syslog logging in log_msg()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When config.log_to_syslog is true, every call to log_msg() spawns a new shell process to run logger. For a scan of thousands of files with debug enabled, this spawns thousands of processes. On embedded systems with limited process table size and slow fork(), this can severely degrade performance or exhaust system resources.
- **Fix:** Rate-limit syslog calls (e.g., only log warn/error/info to syslog, not debug), or batch syslog writes. At minimum, document that --syslog with --debug is not recommended on embedded systems.

### 🔧 22. [MEDIUM] Boundary string not verified to be absent from file content
- **Location:** build_multipart_body() — boundary generation
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The multipart boundary is generated as '----ThunderstormBoundary' + os.time() + math.random(10000,99999). This boundary is NOT checked against the file content. If a binary file happens to contain this exact byte sequence, the multipart body will be malformed, causing the server to reject or misparse the upload. While the probability is low for any single file, over millions of files it becomes a real risk.
- **Fix:** After reading file content, verify the boundary is not present: while content:find(boundary, 1, true) do boundary = regenerate() end. Or use a longer random boundary (e.g., 32 hex chars from os.time + multiple math.random calls).

### 🔧 23. [MEDIUM] Unknown options after valid options are silently ignored if they don't start with '-'
- **Location:** parse_args() — unknown option handling
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** parse_args() only checks a:sub(1,1) == '-' for unknown option detection. Positional arguments (non-flag tokens) are silently ignored. A user typo like 'lua collector.lua --server foo.com /tmp' would silently ignore '/tmp' instead of warning. This is a usability issue but could also mask misconfiguration.
- **Fix:** Add an else clause to the option parsing chain that warns about unrecognized non-flag arguments: else if a:sub(1,1) ~= '-' then io.stderr:write('[warn] Ignoring unexpected argument: ' .. a .. '\n') end

### 🔧 24. [MEDIUM] Race condition between file_size_kb() check and actual upload
- **Location:** file_size_kb()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** file_size_kb() opens the file to seek to end for size, then closes it. The actual upload happens later in submit_file(). Between these two operations, the file could grow beyond max_size_kb (e.g., an active log file). The upload would then send a file larger than the configured limit.
- **Fix:** This is an inherent TOCTOU race on a live filesystem. Document it as a known limitation. Optionally, re-check file size in the upload function before sending, or use the Content-Length from the actual bytes read.

### 🔧 25. [MEDIUM] No signal handling — interrupted runs send no 'interrupted' collection marker (parity gap)
- **Location:** main() — signal handling
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 collectors send an 'interrupted' collection marker with stats when receiving SIGINT/SIGTERM. This Lua script has no signal handling at all. When killed, it exits immediately without sending the end marker or interrupted marker, leaving the server-side collection in an unknown state.
- **Fix:** Document this as a known Lua 5.1 limitation (no native signal handling). Provide a shell wrapper that traps SIGINT/SIGTERM and calls the script with a flag, or use a trap in the calling shell. Add a note in the script header about this limitation.

### 🔧 26. [MEDIUM] GNU wget --post-file does not set Content-Length, causing chunked transfer issues
- **Location:** upload_with_wget() — wget --post-file with multipart
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** GNU wget's --post-file sends the file contents but does not automatically set Content-Length (it uses chunked transfer encoding or relies on the server to handle it). The --header only sets Content-Type. Some HTTP/1.0 servers or simple Thunderstorm implementations may not handle chunked transfer encoding, causing upload failures. The body_len variable is calculated but never used in the wget upload.
- **Fix:** Add --header='Content-Length: <body_len>' to the wget command. The body_len is already calculated by build_multipart_body() but unused in upload_with_wget().

### 🔧 27. [LOW] os.tmpname() on some systems returns a name without creating the file, creating a TOCTOU race
- **Location:** mktemp()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The code comments acknowledge this: 'os.tmpname may just return a name on some systems'. The workaround (opening and closing the file) is implemented. However, on systems where os.tmpname() returns a name in /tmp that doesn't exist yet, there's a brief window between the name generation and file creation where another process could create a file with the same name (symlink attack). On embedded systems this is very low risk but worth noting.
- **Fix:** On Linux, prefer using mktemp shell command: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). Fall back to os.tmpname() if mktemp is unavailable.

### 🔧 28. [LOW] Console log output missing timestamp (inconsistency with file log)
- **Location:** log_msg() — console output
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** File log entries include timestamp: '%s %s %s\n' (ts, level, clean). Console (stderr) output only shows '[level] message' without timestamp. The other collectors consistently include timestamps in console output.
- **Fix:** Change console output to: io.stderr:write(string.format('[%s] [%s] %s\n', ts, level, clean))

### 🔧 29. [LOW] All variables are global — risk of accidental pollution and harder debugging
- **Location:** global scope
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** config, counters, EXCLUDE_PATHS, dynamic_excludes, temp_files, log_file_handle, and all functions are global. In Lua 5.1, this means any typo in a variable name silently creates a new global instead of erroring. On embedded systems with multiple Lua scripts, global pollution could cause subtle bugs if this script is require()'d.
- **Fix:** Add 'local' declarations for module-level variables. At minimum, add a comment that this script is designed to be run standalone, not require()'d.
