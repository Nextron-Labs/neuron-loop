# Neuron-Loop Report — Iteration 1
Generated: 2026-03-08 12:00:01

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
| gpt54 | 8 | T1 |
| sonnet | 18 | T1 |

## Triaged: 26 to fix, 0 skipped (from 26 raw findings, 26 unique)

### 🔧 1. [CRITICAL] Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures
- **Location:** die() / main()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine', 'some uploads failed', and 'fatal misconfiguration'.
- **Fix:** At the end of main(), use: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end. Change die() to os.exit(2) for fatal errors. Update --help to document exit codes.

### 🔧 2. [CRITICAL] Shell injection via filepath in curl --form argument
- **Location:** upload_with_curl() / shell_quote()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The form value string.format('file=@%s;filename="%s"', filepath, safe_name) embeds filepath raw. If filepath contains a double-quote character, it terminates the filename= value inside the curl form spec. While shell_quote wraps the whole thing in single quotes preventing shell injection, curl itself parses the semicolon-separated form spec, so a filepath with a semicolon would be misinterpreted by curl's form parser as a type= or filename= separator.
- **Fix:** Use curl's --form-string or pass the file path separately: curl -F 'file=@/path/to/file' with the filename set via a separate -F 'filename=...' or use --form with proper escaping. Alternatively, write the file path to a temp file and use curl's @filename syntax only for the actual file, keeping the display filename in a separate field.

### 🔧 3. [CRITICAL] Entire file content loaded into Lua memory — fatal on embedded systems with large files
- **Location:** build_multipart_body()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file (max_size_kb default), this creates at least 3 copies of the file in memory simultaneously: the raw content string, the parts table entry, and the body concatenation. On a 2-4 MB RAM embedded device this will cause OOM or Lua memory errors.
- **Fix:** Stream the multipart body directly to the temp file without holding it in memory: open the temp file for writing, write the headers, then copy the source file in chunks (e.g., 4096-byte reads in a loop), then write the closing boundary. Remove the in-memory body concatenation entirely. The body_len can be computed as header_len + file_size + footer_len without reading the file.

### 🔧 4. [HIGH] Exit codes do not follow the documented collector contract
- **Location:** die / main / parse_args / process exit handling
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script exits with status 1 for fatal configuration/runtime errors via die(), and otherwise falls off the end of main() with exit status 0 even when some file uploads failed. The hardened collectors are expected to use 0=clean, 1=partial failure, 2=fatal error. This implementation currently cannot distinguish partial upload failures from a clean run, and fatal errors are reported with the wrong code.
- **Fix:** Introduce a final exit-status computation and use 2 for fatal errors. For example: make die() call os.exit(2), and at the end of main() call os.exit(counters.files_failed > 0 and 1 or 0). Also ensure unknown-option/config-validation fatal paths use die() or os.exit(2).

### 🔧 5. [HIGH] Begin collection marker is not retried on initial failure
- **Location:** main / send_collection_marker begin flow
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script sends the begin marker exactly once: `scan_id = send_collection_marker(base_url, "begin", nil, nil)`. The hardening requirements explicitly call for a single retry after 2 seconds on initial failure. If the first marker request fails transiently, the run proceeds without a scan_id and without retrying.
- **Fix:** If the first begin marker call returns an empty scan_id, sleep 2 seconds and retry once before proceeding. Log both attempts. Example: call send_collection_marker() again after `os.execute("sleep 2")` when the first result is empty.

### 🔧 6. [HIGH] Custom CA bundle support is missing despite required hardening parity
- **Location:** CLI parsing / upload_with_curl / upload_with_wget / send_collection_marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script supports `--ssl` and `--insecure` but does not implement the required `--ca-cert PATH` option. As a result, users on embedded systems with private PKI or custom trust stores cannot validate TLS using a supplied CA bundle. The only workaround is `--insecure`, which disables verification entirely.
- **Fix:** Add `config.ca_cert`, parse `--ca-cert <path>`, validate the file exists, and pass it through to the selected backend: curl `--cacert`, wget `--ca-certificate`, and marker requests as well. If using nc, reject HTTPS when a CA bundle is required because nc cannot validate TLS.

### 🔧 7. [HIGH] Netcat backend cannot perform HTTPS uploads but is still selected for SSL mode
- **Location:** upload_with_nc / detect_upload_tool
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When curl and wget are unavailable, detect_upload_tool() selects `nc` even if `config.ssl` is true, only logging a warning. However, upload_with_nc() always emits a plain HTTP request over a raw TCP socket and never performs a TLS handshake. For `https://...` endpoints this will fail or send invalid traffic to the server.
- **Fix:** Do not select nc when `config.ssl` is true unless an actual TLS-capable wrapper is available. Treat this as a fatal capability mismatch: `if config.ssl and only nc is available then die("HTTPS requires curl or wget; nc cannot upload over TLS")`.

### 🔧 8. [HIGH] Shell injection via --post-data with unquoted body containing shell metacharacters
- **Location:** send_collection_marker() — wget branch
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In send_collection_marker(), the wget command uses --post-data=%s where the body is passed through shell_quote(). However, the wget command string itself uses single-quoted --header='Content-Type: application/json' hardcoded in the format string, which is fine. But --post-data=shell_quote(body) is correct only if shell_quote works. The real issue: the format string contains literal single quotes around --header='...' that are part of the Lua string passed to os.execute(). On some shells (dash, a
- **Fix:** Write the JSON body to a temp file and use --post-file= instead of --post-data= to avoid any shell quoting issues with binary or special characters in the body.

### 🔧 9. [HIGH] find prune logic is incorrect — pruned paths are still printed
- **Location:** build_find_command()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command is built as: find DIR (-path P1 -prune -o -path P2 -prune -o ...) -type f -mtime -N -print. The prune_str ends with ' -o ' before '-type f'. This means the full expression is: (-path P1 -prune -o -path P2 -prune -o -type f -mtime -N -print). This is correct ONLY if the pruned directories themselves are not printed. However, the -prune action returns true but does not print, so the -o chain correctly skips to the next alternative. BUT: the issue is that -prune only prevents desce
- **Fix:** Wrap prune clauses in escaped parentheses: prune_str = '\( ' .. table.concat(prune_parts, ' -o ') .. ' \) -o '. This ensures correct precedence across all POSIX find implementations.

### 🔧 10. [HIGH] No retry on begin-marker failure; scan_id silently empty
- **Location:** send_collection_marker() — begin marker retry missing
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 hardened collectors implement a single retry after 2 seconds if the begin marker fails (returns empty scan_id). This script sends the begin marker once and silently continues with scan_id='' if it fails. An empty scan_id means the server cannot correlate uploaded files with a collection session.
- **Fix:** After the first send_collection_marker call returns '', sleep 2 seconds and retry once: if scan_id == '' then os.execute('sleep 2'); scan_id = send_collection_marker(base_url, 'begin', nil, nil) end. Log a warning if still empty after retry.

### 🔧 11. [HIGH] nc response reading via exec_capture uses a pipe that may deadlock or truncate
- **Location:** upload_with_nc()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** upload_with_nc() uses exec_capture() which calls io.popen() to run 'cat FILE | nc -w 30 HOST PORT'. The nc command sends the request and then reads the response. io.popen() captures stdout of the entire pipeline. However, nc's -w 30 timeout applies to inactivity, not total time. More critically, on BusyBox nc, the -w flag behavior varies. The response is read with handle:read('*a') which blocks until nc closes. If the server keeps the connection open (HTTP/1.1 keep-alive), nc will hang until the
- **Fix:** Add explicit timeout handling. Use nc -q 1 (if supported) or nc -w 5 for the response wait. Alternatively, parse the Content-Length from the HTTP response and read only that many bytes. Also consider using 'nc -w 10' with a shorter timeout.

### 🔧 12. [HIGH] Backslash escaping pattern is wrong — gsub pattern '["\\;]' does not escape backslash correctly in Lua
- **Location:** sanitize_filename()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The pattern '["\\;]' in Lua: the string literal '["%\\;]' — in Lua source, \\ is a single backslash, so the pattern is ["%\;] which is a character class containing double-quote, percent, backslash, semicolon. Wait — re-examining: the source has '["\\;]' which in Lua string is the 4 chars [, ", \, ;, ] — that's actually correct for matching backslash. BUT the comment says 'Proper JSON escaping for source names' requires escaping control chars, backslashes, and quotes. The sanitize_filename functi
- **Fix:** Verify the pattern is correct for the use case. Consider also replacing null bytes (\0) which would truncate C-string processing in curl.

### 🔧 13. [HIGH] No --ca-cert option for custom CA bundle, parity gap with all other 8 collectors
- **Location:** main() — ca-cert option missing
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** All 8 other hardened collectors support --ca-cert PATH for TLS certificate validation with custom CA bundles. This Lua collector has no --ca-cert option. The only TLS option is --insecure (-k). On embedded systems with self-signed certificates (common in enterprise Thunderstorm deployments), users must either skip verification entirely or cannot use this collector.
- **Fix:** Add config.ca_cert = '' field. Add --ca-cert <path> CLI option. In upload_with_curl(), add: if config.ca_cert ~= '' then insecure = '--cacert ' .. shell_quote(config.ca_cert) .. ' ' end. In upload_with_wget(), add --ca-certificate=PATH. Document that nc does not support CA certs.

### 🔧 14. [HIGH] wget --post-file sends raw multipart body but --header only sets one Content-Type; wget may add its own Content-Type overriding the boundary
- **Location:** upload_with_wget() / upload_with_busybox_wget()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** GNU wget with --post-file does not automatically set Content-Type. The script sets it via --header='Content-Type: multipart/form-data; boundary=...'. However, BusyBox wget's --post-file behavior varies: some versions ignore custom Content-Type headers when --post-file is used and set application/x-www-form-urlencoded instead, breaking the multipart upload. Additionally, wget's --header flag syntax requires the value to not contain newlines, which is satisfied here, but the boundary value could t
- **Fix:** Test BusyBox wget behavior explicitly. Consider using --header with explicit quoting. For BusyBox wget, consider falling back to a different upload strategy or documenting the limitation more prominently.

### 🔧 15. [MEDIUM] Collection markers are never sent when nc is the detected upload tool
- **Location:** send_collection_marker / tool selection for markers
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** send_collection_marker() only implements curl and wget/busybox-wget branches. If detect_upload_tool() selected `nc`, `tool` remains `nc`, no request is sent, and the function silently returns an empty scan_id. This means begin/end markers are skipped entirely on nc-only systems.
- **Fix:** Either implement JSON POST via nc for plain HTTP, or explicitly log that markers are unsupported with nc and treat missing marker support as a degraded/partial-failure condition. If SSL is enabled, fail earlier as noted in F4.

### 🔧 16. [MEDIUM] Required interruption marker handling is absent and not documented as a limitation
- **Location:** main / signal handling parity gap
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The hardened collectors are expected to send an `interrupted` collection marker with stats on SIGINT/SIGTERM. This Lua implementation has no such handling, and although the prompt notes native signal handling is unavailable on minimal Lua 5.1, the script neither provides a shell-wrapper approach nor clearly documents the limitation in behavior.
- **Fix:** Because pure Lua 5.1 cannot reliably trap signals on the target, document this limitation explicitly and provide a companion shell wrapper that traps INT/TERM and invokes marker submission before terminating the Lua process, or at minimum update help/comments to state interruption markers are unsupported in pure Lua mode.

### 🔧 17. [MEDIUM] Progress reporting and TTY auto-detection are missing
- **Location:** CLI / user interface parity
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The hardening baseline includes progress reporting with TTY auto-detection and `--progress` / `--no-progress`. This script has neither the CLI options nor any progress behavior. While not a security issue, it is a stated parity requirement for the collector family.
- **Fix:** Add `config.progress` with auto-detection based on whether stdout/stderr is a TTY, implement `--progress` and `--no-progress`, and emit lightweight periodic progress updates without excessive memory use.

### 🔧 18. [MEDIUM] Multipart body construction reads entire file into memory
- **Location:** build_multipart_body / upload_with_wget / upload_with_nc
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** build_multipart_body() reads the full sample into a Lua string (`content = f:read("*a")`) and then concatenates it into another full multipart body string before writing to a temp file. For files near the 2000 KB limit this can transiently consume multiple megabytes per upload, which is significant on the stated 2–16 MB RAM targets.
- **Fix:** Stream the multipart body directly to the temp file instead of materializing both the file content and full body in memory. Write the headers, then copy the file in chunks (e.g. 8–32 KB), then write the trailer. Compute Content-Length from file size plus header/trailer lengths.

### 🔧 19. [MEDIUM] os.tmpname() race condition — TOCTOU between name generation and file creation
- **Location:** mktemp() / os.tmpname()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** os.tmpname() returns a filename but does not create the file atomically. The script then opens the file with io.open(path, 'wb') to create it. Between tmpname() returning and io.open() creating the file, another process could create a file or symlink at that path (classic TOCTOU). On embedded systems running as root (common), this could be exploited to redirect writes to arbitrary paths.
- **Fix:** Use mktemp shell command instead: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). This creates the file atomically. Fall back to os.tmpname() only if mktemp is unavailable.

### 🔧 20. [MEDIUM] io.popen() handle not closed on error paths; resource leak
- **Location:** scan_directory() / io.popen()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In scan_directory(), if handle:lines() iteration is interrupted by a Lua error (e.g., out of memory processing a file path), the popen handle is never closed. Lua's garbage collector will eventually close it, but on embedded systems with limited file descriptors, leaked handles from multiple scan_directory() calls could exhaust the fd limit.
- **Fix:** Wrap the iteration in pcall or use a manual loop with explicit handle:close() in a finally-equivalent pattern: local ok, err = pcall(function() for file_path in handle:lines() do ... end end); handle:close(); if not ok then log_msg('error', err) end

### 🔧 21. [MEDIUM] Mount point paths with spaces are not handled correctly
- **Location:** parse_proc_mounts()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The pattern '^(%S+)%s+(%S+)%s+(%S+)' matches non-whitespace tokens. In /proc/mounts, mount points with spaces are encoded as \040 (octal escape), not literal spaces. This is actually handled correctly by the pattern since \040 is not whitespace. However, the extracted mount point path will contain the literal string \040 instead of a space, while the actual filesystem path uses a real space. When this path is later used in find -path exclusions, the shell_quote() will quote \040 literally, which
- **Fix:** After extracting mp, decode octal escapes: mp = mp:gsub('\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end). This converts \040 to actual space before using in exclusions.

### 🔧 22. [MEDIUM] Source name not JSON-escaped before use in collection markers
- **Location:** detect_source_name()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** config.source is set from hostname command output via trim(). While json_escape() is called when building the collection marker JSON, the source is also used directly in the query string via urlencode(config.source) which is correct for URLs. However, if hostname returns a value with characters that survive urlencode but are semantically significant in the API (e.g., a hostname with a hash or question mark), the endpoint URL could be malformed. More critically, the source name is used in log mes
- **Fix:** urlencode() already handles this correctly for URL context. The json_escape() handles JSON context. This is mostly fine, but add a length limit on source name (e.g., truncate to 253 chars, max DNS name length) to prevent excessively long URLs.

### 🔧 23. [MEDIUM] No signal handling — SIGINT/SIGTERM leaves collection in 'begun' state with no end marker
- **Location:** main() — signal handling
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 collectors implement signal handling to send an 'interrupted' collection marker with current stats when SIGINT/SIGTERM is received. Lua 5.1 has no native signal handling, but the script doesn't even document this limitation or suggest a workaround. If the user presses Ctrl+C, the script exits immediately, the begin marker was sent but no end marker is sent, and the server's collection session is left open indefinitely.
- **Fix:** Document this as a known limitation in the script header (already partially done). Optionally provide a shell wrapper script that traps SIGINT/SIGTERM and sends the end marker. Add a note in --help output. Consider registering an atexit-equivalent using pcall around main() to send the end marker even on Lua errors.

### 🔧 24. [MEDIUM] Boundary value could theoretically appear in binary file content
- **Location:** build_multipart_body()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The multipart boundary is 'ThunderstormBoundary' + os.time() + math.random(10000,99999). While collisions are unlikely for text files, binary files could contain this exact byte sequence. The multipart RFC requires that the boundary not appear in the body content. No check is performed to verify the boundary doesn't appear in the file content.
- **Fix:** After reading file content, verify the boundary doesn't appear: if content:find(boundary, 1, true) then regenerate boundary end. Or use a longer random boundary (add more random components) to make collision probability negligible. curl handles this automatically when using --form, which is another reason to prefer curl's native multipart handling.

### 🔧 25. [LOW] Timestamp not included in console output, only in file output
- **Location:** log_msg()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** Console output format is '[level] message' without timestamp, while file output includes timestamp. This is inconsistent and makes it harder to correlate console output with log file entries during debugging.
- **Fix:** Add timestamp to console output: io.stderr:write(string.format('[%s] [%s] %s\n', ts, level, clean))

### 🔧 26. [LOW] HTTP/1.0 would be safer than HTTP/1.1 for nc-based uploads
- **Location:** upload_with_nc()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc upload sends 'POST %s HTTP/1.1' with 'Connection: close'. HTTP/1.1 requires the server to support chunked transfer encoding and other features. Using HTTP/1.0 would be simpler and more reliable for a raw nc implementation since HTTP/1.0 closes the connection after the response by default, eliminating the need for Connection: close and avoiding HTTP/1.1 compliance issues.
- **Fix:** Change to 'POST %s HTTP/1.0\r\n' and remove the 'Connection: close' header. HTTP/1.0 is universally supported and simpler for raw socket communication.
