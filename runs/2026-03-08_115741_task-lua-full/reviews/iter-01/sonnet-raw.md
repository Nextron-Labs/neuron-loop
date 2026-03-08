```json
[
  {
    "id": "F1",
    "severity": "CRITICAL",
    "location": "die() / main()",
    "title": "Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures",
    "description": "The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine', 'some uploads failed', and 'fatal misconfiguration'.",
    "impact": "Orchestration systems that rely on exit codes to distinguish partial vs fatal failures will misinterpret results. A run where 100% of uploads failed silently exits 0.",
    "suggestion": "At the end of main(), use: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end. Change die() to os.exit(2) for fatal errors. Update --help to document exit codes.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "CRITICAL",
    "location": "upload_with_curl() / shell_quote()",
    "title": "Shell injection via filepath in curl --form argument",
    "description": "In upload_with_curl(), the form argument is built as: string.format('file=@%s;filename=\"%s\"', filepath, safe_name). The filepath is NOT shell-quoted before being embedded inside the outer shell_quote() call. shell_quote() wraps in single quotes and escapes embedded single quotes, but the filepath is placed inside a double-quoted string within the form value. A filepath containing a double-quote or semicolon (e.g. /tmp/foo\";rm -rf /;echo \") would break out of the filename field and inject curl options or shell metacharacters. The outer shell_quote wraps the entire --form value, but the inner filepath is not sanitized for the curl @filename syntax.",
    "description": "The form value string.format('file=@%s;filename=\"%s\"', filepath, safe_name) embeds filepath raw. If filepath contains a double-quote character, it terminates the filename= value inside the curl form spec. While shell_quote wraps the whole thing in single quotes preventing shell injection, curl itself parses the semicolon-separated form spec, so a filepath with a semicolon would be misinterpreted by curl's form parser as a type= or filename= separator.",
    "impact": "Maliciously named files (or files with unusual names from find output) could cause curl to misparse the form field, leading to upload failure or unexpected curl behavior.",
    "suggestion": "Use curl's --form-string or pass the file path separately: curl -F 'file=@/path/to/file' with the filename set via a separate -F 'filename=...' or use --form with proper escaping. Alternatively, write the file path to a temp file and use curl's @filename syntax only for the actual file, keeping the display filename in a separate field.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F3",
    "severity": "CRITICAL",
    "location": "build_multipart_body()",
    "title": "Entire file content loaded into Lua memory — fatal on embedded systems with large files",
    "description": "build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file (max_size_kb default), this creates at least 3 copies of the file in memory simultaneously: the raw content string, the parts table entry, and the body concatenation. On a 2-4 MB RAM embedded device this will cause OOM or Lua memory errors.",
    "impact": "On target embedded systems (2-16 MB RAM), uploading even moderately sized files will exhaust memory, crash the collector, and potentially destabilize the device.",
    "suggestion": "Stream the multipart body directly to the temp file without holding it in memory: open the temp file for writing, write the headers, then copy the source file in chunks (e.g., 4096-byte reads in a loop), then write the closing boundary. Remove the in-memory body concatenation entirely. The body_len can be computed as header_len + file_size + footer_len without reading the file.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "send_collection_marker() — wget branch",
    "title": "Shell injection via --post-data with unquoted body containing shell metacharacters",
    "description": "In send_collection_marker(), the wget command uses --post-data=%s where the body is passed through shell_quote(). However, the wget command string itself uses single-quoted --header='Content-Type: application/json' hardcoded in the format string, which is fine. But --post-data=shell_quote(body) is correct only if shell_quote works. The real issue: the format string contains literal single quotes around --header='...' that are part of the Lua string passed to os.execute(). On some shells (dash, ash) this works, but the body JSON may contain characters that interact with the shell_quote escaping in edge cases. More critically, the body is built with string.format and json_escape, but if json_escape fails to escape a character (e.g., a NUL byte in source name), the shell command will be malformed.",
    "impact": "Malformed shell commands cause silent failures of collection markers; begin/end markers not sent means the server cannot correlate scan results.",
    "suggestion": "Write the JSON body to a temp file and use --post-file= instead of --post-data= to avoid any shell quoting issues with binary or special characters in the body.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "HIGH",
    "location": "build_find_command()",
    "title": "find prune logic is incorrect — pruned paths are still printed",
    "description": "The find command is built as: find DIR (-path P1 -prune -o -path P2 -prune -o ...) -type f -mtime -N -print. The prune_str ends with ' -o ' before '-type f'. This means the full expression is: (-path P1 -prune -o -path P2 -prune -o -type f -mtime -N -print). This is correct ONLY if the pruned directories themselves are not printed. However, the -prune action returns true but does not print, so the -o chain correctly skips to the next alternative. BUT: the issue is that -prune only prevents descending; the directory entry itself matches -path and gets pruned. The real bug is that when there are NO prune_parts, prune_str is empty and the command is 'find DIR -type f -mtime -N -print' which is correct. When there ARE prune parts, the expression needs explicit grouping with escaped parentheses: find DIR \\( -path P1 -prune -o -path P2 -prune \\) -o -type f -mtime -N -print. Without the grouping, operator precedence may cause -type f to bind to the last -prune's -o incorrectly on some find implementations.",
    "impact": "On BusyBox find (common on OpenWrt), without explicit grouping, excluded paths like /proc may still be descended into, causing hangs or spurious output.",
    "suggestion": "Wrap prune clauses in escaped parentheses: prune_str = '\\( ' .. table.concat(prune_parts, ' -o ') .. ' \\) -o '. This ensures correct precedence across all POSIX find implementations.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F6",
    "severity": "HIGH",
    "location": "send_collection_marker() — begin marker retry missing",
    "title": "No retry on begin-marker failure; scan_id silently empty",
    "description": "The other 8 hardened collectors implement a single retry after 2 seconds if the begin marker fails (returns empty scan_id). This script sends the begin marker once and silently continues with scan_id='' if it fails. An empty scan_id means the server cannot correlate uploaded files with a collection session.",
    "impact": "Transient network errors at startup cause the entire collection to be unattributed on the server side, defeating the purpose of collection markers.",
    "suggestion": "After the first send_collection_marker call returns '', sleep 2 seconds and retry once: if scan_id == '' then os.execute('sleep 2'); scan_id = send_collection_marker(base_url, 'begin', nil, nil) end. Log a warning if still empty after retry.",
    "false_positive_risk": "low"
  },
  {
    "id": "F7",
    "severity": "HIGH",
    "location": "upload_with_nc()",
    "title": "nc response reading via exec_capture uses a pipe that may deadlock or truncate",
    "description": "upload_with_nc() uses exec_capture() which calls io.popen() to run 'cat FILE | nc -w 30 HOST PORT'. The nc command sends the request and then reads the response. io.popen() captures stdout of the entire pipeline. However, nc's -w 30 timeout applies to inactivity, not total time. More critically, on BusyBox nc, the -w flag behavior varies. The response is read with handle:read('*a') which blocks until nc closes. If the server keeps the connection open (HTTP/1.1 keep-alive), nc will hang until the 30s timeout. The HTTP request correctly sends 'Connection: close' but the server may not honor it immediately.",
    "impact": "Each nc upload could block for up to 30 seconds waiting for connection close, making the collector extremely slow on embedded systems.",
    "suggestion": "Add explicit timeout handling. Use nc -q 1 (if supported) or nc -w 5 for the response wait. Alternatively, parse the Content-Length from the HTTP response and read only that many bytes. Also consider using 'nc -w 10' with a shorter timeout.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F8",
    "severity": "HIGH",
    "location": "sanitize_filename()",
    "title": "Backslash escaping pattern is wrong — gsub pattern '[\"\\\\;]' does not escape backslash correctly in Lua",
    "description": "The pattern '[\"\\\\;]' in Lua: the string literal '[\"%\\\\;]' — in Lua source, \\\\ is a single backslash, so the pattern is [\"%\\;] which is a character class containing double-quote, percent, backslash, semicolon. Wait — re-examining: the source has '[\"\\\\;]' which in Lua string is the 4 chars [, \", \\, ;, ] — that's actually correct for matching backslash. BUT the comment says 'Proper JSON escaping for source names' requires escaping control chars, backslashes, and quotes. The sanitize_filename function replaces these with underscore, which is used for the curl filename= field. The issue is that the curl form spec uses semicolons as separators (filename=foo;type=bar), so a semicolon in the filename would be misinterpreted. The pattern does include semicolon, so that's handled. However, the function does NOT escape forward slashes, which in a filename= context are harmless but in a path context could cause issues. More importantly, this function is used for the curl --form filename display value, not for JSON — the json_escape function is separate and correct.",
    "impact": "Low direct impact since sanitize_filename is only used for the display filename in multipart uploads, not for path operations.",
    "suggestion": "Verify the pattern is correct for the use case. Consider also replacing null bytes (\\0) which would truncate C-string processing in curl.",
    "false_positive_risk": "high"
  },
  {
    "id": "F9",
    "severity": "HIGH",
    "location": "main() — ca-cert option missing",
    "title": "No --ca-cert option for custom CA bundle, parity gap with all other 8 collectors",
    "description": "All 8 other hardened collectors support --ca-cert PATH for TLS certificate validation with custom CA bundles. This Lua collector has no --ca-cert option. The only TLS option is --insecure (-k). On embedded systems with self-signed certificates (common in enterprise Thunderstorm deployments), users must either skip verification entirely or cannot use this collector.",
    "impact": "Forces users to choose between no TLS verification (security risk) and inability to use the collector against servers with custom CA certificates.",
    "suggestion": "Add config.ca_cert = '' field. Add --ca-cert <path> CLI option. In upload_with_curl(), add: if config.ca_cert ~= '' then insecure = '--cacert ' .. shell_quote(config.ca_cert) .. ' ' end. In upload_with_wget(), add --ca-certificate=PATH. Document that nc does not support CA certs.",
    "false_positive_risk": "low"
  },
  {
    "id": "F10",
    "severity": "HIGH",
    "location": "upload_with_wget() / upload_with_busybox_wget()",
    "title": "wget --post-file sends raw multipart body but --header only sets one Content-Type; wget may add its own Content-Type overriding the boundary",
    "description": "GNU wget with --post-file does not automatically set Content-Type. The script sets it via --header='Content-Type: multipart/form-data; boundary=...'. However, BusyBox wget's --post-file behavior varies: some versions ignore custom Content-Type headers when --post-file is used and set application/x-www-form-urlencoded instead, breaking the multipart upload. Additionally, wget's --header flag syntax requires the value to not contain newlines, which is satisfied here, but the boundary value could theoretically contain characters that confuse the header parser.",
    "impact": "On BusyBox wget (the last-resort tool for embedded systems), file uploads may be sent with wrong Content-Type, causing server-side parse failures for all files.",
    "suggestion": "Test BusyBox wget behavior explicitly. Consider using --header with explicit quoting. For BusyBox wget, consider falling back to a different upload strategy or documenting the limitation more prominently.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F11",
    "severity": "MEDIUM",
    "location": "mktemp() / os.tmpname()",
    "title": "os.tmpname() race condition — TOCTOU between name generation and file creation",
    "description": "os.tmpname() returns a filename but does not create the file atomically. The script then opens the file with io.open(path, 'wb') to create it. Between tmpname() returning and io.open() creating the file, another process could create a file or symlink at that path (classic TOCTOU). On embedded systems running as root (common), this could be exploited to redirect writes to arbitrary paths.",
    "impact": "On multi-user systems or systems with untrusted processes, temp file creation could be hijacked. Less critical on single-purpose embedded devices but still a correctness issue.",
    "suggestion": "Use mktemp shell command instead: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). This creates the file atomically. Fall back to os.tmpname() only if mktemp is unavailable.",
    "false_positive_risk": "low"
  },
  {
    "id": "F12",
    "severity": "MEDIUM",
    "location": "scan_directory() / io.popen()",
    "title": "io.popen() handle not closed on error paths; resource leak",
    "description": "In scan_directory(), if handle:lines() iteration is interrupted by a Lua error (e.g., out of memory processing a file path), the popen handle is never closed. Lua's garbage collector will eventually close it, but on embedded systems with limited file descriptors, leaked handles from multiple scan_directory() calls could exhaust the fd limit.",
    "impact": "On systems scanning many directories, fd exhaustion could prevent further file operations including log writes.",
    "suggestion": "Wrap the iteration in pcall or use a manual loop with explicit handle:close() in a finally-equivalent pattern: local ok, err = pcall(function() for file_path in handle:lines() do ... end end); handle:close(); if not ok then log_msg('error', err) end",
    "false_positive_risk": "low"
  },
  {
    "id": "F13",
    "severity": "MEDIUM",
    "location": "parse_proc_mounts()",
    "title": "Mount point paths with spaces are not handled correctly",
    "description": "The pattern '^(%S+)%s+(%S+)%s+(%S+)' matches non-whitespace tokens. In /proc/mounts, mount points with spaces are encoded as \\040 (octal escape), not literal spaces. This is actually handled correctly by the pattern since \\040 is not whitespace. However, the extracted mount point path will contain the literal string \\040 instead of a space, while the actual filesystem path uses a real space. When this path is later used in find -path exclusions, the shell_quote() will quote \\040 literally, which won't match the actual path with a space.",
    "impact": "Mount points with spaces in their names will not be properly excluded, potentially causing the collector to scan network or special filesystems.",
    "suggestion": "After extracting mp, decode octal escapes: mp = mp:gsub('\\\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end). This converts \\040 to actual space before using in exclusions.",
    "false_positive_risk": "low"
  },
  {
    "id": "F14",
    "severity": "MEDIUM",
    "location": "submit_file() — exponential backoff",
    "title": "Exponential backoff calculation is O(n) loop instead of bit shift; also starts at 1s not 2s",
    "description": "The backoff is computed as: local delay = 1; for _ = 2, attempt do delay = delay * 2 end. For attempt=1, the loop runs 0 times, delay=1s. For attempt=2, delay=2s. For attempt=3, delay=4s. This is correct exponential backoff but the loop is unnecessary (use math.pow or 2^(attempt-1) pattern). More importantly, the other collectors use 2s as the initial retry delay. Minor inconsistency but worth noting.",
    "impact": "Negligible performance impact. Minor inconsistency with other collectors.",
    "suggestion": "Replace with: local delay = math.max(1, 2 ^ (attempt - 1)) — but since Lua 5.1 doesn't have integer exponentiation issues for small values, this is fine. Or simply: local delays = {1, 2, 4, 8}; local delay = delays[attempt] or 8.",
    "false_positive_risk": "low"
  },
  {
    "id": "F15",
    "severity": "MEDIUM",
    "location": "upload_with_curl()",
    "title": "Response body check for '\"reason\"' is too broad — may false-positive on legitimate responses",
    "description": "The code checks if resp_body:lower():find('\"reason\"') to detect server-side rejection. A legitimate Thunderstorm API response that happens to contain the word 'reason' in any JSON field (e.g., a scan result with a 'reason' field for a detection) would be incorrectly treated as a rejection, causing the upload to be counted as failed even though it succeeded.",
    "impact": "Files that are successfully uploaded and scanned but return a response containing 'reason' (e.g., detection results) will be incorrectly counted as failures, inflating files_failed counter.",
    "suggestion": "Check for a more specific rejection pattern, such as an HTTP error status code (curl --fail already handles this) or a specific JSON structure like '{\"error\":' or check the HTTP status code separately. Since --fail is already used, a non-2xx response causes curl to return non-zero exit code, so the response body check for 'reason' may be redundant and should be removed or made more specific.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F16",
    "severity": "MEDIUM",
    "location": "detect_source_name()",
    "title": "Source name not JSON-escaped before use in collection markers",
    "description": "config.source is set from hostname command output via trim(). While json_escape() is called when building the collection marker JSON, the source is also used directly in the query string via urlencode(config.source) which is correct for URLs. However, if hostname returns a value with characters that survive urlencode but are semantically significant in the API (e.g., a hostname with a hash or question mark), the endpoint URL could be malformed. More critically, the source name is used in log messages without sanitization, which is minor but could cause log injection.",
    "impact": "Unusual hostnames (valid in some configurations) could malform the API endpoint URL.",
    "suggestion": "urlencode() already handles this correctly for URL context. The json_escape() handles JSON context. This is mostly fine, but add a length limit on source name (e.g., truncate to 253 chars, max DNS name length) to prevent excessively long URLs.",
    "false_positive_risk": "high"
  },
  {
    "id": "F17",
    "severity": "MEDIUM",
    "location": "main() — signal handling",
    "title": "No signal handling — SIGINT/SIGTERM leaves collection in 'begun' state with no end marker",
    "description": "The other 8 collectors implement signal handling to send an 'interrupted' collection marker with current stats when SIGINT/SIGTERM is received. Lua 5.1 has no native signal handling, but the script doesn't even document this limitation or suggest a workaround. If the user presses Ctrl+C, the script exits immediately, the begin marker was sent but no end marker is sent, and the server's collection session is left open indefinitely.",
    "impact": "Interrupted collections leave dangling sessions on the Thunderstorm server, potentially causing server-side resource leaks or incorrect reporting.",
    "suggestion": "Document this as a known limitation in the script header (already partially done). Optionally provide a shell wrapper script that traps SIGINT/SIGTERM and sends the end marker. Add a note in --help output. Consider registering an atexit-equivalent using pcall around main() to send the end marker even on Lua errors.",
    "false_positive_risk": "low"
  },
  {
    "id": "F18",
    "severity": "MEDIUM",
    "location": "build_multipart_body()",
    "title": "Boundary value could theoretically appear in binary file content",
    "description": "The multipart boundary is 'ThunderstormBoundary' + os.time() + math.random(10000,99999). While collisions are unlikely for text files, binary files could contain this exact byte sequence. The multipart RFC requires that the boundary not appear in the body content. No check is performed to verify the boundary doesn't appear in the file content.",
    "impact": "For binary files (which is the primary use case for malware scanning), a boundary collision would cause the server to misparse the multipart body, resulting in a truncated or malformed file upload — the file would appear to upload successfully but the server receives corrupted data.",
    "suggestion": "After reading file content, verify the boundary doesn't appear: if content:find(boundary, 1, true) then regenerate boundary end. Or use a longer random boundary (add more random components) to make collision probability negligible. curl handles this automatically when using --form, which is another reason to prefer curl's native multipart handling.",
    "false_positive_risk": "low"
  },
  {
    "id": "F19",
    "severity": "LOW",
    "location": "log_msg()",
    "title": "Timestamp not included in console output, only in file output",
    "description": "Console output format is '[level] message' without timestamp, while file output includes timestamp. This is inconsistent and makes it harder to correlate console output with log file entries during debugging.",
    "impact": "Minor usability issue during debugging.",
    "suggestion": "Add timestamp to console output: io.stderr:write(string.format('[%s] [%s] %s\\n', ts, level, clean))",
    "false_positive_risk": "low"
  },
  {
    "id": "F20",
    "severity": "LOW",
    "location": "upload_with_nc()",
    "title": "HTTP/1.0 would be safer than HTTP/1.1 for nc-based uploads",
    "description": "The nc upload sends 'POST %s HTTP/1.1' with 'Connection: close'. HTTP/1.1 requires the server to support chunked transfer encoding and other features. Using HTTP/1.0 would be simpler and more reliable for a raw nc implementation since HTTP/1.0 closes the connection after the response by default, eliminating the need for Connection: close and avoiding HTTP/1.1 compliance issues.",
    "impact": "Some HTTP/1.1 servers may send chunked responses that the simple response parser (looking for HTTP/1.x 2xx) doesn't handle correctly.",
    "suggestion": "Change to 'POST %s HTTP/1.0\\r\\n' and remove the 'Connection: close' header. HTTP/1.0 is universally supported and simpler for raw socket communication.",
    "false_positive_risk": "low"
  }
]
```