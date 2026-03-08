```json
[
  {
    "id": "F1",
    "severity": "CRITICAL",
    "location": "die() / main()",
    "title": "Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures",
    "description": "The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine', 'some uploads failed', and 'fatal misconfiguration'.",
    "impact": "Orchestration systems that rely on exit codes to distinguish partial vs fatal failures will misinterpret results. A run where 100% of uploads failed will still exit 0.",
    "suggestion": "At the end of main(), use: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end. Change die() to os.exit(2) for fatal errors. Update parse_args unknown-option handler to also use os.exit(2).",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "CRITICAL",
    "location": "upload_with_curl() / shell_quote()",
    "title": "Shell injection via filename in curl --form argument",
    "description": "upload_with_curl builds the --form argument as: 'file=@<filepath>;filename=\"<safe_name>\"'. The filepath is passed through shell_quote() which wraps in single quotes and escapes embedded single quotes. However, safe_name (from sanitize_filename) only strips backslash, double-quote, semicolon, CR, LF — it does NOT strip NUL bytes or other characters. More critically, the entire --form value is a single shell_quote() call containing both the @ path and the filename= part. If filepath itself contains a double-quote (which shell_quote does not protect inside the form value string), the curl argument parsing could be confused. The real issue: the form value string is constructed with string.format and then shell_quote'd as a whole, so a filepath like /tmp/foo'bar would be escaped by shell_quote, but the inner filename= value uses double-quotes and safe_name only strips backslash/quote/semicolon — a filename with a double-quote is replaced with underscore, so that part is safe. However, the @ path is NOT sanitized — only shell_quote'd. A path with a newline (noted as unsupported) would break the shell command. This is a known limitation but not documented for the curl case specifically.",
    "impact": "On systems where filenames can contain special characters not handled by shell_quote (e.g., paths from untrusted sources), shell injection is possible.",
    "suggestion": "For the filepath in the curl --form value, additionally validate that it contains no characters that could escape the shell_quote boundary. Consider using curl's --form-string for the filename part and a separate --form for the file reference.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F3",
    "severity": "CRITICAL",
    "location": "build_multipart_body()",
    "title": "Entire file loaded into Lua memory — catastrophic on embedded systems with large files",
    "description": "build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file (max_size_kb default), this creates at least 3 copies of the file content in memory simultaneously: the raw content string, the parts table entry, and the body string from table.concat. On a 2–16 MB RAM embedded device, a 2 MB file would consume 6+ MB just for this operation, likely causing OOM.",
    "impact": "Out-of-memory crash on embedded targets when processing files near the max_size_kb limit. This defeats the purpose of the max_size_kb guard.",
    "suggestion": "Write the multipart body directly to the temp file in chunks rather than building it in memory. Write the headers first, then copy the source file in chunks (e.g., 64KB at a time), then write the closing boundary. Calculate body_len separately using file_size_kb * 1024 + header/footer lengths.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "send_collection_marker() / wget/busybox-wget branch",
    "title": "Shell injection via --post-data with unquoted body containing special characters",
    "description": "In send_collection_marker(), the wget branch uses --post-data=<shell_quote(body)>. The body is a JSON string containing config.source which comes from hostname output or --source CLI argument. shell_quote() wraps in single quotes and escapes embedded single quotes. However, the wget command is built as a format string where --post-data=%s uses shell_quote(body). If body contains characters that interact with wget's own argument parsing (e.g., very long strings, or if shell_quote fails for some edge case), this could be problematic. More concretely: the --header option uses --header='Content-Type: ...' with literal single quotes in the format string, NOT through shell_quote. This means if the format string itself is passed to a shell that interprets it, the quoting is inconsistent. The --header value is hardcoded so this is low risk there, but --post-data uses shell_quote correctly.",
    "impact": "Potential command injection if source name contains adversarial content not fully neutralized by shell_quote.",
    "suggestion": "Write the JSON body to a temp file and use --post-file= instead of --post-data= for the wget marker call, consistent with how upload_with_wget works.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "HIGH",
    "location": "build_find_command()",
    "title": "find prune logic is incorrect — pruned paths are still printed",
    "description": "The find command is built as: find <dir> -path X -prune -o -path Y -prune -o ... -o -type f -mtime -N -print. This is the correct POSIX pattern. However, the prune_str is constructed as: table.concat(prune_parts, ' -o ') .. ' -o '. Each prune_part is '-path X -prune'. The final command becomes: find dir -path X -prune -o -path Y -prune -o -type f -mtime -N -print. This is actually correct POSIX find syntax. BUT: if a pruned directory itself matches -type f (it won't, it's a dir), or if the prune path is a prefix of the scan dir itself, find may behave unexpectedly. The real bug: -path matching in find uses glob patterns, and the paths in EXCLUDE_PATHS like '/proc' will match '/proc' exactly but NOT '/proc/something' unless the pattern is '/proc/*'. The correct pattern for pruning a directory tree is '-path /proc -prune -o -path /proc/* -prune'. As written, files directly inside /proc would be pruned (since /proc matches), but this depends on find implementation. On BusyBox find, -path /proc matches the directory /proc itself, so -prune prevents descent — this is actually correct behavior for directory pruning.",
    "impact": "On some find implementations, excluded directories may not be fully pruned, causing scans of /proc, /sys, etc., which can hang or produce errors.",
    "suggestion": "Test the find prune behavior on BusyBox. Consider using '-path /proc -prune -o -path /proc/* -prune' for robustness, or use the pattern '-path \"/proc*\" -prune' to catch both the dir and its contents.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F6",
    "severity": "HIGH",
    "location": "upload_with_nc()",
    "title": "nc (netcat) upload reads entire response into memory and has no timeout on response reading",
    "description": "exec_capture() uses io.popen() to run the nc command and reads the entire response with handle:read('*a'). The nc command has -w 30 (30s write timeout) but the response reading in Lua has no timeout. If the server sends a partial response and keeps the connection open, io.popen read will block indefinitely. Additionally, exec_capture captures stdout of the pipeline 'cat file | nc ...', which is the server's HTTP response — this could be megabytes if the server misbehaves.",
    "impact": "Script hangs indefinitely waiting for nc response on a slow/misbehaving server. On embedded systems this could freeze the device.",
    "suggestion": "Add a timeout wrapper: use 'timeout 35 sh -c \"cat ... | nc -w 30 ...\"' or redirect nc output to a temp file with a timeout, then read the temp file. Also limit response reading to first 4KB.",
    "false_positive_risk": "low"
  },
  {
    "id": "F7",
    "severity": "HIGH",
    "location": "send_collection_marker() — begin marker retry",
    "title": "Missing begin-marker retry (parity gap with other 8 collectors)",
    "description": "The other 8 hardened collectors implement a single retry after 2 seconds if the begin marker fails. This script sends the begin marker once with no retry. If the server is temporarily unavailable at startup, the scan_id will be empty and all subsequent uploads will lack scan_id association, making the collection untrackable on the server.",
    "impact": "Collections started during brief server unavailability are not associated with a scan_id, breaking server-side collection tracking.",
    "suggestion": "After send_collection_marker returns '' for the begin marker, wait 2 seconds and retry once: if scan_id == '' then os.execute('sleep 2'); scan_id = send_collection_marker(base_url, 'begin', nil, nil) end",
    "false_positive_risk": "low"
  },
  {
    "id": "F8",
    "severity": "HIGH",
    "location": "main() — --ca-cert option missing",
    "title": "Missing --ca-cert option for custom CA bundle (parity gap with other 8 collectors)",
    "description": "The other 8 hardened collectors support --ca-cert PATH for TLS certificate validation with custom CA bundles. This script has no --ca-cert option. When --ssl is used on embedded systems that lack system CA stores, there is no way to provide a custom CA certificate, forcing users to use --insecure (-k) which disables all TLS validation.",
    "impact": "Users on embedded systems with --ssl must use --insecure, completely defeating TLS security. This is a security regression compared to the other collectors.",
    "suggestion": "Add config.ca_cert = '' field, add --ca-cert <path> CLI option in parse_args(), and pass --cacert <path> to curl or --ca-certificate <path> to wget when config.ca_cert ~= ''.",
    "false_positive_risk": "low"
  },
  {
    "id": "F9",
    "severity": "HIGH",
    "location": "sanitize_filename()",
    "title": "Backslash escape pattern in gsub is incorrect — only strips backslash, not escaping it",
    "description": "sanitize_filename() uses: r = s:gsub('[\"\\\\;]', '_'). In a Lua character class, \\\\ is a single backslash. So the pattern '[\"\\\\;]' matches double-quote, backslash, and semicolon. This appears correct. However, the intent is to sanitize for use in a Content-Disposition header filename= value which is double-quoted. The function replaces these with underscore, which is safe. BUT: it does not handle forward slashes in the basename. Since filename is extracted as filepath:match('([^/]+)$'), it won't contain slashes. It also doesn't handle NUL bytes (\\0) which could truncate C-string processing in curl/wget. NUL bytes in filenames are extremely rare but possible on Linux.",
    "impact": "NUL bytes in filenames could cause truncated filenames in the Content-Disposition header, potentially causing server-side misidentification.",
    "suggestion": "Add NUL byte stripping: r = r:gsub('%z', '_') (Lua pattern %z matches NUL). Also consider stripping other control characters.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F10",
    "severity": "HIGH",
    "location": "upload_with_curl()",
    "title": "curl response and error written to same file, causing response body corruption",
    "description": "The curl command uses: -o <resp_file> 2><resp_file>.err. The response body goes to resp_file and stderr goes to resp_file.err. This is correct. However, the code then checks resp_file for '\"reason\"' to detect server rejection. If curl fails (non-zero exit), the response file may be empty or partial, and the error details are in resp_file.err. The code correctly reads resp_file.err on failure. This part is actually fine. The real issue: --fail causes curl to exit non-zero on HTTP 4xx/5xx AND suppresses the response body. So if the server returns a 400 with a JSON body containing '\"reason\"', curl --fail will exit non-zero (caught by exec_ok returning false) and the response body check is never reached. The server rejection detection via '\"reason\"' in the response body is dead code when --fail is used.",
    "impact": "Server-side rejection messages are never logged when using curl, making debugging upload failures impossible.",
    "suggestion": "Remove --fail from the curl command and instead check the HTTP status code. Use -w '%{http_code}' written to a separate file, or parse the response body for error indicators without relying on curl's exit code for HTTP errors.",
    "false_positive_risk": "low"
  },
  {
    "id": "F11",
    "severity": "HIGH",
    "location": "scan_directory() / io.popen()",
    "title": "io.popen handle not closed on early return paths; resource leak",
    "description": "In scan_directory(), if handle:lines() iteration is interrupted by an error in a called function (e.g., submit_file throws an uncaught error via pcall boundary), the popen handle is never closed. More practically: if the script is killed (SIGTERM), the popen handle leaks. In Lua 5.1 on embedded systems, unclosed popen handles can leave zombie find processes running.",
    "impact": "Zombie find processes consuming resources on embedded systems. File descriptor leak.",
    "suggestion": "Wrap the iteration in a pcall or use a pattern that ensures handle:close() is always called: local ok, err = pcall(function() for file_path in handle:lines() do ... end end); handle:close(); if not ok then log_msg('error', err) end",
    "false_positive_risk": "low"
  },
  {
    "id": "F12",
    "severity": "MEDIUM",
    "location": "json_escape()",
    "title": "json_escape %c pattern also matches \\n, \\r, \\t which are already escaped above it",
    "description": "json_escape() first replaces \\n, \\r, \\t with their JSON escape sequences, then applies s:gsub('%c', ...) which matches ALL control characters including \\n (0x0A), \\r (0x0D), \\t (0x09). Since gsub processes the string sequentially and the prior replacements have already converted these to multi-character escape sequences (e.g., \\n becomes the two characters backslash+n), the %c pattern will NOT re-match them (backslash is 0x5C, not a control char; 'n' is 0x6E). So this is actually safe. However, it's fragile and confusing. More importantly: the %c pattern in Lua matches characters where iscntrl() is true, which includes 0x7F (DEL). DEL should also be escaped in JSON (it's not required by JSON spec but is good practice). This is a minor correctness issue.",
    "impact": "DEL character (0x7F) in source names or other JSON fields passes through unescaped. Most JSON parsers handle this fine, but it's technically not clean JSON.",
    "suggestion": "After the %c gsub, add: s = s:gsub('\\x7f', '\\\\u007f'). Or rewrite json_escape to handle all cases in a single pass.",
    "false_positive_risk": "low"
  },
  {
    "id": "F13",
    "severity": "MEDIUM",
    "location": "upload_with_nc() — path_rest extraction",
    "title": "URL path extraction regex fails for URLs with no path component",
    "description": "In upload_with_nc(), path_rest is extracted with: hostpath:match('^[^/]+/(.*)$'). If the URL is 'http://host:8080' (no trailing slash, no path), hostpath is 'host:8080' and path_rest is nil, so path_query becomes '/'. But the actual endpoint always has '/api/checkAsync?...' so this shouldn't occur in practice. However, if config.server contains a slash (e.g., user error), hostpath parsing breaks entirely. The host extraction host = hostport:match('^([^:]+)') would also fail if hostport is nil.",
    "impact": "nc upload silently fails with a nil error if the endpoint URL is malformed.",
    "suggestion": "Add nil checks: if not hostport then log_msg('error', 'Invalid endpoint URL for nc'); return false end. Validate config.server doesn't contain slashes in validate_config().",
    "false_positive_risk": "low"
  },
  {
    "id": "F14",
    "severity": "MEDIUM",
    "location": "detect_upload_tool() / wget_is_busybox()",
    "title": "wget_is_busybox() spawns a subprocess even when wget is not available",
    "description": "detect_upload_tool() calls wget_is_busybox() only after confirming wget exists (has_wget is true), so this is actually fine. However, wget_is_busybox() uses exec_capture('wget --version 2>&1') which on some BusyBox systems causes wget to actually attempt a connection or print usage to stderr and exit non-zero. The 2>&1 redirect captures both, so the output check works. But on systems where 'wget --version' is not recognized (BusyBox wget may not support --version), it may print usage/error text that doesn't contain 'busybox', causing it to be misidentified as GNU wget.",
    "impact": "BusyBox wget misidentified as GNU wget, leading to use of GNU wget multipart upload syntax that BusyBox wget doesn't support, causing all uploads to fail silently.",
    "suggestion": "Also check if the output contains 'GNU Wget' to positively identify GNU wget, rather than relying solely on absence of 'busybox': if output:lower():find('gnu wget') then return false (it's GNU); elseif output:lower():find('busybox') then return true; else return true (assume busybox if unknown) end.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F15",
    "severity": "MEDIUM",
    "location": "main() — syslog logging in log_msg()",
    "title": "Syslog via os.execute('logger ...') called for every log message — severe performance issue",
    "description": "When config.log_to_syslog is true, every call to log_msg() spawns a new shell process to run logger. For a scan of thousands of files with debug enabled, this spawns thousands of processes. On embedded systems with limited process table size and slow fork(), this can severely degrade performance or exhaust system resources.",
    "impact": "Extreme slowdown and potential resource exhaustion on embedded systems when syslog is enabled with debug logging.",
    "suggestion": "Rate-limit syslog calls (e.g., only log warn/error/info to syslog, not debug), or batch syslog writes. At minimum, document that --syslog with --debug is not recommended on embedded systems.",
    "false_positive_risk": "low"
  },
  {
    "id": "F16",
    "severity": "MEDIUM",
    "location": "build_multipart_body() — boundary generation",
    "title": "Boundary string not verified to be absent from file content",
    "description": "The multipart boundary is generated as '----ThunderstormBoundary' + os.time() + math.random(10000,99999). This boundary is NOT checked against the file content. If a binary file happens to contain this exact byte sequence, the multipart body will be malformed, causing the server to reject or misparse the upload. While the probability is low for any single file, over millions of files it becomes a real risk.",
    "impact": "Malformed multipart upload for files containing the boundary string, causing server-side parse errors and failed uploads without clear error messages.",
    "suggestion": "After reading file content, verify the boundary is not present: while content:find(boundary, 1, true) do boundary = regenerate() end. Or use a longer random boundary (e.g., 32 hex chars from os.time + multiple math.random calls).",
    "false_positive_risk": "low"
  },
  {
    "id": "F17",
    "severity": "MEDIUM",
    "location": "parse_args() — unknown option handling",
    "title": "Unknown options after valid options are silently ignored if they don't start with '-'",
    "description": "parse_args() only checks a:sub(1,1) == '-' for unknown option detection. Positional arguments (non-flag tokens) are silently ignored. A user typo like 'lua collector.lua --server foo.com /tmp' would silently ignore '/tmp' instead of warning. This is a usability issue but could also mask misconfiguration.",
    "impact": "User-specified directories via positional args are silently ignored, causing the script to scan default directories instead of intended ones.",
    "suggestion": "Add an else clause to the option parsing chain that warns about unrecognized non-flag arguments: else if a:sub(1,1) ~= '-' then io.stderr:write('[warn] Ignoring unexpected argument: ' .. a .. '\\n') end",
    "false_positive_risk": "low"
  },
  {
    "id": "F18",
    "severity": "MEDIUM",
    "location": "file_size_kb()",
    "title": "Race condition between file_size_kb() check and actual upload",
    "description": "file_size_kb() opens the file to seek to end for size, then closes it. The actual upload happens later in submit_file(). Between these two operations, the file could grow beyond max_size_kb (e.g., an active log file). The upload would then send a file larger than the configured limit.",
    "impact": "Files larger than max_size_kb may be uploaded, potentially causing server-side rejection or consuming excessive bandwidth.",
    "suggestion": "This is an inherent TOCTOU race on a live filesystem. Document it as a known limitation. Optionally, re-check file size in the upload function before sending, or use the Content-Length from the actual bytes read.",
    "false_positive_risk": "low"
  },
  {
    "id": "F19",
    "severity": "MEDIUM",
    "location": "main() — signal handling",
    "title": "No signal handling — interrupted runs send no 'interrupted' collection marker (parity gap)",
    "description": "The other 8 collectors send an 'interrupted' collection marker with stats when receiving SIGINT/SIGTERM. This Lua script has no signal handling at all. When killed, it exits immediately without sending the end marker or interrupted marker, leaving the server-side collection in an unknown state.",
    "impact": "Server cannot distinguish between a completed collection and an interrupted one. Collections killed mid-run appear as 'begun but never ended' on the server.",
    "suggestion": "Document this as a known Lua 5.1 limitation (no native signal handling). Provide a shell wrapper that traps SIGINT/SIGTERM and calls the script with a flag, or use a trap in the calling shell. Add a note in the script header about this limitation.",
    "false_positive_risk": "low"
  },
  {
    "id": "F20",
    "severity": "MEDIUM",
    "location": "upload_with_wget() — wget --post-file with multipart",
    "title": "GNU wget --post-file does not set Content-Length, causing chunked transfer issues",
    "description": "GNU wget's --post-file sends the file contents but does not automatically set Content-Length (it uses chunked transfer encoding or relies on the server to handle it). The --header only sets Content-Type. Some HTTP/1.0 servers or simple Thunderstorm implementations may not handle chunked transfer encoding, causing upload failures. The body_len variable is calculated but never used in the wget upload.",
    "impact": "Upload failures on servers that require Content-Length for multipart uploads.",
    "suggestion": "Add --header='Content-Length: <body_len>' to the wget command. The body_len is already calculated by build_multipart_body() but unused in upload_with_wget().",
    "false_positive_risk": "medium"
  },
  {
    "id": "F21",
    "severity": "LOW",
    "location": "mktemp()",
    "title": "os.tmpname() on some systems returns a name without creating the file, creating a TOCTOU race",
    "description": "The code comments acknowledge this: 'os.tmpname may just return a name on some systems'. The workaround (opening and closing the file) is implemented. However, on systems where os.tmpname() returns a name in /tmp that doesn't exist yet, there's a brief window between the name generation and file creation where another process could create a file with the same name (symlink attack). On embedded systems this is very low risk but worth noting.",
    "impact": "Theoretical symlink attack on multi-user embedded systems. Very low practical risk.",
    "suggestion": "On Linux, prefer using mktemp shell command: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). Fall back to os.tmpname() if mktemp is unavailable.",
    "false_positive_risk": "high"
  },
  {
    "id": "F22",
    "severity": "LOW",
    "location": "log_msg() — console output",
    "title": "Console log output missing timestamp (inconsistency with file log)",
    "description": "File log entries include timestamp: '%s %s %s\\n' (ts, level, clean). Console (stderr) output only shows '[level] message' without timestamp. The other collectors consistently include timestamps in console output.",
    "impact": "Minor: harder to correlate console output with log file entries during debugging.",
    "suggestion": "Change console output to: io.stderr:write(string.format('[%s] [%s] %s\\n', ts, level, clean))",
    "false_positive_risk": "low"
  },
  {
    "id": "F23",
    "severity": "LOW",
    "location": "global scope",
    "title": "All variables are global — risk of accidental pollution and harder debugging",
    "description": "config, counters, EXCLUDE_PATHS, dynamic_excludes, temp_files, log_file_handle, and all functions are global. In Lua 5.1, this means any typo in a variable name silently creates a new global instead of erroring. On embedded systems with multiple Lua scripts, global pollution could cause subtle bugs if this script is require()'d.",
    "impact": "Accidental global variable creation from typos; potential conflicts if script is loaded as a module.",
    "suggestion": "Add 'local' declarations for module-level variables. At minimum, add a comment that this script is designed to be run standalone, not require()'d.",
    "false_positive_risk": "low"
  }
]
```