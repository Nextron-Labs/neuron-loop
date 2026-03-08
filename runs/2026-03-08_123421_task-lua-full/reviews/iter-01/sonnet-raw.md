```json
[
  {
    "id": "F1",
    "severity": "CRITICAL",
    "location": "die() / main()",
    "title": "Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures",
    "description": "The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine but some uploads failed' (should be 1) and 'could not start at all' (should be 2), and a clean run with zero failures should exit 0.",
    "impact": "Callers and orchestration scripts that rely on exit codes to detect partial vs fatal failures will misinterpret results. A run where every file upload failed silently exits 0.",
    "suggestion": "Change die() to call os.exit(2). At the end of main(), add: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "CRITICAL",
    "location": "upload_with_curl() ~line 290",
    "title": "Shell injection via unsanitized filepath in curl --form argument",
    "description": "The curl --form value is constructed as: string.format('file=@%s;filename=\"%s\"', filepath, safe_name). The filepath is passed through shell_quote() at the outer level, but the inner string.format embeds filepath directly before shell_quote wraps the whole thing. If filepath contains a double-quote or semicolon (e.g. /tmp/evil\";type=text/html), the curl --form parsing can be manipulated. More critically, the filepath is not sanitized before being embedded inside the single-quoted shell_quote wrapper — a filepath containing a single quote would break out of the quoting even after shell_quote, because shell_quote only escapes the outer quotes, not the inner format string content.",
    "description": "shell_quote wraps the entire --form value, but the filepath is interpolated raw into the format string before shell_quote sees it. A filename like /tmp/a'b would produce --form 'file=@/tmp/a'\"'\"'b;filename=...' which is correct for the outer shell quoting, BUT the curl --form parser itself sees the semicolon as a separator for curl options (e.g. ;type=...). A file at /tmp/evil;type=text/html would cause curl to set Content-Type to text/html instead of application/octet-stream, bypassing server-side type checks.",
    "impact": "Attacker-controlled filenames can manipulate the curl --form field type, potentially bypassing server-side content-type validation or causing unexpected behavior.",
    "suggestion": "Use curl's separate --form-string or pass filename via a separate -F field. Better: use the multipart body builder (build_multipart_body) for curl too, passing the body file with --data-binary @file and setting Content-Type header manually, eliminating the --form parsing issue entirely.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F3",
    "severity": "CRITICAL",
    "location": "build_multipart_body() ~line 250",
    "title": "Entire file content loaded into RAM — catastrophic on 2-16 MB embedded devices",
    "description": "build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file this means ~4 MB of peak RAM usage just for one file (original content + concatenated body). On a device with 4 MB total RAM this will cause OOM. The same issue exists in upload_with_nc() which reads the body_file again into memory via exec_capture.",
    "impact": "OOM crash or swap exhaustion on embedded targets with 2-16 MB RAM, which are the primary deployment targets.",
    "suggestion": "For the multipart body, write the headers directly to the temp file, then use shell-level concatenation (cat header_file file body_file > combined) or stream the file in chunks. For curl, use -F 'file=@filepath' directly (already done in upload_with_curl, so build_multipart_body is only needed for wget/nc). For nc, pipe the request: { printf 'POST ...\\r\\n...\\r\\n'; cat filepath; printf '\\r\\n--boundary--\\r\\n'; } | nc host port",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "send_collection_marker() ~line 340",
    "title": "begin-marker has no retry; a transient failure silently loses scan_id and all files are uploaded without association",
    "description": "The other 8 hardened collectors implement a single retry after 2 seconds on initial begin-marker failure. This script calls send_collection_marker() once with no retry. If the server is temporarily unavailable at startup, scan_id remains '' and all subsequent file uploads proceed without a scan_id, making them unassociated on the server side. There is no warning logged when scan_id comes back empty.",
    "impact": "All uploaded files are orphaned on the server with no collection context, making triage impossible. This is a silent failure.",
    "suggestion": "After the first send_collection_marker call returns '', sleep 2 seconds and retry once. Log a warning if scan_id is still '' after the retry.",
    "false_positive_risk": "low"
  },
  {
    "id": "F5",
    "severity": "HIGH",
    "location": "upload_with_nc() ~line 310",
    "title": "nc response captured via exec_capture (io.popen) loads entire HTTP response into RAM and loses binary safety",
    "description": "exec_capture() uses io.popen and read('*a') to capture nc's stdout. For large responses this wastes RAM. More importantly, io.popen on some BusyBox Lua builds is not binary-safe and may truncate at NUL bytes. The HTTP response from the server is text, so this is usually fine, but the real bug is that exec_capture runs 'cat file | nc ...' — the cat+pipe means the request body (which IS binary) is piped through the shell. On BusyBox, the pipe buffer may be limited and large files may stall.",
    "impact": "Uploads of binary files via nc may stall or fail silently on BusyBox systems with small pipe buffers.",
    "suggestion": "Use 'nc -w 30 host port < req_file > resp_file' and read resp_file afterward, avoiding the pipe entirely. This also eliminates the useless cat process.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F6",
    "severity": "HIGH",
    "location": "build_find_command() ~line 390",
    "title": "find -prune logic is incorrect — pruned paths are also printed as files",
    "description": "The generated find command is: find DIR (-path P1 -prune -o -path P2 -prune -o) -type f -mtime -N -print. The -prune action prevents descending but does NOT prevent the pruned directory itself from being printed if it matches -type f (it won't since it's a dir), but more importantly the -o (OR) chain means: if the path matches a prune pattern, prune it (and implicitly print nothing for that node due to -prune's false return), otherwise if it's a regular file modified within N days, print it. This is actually the standard idiom and is correct for directories. HOWEVER, if a pruned path is itself a file (e.g. EXCLUDE_PATHS contains a file path), -prune on a file is a no-op and the file will still be printed if it matches -type f -mtime. More critically: the prune_str ends with ' -o ' and then '-type f -mtime -N -print' follows. If prune_parts is empty, prune_str is '' and the command is correct. But if prune_parts is non-empty, the structure is: '( -path P -prune -o -path Q -prune -o ) -type f ...' — the trailing -o before -type f means: if none of the prune patterns matched, evaluate '-type f'. This is correct. But the issue is that -path matching uses shell glob patterns, and paths like /proc will not match /proc/net/foo because -path matches the full path. The correct idiom requires the prune pattern to be -path '/proc' OR -path '/proc/*'. Currently only -path '/proc' is used, so files directly under /proc (if any) would be excluded but /proc/net/foo would NOT be pruned — find would still try to descend into /proc.",
    "impact": "find will attempt to descend into /proc, /sys, /dev etc., causing hangs (reading from /proc/kmsg blocks), massive output, or errors on embedded systems.",
    "suggestion": "Change the prune pattern to match both the directory and its contents: string.format('\\( -path %s -o -path %s \\) -prune', shell_quote(p), shell_quote(p .. '/*')). Or use: -path 'P' -prune -o -path 'P/*' -prune",
    "false_positive_risk": "low"
  },
  {
    "id": "F7",
    "severity": "HIGH",
    "location": "sanitize_filename() ~line 95",
    "title": "Backslash escaping in gsub pattern is wrong — literal backslash in filename not sanitized",
    "description": "The pattern '[\"\\\\;]' in Lua is the string '[\"\\\\ ;]' after Lua string escape processing, which becomes the pattern character class containing: double-quote, backslash, semicolon. Wait — let's be precise: in Lua source, '[\"\\\\;]' — the \\\\ is two backslashes in source which Lua processes to one backslash, so the pattern is [\"\\ ;] which in Lua pattern syntax means: double-quote, backslash, semicolon. Actually this looks correct at first glance. BUT: Lua patterns use % as escape, not backslash. A backslash in a Lua pattern character class is treated as a literal backslash. So the pattern '[\"\\\\;]' with Lua string escaping gives pattern string [\"\\;] which matches double-quote, backslash, or semicolon. This IS correct. However, the real bug is that sanitize_filename is used to produce the filename in the Content-Disposition header, which is embedded in a double-quoted string. The sanitization replaces backslash with underscore, but does NOT handle other characters that are problematic in Content-Disposition filename fields, such as forward slashes (a filename from filepath:match('([^/]+)$') shouldn't have slashes, but the function itself accepts arbitrary input). More importantly, the function is also applied to the full filepath in upload_with_curl's --form value, where the safe_name is embedded inside double-quotes in the curl argument — a filename containing a double-quote would be replaced with underscore, which is correct, but a filename containing a percent sign would not be escaped and could confuse some parsers.",
    "impact": "Low direct impact since filenames are extracted from the last path component, but the function provides false security for arbitrary inputs.",
    "suggestion": "This is a minor issue; the function is adequate for its actual use case. Consider documenting its limitations.",
    "false_positive_risk": "high"
  },
  {
    "id": "F8",
    "severity": "HIGH",
    "location": "upload_with_wget() / send_collection_marker() ~line 295, 340",
    "title": "wget --post-data with shell_quote passes JSON/body as command-line argument — NUL bytes and very long bodies will fail",
    "description": "In send_collection_marker(), the JSON body is passed via --post-data=shell_quote(body). For wget, --post-data takes the data as a command-line argument. Command-line arguments on Linux are limited to ARG_MAX (typically 128KB-2MB) and cannot contain NUL bytes. For the collection marker this is fine (small JSON). But in upload_with_wget(), the multipart body is passed via --post-file which reads from a file — this is correct. However, the Content-Type header is passed via --header=shell_quote(...) which is also a command-line argument and is fine. The real issue in send_collection_marker is that if config.source contains special characters that survive json_escape but are problematic in shell context, shell_quote handles it. This is actually OK. The wget --post-data issue is real for large sources but the collection marker body is small.",
    "impact": "Low for collection markers. The wget upload path correctly uses --post-file.",
    "suggestion": "For send_collection_marker, write the JSON body to a temp file and use --post-file instead of --post-data to be consistent and avoid argument length limits.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F9",
    "severity": "HIGH",
    "location": "main() — no --ca-cert support",
    "title": "Missing --ca-cert option for custom CA bundle TLS validation",
    "description": "The other 8 hardened collectors all support --ca-cert PATH for TLS certificate validation with custom CA bundles. This script has --ssl and -k/--insecure but no --ca-cert. On embedded systems, the system CA bundle is often absent or outdated, making --ca-cert essential for secure HTTPS uploads to internal Thunderstorm servers with private CA certificates.",
    "impact": "Users must either use --insecure (disabling all TLS validation) or rely on a system CA bundle that may not exist on embedded targets. This is a security regression compared to all other collectors.",
    "suggestion": "Add config.ca_cert = '' and --ca-cert <path> CLI option. In upload_with_curl, add --cacert shell_quote(config.ca_cert) when ca_cert ~= ''. In upload_with_wget, add --ca-certificate=shell_quote(config.ca_cert). Document that nc does not support CA certs.",
    "false_positive_risk": "low"
  },
  {
    "id": "F10",
    "severity": "HIGH",
    "location": "scan_directory() / handle:close() ~line 420",
    "title": "io.popen handle for find is never checked for errors; find failures are silently ignored",
    "description": "handle:close() on an io.popen handle in Lua 5.2+ returns the exit status of the process, but in Lua 5.1 it always returns true. There is no check of find's exit status. More importantly, if find exits with an error (e.g., permission denied on the root scan dir itself), the loop simply processes zero lines with no error logged. The existing check 'if not handle' only catches the case where io.popen itself fails (extremely rare).",
    "impact": "Silent scan failures — the script reports 0 files scanned with no error, giving false confidence that the directory was clean.",
    "suggestion": "After handle:close(), check if files_scanned for this directory is still 0 and log a warning. Alternatively, redirect find's stderr to a temp file and check it after the loop.",
    "false_positive_risk": "low"
  },
  {
    "id": "F11",
    "severity": "HIGH",
    "location": "upload_with_curl() ~line 280",
    "title": "curl stderr and stdout redirected to same file (resp_file and resp_file.err overlap in cmd)",
    "description": "The curl command is: curl ... -o resp_file 2>resp_file.err. The response body goes to resp_file and stderr goes to resp_file.err. Then the code reads resp_file for the response body and resp_file.err for error messages. This is correct in isolation. However, resp_file.err is added to temp_files for cleanup, but resp_file itself is also in temp_files (added by mktemp()). The issue is that if curl fails AND writes a partial response to resp_file, the code returns false without checking resp_file — this is correct. But if curl succeeds (exit 0) but the server returns a JSON error body containing '\"reason\"', the code correctly detects it and returns false. This logic is sound. The actual bug: --fail causes curl to exit non-zero on HTTP 4xx/5xx, so the server rejection check (looking for '\"reason\"' in the body) is actually dead code for HTTP errors — curl will have already returned non-zero. The '\"reason\"' check only fires for HTTP 2xx responses that contain a reason field, which is an unusual server behavior. This is a logic issue but not a critical bug.",
    "impact": "Server-side soft rejections (HTTP 200 with error JSON) are handled, but this is an edge case. The dead code path for HTTP errors is harmless.",
    "suggestion": "Remove --fail from curl to always capture the response body, then check HTTP status from the response or use -w '%{http_code}' to get the status code separately.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F12",
    "severity": "MEDIUM",
    "location": "parse_proc_mounts() ~line 200",
    "title": "Mount point paths with spaces or escape sequences in /proc/mounts are not handled",
    "description": "/proc/mounts encodes spaces in paths as \\040 and other special characters with octal escapes (e.g., \\011 for tab). The current parser uses a simple %S+ pattern which will correctly read the encoded mountpoint string, but the resulting path stored in dynamic_excludes will contain the literal string '\\040' instead of a space. When this path is later compared against file paths returned by find (which use real spaces), the exclusion will never match.",
    "impact": "Network/special filesystems mounted at paths containing spaces will not be excluded, causing the collector to scan them.",
    "suggestion": "After extracting mp, decode octal escapes: mp = mp:gsub('\\\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end)",
    "false_positive_risk": "low"
  },
  {
    "id": "F13",
    "severity": "MEDIUM",
    "location": "mktemp() ~line 110",
    "title": "os.tmpname() race condition — TOCTOU between name generation and file creation",
    "description": "os.tmpname() returns a filename but does not create it atomically on all platforms. The subsequent io.open(path, 'wb') creates the file, but between tmpname() and open() another process could create a file with the same name (symlink attack or race). On Linux with glibc, os.tmpname() calls tmpnam() which is documented as insecure for this reason. On BusyBox Lua, behavior varies.",
    "impact": "On multi-user systems or systems with untrusted local users, a symlink placed at the temp path between tmpname() and open() could cause the script to write file contents to an attacker-controlled location.",
    "suggestion": "Use mktemp shell command: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). Fall back to os.tmpname() if mktemp is unavailable. This is atomic.",
    "false_positive_risk": "low"
  },
  {
    "id": "F14",
    "severity": "MEDIUM",
    "location": "log_msg() ~line 155",
    "title": "Syslog injection via unsanitized log message passed to shell",
    "description": "log_msg() passes the 'clean' message to logger via shell_quote(). shell_quote() correctly escapes single quotes, so shell injection is prevented. However, the message passed to logger can contain arbitrary content from file paths, server responses, etc. The logger command itself is safe due to shell_quote. BUT: the 'clean' variable only strips \\r and \\n — it does not strip other control characters (0x01-0x08, 0x0B-0x0C, 0x0E-0x1F) that could confuse syslog parsers or terminal emulators when written to stderr.",
    "impact": "Terminal escape sequence injection via maliciously named files (e.g., a file named with ESC[2J could clear the terminal when its path is logged).",
    "suggestion": "In log_msg, strip or replace all control characters before output: clean = message:gsub('[%c]', function(c) if c == '\\n' or c == '\\r' then return ' ' else return string.format('<0x%02x>', string.byte(c)) end end)",
    "false_positive_risk": "low"
  },
  {
    "id": "F15",
    "severity": "MEDIUM",
    "location": "main() — no --progress / --no-progress support",
    "title": "Missing progress reporting with TTY auto-detection",
    "description": "The other 8 hardened collectors implement --progress / --no-progress flags with TTY auto-detection. This script has no progress reporting at all. On long-running scans of large directories, there is no feedback to the operator about how many files have been processed.",
    "impact": "Operators cannot distinguish a hung script from a slow scan. On interactive terminals, no progress is shown.",
    "suggestion": "Add a progress counter that prints to stderr every N files (e.g., every 100) when stderr is a TTY. TTY detection in Lua 5.1 can be approximated by checking if 'tty -s 2>/dev/null' exits 0.",
    "false_positive_risk": "low"
  },
  {
    "id": "F16",
    "severity": "MEDIUM",
    "location": "upload_with_nc() ~line 315",
    "title": "HTTP/1.1 request without proper chunked encoding or exact Content-Length may fail with some servers",
    "description": "The nc upload builds an HTTP/1.1 request with Content-Length set to body_len (the multipart body size). This is correct. However, HTTP/1.1 servers may send a 100-Continue response before the client sends the body, and nc will not handle this — it just dumps the full request. Most HTTP/1.1 servers accept this for small requests, but some strict servers require the Expect: 100-continue handshake. Additionally, using HTTP/1.0 would be simpler and more compatible with nc (no persistent connection complications).",
    "impact": "Uploads via nc may fail against strict HTTP/1.1 servers that require Expect: 100-continue.",
    "suggestion": "Change the request to use HTTP/1.0 instead of HTTP/1.1, or add 'Expect: ' (empty) header to suppress 100-continue behavior.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F17",
    "severity": "MEDIUM",
    "location": "detect_source_name() ~line 230",
    "title": "Source name not JSON-escaped before use in collection markers",
    "description": "config.source is set from hostname output and used directly in send_collection_marker() via json_escape(config.source), which is correct. However, config.source is also appended to the API endpoint URL via urlencode(config.source), which is correct. The issue is in the log output: log_msg('info', 'Source: ' .. config.source) — if the hostname contains control characters or terminal escape sequences, this could cause terminal injection (covered by F14). Additionally, config.source set via --source CLI arg is not validated for length or character set.",
    "impact": "A very long source name could cause issues with URL length limits or HTTP header size limits.",
    "suggestion": "Truncate config.source to a reasonable length (e.g., 253 chars for a valid FQDN) and validate it contains only printable characters.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F18",
    "severity": "MEDIUM",
    "location": "submit_file() — exponential backoff ~line 370",
    "title": "Exponential backoff implementation is O(n) loop instead of bit shift — minor but incorrect for large retry counts",
    "description": "The backoff delay is computed as: local delay = 1; for _ = 2, attempt do delay = delay * 2 end. For attempt=1, the loop runs 0 times (2 to 1 is empty), giving delay=1. For attempt=2, loop runs once, delay=2. For attempt=3, delay=4. This is correct for small values. However, with config.retries=10 and attempt=9, delay=256 seconds — the script will stall for over 4 minutes on a single file. There is no cap on the backoff delay.",
    "impact": "With high retry counts, the script can stall for extremely long periods on a single file, making the overall scan take hours on embedded systems with limited time windows.",
    "suggestion": "Cap the backoff: local delay = math.min(30, 2^(attempt-1)) — but since Lua 5.1 has no ** operator, use: local delay = math.min(30, math.pow and math.pow(2, attempt-1) or (1 * (2^(attempt-1)))). Actually in Lua 5.1, ^ is the power operator: local delay = math.min(30, 2^(attempt-1))",
    "false_positive_risk": "low"
  },
  {
    "id": "F19",
    "severity": "MEDIUM",
    "location": "build_multipart_body() ~line 250",
    "title": "Boundary string could theoretically appear in file content, corrupting the multipart body",
    "description": "The multipart boundary is 'ThunderstormBoundary' + timestamp + random(10000,99999). If the file being uploaded happens to contain this exact byte sequence, the multipart parser on the server will incorrectly split the body. The probability is low but non-zero, especially since the boundary is predictable (based on os.time() which has 1-second resolution).",
    "impact": "Rare but possible corruption of uploaded file content, causing the server to receive a truncated or malformed file.",
    "suggestion": "Use a longer, more random boundary. Since Lua 5.1 has no crypto random, combine multiple math.random() calls and include a counter: boundary = 'ThunderstormBoundary' .. os.time() .. math.random(100000000, 999999999) .. math.random(100000000, 999999999). Also consider checking if the boundary appears in the content and regenerating if so.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F20",
    "severity": "LOW",
    "location": "main() — global variable namespace pollution",
    "title": "All variables are global — risk of accidental cross-contamination in embedded Lua environments",
    "description": "VERSION, config, counters, EXCLUDE_PATHS, dynamic_excludes, temp_files, log_file_handle, and all functions are defined in the global namespace. On some embedded Lua environments that run multiple scripts in the same interpreter instance, or if this script is require()'d, these globals will pollute the shared namespace.",
    "impact": "Low risk for a standalone script, but could cause issues if the script is ever embedded or if the Lua interpreter reuses state.",
    "suggestion": "Wrap everything in a local scope or use local variables where possible. At minimum, add 'local' to module-level variables that don't need to be global.",
    "false_positive_risk": "high"
  },
  {
    "id": "F21",
    "severity": "LOW",
    "location": "wget_is_busybox() ~line 215",
    "title": "wget --version may not be available on all BusyBox wget builds",
    "description": "BusyBox wget may not support --version and could print an error or return non-zero. The function uses exec_capture which captures both stdout and stderr (only stdout via io.popen). If BusyBox wget prints 'BusyBox' to stderr for --version, the check will fail to detect it.",
    "impact": "BusyBox wget may be misidentified as GNU wget, leading to use of GNU wget options that BusyBox wget doesn't support (e.g., --post-file may work, but other options may differ).",
    "suggestion": "Also check 'wget --help 2>&1' output, or use 'busybox wget --help 2>&1' as a fallback detection method.",
    "false_positive_risk": "medium"
  }
]
```