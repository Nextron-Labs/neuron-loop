# Neuron-Loop Report — Iteration 1
Generated: 2026-03-08 12:37:01

## Tests: ✅ PASS

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 9 | T1 |
| sonnet | 19 | T1 |

## Triaged: 28 to fix, 0 skipped (from 28 raw findings, 28 unique)

### 🔧 1. [CRITICAL] Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures
- **Location:** die() / main()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine but some uploads failed' (should be 1) and 'could not start at all' (should be 2), and a clean run with zero failures should exit 0.
- **Fix:** Change die() to call os.exit(2). At the end of main(), add: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end

### 🔧 2. [CRITICAL] Shell injection via unsanitized filepath in curl --form argument
- **Location:** upload_with_curl() ~line 290
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** shell_quote wraps the entire --form value, but the filepath is interpolated raw into the format string before shell_quote sees it. A filename like /tmp/a'b would produce --form 'file=@/tmp/a'"'"'b;filename=...' which is correct for the outer shell quoting, BUT the curl --form parser itself sees the semicolon as a separator for curl options (e.g. ;type=...). A file at /tmp/evil;type=text/html would cause curl to set Content-Type to text/html instead of application/octet-stream, bypassing server-s
- **Fix:** Use curl's separate --form-string or pass filename via a separate -F field. Better: use the multipart body builder (build_multipart_body) for curl too, passing the body file with --data-binary @file and setting Content-Type header manually, eliminating the --form parsing issue entirely.

### 🔧 3. [HIGH] Exit codes do not follow the documented collector contract
- **Location:** die / main / parse_args / validate_config
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script exits with status 1 for fatal configuration/runtime errors via die(), and main() never returns a non-zero status when uploads fail. The stated hardened behavior for sibling collectors is 0=clean, 1=partial failure, 2=fatal error. In this implementation, fatal errors are reported as 1, and runs with failed file uploads still exit 0 after printing the summary.
- **Fix:** Adopt the shared exit-code contract consistently: make die() use os.exit(2), and at the end of main() exit 1 when counters.files_failed > 0, else 0. Also ensure unknown-option and similar fatal parse failures use 2.

### 🔧 4. [HIGH] Begin-marker retry hardening is missing
- **Location:** main / send_collection_marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script sends the initial "begin" collection marker only once. The prompt explicitly states the other collectors were hardened with a single retry after 2 seconds on initial begin-marker failure. Here, if the first marker request fails transiently, the run proceeds without a scan_id and without retrying.
- **Fix:** Wrap the initial begin marker send in retry logic: if the first call returns an empty scan_id, sleep 2 seconds and retry once before continuing. Log the retry and final failure clearly.

### 🔧 5. [HIGH] --ca-cert support is missing despite required hardening parity
- **Location:** print_help / parse_args / upload_with_curl / upload_with_wget / send_collection_marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script supports --insecure but has no --ca-cert option and never passes a custom CA bundle to curl or wget. The prompt explicitly lists --ca-cert PATH as a hardened feature already implemented in the other collectors.
- **Fix:** Add a config.ca_cert field, parse --ca-cert PATH, validate the file exists, and pass it to curl (--cacert) and wget (--ca-certificate). Apply it to both file uploads and collection-marker requests.

### 🔧 6. [HIGH] No interruption handling means end/interrupted markers and cleanup are skipped on SIGINT/SIGTERM
- **Location:** main / overall process lifecycle
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The prompt requires signal handling parity, but this Lua 5.1 script has no mechanism to handle SIGINT/SIGTERM. The context explicitly notes native signal handling is unavailable and should use a shell-wrapper approach or be documented as a limitation. The current script neither implements a wrapper strategy nor emits an interrupted marker, and temp-file/log cleanup only happens on normal completion or die().
- **Fix:** At minimum, document this limitation clearly in help/output. Preferably provide a shell wrapper that traps INT/TERM, invokes the Lua collector, and sends an interrupted collection marker with current stats. If wrapper integration is out of scope, note the parity gap explicitly.

### 🔧 7. [HIGH] Multipart body construction loads entire file into memory, risking OOM on embedded targets
- **Location:** build_multipart_body / upload_with_wget / upload_with_nc
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** build_multipart_body() reads the full file into a Lua string, concatenates multipart headers and payload into another large string, then writes that combined body to a temp file. For files up to the configured 2000 KB limit, this can transiently require multiple copies of the payload in memory. upload_with_nc() then reads the generated body file fully again when appending it to the request file.
- **Fix:** Stream multipart construction directly to the output file instead of assembling the whole body in memory. For nc, write headers to req_file and then copy the source file in chunks. For wget, write multipart preamble, stream file content in chunks, then write epilogue. Avoid read('*a') for payloads.

### 🔧 8. [HIGH] begin-marker has no retry; a transient failure silently loses scan_id and all files are uploaded without association
- **Location:** send_collection_marker() ~line 340
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 hardened collectors implement a single retry after 2 seconds on initial begin-marker failure. This script calls send_collection_marker() once with no retry. If the server is temporarily unavailable at startup, scan_id remains '' and all subsequent file uploads proceed without a scan_id, making them unassociated on the server side. There is no warning logged when scan_id comes back empty.
- **Fix:** After the first send_collection_marker call returns '', sleep 2 seconds and retry once. Log a warning if scan_id is still '' after the retry.

### 🔧 9. [HIGH] nc response captured via exec_capture (io.popen) loads entire HTTP response into RAM and loses binary safety
- **Location:** upload_with_nc() ~line 310
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** exec_capture() uses io.popen and read('*a') to capture nc's stdout. For large responses this wastes RAM. More importantly, io.popen on some BusyBox Lua builds is not binary-safe and may truncate at NUL bytes. The HTTP response from the server is text, so this is usually fine, but the real bug is that exec_capture runs 'cat file | nc ...' — the cat+pipe means the request body (which IS binary) is piped through the shell. On BusyBox, the pipe buffer may be limited and large files may stall.
- **Fix:** Use 'nc -w 30 host port < req_file > resp_file' and read resp_file afterward, avoiding the pipe entirely. This also eliminates the useless cat process.

### 🔧 10. [HIGH] find -prune logic is incorrect — pruned paths are also printed as files
- **Location:** build_find_command() ~line 390
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The generated find command is: find DIR (-path P1 -prune -o -path P2 -prune -o) -type f -mtime -N -print. The -prune action prevents descending but does NOT prevent the pruned directory itself from being printed if it matches -type f (it won't since it's a dir), but more importantly the -o (OR) chain means: if the path matches a prune pattern, prune it (and implicitly print nothing for that node due to -prune's false return), otherwise if it's a regular file modified within N days, print it. Thi
- **Fix:** Change the prune pattern to match both the directory and its contents: string.format('\( -path %s -o -path %s \) -prune', shell_quote(p), shell_quote(p .. '/*')). Or use: -path 'P' -prune -o -path 'P/*' -prune

### 🔧 11. [HIGH] Backslash escaping in gsub pattern is wrong — literal backslash in filename not sanitized
- **Location:** sanitize_filename() ~line 95
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The pattern '["\\;]' in Lua is the string '["\\ ;]' after Lua string escape processing, which becomes the pattern character class containing: double-quote, backslash, semicolon. Wait — let's be precise: in Lua source, '["\\;]' — the \\ is two backslashes in source which Lua processes to one backslash, so the pattern is ["\ ;] which in Lua pattern syntax means: double-quote, backslash, semicolon. Actually this looks correct at first glance. BUT: Lua patterns use % as escape, not backslash. A back
- **Fix:** This is a minor issue; the function is adequate for its actual use case. Consider documenting its limitations.

### 🔧 12. [HIGH] wget --post-data with shell_quote passes JSON/body as command-line argument — NUL bytes and very long bodies will fail
- **Location:** upload_with_wget() / send_collection_marker() ~line 295, 340
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In send_collection_marker(), the JSON body is passed via --post-data=shell_quote(body). For wget, --post-data takes the data as a command-line argument. Command-line arguments on Linux are limited to ARG_MAX (typically 128KB-2MB) and cannot contain NUL bytes. For the collection marker this is fine (small JSON). But in upload_with_wget(), the multipart body is passed via --post-file which reads from a file — this is correct. However, the Content-Type header is passed via --header=shell_quote(...)
- **Fix:** For send_collection_marker, write the JSON body to a temp file and use --post-file instead of --post-data to be consistent and avoid argument length limits.

### 🔧 13. [HIGH] Missing --ca-cert option for custom CA bundle TLS validation
- **Location:** main() — no --ca-cert support
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 hardened collectors all support --ca-cert PATH for TLS certificate validation with custom CA bundles. This script has --ssl and -k/--insecure but no --ca-cert. On embedded systems, the system CA bundle is often absent or outdated, making --ca-cert essential for secure HTTPS uploads to internal Thunderstorm servers with private CA certificates.
- **Fix:** Add config.ca_cert = '' and --ca-cert <path> CLI option. In upload_with_curl, add --cacert shell_quote(config.ca_cert) when ca_cert ~= ''. In upload_with_wget, add --ca-certificate=shell_quote(config.ca_cert). Document that nc does not support CA certs.

### 🔧 14. [HIGH] io.popen handle for find is never checked for errors; find failures are silently ignored
- **Location:** scan_directory() / handle:close() ~line 420
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** handle:close() on an io.popen handle in Lua 5.2+ returns the exit status of the process, but in Lua 5.1 it always returns true. There is no check of find's exit status. More importantly, if find exits with an error (e.g., permission denied on the root scan dir itself), the loop simply processes zero lines with no error logged. The existing check 'if not handle' only catches the case where io.popen itself fails (extremely rare).
- **Fix:** After handle:close(), check if files_scanned for this directory is still 0 and log a warning. Alternatively, redirect find's stderr to a temp file and check it after the loop.

### 🔧 15. [MEDIUM] os.tmpname() is unsafe/unreliable on embedded Unix targets
- **Location:** mktemp
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** mktemp() uses os.tmpname() and then opens the returned path. On Unix-like systems, os.tmpname() is historically race-prone because it may return a predictable name that is created in a separate step. On some minimal environments it can also return unusable paths. This is especially problematic because the script stores upload bodies and server responses in temp files.
- **Fix:** Prefer invoking a shell mktemp utility when available (e.g. `mktemp /tmp/thunderstorm.XXXXXX`) and fall back carefully if absent. Open the file immediately after creation and verify it is a regular file in a trusted temp directory.

### 🔧 16. [MEDIUM] find pruning expression is malformed and may not exclude mounted/special paths reliably
- **Location:** build_find_command
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The generated command has the form `find <dir> <prunes> -type f -mtime -N -print`, where `<prunes>` expands to repeated `-path X -prune -o ...`. Without grouping parentheses around the prune expression, operator precedence can produce unintended evaluation, and excluded paths may still be traversed or matched inconsistently across find implementations.
- **Fix:** Build the command using grouped prune logic, e.g. `find DIR \( -path P1 -o -path P2 ... \) -prune -o -type f -mtime -N -print`. Keep shell quoting around each path.

### 🔧 17. [MEDIUM] Progress reporting options required for parity are missing
- **Location:** parse_args / print_help / overall CLI
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The hardened collectors are described as supporting TTY-aware progress reporting with --progress / --no-progress. This Lua script implements neither option nor any TTY detection logic.
- **Fix:** Add config.progress with auto-detection based on whether stdout/stderr is a TTY, parse --progress and --no-progress, and emit lightweight periodic progress updates without flooding logs.

### 🔧 18. [MEDIUM] Collection marker requests ignore transport failures and HTTP error status
- **Location:** send_collection_marker
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** send_collection_marker() executes curl/wget but does not check the command exit status. It simply reads the response file if present and returns an extracted scan_id or empty string. For curl it also omits --fail, so HTTP 4xx/5xx can still produce a body and appear superficially successful. This makes marker delivery failures silent.
- **Fix:** Use exec_ok() for marker commands, add curl --fail/--show-error, and log failures explicitly. Consider checking for expected HTTP success semantics before parsing scan_id.

### 🔧 19. [MEDIUM] Mount point paths with spaces or escape sequences in /proc/mounts are not handled
- **Location:** parse_proc_mounts() ~line 200
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** /proc/mounts encodes spaces in paths as \040 and other special characters with octal escapes (e.g., \011 for tab). The current parser uses a simple %S+ pattern which will correctly read the encoded mountpoint string, but the resulting path stored in dynamic_excludes will contain the literal string '\040' instead of a space. When this path is later compared against file paths returned by find (which use real spaces), the exclusion will never match.
- **Fix:** After extracting mp, decode octal escapes: mp = mp:gsub('\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end)

### 🔧 20. [MEDIUM] os.tmpname() race condition — TOCTOU between name generation and file creation
- **Location:** mktemp() ~line 110
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** os.tmpname() returns a filename but does not create it atomically on all platforms. The subsequent io.open(path, 'wb') creates the file, but between tmpname() and open() another process could create a file with the same name (symlink attack or race). On Linux with glibc, os.tmpname() calls tmpnam() which is documented as insecure for this reason. On BusyBox Lua, behavior varies.
- **Fix:** Use mktemp shell command: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). Fall back to os.tmpname() if mktemp is unavailable. This is atomic.

### 🔧 21. [MEDIUM] Syslog injection via unsanitized log message passed to shell
- **Location:** log_msg() ~line 155
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** log_msg() passes the 'clean' message to logger via shell_quote(). shell_quote() correctly escapes single quotes, so shell injection is prevented. However, the message passed to logger can contain arbitrary content from file paths, server responses, etc. The logger command itself is safe due to shell_quote. BUT: the 'clean' variable only strips \r and \n — it does not strip other control characters (0x01-0x08, 0x0B-0x0C, 0x0E-0x1F) that could confuse syslog parsers or terminal emulators when writ
- **Fix:** In log_msg, strip or replace all control characters before output: clean = message:gsub('[%c]', function(c) if c == '\n' or c == '\r' then return ' ' else return string.format('<0x%02x>', string.byte(c)) end end)

### 🔧 22. [MEDIUM] Missing progress reporting with TTY auto-detection
- **Location:** main() — no --progress / --no-progress support
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The other 8 hardened collectors implement --progress / --no-progress flags with TTY auto-detection. This script has no progress reporting at all. On long-running scans of large directories, there is no feedback to the operator about how many files have been processed.
- **Fix:** Add a progress counter that prints to stderr every N files (e.g., every 100) when stderr is a TTY. TTY detection in Lua 5.1 can be approximated by checking if 'tty -s 2>/dev/null' exits 0.

### 🔧 23. [MEDIUM] HTTP/1.1 request without proper chunked encoding or exact Content-Length may fail with some servers
- **Location:** upload_with_nc() ~line 315
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc upload builds an HTTP/1.1 request with Content-Length set to body_len (the multipart body size). This is correct. However, HTTP/1.1 servers may send a 100-Continue response before the client sends the body, and nc will not handle this — it just dumps the full request. Most HTTP/1.1 servers accept this for small requests, but some strict servers require the Expect: 100-continue handshake. Additionally, using HTTP/1.0 would be simpler and more compatible with nc (no persistent connection co
- **Fix:** Change the request to use HTTP/1.0 instead of HTTP/1.1, or add 'Expect: ' (empty) header to suppress 100-continue behavior.

### 🔧 24. [MEDIUM] Source name not JSON-escaped before use in collection markers
- **Location:** detect_source_name() ~line 230
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** config.source is set from hostname output and used directly in send_collection_marker() via json_escape(config.source), which is correct. However, config.source is also appended to the API endpoint URL via urlencode(config.source), which is correct. The issue is in the log output: log_msg('info', 'Source: ' .. config.source) — if the hostname contains control characters or terminal escape sequences, this could cause terminal injection (covered by F14). Additionally, config.source set via --sourc
- **Fix:** Truncate config.source to a reasonable length (e.g., 253 chars for a valid FQDN) and validate it contains only printable characters.

### 🔧 25. [MEDIUM] Exponential backoff implementation is O(n) loop instead of bit shift — minor but incorrect for large retry counts
- **Location:** submit_file() — exponential backoff ~line 370
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The backoff delay is computed as: local delay = 1; for _ = 2, attempt do delay = delay * 2 end. For attempt=1, the loop runs 0 times (2 to 1 is empty), giving delay=1. For attempt=2, loop runs once, delay=2. For attempt=3, delay=4. This is correct for small values. However, with config.retries=10 and attempt=9, delay=256 seconds — the script will stall for over 4 minutes on a single file. There is no cap on the backoff delay.
- **Fix:** Cap the backoff: local delay = math.min(30, 2^(attempt-1)) — but since Lua 5.1 has no ** operator, use: local delay = math.min(30, math.pow and math.pow(2, attempt-1) or (1 * (2^(attempt-1)))). Actually in Lua 5.1, ^ is the power operator: local delay = math.min(30, 2^(attempt-1))

### 🔧 26. [MEDIUM] Boundary string could theoretically appear in file content, corrupting the multipart body
- **Location:** build_multipart_body() ~line 250
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The multipart boundary is 'ThunderstormBoundary' + timestamp + random(10000,99999). If the file being uploaded happens to contain this exact byte sequence, the multipart parser on the server will incorrectly split the body. The probability is low but non-zero, especially since the boundary is predictable (based on os.time() which has 1-second resolution).
- **Fix:** Use a longer, more random boundary. Since Lua 5.1 has no crypto random, combine multiple math.random() calls and include a counter: boundary = 'ThunderstormBoundary' .. os.time() .. math.random(100000000, 999999999) .. math.random(100000000, 999999999). Also consider checking if the boundary appears in the content and regenerating if so.

### 🔧 27. [LOW] All variables are global — risk of accidental cross-contamination in embedded Lua environments
- **Location:** main() — global variable namespace pollution
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** VERSION, config, counters, EXCLUDE_PATHS, dynamic_excludes, temp_files, log_file_handle, and all functions are defined in the global namespace. On some embedded Lua environments that run multiple scripts in the same interpreter instance, or if this script is require()'d, these globals will pollute the shared namespace.
- **Fix:** Wrap everything in a local scope or use local variables where possible. At minimum, add 'local' to module-level variables that don't need to be global.

### 🔧 28. [LOW] wget --version may not be available on all BusyBox wget builds
- **Location:** wget_is_busybox() ~line 215
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** BusyBox wget may not support --version and could print an error or return non-zero. The function uses exec_capture which captures both stdout and stderr (only stdout via io.popen). If BusyBox wget prints 'BusyBox' to stderr for --version, the check will fail to detect it.
- **Fix:** Also check 'wget --help 2>&1' output, or use 'busybox wget --help 2>&1' as a fallback detection method.
