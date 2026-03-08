# Neuron-Loop Report — Iteration 3
Generated: 2026-03-08 12:26:05

## Tests: ✅ PASS

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 6 | T1 |
| sonnet | 19 | T1 |

## Triaged: 25 to fix, 0 skipped (from 25 raw findings, 25 unique)

### 🔧 1. [CRITICAL] Content-Length header sent to curl is redundant and may cause duplicate-header rejection
- **Location:** upload_with_curl / build_multipart_body
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In `upload_with_curl`, the code passes `-H 'Content-Length: N'` explicitly while also using `--data-binary @file`. curl already computes and sends Content-Length from the file size. Sending it twice causes curl to emit two `Content-Length` headers, which is a violation of RFC 7230 and causes many HTTP/1.1 servers (and proxies) to reject the request with 400 Bad Request or to treat it as a request-smuggling attempt.
- **Fix:** Remove the explicit `-H 'Content-Length: ...'` from the curl command. curl handles this automatically when `--data-binary @file` is used.

### 🔧 2. [CRITICAL] Boundary collision check reads file into memory — can OOM on embedded systems for files up to 64 KB
- **Location:** build_multipart_body / boundary collision check
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The collision check does `src_f:read('*a')` for files up to 65536 bytes. On a 2 MB RAM embedded device this is acceptable for 64 KB, but the real problem is that after the collision check the file is read *again* in the streaming loop. So for files at the 64 KB boundary the file content is held in memory twice simultaneously (once in `sample`, once in the chunk buffer). More importantly, `sample` is a Lua string that stays alive until GC collects it — on Lua 5.1 with no incremental GC tuning thi
- **Fix:** For the collision check, read the file in chunks and search for the boundary incrementally rather than loading the whole file. For boundary uniqueness, combine `os.time()`, `math.random`, and a per-call counter.

### 🔧 3. [HIGH] Files exactly at max-age boundary are incorrectly excluded
- **Location:** build_find_command / age filter construction
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The code claims to use minute-granularity filtering so files exactly at the configured age limit are included, but it builds the command with `-mmin -%d`. In `find`, `-mmin -N` means strictly less than N minutes old, so a file exactly N minutes old is still excluded. This contradicts the stated hardening goal and can skip borderline files that should be collected.
- **Fix:** Adjust the predicate to include the boundary explicitly, e.g. use a range such as `-mmin -<N+1>` if acceptable for BusyBox/GNU portability, or switch to a shell-side timestamp comparison approach that includes equality. At minimum, fix the comment because the current implementation does not provide the promised behavior.

### 🔧 4. [HIGH] nc marker transport treats successful HTTP responses as failures
- **Location:** send_collection_marker / nc branch
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** Unlike `upload_with_nc`, the `send_collection_marker` nc path checks `exec_ok(nc_cmd)` and logs failure if netcat exits non-zero. On BusyBox/OpenBSD netcat variants, a non-zero exit can still occur even when a complete HTTP response was received. The file upload nc backend already avoids trusting the exit code and validates the response body instead, but the marker path does not. This can cause begin/end markers to be reported as failed even when the server accepted them.
- **Fix:** Mirror the logic used in `upload_with_nc`: ignore the raw `nc` exit status, read the response file, validate the HTTP status line/body, and only then decide success/failure.

### 🔧 5. [HIGH] BusyBox wget fallback is bypassed for collection markers
- **Location:** send_collection_marker / tool fallback selection
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** When `config.upload_tool` is empty, marker sending falls back by probing `curl`, then any `wget`, then `nc`. If only BusyBox wget is installed, this path sets `tool = "wget"` and executes the GNU wget code path. Earlier in the script, upload tool detection distinguishes GNU wget from BusyBox wget because behavior differs materially. The marker fallback ignores that distinction, so marker delivery may use unsupported or incompatible wget options on minimal systems.
- **Fix:** Reuse `detect_upload_tool()` or at least apply the same `wget_is_busybox()` check in the fallback path so `tool` becomes `busybox-wget` when appropriate.

### 🔧 6. [HIGH] HTTP/2 response pattern is matched twice with overlapping regexes — one pattern is unreachable
- **Location:** upload_with_nc / response parsing
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc response check has three patterns:
1. `resp:match('HTTP/1%.%d 2%d%d')`
2. `resp:match('HTTP/2%.?%d? 2%d%d')`
3. `resp:match('HTTP/2 2%d%d')`
Pattern 2 already matches `HTTP/2 2xx` (since `%.?` makes the dot optional and `%d?` makes the digit optional), so pattern 3 is dead code. More importantly, nc is a raw TCP tool — it cannot speak TLS, so HTTP/2 (which requires ALPN/TLS in practice) will never be returned. The patterns are harmless but indicate copy-paste confusion. The real bug is th
- **Fix:** Simplify to: `if resp:match('HTTP/%d[%.%d]* 2%d%d') then return true end`. Remove the redundant third pattern.

### 🔧 7. [HIGH] nc marker Content-Length uses `#body` (UTF-8 character count) not byte count
- **Location:** send_collection_marker / nc branch
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In the nc branch of `send_collection_marker`, the Content-Length is set to `#body` where `body` is a Lua string. In Lua, `#` on a string returns the number of bytes, which is correct for ASCII. However, `json_escape` can emit `\uXXXX` sequences (6 bytes each) for control characters, and `config.source` or `VERSION` could theoretically contain multi-byte UTF-8 sequences. If the source name contains non-ASCII characters, `#body` still returns bytes (correct), but the `json_escape` function emits `
- **Fix:** In the nc branch, skip writing `body_file` and write `body` directly into the request file (as already done). Move the `body_file` creation inside the curl/wget branches only.

### 🔧 8. [HIGH] `io.popen` handle closed after `pcall` but `handle:lines()` iterator may leave handle open on error
- **Location:** scan_directory / handle:close()
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The code wraps `handle:lines()` iteration in `pcall`. If an error is thrown inside the loop body (e.g., from `submit_file`), `pcall` catches it and execution falls through to `handle:close()`. This is correct. However, `io.popen` in Lua 5.1 returns a file handle whose `lines()` iterator holds an internal reference. When `pcall` catches an error mid-iteration, the iterator is abandoned but the underlying pipe process may still be running (waiting for its stdout to be read). Calling `handle:close(
- **Fix:** Before closing, drain remaining output or use `os.execute` with a temp file instead of `io.popen` for the find command. Alternatively, document this as a known limitation.

### 🔧 9. [HIGH] `-mmin` with value 0 when `max_age=0` causes `find` to return no files or behave unexpectedly
- **Location:** build_find_command
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When `config.max_age = 0`, `max_age_min = 0 * 1440 = 0`, and the find command becomes `find ... -mmin -0 -print`. The predicate `-mmin -0` means "modified less than 0 minutes ago" which on GNU find matches nothing (no file can be modified in negative time). On BusyBox find the behavior may differ. The `validate_config` function only checks `max_age >= 0`, so 0 is allowed.
- **Fix:** Either reject `max_age = 0` in `validate_config` with a clear error, or treat 0 as "no age filter" (omit the `-mmin` clause entirely).

### 🔧 10. [HIGH] `exec_ok` mishandles Lua 5.2+ three-return-value case — false negatives possible
- **Location:** exec_ok
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In Lua 5.2+, `os.execute` returns `(true, 'exit', 0)` on success and `(false, 'exit', N)` or `(false, 'signal', N)` on failure. The current code checks `if a == false or a == nil then ... if b == 'exit' and c == 0 then return true end`. This means: if `a == false` (failure), it then checks if `b == 'exit' and c == 0` — but that combination (`false` + `exit` + `0`) should never occur in practice. The real issue is the ordering: `if a == true then return true` is checked first (correct for 5.2+ su
- **Fix:** Simplify: `if type(a) == 'boolean' then return a end; if type(a) == 'number' then return a == 0 end; return false`

### 🔧 11. [HIGH] scan_id is not URL-encoded before appending to api_endpoint
- **Location:** main / scan_id appended to api_endpoint
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The scan_id received from the server is appended to the API endpoint URL: `api_endpoint .. sep .. 'scan_id=' .. urlencode(scan_id)`. This uses `urlencode`, which is correct. However, `scan_id` is extracted from the JSON response via `resp:match('"scan_id"%s*:%s*"([^"]+)"')`. If the server returns a scan_id containing characters that are valid in JSON strings but not in URLs (e.g., spaces, `+`, `#`), `urlencode` will handle them. But if the scan_id contains a `"` (escaped in JSON as `\"`), the re
- **Fix:** Use a more robust JSON extraction that handles `\"` inside the value, or validate that the extracted scan_id matches an expected format (e.g., UUID pattern) before use.

### 🔧 12. [HIGH] nc backend does not handle chunked Transfer-Encoding or HTTP/1.1 persistent connections — response body may be empty
- **Location:** upload_with_nc
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc backend sends `Connection: close` which is correct for HTTP/1.1 to signal the server should close after responding. However, if the server responds with `Transfer-Encoding: chunked` (common for HTTP/1.1 servers), the response body read by nc will contain chunk-size headers interspersed with data. The code reads the first 4096 bytes and checks for `HTTP/x.x 2xx` in the status line — this part is fine. But the success check only looks at the status line, not the body, so chunked encoding do
- **Fix:** Add `Expect:` header set to empty string in the nc request to suppress 100-Continue: `req_f:write('Expect:\r\n')`. Or handle 100-Continue by skipping to the next HTTP response in the buffer.

### 🔧 13. [MEDIUM] Retry sleep command is shell-invoked without availability check
- **Location:** main / begin marker retry sleep
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script relies on `os.execute("sleep 2")` for begin-marker retry and backoff delays. On most BusyBox systems this exists, but the code treats these sleeps as unconditional and never checks whether the command is available or succeeded. This is inconsistent with the otherwise defensive runtime probing approach used for `timeout` and upload tools.
- **Fix:** Probe `sleep` once or tolerate failure explicitly, e.g. wrap it in a helper that ignores absence but logs at debug level. If portability is a concern, document the dependency clearly.

### 🔧 14. [MEDIUM] Interrupted collection marker is not implemented despite stated hardening baseline
- **Location:** main / signal handling parity gap
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The prompt states the other collectors send an `interrupted` collection marker with stats on SIGINT/SIGTERM. This Lua script only documents a shell-wrapper workaround in comments and does not provide an actual wrapper or integrated mechanism to emit the marker on interruption. Given Lua 5.1 limitations this is understandable, but it is still a real parity gap versus the hardened baseline.
- **Fix:** Ship a companion POSIX shell wrapper alongside the Lua script that traps INT/TERM, forwards termination to the Lua process, and sends the `interrupted` marker with current stats. If that is out of scope, document this as an explicit unsupported feature rather than implying parity.

### 🔧 15. [MEDIUM] find command failures after partial output are not detected
- **Location:** scan_directory / handle:close result ignored
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The code reads `find` output via `io.popen(...):lines()` and always calls `handle:close()`, but it ignores the close result. If `find` encounters an execution error after emitting some paths, or exits non-zero for another reason, the scan continues as if successful. The surrounding `pcall` only catches Lua iteration errors, not the subprocess exit status.
- **Fix:** Capture and evaluate the return value from `handle:close()` (or use a helper similar to `exec_ok` for popen-backed commands) and increment failure state / log a warning when `find` exits non-zero.

### 🔧 16. [MEDIUM] Mountpoint with trailing slash causes incorrect prefix matching in `is_excluded_path`
- **Location:** parse_proc_mounts
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** If `/proc/mounts` contains a mountpoint with a trailing slash (non-standard but possible), `decode_mounts_field` returns it as-is, e.g., `/mnt/nfs/`. Then `is_excluded_path` checks `path:sub(1, #p + 1) == p .. '/'` which becomes `path:sub(1, len+1) == '/mnt/nfs//'` — a double slash — which will never match a real path. The exact-match check `path == p` would match `/mnt/nfs/` but real paths never end with `/`.
- **Fix:** Strip trailing slashes from mountpoints after decoding: `mp = mp:gsub('/*$', '')`

### 🔧 17. [MEDIUM] Temp file for multipart body is registered in `temp_files` via `mktemp()` but body_file is never explicitly cleaned up between retries
- **Location:** build_multipart_body
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** Each call to `build_multipart_body` calls `mktemp()` which appends to `temp_files`. In `submit_file`, `build_multipart_body` is called once per retry attempt (up to `config.retries` times). Each call creates a new temp file. With 3 retries and 1000 files, this creates up to 3000 temp files that accumulate until `cleanup_temp_files()` at the end of `main()`. On embedded systems with small /tmp (e.g., tmpfs with 4MB), this can exhaust temp space mid-run.
- **Fix:** In `submit_file`, call `build_multipart_body` once before the retry loop and reuse the same body file across retries (the file content doesn't change between retries). Or explicitly remove the body temp file after each failed attempt.

### 🔧 18. [MEDIUM] `wget_is_busybox()` is called even when wget is not found, and its result is not cached
- **Location:** detect_upload_tool / wget_is_busybox
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `has_wget` is set to the result of `exec_ok('which wget ...')`. If `has_wget` is false, the code skips the `not wget_is_busybox()` check. But `wget_is_busybox()` itself calls `exec_capture('wget --version 2>&1')` which spawns a subprocess. If wget is not installed, this call will fail/return nil, and `wget_is_busybox()` returns `true` (conservative). The result is not cached, so if `detect_upload_tool()` is called multiple times (it is called twice in `main()`), `wget --version` is executed mult
- **Fix:** Cache the result of `wget_is_busybox()` in a module-level variable, similar to `has_timeout_cmd`.

### 🔧 19. [MEDIUM] Unused `body_len` variable from `build_multipart_body` — wrong function called for markers
- **Location:** send_collection_marker
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In `send_collection_marker`, the code does NOT call `build_multipart_body` — it builds the JSON body directly. This is correct. However, the `body_file` temp file is written and then used in curl/wget commands via `--data-binary @body_file` / `--post-file=body_file`. The `body_len` is computed as `#body` in the nc branch. This is consistent. The issue is that `body_file` is created unconditionally at the top of the function (before knowing which tool will be used), but in the nc branch the body 
- **Fix:** Create `body_file` only in the curl/wget branches.

### 🔧 20. [MEDIUM] Begin marker retry appends scan_id to endpoint even when scan_id is empty string from first attempt
- **Location:** main / begin marker retry logic
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** After the begin marker retry logic, the code checks `if scan_id ~= ''` before appending to the endpoint. This is correct. However, if the first attempt returns a non-empty scan_id but the second attempt (retry) returns empty, the code uses the scan_id from the retry (empty), discarding the potentially valid scan_id from the first attempt. The retry overwrites `scan_id` unconditionally: `scan_id = send_collection_marker(...)` (second call). If the first call succeeded and returned a scan_id, the 
- **Fix:** No change needed.

### 🔧 21. [MEDIUM] curl error file (`resp_file .. '.err'`) may collide with another temp file if resp_file path ends in a pattern that creates a valid existing path
- **Location:** upload_with_curl
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The error file is constructed as `resp_file .. '.err'`. `resp_file` is created by `mktemp()` which uses the system's mktemp utility (e.g., `/tmp/tmp.XXXXXX`). Appending `.err` gives `/tmp/tmp.XXXXXX.err`. This path is added to `temp_files` for cleanup. However, it is NOT created via `mktemp()` — it's just a derived name. If by coincidence `/tmp/tmp.XXXXXX.err` already exists (e.g., from a previous crashed run), curl will overwrite it. More importantly, if two concurrent instances of the script r
- **Fix:** Use `mktemp()` for the error file as well, rather than deriving it from `resp_file`.

### 🔧 22. [MEDIUM] Server hostname validation only checks for `/` but not for other injection characters
- **Location:** validate_config
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The server validation checks `config.server:find('/')` to prevent URL paths. However, a server value like `evil.com:8080@attacker.com` or `evil.com #comment` or `evil.com\nHost: injected` could still pass validation and be interpolated into shell commands via `shell_quote`. `shell_quote` wraps in single quotes and escapes internal single quotes, so shell injection is prevented. But a server with embedded newlines could break the HTTP `Host:` header in the nc backend. The nc backend writes `Host:
- **Fix:** Add validation: `if config.server:match('[%c%s]') then die('Server hostname contains invalid characters') end`

### 🔧 23. [MEDIUM] Prune clauses use `-o` (OR) without wrapping in parentheses — logical operator precedence may cause incorrect pruning
- **Location:** build_find_command
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command is built as: `find DIR (prune1 -o prune2 -o ... -o) -type f -mmin -N -print`. The prune string ends with ` -o ` and then `-type f` follows. In POSIX find, the expression is evaluated left-to-right with `-o` having lower precedence than implicit AND. The structure `(-path X -prune) -o (-path Y -prune) -o -type f -mmin -N -print` is the standard idiom and is correct — when a prune matches, it short-circuits and doesn't evaluate the right side. However, without explicit parentheses
- **Fix:** Wrap the prune clauses in escaped parentheses: `prune_str = '\\( ' .. table.concat(prune_parts, ' -o ') .. ' \\) -o '`

### 🔧 24. [LOW] Syslog `logger` command is called with `os.execute` (not `exec_ok`) — failures are silently ignored
- **Location:** log_msg / syslog branch
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The syslog branch calls `os.execute(...)` directly without checking the return value. If `logger` is not installed or fails, the failure is silently ignored. This is intentional for a best-effort logging path, but it's inconsistent with the rest of the codebase which uses `exec_ok` for subprocess calls.
- **Fix:** Either use `exec_ok` and log a one-time warning if it fails, or document that syslog failures are intentionally ignored.

### 🔧 25. [LOW] `detect_upload_tool()` called twice — once in the dry-run block and once implicitly via `detect_timeout_cmd` probe
- **Location:** main
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `detect_upload_tool()` is called in the `if not config.dry_run` block and also in the `else` block. Then `detect_timeout_cmd()` is called separately. The upload tool detection involves spawning `which curl`, `which wget`, `wget --version`, `which nc` subprocesses. Calling it twice (in the dry-run else branch) means these subprocesses run twice. The result is not cached in a module-level variable.
- **Fix:** Call `detect_upload_tool()` once before the dry-run check and store the result.
