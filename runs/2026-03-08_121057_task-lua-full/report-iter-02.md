# Neuron-Loop Report — Iteration 2
Generated: 2026-03-08 12:19:34

## Tests: ✅ PASS

## Review Summary
| Model | Findings | Tier |
|-------|----------|------|
| gpt54 | 6 | T1 |
| sonnet | 22 | T1 |

## Triaged: 28 to fix, 0 skipped (from 28 raw findings, 28 unique)

### 🔧 1. [CRITICAL] Shell injection via filepath in curl --form argument
- **Location:** upload_with_curl / build around line 330
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The curl command constructs the --form value as `file=@<filepath>;filename="<safe_name>"`. The `filepath` is wrapped in `shell_quote()` (single-quote escaping), but the entire string passed to `shell_quote()` is `string.format('file=@%s;filename="%s"', filepath, safe_name)`. The `filepath` is interpolated into the format string BEFORE shell_quote is applied to the whole thing. So if `filepath` contains a single-quote, the shell_quote wrapping of the outer string will be broken because `filepath`
- **Fix:** Use `shell_quote(filepath)` separately and pass it as a curl variable, or write the form spec to a temp file and use `--config`. Alternatively: `local form_val = 'file=@' .. filepath .. ';filename="' .. safe_name .. '"'` then pass `shell_quote(form_val)` — but this still embeds the raw filepath. The safest fix is to use curl's `-F` with a file reference written to a curl config file, or to use the multipart body builder (like wget/nc backends do) and pass `--data-binary @tmpfile` with explicit C

### 🔧 2. [CRITICAL] body_len calculation uses pre-read src_size but file may be re-read with different size
- **Location:** build_multipart_body / ~line 270
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The function reads `src_size = file_size_bytes(filepath)` (via seek), then for small files reads the entire content into `sample` for boundary checking, then opens the file AGAIN to stream it into the temp file. Between the size measurement and the second open, the file could change size (TOCTOU). More critically, the `body_len` is computed as `#header + src_size + #footer`, but the actual bytes written to the temp file may differ if the file changed. This causes an incorrect `Content-Length` he
- **Fix:** After streaming the file to the temp file, seek to end of the temp file to get the actual body size, then update body_len. Or: compute body_len from the actual temp file size after writing. Also, fix the boundary regeneration logic to regenerate `header` and `footer` after changing the boundary.

### 🔧 3. [CRITICAL] Boundary regenerated but header/footer not rebuilt with new boundary
- **Location:** build_multipart_body / boundary regeneration block ~line 285
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** When a boundary collision is detected in the file sample, the code regenerates `boundary` up to 5 times. However, `header` and `footer` are computed AFTER the boundary-check block, so they will use the final boundary value. But `body_len` is computed using `#header + src_size + #footer` which also comes after. So the header/footer/body_len are consistent with the final boundary. HOWEVER: for the large-file path (src_size > 65536), the boundary is regenerated unconditionally at the bottom of the 
- **Fix:** Restructure so boundary finalization happens before header/footer construction, with a clear comment.

### 🔧 4. [HIGH] os.execute success detection is wrong on many Lua 5.1 builds
- **Location:** exec_ok / utility function used throughout uploads and marker sending
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The helper assumes Lua 5.1 returns numeric 0 on success and Lua 5.2+ returns true. On many real Lua 5.1/5.1-derived environments, especially embedded builds, os.execute may return values that are not exactly 0/true (for example a platform-dependent status code, or multiple return values in patched runtimes). As written, successful commands can be treated as failures, breaking tool detection, CA file validation, directory checks, uploads, and marker delivery.
- **Fix:** Normalize os.execute handling more defensively. In Lua 5.1, treat both numeric 0 and true as success, and if multiple returns are available, accept true or an exit code of 0. A compatibility wrapper like `local a,b,c = os.execute(cmd); if a == true then return true elseif type(a) == 'number' then return a == 0 elseif b == 'exit' and c == 0 then return true else return false end` is safer.

### 🔧 5. [HIGH] nc backend is effectively broken due to double shell-quoting of host and port
- **Location:** upload_with_nc / command construction for timeout + sh -c
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The command passed to `sh -c` is built as `cat <req> | nc -w 30 'host' 'port'`, where `host` and `port` are already shell-quoted before being embedded into another shell command string that is itself shell-quoted. Those literal quote characters survive into the inner shell and become part of the arguments, so nc receives a hostname like `'example.com'` instead of `example.com`.
- **Fix:** Do not pre-quote host/port inside the inner command string. Quote only once at the shell boundary, or avoid `sh -c` entirely. For example, build the inner command as `string.format("cat %s | nc -w 30 %s %s", shell_quote(req_file), host, port)` and then shell-quote that whole string for `sh -c`, or better: `timeout 35 nc -w 30 ... < req_file > resp_file`.

### 🔧 6. [HIGH] Collection markers are never sent when nc is the selected upload tool
- **Location:** send_collection_marker / tool fallback logic
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The marker sender only implements curl and wget/busybox-wget branches. If runtime detection selected `nc`, `tool` remains `nc`, no upload branch executes, and the function silently returns an empty scan_id. That means begin/end markers are skipped on exactly the minimal environments where nc is chosen.
- **Fix:** Implement JSON POST via nc as a third backend, or explicitly fall back to curl/wget only if available and otherwise log a clear warning that markers are unsupported with nc. Given the stated target constraints, adding an nc JSON POST path is the correct fix.

### 🔧 7. [HIGH] Max-age filter is off by almost a full day
- **Location:** build_find_command / use of `-mtime -%d`
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The script interprets `--max-age <days>` as a day-based age limit, but uses `find -mtime -N`. In POSIX/GNU/BusyBox find semantics, `-mtime -14` means strictly less than 14*24 hours, not 'within the last 14 calendar days'. Files that are 14 days old plus a few minutes are excluded, even though users typically expect them to be included under a 14-day limit.
- **Fix:** Use minute granularity for an exact threshold, e.g. `-mmin -<days*1440>`, or document the strict `find` semantics clearly. If parity matters, match the behavior of the other collectors exactly.

### 🔧 8. [HIGH] nc command uses cat piped to nc, which may not work on all BusyBox nc variants; also no SSL support warning is insufficient
- **Location:** upload_with_nc / ~line 390
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The nc backend uses `cat <req_file> | nc -w 30 <host> <port>`. On some BusyBox nc implementations, `-w` sets the timeout for connection establishment only, not for the full transfer. More importantly, the response reading relies on nc closing after the server closes the connection (`Connection: close`), but some nc variants exit immediately after stdin closes without waiting for the server response. This means `resp` will often be empty, causing the function to return false even on successful up
- **Fix:** After writing the request, use `nc -w 30 host port < req_file > resp_file` (redirect, not pipe) which is more portable. Also consider using `timeout` around the entire nc invocation. The current code already uses timeout 35 but the inner nc -w 30 may not honor it on all implementations.

### 🔧 9. [HIGH] wget marker command uses single-quoted --header flag which breaks on some BusyBox wget
- **Location:** send_collection_marker / ~line 460
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The wget command for sending the collection marker uses `--header='Content-Type: application/json'` with single quotes embedded in the format string, not via shell_quote. The format string is: `"wget -q -O %s %s--header='Content-Type: application/json' --post-file=%s --timeout=10 %s"`. The single quotes here are literal characters in the Lua string, passed directly to `os.execute()` via a shell. This works in bash/sh but on some minimal BusyBox sh implementations the quoting may be interpreted d
- **Fix:** Use `shell_quote('Content-Type: application/json')` and pass it via `--header=` with proper quoting: `'--header=' .. shell_quote('Content-Type: application/json')`.

### 🔧 10. [HIGH] find prune logic is incorrect — -prune without -o -false causes find to print pruned dirs
- **Location:** build_find_command / ~line 510
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The find command is built as: `find <dir> ( -path X -prune -o -path X/* -prune -o ... ) -o -type f -mtime -N -print`. The prune_str ends with ` -o ` and then `-type f -mtime -N -print` follows. This means the full expression is: `(-path X -prune) -o (-path X/* -prune) -o ... -o (-type f -mtime -N -print)`. When a pruned directory matches, `-prune` returns true and the `-o` short-circuits, so the directory itself is NOT printed (because `-print` is only in the last clause). This is actually corre
- **Fix:** Test with BusyBox find. Consider using `-path 'X' -prune -o -path 'X/*' -prune` but also add a fallback: after getting each file path from find, do a prefix check in Lua against the exclude list as a second line of defense.

### 🔧 11. [HIGH] io.popen handle not closed on early return paths
- **Location:** scan_directory / ~line 545
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** In `scan_directory`, `handle = io.popen(cmd)` is opened, then a `pcall` wraps the iteration. If `handle:lines()` itself throws (which it can on some Lua implementations when the process has already exited), the pcall catches it and `handle:close()` is called after. This part is OK. However, if `exec_ok("test -d " .. shell_quote(dir))` returns false, the function returns early without ever opening a handle — that's fine. The real issue: `io.popen` on Lua 5.1 returns a file handle even if the comm
- **Fix:** N/A

### 🔧 12. [HIGH] scan_id appended to api_endpoint inside the directory loop causes double-appending on second iteration
- **Location:** main / scan_id append to api_endpoint ~line 610
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The scan_id is appended to `api_endpoint` once before the directory scan loop: `api_endpoint = api_endpoint .. sep .. 'scan_id=' .. urlencode(scan_id)`. This happens once, outside the loop, so it's fine — `api_endpoint` is modified once and then used for all directories. This is not a bug. Retracting.
- **Fix:** N/A

### 🔧 13. [HIGH] wget --post-file sends multipart body but wget may add its own Content-Length incorrectly
- **Location:** upload_with_wget / ~line 355
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** GNU wget with `--post-file` reads the file and sends it, but it computes Content-Length from the file size automatically. The script also adds an explicit `--header='Content-Length: N'` header. This results in a duplicate Content-Length header being sent (one from wget's automatic calculation, one from the explicit header). RFC 7230 says duplicate Content-Length headers with differing values are an error. If wget's auto-calculated size matches the manually computed `body_len`, there's no problem
- **Fix:** Remove the explicit `Content-Length` header from the wget command and rely on wget's automatic calculation, OR compute body_len from the actual temp file size after writing (which eliminates the TOCTOU issue for the temp file itself).

### 🔧 14. [HIGH] Mount point paths with spaces are not handled correctly
- **Location:** parse_proc_mounts / ~line 175
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The /proc/mounts parser uses `line:match("^(%S+)%s+(%S+)%s+(%S+)")` which splits on whitespace. Mount points with spaces in their names (encoded as `\040` in /proc/mounts) will be split incorrectly. The raw /proc/mounts format encodes spaces as `\040`, so the pattern would actually capture `\040` as part of the mount point string rather than splitting on it. However, the captured mount point string would then contain the literal `\040` escape sequence rather than a space, meaning the exclusion p
- **Fix:** After extracting `mp`, decode `\040` to space: `mp = mp:gsub('\\040', ' ')`. Also handle `\011` (tab) and `\012` (newline) for completeness.

### 🔧 15. [MEDIUM] Dynamic mount exclusions fail for escaped mountpoints in /proc/mounts
- **Location:** parse_proc_mounts / parsing `/proc/mounts`
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** Mountpoints in `/proc/mounts` encode spaces and some special characters as escape sequences such as `\040`. The parser stores the raw escaped text into `dynamic_excludes`, but `find` emits real filesystem paths, so exclusion checks built from those mountpoints will not match actual paths containing spaces or escaped characters.
- **Fix:** Unescape mountpoint fields from `/proc/mounts` before storing them, at least handling `\040`, `\011`, `\012`, and `\\` per fstab/proc mount escaping rules.

### 🔧 16. [MEDIUM] nc backend depends on external `timeout` despite stated minimal-tool constraints
- **Location:** upload_with_nc / unconditional use of `timeout`
- **Models:** gpt54 (1 model)
- **Action:** fix
- **Details:** The nc uploader shells out to `timeout 35 ...`, but `timeout` is not one of the declared runtime requirements and is absent on many BusyBox deployments unless specifically enabled. If nc exists but timeout does not, the command fails and uploads never work.
- **Fix:** Probe for `timeout` before using it and fall back to plain `nc -w` if unavailable, or structure the command so nc's own timeout is sufficient. If an outer timeout is truly required, include it in documented prerequisites and detection logic.

### 🔧 17. [MEDIUM] Error and warn messages suppressed by --quiet flag
- **Location:** log_msg / ~line 130
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The `log_msg` function gates ALL console output (including `error` and `warn` level messages) behind `if not config.quiet`. The comment says 'errors always shown' but the code does not implement this — errors are suppressed in quiet mode just like info messages. This means fatal errors and warnings are silently swallowed when `--quiet` is used.
- **Fix:** Change the condition to: `if not config.quiet or level == 'error' or level == 'warn' then` to always show errors and warnings regardless of quiet mode.

### 🔧 18. [MEDIUM] Exponential backoff calculation is O(n) loop instead of bit shift, and produces wrong values
- **Location:** submit_file / exponential backoff ~line 430
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The backoff delay is computed as: `local delay = 1; for _ = 2, attempt do delay = delay * 2 end`. For attempt=1: loop runs 0 times (2 to 1 is empty), delay=1. For attempt=2: loop runs once, delay=2. For attempt=3: loop runs twice, delay=4. This gives delays of 1, 2, 4 seconds for attempts 1, 2, 3. The comment says '2^(attempt-1)' which matches. However, with default retries=3, the maximum delay is 4 seconds between attempt 2 and 3. This is fine functionally. The loop-based power calculation is j
- **Fix:** Use `math.pow(2, attempt-1)` or `2^(attempt-1)` (Lua supports `^` operator) for clarity: `local delay = math.floor(2^(attempt-1))`.

### 🔧 19. [MEDIUM] wget_is_busybox() spawns a subprocess and reads output but doesn't handle io.popen failure
- **Location:** detect_upload_tool / ~line 230
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `wget_is_busybox()` calls `exec_capture("wget --version 2>&1")`. If `io.popen` fails (returns nil), `exec_capture` returns nil, and `wget_is_busybox()` returns `true` (assumes BusyBox). This is the safe/conservative fallback. However, `exec_capture` itself doesn't handle the case where `handle:read("*a")` returns nil (possible if the process was killed). In that case it returns nil, and `wget_is_busybox()` correctly returns true. This is acceptable behavior. Minor issue: `wget --version` may not
- **Fix:** Also check for `wget -V` as an alternative version flag for completeness.

### 🔧 20. [MEDIUM] nc response check uses HTTP/1.x pattern but server may respond with HTTP/2 or malformed status
- **Location:** upload_with_nc / HTTP response parsing ~line 415
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The response success check is `resp:match("HTTP/1%.%d 2%d%d")`. This correctly matches HTTP/1.0 and HTTP/1.1 2xx responses. However, if the server sends HTTP/1.1 200 OK with a space before the status code (non-standard but seen in some embedded servers), or if the response is truncated (only 4096 bytes read), the match may fail. More practically: if the nc connection succeeds but the server sends a redirect (301/302), the upload is treated as a failure even though the file was received. This is 
- **Fix:** The pattern is reasonable. Consider also matching `HTTP/2 2` for HTTP/2 cleartext responses, though nc-based HTTP/2 is unlikely.

### 🔧 21. [MEDIUM] config.retries validation allows retries=0 to pass if --retries 0 is given
- **Location:** validate_config / ~line 205
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The validation checks `if config.retries <= 0 then die(...)`. The `is_integer` check only accepts `^%d+$` (digits only, no sign), so negative values are rejected at parse time. However, `--retries 0` passes `is_integer` (returns true for '0') and `tonumber('0') = 0`, which then fails the `<= 0` check and calls `die()`. So retries=0 is correctly rejected. This is fine. Not a real bug.
- **Fix:** N/A

### 🔧 22. [MEDIUM] Boundary collision check reads entire file into memory for files up to 64KB
- **Location:** build_multipart_body / small file boundary check ~line 278
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** For files up to 65536 bytes, the function reads the entire file content into `sample` (a Lua string) to check for boundary collisions. This is done in addition to the streaming copy that follows. So for small files, the file is read twice: once into memory for the boundary check, and once streamed to the temp file. On a system with 2MB RAM scanning many small files, this doubles memory pressure for the boundary check phase. The `sample` string is not explicitly freed (Lua GC will collect it even
- **Fix:** Either skip the boundary check entirely (the random boundary is sufficiently unique in practice) or do the boundary check during the streaming copy to avoid the double-read.

### 🔧 23. [MEDIUM] api_endpoint has scan_id appended with urlencode but scan_id from server may already be URL-safe
- **Location:** main / ~line 590
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The scan_id extracted from the server response via `resp:match('"scan_id"%s*:%s*"([^"]+)"')` could theoretically contain characters that need URL encoding (e.g., if the server returns a UUID with `+` or special chars, though UUIDs are URL-safe). The `urlencode(scan_id)` call handles this correctly. However, the `sep` logic checks `if not api_endpoint:find('?')` — but `api_endpoint` already has `?source=...` appended if source is non-empty. The `find('?')` check is correct. This is fine.
- **Fix:** N/A

### 🔧 24. [MEDIUM] curl response file and error file are registered in temp_files but resp_file itself is also registered via mktemp — double registration
- **Location:** upload_with_curl / ~line 330
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `resp_file = mktemp()` registers `resp_file` in `temp_files`. Then `temp_files[#temp_files + 1] = resp_file .. '.err'` manually adds the `.err` file. The `.err` file is never created via `mktemp()` so it won't be cleaned up unless the manual addition works. This is correct. However, if `upload_with_curl` is called multiple times (retries), a new `resp_file` and `.err` file are created each time and all are registered. With 3 retries across many files, this could accumulate many temp file entries
- **Fix:** Reuse a single resp_file per upload session (pass it in or create it once in submit_file), or clean up resp_file immediately after each upload attempt rather than deferring to cleanup_temp_files.

### 🔧 25. [LOW] sanitize_filename uses Lua pattern '["\\;]' which has incorrect escaping
- **Location:** sanitize_filename / ~line 85
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The pattern `'["\\;]'` in Lua: the `\\` in a Lua string literal is a single backslash `\`, so the character class is `["\ ;]` — double-quote, backslash, semicolon. This is the intended behavior (replace these three characters). However, the Lua pattern `["\;]` would also work since inside a character class `\` doesn't need escaping in Lua patterns (it's not a magic character there). The current code works correctly but is confusing.
- **Fix:** Add a comment: `-- character class: double-quote, backslash, semicolon` to clarify intent.

### 🔧 26. [LOW] nc is not used as a fallback for collection markers even though it's a supported upload tool
- **Location:** send_collection_marker / ~line 460
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** The `send_collection_marker` function only handles `curl`, `wget`, and `busybox-wget` upload tools. If `config.upload_tool == 'nc'`, the function silently does nothing (no marker is sent, empty string is returned). This means on nc-only systems, begin/end markers are never sent, and the server has no collection tracking.
- **Fix:** Add an `elseif tool == 'nc' then` branch that uses the nc backend to POST the JSON body, similar to `upload_with_nc` but for JSON content-type. Or at minimum, log a warning: `log_msg('warn', 'Collection markers not supported with nc upload tool')`.

### 🔧 27. [LOW] api_endpoint query string separator logic has off-by-one: scan_id separator check uses api_endpoint which already has ?source= but the check is correct
- **Location:** main / ~line 570
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** After appending `?source=...` to `api_endpoint`, the code checks `if not api_endpoint:find('?') then sep = '?' else sep = '&' end` before appending `scan_id`. Since `?source=` was already appended, `find('?')` returns non-nil and `sep = '&'` is used. This is correct. However, if `config.source == ''`, then `query_source = ''` and `api_endpoint` has no `?`. Then `sep = '?'` is used for scan_id. This is also correct. No bug here.
- **Fix:** N/A

### 🔧 28. [LOW] math.randomseed not called before math.random usage in build_multipart_body
- **Location:** global scope
- **Models:** sonnet (1 model)
- **Action:** fix
- **Details:** `build_multipart_body` uses `math.random(10000, 99999)` to generate boundary components. Without calling `math.randomseed()`, Lua 5.1 uses a fixed seed (implementation-defined, often 1), meaning the same sequence of random numbers is generated on every run. Combined with `os.time()` in the boundary, this provides some uniqueness, but if two processes start within the same second, they will generate identical boundaries.
- **Fix:** Add `math.randomseed(os.time())` near the top of `main()` before any `math.random()` calls.
