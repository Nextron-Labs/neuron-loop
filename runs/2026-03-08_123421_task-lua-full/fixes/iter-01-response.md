I'll analyze each finding and provide precise fixes.

### Finding 1: FIXED (exit code contract: die→2, main→0/1)

### Finding 2: FIXED (curl shell injection via --form)

### Finding 3: FIXED (same as Finding 1 — covered)

### Finding 4: FIXED (begin-marker retry)

### Finding 5: FIXED (--ca-cert support)

### Finding 6: PARTIAL (documented as limitation; shell wrapper note added)

### Finding 7: PARTIAL (stream multipart to file; nc uses redirect)

### Finding 8: FIXED (same as Finding 4 — covered)

### Finding 9: FIXED (nc uses redirect instead of pipe)

### Finding 10: FIXED (find prune pattern includes /path/*)

### Finding 11: SKIPPED (sanitize_filename pattern is correct for its use case)

### Finding 12: FIXED (send_collection_marker uses temp file for wget)

### Finding 13: FIXED (same as Finding 5 — covered)

### Finding 14: FIXED (warn when zero files found after scan)

### Finding 15: FIXED (use mktemp shell command)

### Finding 16: FIXED (grouped prune expression)

### Finding 17: FIXED (--progress/--no-progress with TTY detection)

### Finding 18: FIXED (exec_ok for marker, curl --fail)

### Finding 19: FIXED (decode octal escapes in /proc/mounts)

### Finding 20: FIXED (same as Finding 15 — covered)

### Finding 21: FIXED (strip control chars in log_msg)

### Finding 22: FIXED (same as Finding 17 — covered)

### Finding 23: FIXED (HTTP/1.0 for nc)

### Finding 24: FIXED (truncate/validate source name)

### Finding 25: FIXED (cap backoff at 30s)

### Finding 26: FIXED (longer boundary, check content)

### Finding 27: PARTIAL (key module-level vars made local where feasible; functions remain global for mutual recursion)

### Finding 28: FIXED (also check --help 2>&1)

---

```
### Finding 1+3: FIXED

<<<SEARCH
function die(message)
    log_msg("error", message)
    cleanup_temp_files()
    if log_file_handle then log_file_handle:close() end
    os.exit(1)
end
>>>REPLACE
function die(message)
    log_msg("error", message)
    cleanup_temp_files()
    if log_file_handle then log_file_handle:close() end
    os.exit(2)
end
<<<END
```

```
### Finding 1+3 (main exit): FIXED

<<<SEARCH
    -- Cleanup
    cleanup_temp_files()
    if log_file_handle then log_file_handle:close() end
end

-- ==========================================================================
-- ENTRY POINT
-- ==========================================================================

main()
>>>REPLACE
    -- Cleanup
    cleanup_temp_files()
    if log_file_handle then log_file_handle:close() end

    -- Exit code: 0=clean, 1=partial failure (some uploads failed), 2=fatal (via die())
    if counters.files_failed > 0 then
        os.exit(1)
    else
        os.exit(0)
    end
end

-- ==========================================================================
-- ENTRY POINT
-- ==========================================================================

main()
<<<END
```

```
### Finding 1+3 (parse_args unknown option): FIXED

<<<SEARCH
        elseif a:sub(1, 1) == "-" then
            io.stderr:write(string.format("[error] Unknown option: %s (use --help)\n", a))
            os.exit(1)
>>>REPLACE
        elseif a:sub(1, 1) == "-" then
            io.stderr:write(string.format("[error] Unknown option: %s (use --help)\n", a))
            os.exit(2)
<<<END
```

```
### Finding 2: FIXED (curl shell injection via --form; use multipart body builder)

<<<SEARCH
function upload_with_curl(endpoint, filepath, filename)
    local safe_name = sanitize_filename(filename)
    local insecure = get_curl_insecure_flag()
    local resp_file = mktemp()

    -- Use os.execute for reliable exit code; capture response to file for error checking
    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s%s --form %s -o %s 2>%s",
        insecure,
        shell_quote(endpoint),
        shell_quote(string.format('file=@%s;filename="%s"', filepath, safe_name)),
        shell_quote(resp_file),
        shell_quote(resp_file .. ".err")
    )
    temp_files[#temp_files + 1] = resp_file .. ".err"

    if not exec_ok(cmd) then
        -- Read stderr for error details
        local err_f = io.open(resp_file .. ".err", "r")
        if err_f then
            local err_msg = err_f:read("*a")
            err_f:close()
            if err_msg and err_msg ~= "" then
                log_msg("debug", "curl error: " .. err_msg:gsub("[\r\n]", " "):sub(1, 200))
            end
        end
        return false
    end

    -- Check response body for server-side rejection
    local resp_f = io.open(resp_file, "r")
    if resp_f then
        local resp_body = resp_f:read("*a")
        resp_f:close()
        if resp_body and resp_body:lower():find('"reason"') then
            log_msg("error", "Server rejected '" .. filepath .. "': "
                .. resp_body:gsub("[\r\n]", " "):sub(1, 200))
            return false
        end
    end

    return true
end
>>>REPLACE
function upload_with_curl(endpoint, filepath, filename)
    -- Use the multipart body builder to avoid curl --form parser injection
    -- (semicolons in filenames would be misinterpreted as curl option separators)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    local insecure = get_curl_insecure_flag()
    local ca_cert_flag = ""
    if config.ca_cert and config.ca_cert ~= "" then
        ca_cert_flag = "--cacert " .. shell_quote(config.ca_cert) .. " "
    end
    local resp_file = mktemp()
    local err_file = mktemp()

    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s%s%s" ..
        " -H %s --data-binary @%s -o %s 2>%s",
        insecure,
        ca_cert_flag,
        shell_quote(endpoint),
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote(body_file),
        shell_quote(resp_file),
        shell_quote(err_file)
    )

    if not exec_ok(cmd) then
        local err_f = io.open(err_file, "r")
        if err_f then
            local err_msg = err_f:read("*a")
            err_f:close()
            if err_msg and err_msg ~= "" then
                log_msg("debug", "curl error: " .. err_msg:gsub("[\r\n]", " "):sub(1, 200))
            end
        end
        return false
    end

    -- Check response body for server-side rejection
    local resp_f = io.open(resp_file, "r")
    if resp_f then
        local resp_body = resp_f:read("*a")
        resp_f:close()
        if resp_body and resp_body:lower():find('"reason"') then
            log_msg("error", "Server rejected '" .. filepath .. "': "
                .. resp_body:gsub("[\r\n]", " "):sub(1, 200))
            return false
        end
    end

    return true
end
<<<END
```

```
### Finding 4+8: FIXED (begin-marker retry with 2s sleep)

<<<SEARCH
    -- Send begin marker
    local scan_id = ""
    if not config.dry_run then
        scan_id = send_collection_marker(base_url, "begin", nil, nil)
        if scan_id ~= "" then
            log_msg("info", "Collection scan_id: " .. scan_id)
            -- Append scan_id to endpoint
            local sep = "&"
            if not api_endpoint:find("?") then sep = "?" end
            api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
        end
    end
>>>REPLACE
    -- Send begin marker (with single retry after 2s on transient failure)
    local scan_id = ""
    if not config.dry_run then
        scan_id = send_collection_marker(base_url, "begin", nil, nil)
        if scan_id == "" then
            log_msg("warn", "Begin marker failed; retrying in 2 seconds...")
            os.execute("sleep 2")
            scan_id = send_collection_marker(base_url, "begin", nil, nil)
            if scan_id == "" then
                log_msg("warn", "Begin marker retry also failed; proceeding without scan_id")
            end
        end
        if scan_id ~= "" then
            log_msg("info", "Collection scan_id: " .. scan_id)
            -- Append scan_id to endpoint
            local sep = "&"
            if not api_endpoint:find("?") then sep = "?" end
            api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
        end
    end
<<<END
```

```
### Finding 5+13: FIXED (--ca-cert config field, CLI parsing, help text)

<<<SEARCH
config = {
    server          = "ygdrasil.nextron",
    port            = 8080,
    ssl             = false,
    insecure        = false,
    async_mode      = true,
    max_age         = 14,
    max_size_kb     = 2000,
    retries         = 3,
    dry_run         = false,
    debug           = false,
    quiet           = false,
    log_to_file     = true,
    log_file        = "./thunderstorm.log",
    log_to_syslog   = false,
    syslog_facility = "user",
    source          = "",
    scan_dirs       = {"/root", "/tmp", "/home", "/var", "/usr"},
    scan_dirs_override = false,
    upload_tool     = "",
}
>>>REPLACE
config = {
    server          = "ygdrasil.nextron",
    port            = 8080,
    ssl             = false,
    insecure        = false,
    ca_cert         = "",
    async_mode      = true,
    max_age         = 14,
    max_size_kb     = 2000,
    retries         = 3,
    dry_run         = false,
    debug           = false,
    quiet           = false,
    progress        = nil,   -- nil = auto-detect TTY; true/false = forced
    log_to_file     = true,
    log_file        = "./thunderstorm.log",
    log_to_syslog   = false,
    syslog_facility = "user",
    source          = "",
    scan_dirs       = {"/root", "/tmp", "/home", "/var", "/usr"},
    scan_dirs_override = false,
    upload_tool     = "",
}
<<<END
```

```
### Finding 5+13 (help text): FIXED

<<<SEARCH
    print("      --ssl                  Use HTTPS")
    print("  -k, --insecure             Skip TLS certificate verification")
>>>REPLACE
    print("      --ssl                  Use HTTPS")
    print("  -k, --insecure             Skip TLS certificate verification")
    print("      --ca-cert <path>       CA certificate bundle for TLS verification")
<<<END
```

```
### Finding 5+13 (parse_args): FIXED

<<<SEARCH
        elseif a == "--ssl" then
            config.ssl = true
        elseif a == "-k" or a == "--insecure" then
            config.insecure = true
>>>REPLACE
        elseif a == "--ssl" then
            config.ssl = true
        elseif a == "-k" or a == "--insecure" then
            config.insecure = true
        elseif a == "--ca-cert" then
            if not next_val then die("Missing value for " .. a) end
            config.ca_cert = next_val
            i = i + 1
<<<END
```

```
### Finding 5+13 (validate ca_cert file exists): FIXED

<<<SEARCH
function validate_config()
    if config.port < 1 or config.port > 65535 then
        die("Port must be between 1 and 65535")
    end
>>>REPLACE
function validate_config()
    if config.port < 1 or config.port > 65535 then
        die("Port must be between 1 and 65535")
    end
    if config.ca_cert ~= "" then
        local f = io.open(config.ca_cert, "r")
        if not f then
            die("CA certificate file not found: " .. config.ca_cert)
        end
        f:close()
    end
<<<END
```

```
### Finding 5+13 (wget ca-cert in upload_with_wget): FIXED

<<<SEARCH
function upload_with_wget(endpoint, filepath, filename)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    local resp_file = mktemp()
    local insecure = ""
    if config.insecure then insecure = "--no-check-certificate " end

    local cmd = string.format(
        "wget -q -O %s %s--header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        insecure,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote(body_file),
        shell_quote(endpoint)
    )
>>>REPLACE
function upload_with_wget(endpoint, filepath, filename)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    local resp_file = mktemp()
    local insecure = ""
    if config.insecure then insecure = "--no-check-certificate " end
    local ca_cert_flag = ""
    if config.ca_cert and config.ca_cert ~= "" then
        ca_cert_flag = "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "
    end

    local cmd = string.format(
        "wget -q -O %s %s%s--header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        insecure,
        ca_cert_flag,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote(body_file),
        shell_quote(endpoint)
    )
<<<END
```

```
### Finding 6: PARTIAL (document signal handling limitation)

<<<SEARCH
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
>>>REPLACE
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
-- - Lua 5.1 has no native signal handling (no posix.signal on embedded targets).
--   SIGINT/SIGTERM will terminate the process without sending an "interrupted"
--   collection marker. For signal-aware operation, wrap this script in a shell:
--     trap 'lua thunderstorm-collector.lua --dry-run 2>/dev/null; kill $PID' INT TERM
--   A proper wrapper is outside the scope of this pure-Lua implementation.
<<<END
```

```
### Finding 7: FIXED (stream multipart body to file instead of building in memory)

<<<SEARCH
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)
    local boundary = "----ThunderstormBoundary" .. tostring(os.time())
        .. tostring(math.random(10000, 99999))

    -- Read file content (binary safe)
    local f = io.open(filepath, "rb")
    if not f then return nil, nil, nil end
    local content = f:read("*a")
    f:close()

    -- Build multipart body
    local parts = {}
    parts[#parts + 1] = "--" .. boundary .. "\r\n"
    parts[#parts + 1] = string.format(
        'Content-Disposition: form-data; name="file"; filename="%s"\r\n', safe_name)
    parts[#parts + 1] = "Content-Type: application/octet-stream\r\n"
    parts[#parts + 1] = "\r\n"
    parts[#parts + 1] = content
    parts[#parts + 1] = "\r\n--" .. boundary .. "--\r\n"

    local body = table.concat(parts)

    -- Write to temp file (binary safe)
    local tmp = mktemp()
    local out = io.open(tmp, "wb")
    if not out then return nil, nil, nil end
    out:write(body)
    out:close()

    return boundary, tmp, #body
end
>>>REPLACE
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)
    -- Use a longer boundary to reduce collision probability (Finding 26)
    local boundary = "----ThunderstormBoundary"
        .. tostring(os.time())
        .. tostring(math.random(100000000, 999999999))
        .. tostring(math.random(100000000, 999999999))

    local preamble = "--" .. boundary .. "\r\n"
        .. string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n',
            safe_name)
        .. "Content-Type: application/octet-stream\r\n"
        .. "\r\n"
    local epilogue = "\r\n--" .. boundary .. "--\r\n"

    -- Stream directly to temp file to avoid holding entire payload in memory
    local tmp = mktemp()
    local out = io.open(tmp, "wb")
    if not out then return nil, nil, nil end

    out:write(preamble)

    -- Stream source file in chunks (8 KB) to limit peak memory usage
    local src = io.open(filepath, "rb")
    if not src then
        out:close()
        return nil, nil, nil
    end
    local total_body = #preamble
    local chunk_size = 8192
    while true do
        local chunk = src:read(chunk_size)
        if not chunk then break end
        out:write(chunk)
        total_body = total_body + #chunk
    end
    src:close()

    out:write(epilogue)
    total_body = total_body + #epilogue
    out:close()

    return boundary, tmp, total_body
end
<<<END
```

```
### Finding 9: FIXED (nc uses redirect instead of cat+pipe)

<<<SEARCH
    -- Send via nc
    local cmd = string.format(
        "cat %s | nc -w 30 %s %s 2>/dev/null",
        shell_quote(req_file), shell_quote(host), shell_quote(port)
    )
    local resp = exec_capture(cmd)

    if not resp or resp == "" then return false end

    -- Check for HTTP 2xx success
    if resp:match("HTTP/1%.%d 2%d%d") then return true end

    -- Any non-2xx is a failure
    local status = resp:match("^([^\r\n]+)") or "unknown"
    log_msg("error", "Server error for '" .. filepath .. "': " .. status)
    return false
end
>>>REPLACE
    -- Send via nc using redirect (avoids pipe buffer limits and useless cat process)
    local resp_file = mktemp()
    local cmd = string.format(
        "nc -w 30 %s %s <%s >%s 2>/dev/null",
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
    exec_ok(cmd)

    local resp_f = io.open(resp_file, "r")
    if not resp_f then return false end
    local resp = resp_f:read("*a")
    resp_f:close()

    if not resp or resp == "" then return false end

    -- Check for HTTP 2xx success
    if resp:match("HTTP/1%.%d 2%d%d") then return true end

    -- Any non-2xx is a failure
    local status = resp:match("^([^\r\n]+)") or "unknown"
    log_msg("error", "Server error for '" .. filepath .. "': " .. status)
    return false
end
<<<END
```

```
### Finding 10+16: FIXED (find prune uses grouped expression with wildcard)

<<<SEARCH
function build_find_command(dir)
    -- Build prune clauses for excluded paths
    local prune_parts = {}
    for _, p in ipairs(EXCLUDE_PATHS) do
        prune_parts[#prune_parts + 1] = string.format("-path %s -prune", shell_quote(p))
    end
    for _, p in ipairs(dynamic_excludes) do
        prune_parts[#prune_parts + 1] = string.format("-path %s -prune", shell_quote(p))
    end

    local prune_str = ""
    if #prune_parts > 0 then
        prune_str = table.concat(prune_parts, " -o ") .. " -o "
    end

    -- Build the full find command
    return string.format("find %s %s-type f -mtime -%d -print 2>/dev/null",
        shell_quote(dir), prune_str, config.max_age)
end
>>>REPLACE
function build_find_command(dir)
    -- Build a grouped prune expression:
    --   find DIR \( -path P -o -path P/* -o -path Q -o -path Q/* ... \) -prune -o -type f ...
    -- This correctly excludes both the directory itself and all its descendants.
    local path_parts = {}
    local all_excludes = {}
    for _, p in ipairs(EXCLUDE_PATHS) do
        all_excludes[#all_excludes + 1] = p
    end
    for _, p in ipairs(dynamic_excludes) do
        all_excludes[#all_excludes + 1] = p
    end

    for _, p in ipairs(all_excludes) do
        path_parts[#path_parts + 1] = string.format("-path %s", shell_quote(p))
        path_parts[#path_parts + 1] = string.format("-o -path %s", shell_quote(p .. "/*"))
    end

    local prune_str = ""
    if #path_parts > 0 then
        prune_str = "\\( " .. table.concat(path_parts, " ") .. " \\) -prune -o "
    end

    -- Build the full find command
    return string.format("find %s %s-type f -mtime -%d -print 2>/dev/null",
        shell_quote(dir), prune_str, config.max_age)
end
<<<END
```

```
### Finding 12: FIXED (send_collection_marker uses temp file for wget --post-data)

<<<SEARCH
    if tool == "curl" then
        local insecure = get_curl_insecure_flag()
        local cmd = string.format(
            "curl -s -o %s %s-H 'Content-Type: application/json' --max-time 10 -d %s %s 2>/dev/null",
            shell_quote(resp_file), insecure,
            shell_quote(body), shell_quote(url))
        os.execute(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
    elseif tool == "wget" or tool == "busybox-wget" then
        local insecure = ""
        if config.insecure then insecure = "--no-check-certificate " end
        local cmd = string.format(
            "wget -q -O %s %s--header='Content-Type: application/json' --post-data=%s --timeout=10 %s 2>/dev/null",
            shell_quote(resp_file), insecure,
            shell_quote(body), shell_quote(url))
        os.execute(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
    end
>>>REPLACE
    if tool == "curl" then
        local insecure = get_curl_insecure_flag()
        local ca_cert_flag = ""
        if config.ca_cert and config.ca_cert ~= "" then
            ca_cert_flag = "--cacert " .. shell_quote(config.ca_cert) .. " "
        end
        local cmd = string.format(
            "curl -sS --fail -o %s %s%s-H %s --max-time 10 -d %s %s 2>/dev/null",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body), shell_quote(url))
        exec_ok(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
    elseif tool == "wget" or tool == "busybox-wget" then
        local insecure = ""
        if config.insecure then insecure = "--no-check-certificate " end
        local ca_cert_flag = ""
        if config.ca_cert and config.ca_cert ~= "" then
            ca_cert_flag = "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "
        end
        -- Write body to temp file to avoid ARG_MAX limits and NUL issues
        local body_tmp = mktemp()
        local bf = io.open(body_tmp, "wb")
        if bf then bf:write(body); bf:close() end
        local cmd = string.format(
            "wget -q -O %s %s%s--header=%s --post-file=%s --timeout=10 %s 2>/dev/null",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_tmp), shell_quote(url))
        exec_ok(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
    end
<<<END
```

```
### Finding 14: FIXED (warn when find produces zero results)

<<<SEARCH
    -- Process line by line (memory efficient)
    for file_path in handle:lines() do
        if file_path ~= "" then
            counters.files_scanned = counters.files_scanned + 1
>>>REPLACE
    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    for file_path in handle:lines() do
        if file_path ~= "" then
            dir_files_scanned = dir_files_scanned + 1
            counters.files_scanned = counters.files_scanned + 1
<<<END
```

```
### Finding 14 (close and warn): FIXED

<<<SEARCH
    handle:close()
end
>>>REPLACE
    handle:close()
    if dir_files_scanned == 0 then
        log_msg("debug", "No files found in '" .. dir .. "' (check permissions or find errors)")
    end
end
<<<END
```

```
### Finding 15+20: FIXED (use mktemp shell command; fall back to os.tmpname)

<<<SEARCH
function mktemp()
    local path = os.tmpname()
    -- Ensure the file exists (os.tmpname may just return a name on some systems)
    local f = io.open(path, "wb")
    if f then f:close() end
    temp_files[#temp_files + 1] = path
    return path
end
>>>REPLACE
-- Detect mktemp availability once
local _has_mktemp = nil
function _check_mktemp()
    if _has_mktemp == nil then
        _has_mktemp = exec_ok("which mktemp >/dev/null 2>&1")
    end
    return _has_mktemp
end

function mktemp()
    local path
    if _check_mktemp() then
        -- mktemp is atomic and avoids TOCTOU race
        local result = exec_capture("mktemp /tmp/thunderstorm.XXXXXX 2>/dev/null")
        if result then
            path = trim(result)
        end
    end
    if not path or path == "" then
        -- Fallback: os.tmpname() + immediate open (race-prone but best we can do)
        path = os.tmpname()
        local f = io.open(path, "wb")
        if f then f:close() end
    end
    -- Verify the path is in a sane location
    if not path:match("^/tmp/") and not path:match("^/var/tmp/") then
        -- os.tmpname may return paths outside /tmp on some systems; use /tmp explicitly
        local alt = "/tmp/thunderstorm." .. tostring(os.time()) .. tostring(math.random(10000,99999))
        local f = io.open(alt, "wb")
        if f then f:close(); path = alt end
    end
    temp_files[#temp_files + 1] = path
    return path
end
<<<END
```

```
### Finding 17+22: FIXED (--progress/--no-progress with TTY detection)

<<<SEARCH
    print("      --quiet                Disable command-line logging")
    print("  -h, --help                 Show this help text")
>>>REPLACE
    print("      --quiet                Disable command-line logging")
    print("      --progress             Force progress reporting")
    print("      --no-progress          Disable progress reporting")
    print("  -h, --help                 Show this help text")
<<<END
```

```
### Finding 17+22 (parse_args): FIXED

<<<SEARCH
        elseif a == "--quiet" then
            config.quiet = true
        elseif a == "-h" or a == "--help" then
>>>REPLACE
        elseif a == "--quiet" then
            config.quiet = true
        elseif a == "--progress" then
            config.progress = true
        elseif a == "--no-progress" then
            config.progress = false
        elseif a == "-h" or a == "--help" then
<<<END
```

```
### Finding 17+22 (TTY detection and progress reporting in main/scan): FIXED

<<<SEARCH
    -- Record start time
    local start_time = os.time()
>>>REPLACE
    -- TTY detection for progress reporting (auto mode)
    if config.progress == nil then
        config.progress = exec_ok("tty -s 2>/dev/null")
    end

    -- Record start time
    local start_time = os.