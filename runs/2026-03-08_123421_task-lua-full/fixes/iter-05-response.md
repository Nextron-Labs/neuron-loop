I'll analyze each finding carefully and provide precise fixes.

### Finding 1: FIXED

<<<SEARCH
    -- Note: find exits non-zero on permission errors even with 2>/dev/null.
    -- We increment files_failed to reflect partial scan in the exit code,
    -- but continue processing whatever results were returned.
    -- To capture find's exit status, wrap in sh -c and write status to a temp file.
    local status_file = mktemp()
    local status_cmd = string.format(
        "sh -c %s",
        shell_quote(string.format("(%s); echo $? >%s",
            cmd:gsub("2>/dev/null", ""), shell_quote(status_file))))
    -- We already ran the find via popen above; check exit status via a separate probe.
    -- Since popen already consumed the output, we check if find would have errors by
    -- re-running a lightweight existence check. Instead, track via ok flag from pcall.
    -- If pcall itself failed (scan_err set), files_failed already incremented above.
    -- For find permission errors (non-zero exit but output produced), log a debug note.
    os.remove(status_file)
end
>>>REPLACE
    -- Note: io.popen() in Lua 5.1 does not expose the child process exit status.
    -- Find permission errors (non-zero exit but output produced) are not detectable
    -- here. Use the shell wrapper described in the file header for exit-status-aware
    -- operation.
end
<<<END

### Finding 2: FIXED

<<<SEARCH
    local nc_timeout = math.max(30, 30 + math.floor(body_len / 10240))
>>>REPLACE
    local nc_timeout = math.min(300, math.max(30, 30 + math.floor(body_len / 10240)))
>>>REPLACE
    local nc_timeout = math.min(300, math.max(30, 30 + math.floor(body_len / 10240)))
<<<END

### Finding 3: FIXED

<<<SEARCH
    local cmd = build_find_command(dir)
    log_msg("debug", "find command: " .. cmd)

    local handle = io.popen(cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        counters.files_failed = counters.files_failed + 1
        return
    end
>>>REPLACE
    local cmd = build_find_command(dir)
    log_msg("debug", "find command: " .. cmd)

    -- Wrap find in sh -c to capture its exit status in a temp file.
    -- This allows us to detect permission errors and other non-zero exits.
    local find_status_file = mktemp()
    local wrapped_cmd = string.format("sh -c %s",
        shell_quote(cmd .. "; echo $? >" .. shell_quote(find_status_file)))
    local handle = io.popen(wrapped_cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        counters.files_failed = counters.files_failed + 1
        os.remove(find_status_file)
        -- Remove from temp_files tracking too
        for i = #temp_files, 1, -1 do
            if temp_files[i] == find_status_file then
                table.remove(temp_files, i)
                break
            end
        end
        return
    end
<<<END

<<<SEARCH
    handle:close()
    if not ok then
        log_msg("error", "Error during scan of '" .. dir .. "': " .. tostring(scan_err))
        counters.files_failed = counters.files_failed + 1
    end
    if show_progress and progress_counter > 0 then
>>>REPLACE
    handle:close()
    if not ok then
        log_msg("error", "Error during scan of '" .. dir .. "': " .. tostring(scan_err))
        counters.files_failed = counters.files_failed + 1
    end

    -- Read find's exit status from the temp file written by the sh -c wrapper
    local sf = io.open(find_status_file, "r")
    if sf then
        local status_str = sf:read("*l")
        sf:close()
        local find_exit = tonumber(trim(status_str or ""))
        if find_exit and find_exit ~= 0 then
            log_msg("warn", string.format(
                "find exited with status %d for '%s'; some files may have been skipped due to permission errors",
                find_exit, dir))
            counters.files_failed = counters.files_failed + 1
        end
    else
        log_msg("debug", "Could not read find exit status for '" .. dir .. "'")
    end
    -- Clean up the status file (remove from temp_files tracking)
    os.remove(find_status_file)
    for i = #temp_files, 1, -1 do
        if temp_files[i] == find_status_file then
            table.remove(temp_files, i)
            break
        end
    end

    if show_progress and progress_counter > 0 then
<<<END

### Finding 4: FIXED

<<<SEARCH
function send_collection_marker(base_url, marker_type, scan_id, stats_json)
>>>REPLACE
-- Returns: (success_bool, scan_id_string)
-- success_bool is true if the POST was sent and received a 2xx response (or any response for wget/nc)
-- scan_id_string is the scan_id extracted from the response, or "" if not found/not applicable
function send_collection_marker(base_url, marker_type, scan_id, stats_json)
<<<END

<<<SEARCH
    -- Extract scan_id from response.
    -- Only accept simple alphanumeric/UUID values to avoid using escaped JSON fragments.
    -- If the server returns a scan_id with special characters, it will be ignored safely.
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([A-Za-z0-9_%.%-]+)"')
        if id and id ~= "" then return id end
    end
    return ""
end
>>>REPLACE
    -- Extract scan_id from response.
    -- Only accept simple alphanumeric/UUID values to avoid using escaped JSON fragments.
    -- If the server returns a scan_id with special characters, it will be ignored safely.
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([A-Za-z0-9_%.%-%+%/%=]+)"')
        if id and id ~= "" then return true, id end
        -- Log if scan_id key is present but format was not recognized
        if resp:find('"scan_id"', 1, true) then
            log_msg("debug", "scan_id present in response but format not recognized")
        end
    end
    return (resp ~= nil), ""
end
<<<END

Now update all callers of `send_collection_marker` to handle the new return values:

<<<SEARCH
        scan_id = send_collection_marker(base_url, "begin", nil, nil)
        if scan_id == "" then
            log_msg("warn", "Begin marker failed; retrying in 2 seconds...")
            os.execute("sleep 2")
            scan_id = send_collection_marker(base_url, "begin", nil, nil)
            if scan_id == "" then
                log_msg("warn", "Begin marker retry also failed; proceeding without scan_id")
            end
        end
>>>REPLACE
        local begin_ok
        begin_ok, scan_id = send_collection_marker(base_url, "begin", nil, nil)
        if not begin_ok then
            log_msg("warn", "Begin marker failed; retrying in 2 seconds...")
            os.execute("sleep 2")
            begin_ok, scan_id = send_collection_marker(base_url, "begin", nil, nil)
            if not begin_ok then
                log_msg("warn", "Begin marker retry also failed; proceeding without scan_id")
            end
        end
<<<END

<<<SEARCH
        local end_id = send_collection_marker(base_url, "end", scan_id, stats)
        if end_id == "" and scan_id ~= "" then
            -- end marker failed (scan_id was known, so server should have accepted it)
            log_msg("warn", "End collection marker failed to send; collection state on server may be incomplete")
            counters.files_failed = counters.files_failed + 1
        end
>>>REPLACE
        local end_ok, end_id = send_collection_marker(base_url, "end", scan_id, stats)
        if not end_ok then
            -- end marker failed; collection state on server may be incomplete
            log_msg("warn", "End collection marker failed to send; collection state on server may be incomplete")
            counters.files_failed = counters.files_failed + 1
        end
<<<END

### Finding 5: FIXED

<<<SEARCH
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)
    -- Generate boundary and verify it does not appear in the file content
    local boundary
    local max_attempts = 5
    for attempt = 1, max_attempts do
        local candidate = _make_boundary()
        -- Check candidate does not appear in file
        local src_check = io.open(filepath, "rb")
        local collision = false
        if src_check then
            local needle1 = "\r\n--" .. candidate  -- mid-body and epilogue delimiter
            local needle2 = "--" .. candidate       -- opening delimiter (no leading \r\n)
            local overlap = math.max(#needle1, #needle2)
            local buf = ""
            local chunk_size = 8192
            while true do
                local chunk = src_check:read(chunk_size)
                if not chunk then break end
                local search_buf = buf .. chunk
                if search_buf:find(needle1, 1, true) or search_buf:find(needle2, 1, true) then
                    collision = true
                    break
                end
                -- Keep tail for overlap detection across chunks
                if #search_buf > overlap then
                    buf = search_buf:sub(-(overlap))
                else
                    buf = search_buf
                end
            end
            src_check:close()
        end
        if not collision then
            boundary = candidate
            break
        end
        log_msg("debug", "Boundary collision detected; regenerating (attempt " .. attempt .. ")")
    end
    if not boundary then
        log_msg("error", "Could not generate a collision-free boundary for '" .. filepath .. "'")
        return nil, nil, nil
    end

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
>>>REPLACE
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)

    -- Use a 128-bit random boundary from /dev/urandom.
    -- Collision probability is ~2^-128 per file byte, making a collision check
    -- unnecessary and avoiding the double-read TOCTOU issue.
    local boundary = _make_boundary()

    local preamble = "--" .. boundary .. "\r\n"
        .. string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n',
            safe_name)
        .. "Content-Type: application/octet-stream\r\n"
        .. "\r\n"
    local epilogue = "\r\n--" .. boundary .. "--\r\n"

    -- Open source file first; fail early if unreadable
    local src = io.open(filepath, "rb")
    if not src then
        log_msg("debug", "Cannot open source file for reading: '" .. filepath .. "'")
        return nil, nil, nil
    end

    -- Stream directly to temp file to avoid holding entire payload in memory
    local tmp = mktemp()
    local out = io.open(tmp, "wb")
    if not out then
        src:close()
        return nil, nil, nil
    end

    out:write(preamble)

    -- Stream source file in chunks (8 KB) to limit peak memory usage
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

### Finding 6: FIXED

<<<SEARCH
    if not exec_ok(cmd) then
        local err_f = io.open(err_file, "r")
        if err_f then
            local err_msg = err_f:read("*a")
            err_f:close()
            if err_msg and err_msg ~= "" then
                log_msg("warn", "curl error: " .. err_msg:gsub("[\r\n]", " "):sub(1, 200))
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
    local curl_ok = exec_ok(cmd)

    -- Always read response body (needed for server-side rejection detection and error logging)
    local resp_body = nil
    local resp_f = io.open(resp_file, "r")
    if resp_f then
        resp_body = resp_f:read("*a")
        resp_f:close()
    end

    if not curl_ok then
        local err_f = io.open(err_file, "r")
        if err_f then
            local err_msg = err_f:read("*a")
            err_f:close()
            if err_msg and err_msg ~= "" then
                log_msg("warn", "curl error: " .. err_msg:gsub("[\r\n]", " "):sub(1, 200))
            end
        end
        -- Also log response body if present (server may have returned an error message)
        if resp_body and resp_body ~= "" then
            log_msg("warn", "Server response on failure for '" .. filepath .. "': "
                .. resp_body:gsub("[\r\n]", " "):sub(1, 200))
        end
        return false
    end

    -- Check response body for server-side rejection
    if resp_body and resp_body:lower():find('"reason"', 1, true) then
        log_msg("error", "Server rejected '" .. filepath .. "': "
            .. resp_body:gsub("[\r\n]", " "):sub(1, 200))
        return false
    end

    return true
end
<<<END

### Finding 7: FIXED

This is addressed by Finding 1's fix (removing the dead status-checking block). No additional change needed.

### Finding 7: SKIPPED

Already handled by Finding 1's fix which removes the dead status-checking block entirely.

### Finding 8: FIXED

<<<SEARCH
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
        -- Fallback: use shell mktemp via sh if the standalone mktemp binary was not found.
        -- This avoids non-atomic io.open() creation which is vulnerable to symlink attacks.
        local result2 = exec_capture("sh -c 'mktemp /tmp/thunderstorm.XXXXXX 2>/dev/null'")
        if result2 then
            path = trim(result2)
        end
        if not path or path == "" then
            die("Cannot create temporary file: mktemp not available in /tmp; check permissions")
        end
    end
>>>REPLACE
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
        -- Fallback: use shell mktemp via sh if the standalone mktemp binary was not found
        -- but is accessible through sh's PATH (e.g., as a shell built-in on some systems).
        local result2 = exec_capture("sh -c 'mktemp /tmp/thunderstorm.XXXXXX 2>/dev/null'")
        if result2 then
            path = trim(result2)
        end
        if not path or path == "" then
            -- Pure-Lua fallback: generate a path using /dev/urandom.
            -- Accept the TOCTOU race as a last resort on systems without mktemp.
            local candidate = "/tmp/thunderstorm." .. _urandom_suffix()
            local f = io.open(candidate, "wb")
            if f then
                f:close()
                path = candidate
                log_msg("debug", "mktemp fallback: created temp file via io.open (TOCTOU risk)")
            else
                die("Cannot create temporary file: mktemp not found or /tmp not writable")
            end
        end
    end
<<<END

### Finding 9: FIXED

<<<SEARCH
    -- Check for HTTP 2xx success (anchored to start of response to avoid false matches in body)
    if resp:match("^HTTP/1%.%d 2%d%d") then return true end
>>>REPLACE
    -- Check for HTTP 2xx success. Use find() without anchor to tolerate any leading
    -- whitespace or blank lines that some embedded HTTP servers may prepend.
    if resp:find("HTTP/1[%.%d]+ 2%d%d", 1) then return true end
<<<END

### Finding 10: SKIPPED

The `-mtime -N` semantics are correct for the intended behavior. No fix needed.

### Finding 11: FIXED

<<<SEARCH
    -- Parse URL: http://host:port/path?query
    local hostpath = endpoint:match("^https?://(.+)$")
    if not hostpath then return false end

    local hostport = hostpath:match("^([^/]+)")
    local path_rest = hostpath:match("^[^/]+/(.*)$") or ""
    local path_query = "/" .. path_rest
>>>REPLACE
    -- Parse URL: http://host:port/path?query (supports IPv4, hostnames, and bracketed IPv6)
    local hostpath = endpoint:match("^https?://(.+)$")
    if not hostpath then return false end

    local hostport = hostpath:match("^([^/]+)")
    local path_rest = hostpath:match("^[^/]+/(.*)$") or ""
    local path_query = "/" .. path_rest
<<<END

<<<SEARCH
    local host = hostport:match("^([^:]+)")
    local port = hostport:match(":(%d+)$")
    if not port then
        if config.ssl then port = "443" else port = "80" end
    end
>>>REPLACE
    -- Parse host and port, handling bracketed IPv6 literals: [2001:db8::1]:8080
    local host, port
    local ipv6_host, ipv6_port = hostport:match("^%[(.-)%]:(%d+)$")
    if ipv6_host then
        host = ipv6_host
        port = ipv6_port
    else
        local ipv6_bare = hostport:match("^%[(.-)%]$")
        if ipv6_bare then
            host = ipv6_bare
            port = nil
        else
            host = hostport:match("^([^:]+)")
            port = hostport:match(":(%d+)$")
        end
    end
    if not port then
        if config.ssl then port = "443" else port = "80" end
    end
<<<END

Also fix the same parsing in `send_collection_marker`'s nc block:

<<<SEARCH
            local hostport = hostpath:match("^([^/]+)")
            local path_rest = hostpath:match("^[^/]+/(.*)$")
            local path_query = "/" .. (path_rest or "")
            local host = hostport:match("^([^:]+)")
            local port = hostport:match(":(%d+)$") or "80"
>>>REPLACE
            local hostport = hostpath:match("^([^/]+)")
            local path_rest = hostpath:match("^[^/]+/(.*)$")
            local path_query = "/" .. (path_rest or "")
            -- Handle bracketed IPv6 literals: [2001:db8::1]:8080
            local host, port
            local ipv6_h, ipv6_p = hostport:match("^%[(.-)%]:(%d+)$")
            if ipv6_h then
                host = ipv6_h; port = ipv6_p
            else
                local ipv6_bare = hostport:match("^%[(.-)%]$")
                if ipv6_bare then host = ipv6_bare; port = nil
                else host = hostport:match("^([^:]+)"); port = hostport:match(":(%d+)$") end
            end
            port = port or "80"
<<<END

### Finding 12: FIXED

<<<SEARCH
        if not config.ssl then
                tool = "nc"
            else
                log_msg("debug", "nc skipped for marker: does not support HTTPS")
            end
>>>REPLACE
        if not config.ssl then
                tool = "nc"
            else
                log_msg("warn", "nc cannot be used for HTTPS collection markers; install curl or wget for reliable marker delivery")
            end
<<<END

### Finding 13: SKIPPED

The backoff calculation is correct as analyzed. The finding itself concludes no change is needed.

### Finding 14: FIXED

<<<SEARCH
function sanitize_filename(s)
    if not s then return "" end
    -- Replace characters unsafe in Content-Disposition filename="..." header values:
    -- double-quote (would break the header), backslash (escape prefix), semicolon (param separator)
    local r = s:gsub('[";\\]', "_")
    -- Replace all control characters (0x00-0x1F, 0x7F) including \r, \n, \t, etc.
    r = r:gsub("%c", "_")
    r = r:gsub("\127", "_")
    return r
end
>>>REPLACE
function sanitize_filename(s)
    if not s then return "" end
    -- Replace characters unsafe in Content-Disposition filename="..." header values:
    -- double-quote (would break the header), backslash (escape prefix), semicolon (param separator)
    local r = s:gsub('[";\\]', "_")
    -- Replace NUL bytes explicitly (%z matches NUL in Lua 5.1); must be done before %c
    -- because %c behavior for NUL is implementation-defined in Lua 5.1
    r = r:gsub("%z", "_")
    -- Replace all control characters (0x01-0x1F, 0x7F) including \r, \n, \t, etc.
    r = r:gsub("%c", "_")
    r = r:gsub("\127", "_")
    return r
end
<<<END

### Finding 15: FIXED

Already addressed in Finding 4's fix (widened character class to include `+`, `/`, `=` for base64, and added debug log for unrecognized format).

### Finding 16: FIXED

<<<SEARCH
        -- Decode octal escape sequences used in /proc/mounts
            mp = mp:gsub("\\040", " ")
            mp = mp:gsub("\\011", "\t")
            mp = mp:gsub("\\012", "\n")
            mp = mp:gsub("\\134", "\\")
>>>REPLACE
        -- Decode octal escape sequences used in /proc/mounts (general decoder)
            mp = mp:gsub("\\(%d%d%d)", function(oct)
                return string.char(tonumber(oct, 8))
            end)
<<<END

### Finding 17: FIXED

<<<SEARCH
    local ca_cert_flag = ""
    if config.ca_cert and config.ca_cert ~= "" then
        ca_cert_flag = "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "
    end

    local cmd = string.format(
        "wget -q -O %s %s%s--header=%s --header=%s --post-file=%s %s 2>/dev/null",
>>>REPLACE
    local ca_cert_flag = ""
    if config.ca_cert and config.ca_cert ~= "" then
        -- Use space-separated form so shell_quote wraps only the path argument
        ca_cert_flag = "--ca-certificate " .. shell_quote(config.ca_cert) .. " "
    end

    local cmd = string.format(
        "wget -q -O %s %s%s--header=%s --header=%s --post-file=%s %s 2>/dev/null",
<<<END

Also fix the same issue in `send_collection_marker`'s wget block:

<<<SEARCH
        local ca_cert_flag = ""
        if config.ca_cert and config.ca_cert ~= "" then
            ca_cert_flag = "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "
        end
        -- Write body to temp file to avoid ARG_MAX limits and NUL issues
>>>REPLACE
        local ca_cert_flag = ""
        if config.ca_cert and config.ca_cert ~= "" then
            -- Use space-separated form so shell_quote wraps only the path argument
            ca_cert_flag = "--ca-certificate " .. shell_quote(config.ca_cert) .. " "
        end
        -- Write body to temp file to avoid ARG_MAX limits and NUL issues
<<<END

### Finding 18: FIXED

<<<SEARCH
            local sep = "&"
            if not api_endpoint:find("?") then sep = "?" end
            api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
>>>REPLACE
            local sep = "&"
            if not api_endpoint:find("?", 1, true) then sep = "?" end
            api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
<<<END

### Finding 19: SKIPPED

`syslog_facility` is hardcoded as `"user"` and not user-configurable via CLI. The shell_quote usage is correct. No fix needed.

### Finding 20: SKIPPED

On Linux (the target platform), binary and text mode are identical. The `total_body` calculation is correct. No fix needed.

### Finding 21: FIXED

<<<SEARCH
function detect_upload_tool()
    -- Priority: curl > GNU wget > nc > BusyBox wget
    if exec_ok("which curl >/dev/null 2>&1") then
        config.upload_tool = "curl"
        return true
    end

    local has_wget = exec_ok("which wget >/dev/null 2>&1")
    if has_wget and not wget_is_busybox() then
        config.upload_tool = "wget"
        return true
    end

    if exec_ok("which nc >/dev/null 2>&1") then
        if config.ssl then
            -- nc cannot perform TLS; do not select it for HTTPS
            log_msg("debug", "nc skipped: does not support HTTPS")
        else
            config.upload_tool = "nc"
            return true
        end
    end

    -- BusyBox wget as last resort
    if has_wget then
        config.upload_tool = "busybox-wget"
        log_msg("warn", "BusyBox wget detected; binary files with NUL bytes may fail to upload")
        return true
    end

    -- If SSL is required and only nc was found, it was skipped above; report failure
    if config.ssl and exec_ok("which nc >/dev/null 2>&1") then
        log_msg("warn", "nc is available but cannot be used for HTTPS; install curl or wget")
    end

    return false
end
>>>REPLACE
function detect_upload_tool()
    -- Priority: curl > GNU wget > nc > BusyBox wget
    if exec_ok("which curl >/dev/null 2>&1") then
        config.upload_tool = "curl"
        return true
    end

    local has_wget = exec_ok("which wget >/dev/null 2>&1")
    if has_wget and not wget_is_busybox() then
        config.upload_tool = "wget"
        return true
    end

    -- Cache nc availability to avoid two shell forks for the same check
    local has_nc = exec_ok("which nc >/dev/null 2>&1")
    if has_nc then
        if config.ssl then
            -- nc cannot perform TLS; do not select it for HTTPS
            log_msg("debug", "nc skipped: does not support HTTPS")
        else
            config.upload_tool = "nc"
            return true
        end
    end

    -- BusyBox wget as last resort
    if has_wget then
        config.upload_tool = "busybox-wget"
        log_msg("warn", "BusyBox wget detected; binary files with NUL bytes may fail to upload")
        return true
    end

    -- If SSL is required and only nc was found, it was skipped above; report failure
    if config.ssl and has_nc then
        log_msg("warn", "nc is available but cannot be used for HTTPS; install curl or wget")
    end

    return false
end
<<<END