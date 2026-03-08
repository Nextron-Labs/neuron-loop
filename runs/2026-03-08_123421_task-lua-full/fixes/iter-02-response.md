I'll analyze each finding carefully and provide precise fixes.

### Finding 1: FIXED

<<<SEARCH
    -- Append the body content
    local body_f = io.open(body_file, "rb")
    if body_f then
        req_f:write(body_f:read("*a"))
        body_f:close()
    end
>>>REPLACE
    -- Append the body content in chunks to avoid loading entire file into memory
    local body_f = io.open(body_file, "rb")
    if body_f then
        local chunk_size = 8192
        while true do
            local chunk = body_f:read(chunk_size)
            if not chunk then break end
            req_f:write(chunk)
        end
        body_f:close()
    end
<<<END

### Finding 2: SKIPPED
Reason: After careful analysis, Content-Length computation is correct. The temp file cleanup on error paths is handled by cleanup_temp_files() at exit. No actual bug to fix.

### Finding 3: FIXED

<<<SEARCH
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
>>>REPLACE
    if tool == "curl" then
        local insecure = get_curl_insecure_flag()
        local ca_cert_flag = ""
        if config.ca_cert and config.ca_cert ~= "" then
            ca_cert_flag = "--cacert " .. shell_quote(config.ca_cert) .. " "
        end
        -- Write body to temp file to avoid ARG_MAX limits
        local body_tmp = mktemp()
        local bf = io.open(body_tmp, "wb")
        if bf then bf:write(body); bf:close() end
        local cmd = string.format(
            "curl -sS --fail -o %s %s%s-H %s --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_tmp), shell_quote(url))
        exec_ok(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
<<<END

### Finding 4: FIXED

<<<SEARCH
    -- Banner
    print_banner()
>>>REPLACE
    -- Banner (suppressed in quiet mode)
    if not config.quiet then
        print_banner()
    end
<<<END

<<<SEARCH
    -- Print summary to stdout
    io.write(string.format(
        "Run completed: scanned=%d submitted=%d skipped=%d failed=%d seconds=%d\n",
        counters.files_scanned, counters.files_submitted,
        counters.files_skipped, counters.files_failed, elapsed))
>>>REPLACE
    -- Print summary to stderr (consistent with other collectors; honors --quiet via log_msg)
    if not config.quiet then
        io.stderr:write(string.format(
            "Run completed: scanned=%d submitted=%d skipped=%d failed=%d seconds=%d\n",
            counters.files_scanned, counters.files_submitted,
            counters.files_skipped, counters.files_failed, elapsed))
    end
<<<END

### Finding 5: FIXED

<<<SEARCH
    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    for file_path in handle:lines() do
>>>REPLACE
    -- Determine whether to show progress
    local show_progress = config.progress
    if show_progress == nil then
        -- Auto-detect: check if stderr is a TTY
        show_progress = exec_ok("test -t 2")
    end

    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    local progress_counter = 0
    for file_path in handle:lines() do
>>>REPLACE
    -- Determine whether to show progress
    local show_progress = config.progress
    if show_progress == nil then
        -- Auto-detect: check if stderr is a TTY
        show_progress = exec_ok("test -t 2")
    end

    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    local progress_counter = 0
    for file_path in handle:lines() do
<<<END

<<<SEARCH
        if file_path ~= "" then
            dir_files_scanned = dir_files_scanned + 1
            counters.files_scanned = counters.files_scanned + 1
>>>REPLACE
        if file_path ~= "" then
            dir_files_scanned = dir_files_scanned + 1
            counters.files_scanned = counters.files_scanned + 1
            progress_counter = progress_counter + 1
            if show_progress and (progress_counter % 100 == 0) then
                io.stderr:write(string.format("\r[progress] scanned=%d submitted=%d failed=%d",
                    counters.files_scanned, counters.files_submitted, counters.files_failed))
                io.stderr:flush()
            end
<<<END

<<<SEARCH
    handle:close()
    if dir_files_scanned == 0 then
>>>REPLACE
    handle:close()
    if show_progress and progress_counter > 0 then
        -- Clear progress line
        io.stderr:write("\r" .. string.rep(" ", 60) .. "\r")
        io.stderr:flush()
    end
    if dir_files_scanned == 0 then
<<<END

### Finding 6: FIXED

<<<SEARCH
    if exec_ok("which nc >/dev/null 2>&1") then
        config.upload_tool = "nc"
        if config.ssl then
            log_msg("warn", "nc (netcat) does not support HTTPS; uploads may fail")
        end
        return true
    end
>>>REPLACE
    if exec_ok("which nc >/dev/null 2>&1") then
        if config.ssl then
            -- nc cannot perform TLS; do not select it for HTTPS
            log_msg("debug", "nc skipped: does not support HTTPS")
        else
            config.upload_tool = "nc"
            return true
        end
    end
<<<END

<<<SEARCH
    -- BusyBox wget as last resort
    if has_wget then
        config.upload_tool = "busybox-wget"
        log_msg("warn", "BusyBox wget detected; binary files with NUL bytes may fail to upload")
        return true
    end

    return false
>>>REPLACE
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
<<<END

### Finding 7: FIXED

<<<SEARCH
    -- Use the already-detected upload tool; fall back to checking availability
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then tool = "wget"
        end
    end
>>>REPLACE
    -- Use the already-detected upload tool; fall back to checking availability
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then
            if wget_is_busybox() then tool = "busybox-wget"
            else tool = "wget" end
        end
    end
<<<END

### Finding 8: FIXED

<<<SEARCH
    if config.max_age < 0 then
        die("max-age must be >= 0")
    end
>>>REPLACE
    if config.max_age < 0 then
        die("max-age must be >= 0")
    end
    if config.max_age == 0 then
        log_msg("warn", "max-age=0 will match no files (find -mtime -0 matches nothing)")
    end
<<<END

### Finding 9: FIXED

<<<SEARCH
    -- Send via nc using redirect (avoids pipe buffer limits and useless cat process)
    local resp_file = mktemp()
    local cmd = string.format(
        "nc -w 30 %s %s <%s >%s 2>/dev/null",
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
>>>REPLACE
    -- Send via nc using redirect (avoids pipe buffer limits and useless cat process)
    -- Use -w 10 timeout; Connection: close header ensures server closes after response
    local resp_file = mktemp()
    local cmd = string.format(
        "nc -w 10 %s %s <%s >%s 2>/dev/null",
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
<<<END

### Finding 10: FIXED

<<<SEARCH
function sanitize_filename(s)
    if not s then return "" end
    local r = s:gsub('["%\\;]', "_")
    r = r:gsub("\r", "_")
    r = r:gsub("\n", "_")
    return r
end
>>>REPLACE
function sanitize_filename(s)
    if not s then return "" end
    local r = s:gsub('["%\\;]', "_")
    -- Replace all control characters (0x00-0x1F, 0x7F) including \r, \n, \t, etc.
    r = r:gsub("%c", "_")
    r = r:gsub("\127", "_")
    return r
end
<<<END

### Finding 11: FIXED (also covers Finding 18)

<<<SEARCH
    for line in f:lines() do
        -- /proc/mounts format: device mountpoint fstype options dump pass
        local _, mp, fstype = line:match("^(%S+)%s+(%S+)%s+(%S+)")
        if mp and fstype and fs_set[fstype] then
            dynamic_excludes[#dynamic_excludes + 1] = mp
        end
    end
>>>REPLACE
    for line in f:lines() do
        -- /proc/mounts format: device mountpoint fstype options dump pass
        -- Mountpoints encode spaces as \040 and tabs as \011
        local _, mp, fstype = line:match("^(%S+)%s+(%S+)%s+(%S+)")
        if mp and fstype and fs_set[fstype] then
            -- Decode octal escape sequences used in /proc/mounts
            mp = mp:gsub("\\040", " ")
            mp = mp:gsub("\\011", "\t")
            mp = mp:gsub("\\012", "\n")
            mp = mp:gsub("\\134", "\\")
            dynamic_excludes[#dynamic_excludes + 1] = mp
        end
    end
<<<END

### Finding 12: FIXED

<<<SEARCH
    -- Record start time
    local start_time = os.time()
>>>REPLACE
    -- Seed random number generator for temp file name generation
    math.randomseed(os.time() + math.floor(os.clock() * 1000000))

    -- Record start time
    local start_time = os.time()
<<<END

### Finding 13: FIXED

<<<SEARCH
    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    local progress_counter = 0
    for file_path in handle:lines() do
        if file_path ~= "" then
            dir_files_scanned = dir_files_scanned + 1
            counters.files_scanned = counters.files_scanned + 1
            progress_counter = progress_counter + 1
            if show_progress and (progress_counter % 100 == 0) then
                io.stderr:write(string.format("\r[progress] scanned=%d submitted=%d failed=%d",
                    counters.files_scanned, counters.files_submitted, counters.files_failed))
                io.stderr:flush()
            end

            -- Cloud path exclusion
            if is_cloud_path(file_path) then
                counters.files_skipped = counters.files_skipped + 1
                log_msg("debug", "Skipping cloud storage path '" .. file_path .. "'")
            else
                -- File size check
                local size_kb = file_size_kb(file_path)
                if size_kb < 0 then
                    counters.files_skipped = counters.files_skipped + 1
                    log_msg("debug", "Skipping unreadable file '" .. file_path .. "'")
                elseif size_kb > config.max_size_kb then
                    counters.files_skipped = counters.files_skipped + 1
                    log_msg("debug", string.format("Skipping '%s' due to size (%dKB)",
                        file_path, size_kb))
                else
                    -- Submit or dry-run
                    if config.dry_run then
                        log_msg("info", "DRY-RUN: would submit '" .. file_path .. "'")
                        counters.files_submitted = counters.files_submitted + 1
                    else
                        log_msg("debug", "Submitting '" .. file_path .. "'")
                        if submit_file(api_endpoint, file_path) then
                            counters.files_submitted = counters.files_submitted + 1
                        else
                            counters.files_failed = counters.files_failed + 1
                            log_msg("error", "Could not upload '" .. file_path .. "'")
                        end
                    end
                end
            end
        end
    end
    handle:close()
>>>REPLACE
    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    local progress_counter = 0
    local ok, scan_err = pcall(function()
      for file_path in handle:lines() do
        if file_path ~= "" then
            dir_files_scanned = dir_files_scanned + 1
            counters.files_scanned = counters.files_scanned + 1
            progress_counter = progress_counter + 1
            if show_progress and (progress_counter % 100 == 0) then
                io.stderr:write(string.format("\r[progress] scanned=%d submitted=%d failed=%d",
                    counters.files_scanned, counters.files_submitted, counters.files_failed))
                io.stderr:flush()
            end

            -- Cloud path exclusion
            if is_cloud_path(file_path) then
                counters.files_skipped = counters.files_skipped + 1
                log_msg("debug", "Skipping cloud storage path '" .. file_path .. "'")
            else
                -- File size check
                local size_kb = file_size_kb(file_path)
                if size_kb < 0 then
                    counters.files_skipped = counters.files_skipped + 1
                    log_msg("debug", "Skipping unreadable file '" .. file_path .. "'")
                elseif size_kb > config.max_size_kb then
                    counters.files_skipped = counters.files_skipped + 1
                    log_msg("debug", string.format("Skipping '%s' due to size (%dKB)",
                        file_path, size_kb))
                else
                    -- Submit or dry-run
                    if config.dry_run then
                        log_msg("info", "DRY-RUN: would submit '" .. file_path .. "'")
                        counters.files_submitted = counters.files_submitted + 1
                    else
                        log_msg("debug", "Submitting '" .. file_path .. "'")
                        if submit_file(api_endpoint, file_path) then
                            counters.files_submitted = counters.files_submitted + 1
                        else
                            counters.files_failed = counters.files_failed + 1
                            log_msg("error", "Could not upload '" .. file_path .. "'")
                        end
                    end
                end
            end
        end
      end
    end)
    handle:close()
    if not ok then
        log_msg("error", "Error during scan of '" .. dir .. "': " .. tostring(scan_err))
        counters.files_failed = counters.files_failed + 1
    end
<<<END

### Finding 14: FIXED

<<<SEARCH
    local cmd = string.format(
        "wget -q -O %s %s%s--header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        insecure,
        ca_cert_flag,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote(body_file),
        shell_quote(endpoint)
    )
>>>REPLACE
    local cmd = string.format(
        "wget -q -O %s %s%s--header=%s --header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        insecure,
        ca_cert_flag,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote("Content-Length: " .. tostring(body_len)),
        shell_quote(body_file),
        shell_quote(endpoint)
    )
<<<END

### Finding 15: SKIPPED
Reason: The mktemp binary is already preferred (checked first), and the fallback is documented as race-prone. Adding math.randomseed (Finding 12) improves the fallback. Requiring mktemp and aborting would break compatibility on minimal BusyBox systems where os.tmpname() is the only option. The existing approach with the documented limitation is acceptable for the target platform.

### Finding 16: SKIPPED
Reason: The `-mtime -N` semantics (N×24h periods) are standard POSIX find behavior and consistent with all other collector scripts. This is a documentation issue, not a code bug. The behavior is correct and expected.

### Finding 17: FIXED

<<<SEARCH
    local handle = io.popen(cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        return
    end
>>>REPLACE
    local handle = io.popen(cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        counters.files_failed = counters.files_failed + 1
        return
    end
<<<END

<<<SEARCH
    if show_progress and progress_counter > 0 then
        -- Clear progress line
        io.stderr:write("\r" .. string.rep(" ", 60) .. "\r")
        io.stderr:flush()
    end
    if dir_files_scanned == 0 then
        log_msg("debug", "No files found in '" .. dir .. "' (check permissions or find errors)")
    end
>>>REPLACE
    if show_progress and progress_counter > 0 then
        -- Clear progress line
        io.stderr:write("\r" .. string.rep(" ", 60) .. "\r")
        io.stderr:flush()
    end
    if dir_files_scanned == 0 then
        log_msg("debug", "No files found in '" .. dir .. "' (check permissions or find errors)")
    end
    -- Note: find exits non-zero on permission errors even with 2>/dev/null;
    -- we treat partial results as valid since permission noise is expected.
<<<END

### Finding 18: FIXED
Already covered by Finding 11 fix above (same location, same fix).

### Finding 19: SKIPPED
Reason: After analysis, shell_quote correctly handles all special characters including single quotes via the `'"'"'` technique. No actual injection risk exists.

### Finding 20: SKIPPED
Reason: After analysis, urlencode() protects URL construction and json_escape() protects JSON embedding. Adding a length check is defense-in-depth but not a bug fix. The finding itself concludes it is safe.

### Finding 21: FIXED
Already covered by Finding 5 fix above (progress reporting implemented in scan_directory).

### Finding 22: FIXED

<<<SEARCH
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
>>>REPLACE
    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s%s%s" ..
        " --connect-timeout 30 --max-time 120" ..
        " -H %s --data-binary @%s -o %s 2>%s",
        insecure,
        ca_cert_flag,
        shell_quote(endpoint),
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote(body_file),
        shell_quote(resp_file),
        shell_quote(err_file)
    )
<<<END

### Finding 23: FIXED

<<<SEARCH
    -- macOS cloud storage (/Library/CloudStorage/ or ending with /Library/CloudStorage)
    if lower:find("/library/cloudstorage/", 1, true) then return true end
    if lower:sub(-20) == "/library/cloudstorage" then return true end
>>>REPLACE
    -- macOS cloud storage (/Library/CloudStorage/ or ending with /Library/CloudStorage)
    if lower:find("/library/cloudstorage/", 1, true) then return true end
    local cloud_suffix = "/library/cloudstorage"
    if lower:sub(-(#cloud_suffix)) == cloud_suffix then return true end
<<<END

### Finding 24: FIXED

<<<SEARCH
    -- Syslog output (via logger command)
    if config.log_to_syslog then
        local prio = level
        if prio == "warn" then prio = "warning"
        elseif prio == "error" then prio = "err" end
        os.execute(string.format("logger -p %s %s 2>/dev/null",
            shell_quote(config.syslog_facility .. "." .. prio),
            shell_quote("thunderstorm-collector: " .. clean)))
    end
>>>REPLACE
    -- Syslog output (via logger command); skip debug messages to avoid spawning
    -- a shell process for every file during scans (expensive on embedded systems)
    if config.log_to_syslog and level ~= "debug" then
        local prio = level
        if prio == "warn" then prio = "warning"
        elseif prio == "error" then prio = "err" end
        os.execute(string.format("logger -p %s %s 2>/dev/null",
            shell_quote(config.syslog_facility .. "." .. prio),
            shell_quote("thunderstorm-collector: " .. clean)))
    end
<<<END

### Finding 25: FIXED

<<<SEARCH
function submit_file(endpoint, filepath)
    local filename = filepath:match("([^/]+)$") or filepath

    for attempt = 1, config.retries do
        local success = false

        if config.upload_tool == "curl" then
            success = upload_with_curl(endpoint, filepath, filename)
        elseif config.upload_tool == "wget" then
            success = upload_with_wget(endpoint, filepath, filename)
        elseif config.upload_tool == "nc" then
            success = upload_with_nc(endpoint, filepath, filename)
        elseif config.upload_tool == "busybox-wget" then
            success = upload_with_busybox_wget(endpoint, filepath, filename)
        else
            log_msg("error", "No upload tool available")
            return false
        end

        if success then return true end

        log_msg("warn", string.format("Upload failed for '%s' (attempt %d/%d)",
            filepath, attempt, config.retries))

        if attempt < config.retries then
            -- Exponential backoff: 2^(attempt-1) seconds → 1, 2, 4, ...
            local delay = 1
            for _ = 2, attempt do delay = delay * 2 end
            os.execute("sleep " .. tostring(delay))
        end
    end

    return false
end
>>>REPLACE
function submit_file(endpoint, filepath)
    local filename = filepath:match("([^/]+)$") or filepath

    -- Track temp_files index before this upload so we can clean up after
    local temps_before = #temp_files

    for attempt = 1, config.retries do
        local success = false

        if config.upload_tool == "curl" then
            success = upload_with_curl(endpoint, filepath, filename)
        elseif config.upload_tool == "wget" then
            success = upload_with_wget(endpoint, filepath, filename)
        elseif config.upload_tool == "nc" then
            success = upload_with_nc(endpoint, filepath, filename)
        elseif config.upload_tool == "busybox-wget" then
            success = upload_with_busybox_wget(endpoint, filepath, filename)
        else
            log_msg("error", "No upload tool available")
            return false
        end

        -- Clean up temp files created during this attempt
        for i = temps_before + 1, #temp_files do
            os.remove(temp_files[i])
        end
        -- Truncate the tracked list back to pre-upload state
        for i = #temp_files, temps_before + 1, -1 do
            table.remove(temp_files, i)
        end

        if success then return true end

        log_msg("warn", string.format("Upload failed for '%s' (attempt %d/%d)",
            filepath, attempt, config.retries))

        if attempt < config.retries then
            -- Exponential backoff: 2^(attempt-1) seconds → 1, 2, 4, ...
            local delay = 1
            for _ = 2, attempt do delay = delay * 2 end
            os.execute("sleep " .. tostring(delay))
        end
    end

    return false
end
<<<END

### Finding 26: SKIPPED
Reason: exec_capture intentionally returns output regardless of exit code — callers validate content. This is documented behavior, not a bug. Adding a note in comments is sufficient but not a code fix.

### Finding 27: FIXED

<<<SEARCH
    print("      --retries <num>        Retry attempts per file (default: 3)")
>>>REPLACE
    print("      --retries <num>        Total upload attempts per file (default: 3)")
<<<END

<<<SEARCH
    if config.retries <= 0 then
        die("retries must be > 0")
    end
>>>REPLACE
    if config.retries < 1 then
        die("retries must be >= 1 (minimum 1 attempt)")
    end
<<<END