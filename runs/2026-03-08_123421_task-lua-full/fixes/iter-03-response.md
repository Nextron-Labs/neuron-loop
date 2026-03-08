I'll analyze each finding and provide precise fixes.

### Finding 1: FIXED
(Removes the incomplete loop and `>>>REPLACE` marker, keeping only the pcall-wrapped version)

<<<SEARCH
    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    local progress_counter = 0
    for file_path in handle:lines() do
>>>REPLACE
    -- Process line by line (memory efficient)
    local dir_files_scanned = 0
    local progress_counter = 0
<<<END

### Finding 2: FIXED

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
    if config.server:sub(1, 1) == "-" then
        die("Server hostname must not start with '-'")
    end
<<<END

### Finding 3: FIXED
(Already handled by Finding 1 fix — the stray `for` is removed. No additional block needed.)

### Finding 4: FIXED

<<<SEARCH
        local cmd = string.format(
            "curl -sS --fail -o %s %s%s-H %s --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_tmp), shell_quote(url))
>>>REPLACE
        local cmd = string.format(
            "curl -sS --fail -o %s %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_tmp), shell_quote(url))
<<<END

### Finding 5: FIXED

<<<SEARCH
    -- Extract scan_id from response
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id then return id end
    end
    return ""
end
>>>REPLACE
    -- nc path for collection markers (JSON POST)
    if tool == "nc" and not config.ssl then
        local hostpath = url:match("^https?://(.+)$")
        if hostpath then
            local hostport = hostpath:match("^([^/]+)")
            local path_rest = hostpath:match("^[^/]+/(.*)$")
            local path_query = "/" .. (path_rest or "")
            local host = hostport:match("^([^:]+)")
            local port = hostport:match(":(%d+)$") or "80"

            local req_tmp = mktemp()
            local req_f = io.open(req_tmp, "wb")
            if req_f then
                req_f:write(string.format("POST %s HTTP/1.0\r\n", path_query))
                req_f:write(string.format("Host: %s\r\n", hostport))
                req_f:write("Content-Type: application/json\r\n")
                req_f:write(string.format("Content-Length: %d\r\n", #body))
                req_f:write("Connection: close\r\n")
                req_f:write("\r\n")
                req_f:write(body)
                req_f:close()
                local resp_tmp = mktemp()
                local nc_cmd = string.format(
                    "nc -w 10 %s %s <%s >%s 2>/dev/null",
                    shell_quote(host), shell_quote(port),
                    shell_quote(req_tmp), shell_quote(resp_tmp))
                exec_ok(nc_cmd)
                local rf = io.open(resp_tmp, "r")
                if rf then resp = rf:read("*a"); rf:close() end
            end
        end
    elseif tool == "nc" and config.ssl then
        log_msg("warn", "nc cannot send collection markers over HTTPS; markers skipped")
    end

    -- Extract scan_id from response
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id and id:match("^[A-Za-z0-9_%-%.]+$") then return id end
        if id then return id end
    end
    return ""
end
<<<END

### Finding 6: FIXED

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
>>>REPLACE
-- Generate an unpredictable suffix from /dev/urandom (8 hex chars)
local function _urandom_suffix()
    local f = io.open("/dev/urandom", "rb")
    if f then
        local bytes = f:read(4)
        f:close()
        if bytes and #bytes == 4 then
            return string.format("%02x%02x%02x%02x",
                string.byte(bytes, 1), string.byte(bytes, 2),
                string.byte(bytes, 3), string.byte(bytes, 4))
        end
    end
    -- Last resort: time + math.random (seeded before first call in main)
    return tostring(os.time()) .. tostring(math.random(100000, 999999))
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
        -- Fallback using /dev/urandom for unpredictable name; open with wb to create
        path = "/tmp/thunderstorm." .. _urandom_suffix()
        local f = io.open(path, "wb")
        if f then f:close() else path = "" end
    end
    -- Verify the path is in a sane location
    if path == "" or (not path:match("^/tmp/") and not path:match("^/var/tmp/")) then
        -- Last resort with urandom suffix
        local alt = "/tmp/thunderstorm." .. _urandom_suffix()
        local f = io.open(alt, "wb")
        if f then f:close(); path = alt
        else
            die("Cannot create temporary file in /tmp; check permissions")
        end
    end
    temp_files[#temp_files + 1] = path
    return path
end
<<<END

### Finding 7: FIXED

<<<SEARCH
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)
    -- Use a longer boundary to reduce collision probability (Finding 26)
    local boundary = "----ThunderstormBoundary"
        .. tostring(os.time())
        .. tostring(math.random(100000000, 999999999))
        .. tostring(math.random(100000000, 999999999))
>>>REPLACE
-- Generate a boundary string using /dev/urandom for collision resistance
local function _make_boundary()
    local f = io.open("/dev/urandom", "rb")
    if f then
        local bytes = f:read(16)
        f:close()
        if bytes and #bytes == 16 then
            local hex = ""
            for i = 1, #bytes do
                hex = hex .. string.format("%02x", string.byte(bytes, i))
            end
            return "----ThunderstormBoundary" .. hex
        end
    end
    -- Fallback
    return "----ThunderstormBoundary"
        .. tostring(os.time())
        .. tostring(math.random(100000000, 999999999))
        .. tostring(math.random(100000000, 999999999))
end

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
            local needle = "\r\n--" .. candidate
            local buf = ""
            local chunk_size = 8192
            local overlap = #needle - 1
            while true do
                local chunk = src_check:read(chunk_size)
                if not chunk then break end
                local search_buf = buf .. chunk
                if search_buf:find(needle, 1, true) then
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
<<<END

### Finding 8: FIXED

<<<SEARCH
    -- Send via nc using redirect (avoids pipe buffer limits and useless cat process)
    -- Use -w 10 timeout; Connection: close header ensures server closes after response
    local resp_file = mktemp()
    local cmd = string.format(
        "nc -w 10 %s %s <%s >%s 2>/dev/null",
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
    exec_ok(cmd)

    local resp_f = io.open(resp_file, "r")
    if not resp_f then return false end
    local resp = resp_f:read("*a")
    resp_f:close()

    if not resp or resp == "" then return false end
>>>REPLACE
    -- Send via nc using redirect (avoids pipe buffer limits and useless cat process)
    -- Use -w 10 timeout; Connection: close header ensures server closes after response
    local resp_file = mktemp()
    local cmd = string.format(
        "nc -w 10 %s %s <%s >%s 2>/dev/null",
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
    local nc_ok = exec_ok(cmd)

    local resp_f = io.open(resp_file, "r")
    if not resp_f then return false end
    local resp = resp_f:read("*a")
    resp_f:close()

    if not resp or resp == "" then
        if not nc_ok then
            log_msg("debug", "nc connection failed for '" .. filepath .. "'")
        else
            log_msg("warn", "nc connected but received empty response for '" .. filepath .. "'")
        end
        return false
    end
<<<END

### Finding 9: FIXED

<<<SEARCH
function send_collection_marker(base_url, marker_type, scan_id, stats_json)
    local url = base_url .. "/api/collection"
>>>REPLACE
function send_collection_marker(base_url, marker_type, scan_id, stats_json)
    local url = base_url .. "/api/collection"
    local temps_before = #temp_files
<<<END

<<<SEARCH
    -- Extract scan_id from response
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id and id:match("^[A-Za-z0-9_%-%.]+$") then return id end
        if id then return id end
    end
    return ""
end
>>>REPLACE
    -- Clean up temp files created during this marker send
    for i = #temp_files, temps_before + 1, -1 do
        os.remove(temp_files[i])
        table.remove(temp_files, i)
    end

    -- Extract scan_id from response
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id then return id end
    end
    return ""
end
<<<END

### Finding 10: FIXED

<<<SEARCH
function sanitize_filename(s)
    if not s then return "" end
    local r = s:gsub('["%\\;]', "_")
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
    -- Replace all control characters (0x00-0x1F, 0x7F) including \r, \n, \t, etc.
    r = r:gsub("%c", "_")
    r = r:gsub("\127", "_")
    return r
end
<<<END

### Finding 11: FIXED

<<<SEARCH
    if config.max_size_kb <= 0 then
        die("max-size-kb must be > 0")
    end
>>>REPLACE
    if config.max_size_kb <= 0 then
        die("max-size-kb must be > 0")
    end
    if config.max_age > 3650 then
        log_msg("warn", "max-age > 3650 days; this will scan very old files and may take a long time")
    end
<<<END

### Finding 12: SKIPPED
The `body_len` is computed by counting bytes written to the temp file on Linux (no text-mode translation). The Content-Length matches the actual file size on the target platform. This is not a real bug on embedded Linux targets.

### Finding 13: FIXED

<<<SEARCH
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
            "curl -sS --fail -o %s %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_tmp), shell_quote(url))
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
        local err_tmp = mktemp()
        local cmd = string.format(
            "curl -sS --fail -o %s %s %s -H %s --max-time 10 --data-binary @%s %s 2>%s",
            shell_quote(resp_file), insecure, ca_cert_flag,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_tmp), shell_quote(url), shell_quote(err_tmp))
        if not exec_ok(cmd) then
            local ef = io.open(err_tmp, "r")
            if ef then
                local emsg = ef:read("*a"); ef:close()
                if emsg and emsg ~= "" then
                    log_msg("warn", "Marker curl error: " .. emsg:gsub("[\r\n]", " "):sub(1, 200))
                end
            end
            log_msg("warn", "Failed to send '" .. marker_type .. "' collection marker via curl")
        else
            local f = io.open(resp_file, "r")
            if f then resp = f:read("*a"); f:close() end
        end
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
        if not exec_ok(cmd) then
            log_msg("warn", "Failed to send '" .. marker_type .. "' collection marker via wget")
        else
            local f = io.open(resp_file, "r")
            if f then resp = f:read("*a"); f:close() end
        end
    end
<<<END

### Finding 14: FIXED

<<<SEARCH
    if config.max_age == 0 then
        log_msg("warn", "max-age=0 will match no files (find -mtime -0 matches nothing)")
    end
>>>REPLACE
    if config.max_age == 0 then
        die("max-age=0 will match no files (find -mtime -0 matches nothing); use at least 1")
    end
<<<END

### Finding 15: SKIPPED
Finding 6 already addresses the TOCTOU race by using `/dev/urandom` for unpredictable temp file names and preferring the `mktemp` binary. The additional hardening suggested here (failing closed) is covered by the `die()` call added in Finding 6's fix.

### Finding 16: FIXED

<<<SEARCH
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
-- - Lua 5.1 has no native signal handling (no posix.signal on embedded targets).
--   SIGINT/SIGTERM will terminate the process without sending an "interrupted"
--   collection marker. For signal-aware operation, wrap this script in a shell:
--     trap 'lua thunderstorm-collector.lua --dry-run 2>/dev/null; kill $PID' INT TERM
--   A proper wrapper is outside the scope of this pure-Lua implementation.
>>>REPLACE
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
-- - Lua 5.1 has no native signal handling (no posix.signal on embedded targets).
--   SIGINT/SIGTERM will terminate the process without sending an "interrupted"
--   collection marker. Interrupted markers are NOT supported in pure Lua mode.
--   For signal-aware operation, use a shell wrapper such as:
--
--     #!/bin/sh
--     SERVER="$1"; SOURCE="$2"
--     lua thunderstorm-collector.lua --server "$SERVER" --source "$SOURCE" &
--     COLLECTOR_PID=$!
--     _interrupted() {
--         kill $COLLECTOR_PID 2>/dev/null
--         curl -sS --max-time 10 -X POST \
--             "http://${SERVER}:8080/api/collection" \
--             -H 'Content-Type: application/json' \
--             -d "{\"type\":\"interrupted\",\"source\":\"${SOURCE}\",\"collector\":\"lua-wrapper\"}" \
--             >/dev/null 2>&1
--         exit 1
--     }
--     trap '_interrupted' INT TERM
--     wait $COLLECTOR_PID
--     exit $?
--
--   This wrapper is outside the scope of the pure-Lua implementation.
<<<END

### Finding 17: FIXED

<<<SEARCH
function wget_is_busybox()
    local output = exec_capture("wget --version 2>&1")
    if output and output:lower():find("busybox") then
        return true
    end
    return false
end
>>>REPLACE
local _wget_is_busybox_cache = nil
function wget_is_busybox()
    if _wget_is_busybox_cache ~= nil then return _wget_is_busybox_cache end
    local output = exec_capture("wget --version 2>&1")
    _wget_is_busybox_cache = (output and output:lower():find("busybox") ~= nil) or false
    return _wget_is_busybox_cache
end
<<<END

### Finding 18: FIXED
(Already addressed in Finding 9's replacement of the scan_id extraction block — the pattern is kept but a format validation is applied. The Finding 5 fix already added the alphanumeric check. Let's ensure the final extraction in the cleaned-up `send_collection_marker` is consistent.)

The scan_id extraction was already updated in Finding 9's fix to remove the double-check. The pattern itself is a known limitation documented below:

<<<SEARCH
    -- Extract scan_id from response
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id then return id end
    end
    return ""
end
>>>REPLACE
    -- Extract scan_id from response.
    -- Pattern assumes scan_id values are alphanumeric/UUID (no escaped quotes inside).
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([A-Za-z0-9_%.%-]+)"')
        if id then return id end
        -- Fallback: accept any non-quote sequence (less strict)
        id = resp:match('"scan_id"%s*:%s*"([^"]*)"')
        if id and id ~= "" then return id end
    end
    return ""
end
<<<END

### Finding 19: FIXED

<<<SEARCH
    -- Seed random number generator for temp file name generation
    math.randomseed(os.time() + math.floor(os.clock() * 1000000))

    -- Record start time
    local start_time = os.time()
>>>REPLACE
    -- Record start time
    local start_time = os.time()
>>>REPLACE
(move randomseed to top of main)
<<<END

Let me redo this properly:

<<<SEARCH
function main()
    -- Parse args (before opening log file, so --log-file takes effect)
    parse_args(arg)
>>>REPLACE
function main()
    -- Seed RNG immediately (before any mktemp() fallback calls)
    math.randomseed(os.time() + math.floor(os.clock() * 1000000))

    -- Parse args (before opening log file, so --log-file takes effect)
    parse_args(arg)
<<<END

<<<SEARCH
    -- Seed random number generator for temp file name generation
    math.randomseed(os.time() + math.floor(os.clock() * 1000000))

    -- Record start time
>>>REPLACE
    -- Record start time
<<<END

### Finding 20: FIXED

<<<SEARCH
        if err_msg and err_msg ~= "" then
                log_msg("debug", "curl error: " .. err_msg:gsub("[\r\n]", " "):sub(1, 200))
>>>REPLACE
        if err_msg and err_msg ~= "" then
                log_msg("warn", "curl error: " .. err_msg:gsub("[\r\n]", " "):sub(1, 200))
<<<END

### Finding 21: SKIPPED
BusyBox `find` uses `fnmatch()` for `-path` which correctly handles `/*` wildcards. The prune expression structure is standard and correct for both GNU find and BusyBox find. The edge case of scanning `/` directly is handled by the `test -d` check and the prune expressions. No fix needed.

### Finding 22: FIXED

<<<SEARCH
    req_f:write(string.format("POST %s HTTP/1.1\r\n", path_query))
    req_f:write(string.format("Host: %s\r\n", hostport))
    req_f:write(string.format("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))
    req_f:write(string.format("Content-Length: %d\r\n", body_len))
    req_f:write("Connection: close\r\n")
    req_f:write("\r\n")
>>>REPLACE
    req_f:write(string.format("POST %s HTTP/1.0\r\n", path_query))
    req_f:write(string.format("Host: %s\r\n", hostport))
    req_f:write(string.format("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))
    req_f:write(string.format("Content-Length: %d\r\n", body_len))
    req_f:write("Connection: close\r\n")
    req_f:write("\r\n")
<<<END

Also increase nc timeout based on file size:

<<<SEARCH
    local cmd = string.format(
        "nc -w 10 %s %s <%s >%s 2>/dev/null",
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
    local nc_ok = exec_ok(cmd)
>>>REPLACE
    -- Timeout: base 30s + 1s per 10KB to accommodate slow servers on large files
    local nc_timeout = math.max(30, 30 + math.floor(body_len / 10240))
    local cmd = string.format(
        "nc -w %d %s %s <%s >%s 2>/dev/null",
        nc_timeout,
        shell_quote(host), shell_quote(port),
        shell_quote(req_file), shell_quote(resp_file)
    )
    local nc_ok = exec_ok(cmd)
<<<END

### Finding 23: SKIPPED
The syslog-via-logger behavior is documented in the code comment and is an inherent limitation of the approach. Adding batching would require significant refactoring. The existing comment already warns about this. Operators are advised not to enable syslog on performance-critical embedded systems.

### Finding 24: FIXED

<<<SEARCH
-- Cloud storage directory names (lowercase)
CLOUD_DIR_NAMES = {
    "onedrive", "dropbox", ".dropbox", "googledrive", "nextcloud",
    "owncloud", "mega", "megasync", "tresorit", "syncthing",
}
>>>REPLACE
-- Cloud storage directory names (lowercase) — pre-built as search patterns
CLOUD_DIR_NAMES = {
    "onedrive", "dropbox", ".dropbox", "googledrive", "nextcloud",
    "owncloud", "mega", "megasync", "tresorit", "syncthing",
}
-- Pre-computed prefix/suffix patterns for is_cloud_path (avoids repeated string ops)
local _cloud_mid_patterns = {}
local _cloud_end_suffixes = {}
-- (populated after CLOUD_DIR_NAMES is defined, before first use)
local function _init_cloud_patterns()
    for _, name in ipairs(CLOUD_DIR_NAMES) do
        _cloud_mid_patterns[#_cloud_mid_patterns + 1] = "/" .. name .. "/"
        _cloud_end_suffixes[#_cloud_end_suffixes + 1] = "/" .. name
    end
end
_init_cloud_patterns()
<<<END

<<<SEARCH
function is_cloud_path(path)
    local lower = path:lower()
    for _, name in ipairs(CLOUD_DIR_NAMES) do
        -- Match /name/ in the middle or /name at the end
        if lower:find("/" .. name .. "/", 1, true) then return true end
        if lower:sub(-(#name + 1)) == "/" .. name then return true end
    end
    -- macOS cloud storage (/Library/CloudStorage/ or ending with /Library/CloudStorage)
    if lower:find("/library/cloudstorage/", 1, true) then return true end
    local cloud_suffix = "/library