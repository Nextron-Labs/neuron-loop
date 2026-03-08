# Code Fix Prompt

You are a senior engineer fixing issues found during code review. Apply precise, minimal fixes.

## Context

Review and fix the THOR Thunderstorm Collector Lua script.

This is a file collector for embedded Linux systems (OpenWrt, BusyBox+Lua) that uploads suspicious files to a Thunderstorm server for malware scanning.

Target: Lua 5.1+, pure standard library, no external Lua modules.
Upload tools: curl, wget, nc (detected at runtime).

The other 8 collector scripts (bash, ash, py3, py2, perl, ps1, ps2, bat) have been hardened with:
- Consistent exit codes: 0=clean, 1=partial failure, 2=fatal error
- Begin-marker retry (single retry after 2s on initial failure)
- Signal handling (SIGINT/SIGTERM → sends "interrupted" collection marker with stats)
- --ca-cert PATH for TLS certificate validation with custom CA bundles
- Proper JSON escaping for source names (control chars, backslashes, quotes)
- Errors routed to stderr (not stdout)
- Failed files tracked and reflected in exit code
- Progress reporting with TTY auto-detection (--progress / --no-progress)

Important constraints:
- Lua 5.1 has NO native signal handling (no posix.signal on embedded targets)
- Signal handling should use a shell wrapper approach or be noted as a limitation
- The script must work on minimal BusyBox+Lua systems with only curl, wget, or nc
- Memory usage matters on embedded systems (2-16 MB RAM devices)
- Do NOT use any Lua 5.2+ features (no goto, no bitwise ops, no _ENV)
- Do NOT add external module dependencies (no luasocket, no luaposix)


## Current Code


### thunderstorm-collector.lua
```
#!/usr/bin/env lua
-- ==========================================================================
-- THOR Thunderstorm Collector — Lua 5.1+ Edition
-- Florian Roth / Nextron Systems
--
-- Pure Lua implementation of the Thunderstorm file collector.
-- Target: OpenWrt, embedded Linux, BusyBox+Lua systems, industrial gateways.
-- Requires: Lua 5.1+ standard library + one of: curl, wget, nc
--
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
-- ==========================================================================

VERSION = "0.1.0"

-- ==========================================================================
-- CONFIGURATION
-- ==========================================================================

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

counters = {
    files_scanned   = 0,
    files_submitted = 0,
    files_skipped   = 0,
    files_failed    = 0,
}

-- Static path exclusions
EXCLUDE_PATHS = {"/proc", "/sys", "/dev", "/run", "/snap", "/.snapshots"}

-- Dynamic exclusions populated from /proc/mounts
dynamic_excludes = {}

-- Network filesystem types
NETWORK_FS_TYPES = "nfs nfs4 cifs smbfs smb3 sshfs fuse.sshfs afp webdav davfs2 fuse.rclone fuse.s3fs"

-- Special filesystem types
SPECIAL_FS_TYPES = "proc procfs sysfs devtmpfs devpts cgroup cgroup2 pstore bpf tracefs debugfs securityfs hugetlbfs mqueue autofs fusectl rpc_pipefs nsfs configfs binfmt_misc selinuxfs efivarfs ramfs"

-- Cloud storage directory names (lowercase)
CLOUD_DIR_NAMES = {
    "onedrive", "dropbox", ".dropbox", "googledrive", "nextcloud",
    "owncloud", "mega", "megasync", "tresorit", "syncthing",
}

-- Temp file tracking
temp_files = {}

-- Log file handle
log_file_handle = nil

-- ==========================================================================
-- UTILITIES
-- ==========================================================================

function trim(s)
    if not s then return "" end
    return s:match("^%s*(.-)%s*$")
end

function timestamp()
    return os.date("%Y-%m-%d_%H:%M:%S")
end

function is_integer(s)
    if not s or s == "" then return false end
    return s:match("^%d+$") ~= nil
end

function urlencode(str)
    if not str then return "" end
    local result = {}
    for i = 1, #str do
        local c = str:sub(i, i)
        local b = string.byte(c)
        if (b >= 65 and b <= 90) or (b >= 97 and b <= 122) or
           (b >= 48 and b <= 57) or c == "-" or c == "_" or
           c == "." or c == "~" then
            result[#result + 1] = c
        else
            result[#result + 1] = string.format("%%%02X", b)
        end
    end
    return table.concat(result)
end

function sanitize_filename(s)
    if not s then return "" end
    local r = s:gsub('["%\\;]', "_")
    r = r:gsub("\r", "_")
    r = r:gsub("\n", "_")
    return r
end

function shell_quote(s)
    return "'" .. s:gsub("'", "'\"'\"'") .. "'"
end

function file_size_kb(path)
    local f = io.open(path, "rb")
    if not f then return -1 end
    local size = f:seek("end")
    f:close()
    if not size then return -1 end
    return math.ceil(size / 1024)
end

function mktemp()
    local path = os.tmpname()
    -- Ensure the file exists (os.tmpname may just return a name on some systems)
    local f = io.open(path, "wb")
    if f then f:close() end
    temp_files[#temp_files + 1] = path
    return path
end

function cleanup_temp_files()
    for _, path in ipairs(temp_files) do
        os.remove(path)
    end
    temp_files = {}
end

-- Execute a shell command and return: exit_success (bool)
-- Lua 5.1: os.execute returns a status number (0 = success)
-- Lua 5.2+: os.execute returns true/nil, "exit"/"signal", code
function exec_ok(cmd)
    local result = os.execute(cmd)
    if result == true then return true end       -- Lua 5.2+
    if result == 0 then return true end          -- Lua 5.1
    return false
end

-- Execute a command and capture stdout
function exec_capture(cmd)
    local handle = io.popen(cmd)
    if not handle then return nil end
    local output = handle:read("*a")
    handle:close()
    return output
end

-- ==========================================================================
-- LOGGING
-- ==========================================================================

function log_msg(level, message)
    -- Filter debug messages unless debug enabled
    if level == "debug" and not config.debug then return end

    local ts = timestamp()
    -- Sanitize message (strip control chars)
    local clean = message:gsub("[\r\n]", " ")

    -- Console output (stderr, unless quiet)
    if not config.quiet then
        io.stderr:write(string.format("[%s] %s\n", level, clean))
    end

    -- File output
    if config.log_to_file and log_file_handle then
        local ok, err = pcall(function()
            log_file_handle:write(string.format("%s %s %s\n", ts, level, clean))
            log_file_handle:flush()
        end)
        if not ok then
            config.log_to_file = false
            io.stderr:write(string.format("[warn] Could not write to log file '%s'; disabling\n",
                config.log_file))
        end
    end

    -- Syslog output (via logger command)
    if config.log_to_syslog then
        local prio = level
        if prio == "warn" then prio = "warning"
        elseif prio == "error" then prio = "err" end
        os.execute(string.format("logger -p %s %s 2>/dev/null",
            shell_quote(config.syslog_facility .. "." .. prio),
            shell_quote("thunderstorm-collector: " .. clean)))
    end
end

function die(message)
    log_msg("error", message)
    cleanup_temp_files()
    if log_file_handle then log_file_handle:close() end
    os.exit(1)
end

-- ==========================================================================
-- CLI ARGUMENT PARSING
-- ==========================================================================

function print_banner()
    io.write([[
==============================================================
    ________                __            __
   /_  __/ /  __ _____  ___/ /__ _______ / /____  ______ _
    / / / _ \/ // / _ \/ _  / -_) __(_-</ __/ _ \/ __/  ' \
   /_/ /_//_/\_,_/_//_/\_,_/\__/_/ /___/\__/\___/_/ /_/_/_/
]])
    io.write(string.format("   v%s (Lua 5.1+ edition)\n", VERSION))
    io.write([[

   THOR Thunderstorm Collector for Linux/Unix
==============================================================
]])
end

function print_help()
    print("Usage:")
    print("  lua thunderstorm-collector.lua [options]")
    print("")
    print("Options:")
    print("  -s, --server <host>        Thunderstorm server hostname or IP")
    print("  -p, --port <port>          Thunderstorm port (default: 8080)")
    print("  -d, --dir <path>           Directory to scan (repeatable)")
    print("      --max-age <days>       Max file age in days (default: 14)")
    print("      --max-size-kb <kb>     Max file size in KB (default: 2000)")
    print("      --source <name>        Source identifier (default: hostname)")
    print("      --ssl                  Use HTTPS")
    print("  -k, --insecure             Skip TLS certificate verification")
    print("      --sync                 Use /api/check (default: /api/checkAsync)")
    print("      --retries <num>        Retry attempts per file (default: 3)")
    print("      --dry-run              Do not upload, only show what would be submitted")
    print("      --debug                Enable debug log messages")
    print("      --log-file <path>      Log file path (default: ./thunderstorm.log)")
    print("      --no-log-file          Disable file logging")
    print("      --syslog               Enable syslog logging")
    print("      --quiet                Disable command-line logging")
    print("  -h, --help                 Show this help text")
    print("")
    print("Notes:")
    print("  Requires Lua 5.1+ and one of: curl, wget, or nc for uploads.")
    print("  Filenames containing literal newline characters are not supported.")
    print("")
    print("Examples:")
    print("  lua thunderstorm-collector.lua --server thunderstorm.local")
    print("  lua thunderstorm-collector.lua --server 10.0.0.5 --dir /tmp --dir /home")
end

function parse_args(args)
    local i = 1
    while i <= #args do
        local a = args[i]
        local next_val = args[i + 1]

        if a == "-s" or a == "--server" then
            if not next_val then die("Missing value for " .. a) end
            config.server = next_val
            i = i + 1
        elseif a == "-p" or a == "--port" then
            if not next_val then die("Missing value for " .. a) end
            if not is_integer(next_val) then die("Port must be numeric: " .. next_val) end
            config.port = tonumber(next_val)
            i = i + 1
        elseif a == "-d" or a == "--dir" then
            if not next_val then die("Missing value for " .. a) end
            if not config.scan_dirs_override then
                config.scan_dirs = {}
                config.scan_dirs_override = true
            end
            config.scan_dirs[#config.scan_dirs + 1] = next_val
            i = i + 1
        elseif a == "--max-age" then
            if not next_val then die("Missing value for " .. a) end
            if not is_integer(next_val) then die("max-age must be numeric: " .. next_val) end
            config.max_age = tonumber(next_val)
            i = i + 1
        elseif a == "--max-size-kb" then
            if not next_val then die("Missing value for " .. a) end
            if not is_integer(next_val) then die("max-size-kb must be numeric: " .. next_val) end
            config.max_size_kb = tonumber(next_val)
            i = i + 1
        elseif a == "--source" then
            if not next_val then die("Missing value for " .. a) end
            config.source = next_val
            i = i + 1
        elseif a == "--ssl" then
            config.ssl = true
        elseif a == "-k" or a == "--insecure" then
            config.insecure = true
        elseif a == "--sync" then
            config.async_mode = false
        elseif a == "--retries" then
            if not next_val then die("Missing value for " .. a) end
            if not is_integer(next_val) then die("retries must be numeric: " .. next_val) end
            config.retries = tonumber(next_val)
            i = i + 1
        elseif a == "--dry-run" then
            config.dry_run = true
        elseif a == "--debug" then
            config.debug = true
        elseif a == "--log-file" then
            if not next_val then die("Missing value for " .. a) end
            config.log_file = next_val
            i = i + 1
        elseif a == "--no-log-file" then
            config.log_to_file = false
        elseif a == "--syslog" then
            config.log_to_syslog = true
        elseif a == "--quiet" then
            config.quiet = true
        elseif a == "-h" or a == "--help" then
            print_help()
            os.exit(0)
        elseif a:sub(1, 1) == "-" then
            io.stderr:write(string.format("[error] Unknown option: %s (use --help)\n", a))
            os.exit(1)
        end

        i = i + 1
    end
end

function validate_config()
    if config.port < 1 or config.port > 65535 then
        die("Port must be between 1 and 65535")
    end
    if config.max_age < 0 then
        die("max-age must be >= 0")
    end
    if config.max_size_kb <= 0 then
        die("max-size-kb must be > 0")
    end
    if config.retries <= 0 then
        die("retries must be > 0")
    end
    if config.server == "" then
        die("Server must not be empty")
    end
    if #config.scan_dirs == 0 then
        die("At least one scan directory is required")
    end
end

function detect_source_name()
    if config.source ~= "" then return end

    -- Try hostname -f, hostname, uname -n
    local cmds = {"hostname -f 2>/dev/null", "hostname 2>/dev/null", "uname -n 2>/dev/null"}
    for _, cmd in ipairs(cmds) do
        local handle = io.popen(cmd)
        if handle then
            local result = handle:read("*l")
            handle:close()
            if result and trim(result) ~= "" then
                config.source = trim(result)
                return
            end
        end
    end
    config.source = "unknown-host"
end

-- ==========================================================================
-- FILESYSTEM EXCLUSIONS
-- ==========================================================================

function parse_proc_mounts()
    local f = io.open("/proc/mounts", "r")
    if not f then return end

    local fs_set = {}
    for w in NETWORK_FS_TYPES:gmatch("%S+") do fs_set[w] = true end
    for w in SPECIAL_FS_TYPES:gmatch("%S+") do fs_set[w] = true end

    for line in f:lines() do
        -- /proc/mounts format: device mountpoint fstype options dump pass
        local _, mp, fstype = line:match("^(%S+)%s+(%S+)%s+(%S+)")
        if mp and fstype and fs_set[fstype] then
            dynamic_excludes[#dynamic_excludes + 1] = mp
        end
    end
    f:close()
end

function is_cloud_path(path)
    local lower = path:lower()
    for _, name in ipairs(CLOUD_DIR_NAMES) do
        -- Match /name/ in the middle or /name at the end
        if lower:find("/" .. name .. "/", 1, true) then return true end
        if lower:sub(-(#name + 1)) == "/" .. name then return true end
    end
    -- macOS cloud storage (/Library/CloudStorage/ or ending with /Library/CloudStorage)
    if lower:find("/library/cloudstorage/", 1, true) then return true end
    if lower:sub(-20) == "/library/cloudstorage" then return true end
    return false
end

-- ==========================================================================
-- UPLOAD TOOL DETECTION
-- ==========================================================================

function wget_is_busybox()
    local output = exec_capture("wget --version 2>&1")
    if output and output:lower():find("busybox") then
        return true
    end
    return false
end

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
        config.upload_tool = "nc"
        if config.ssl then
            log_msg("warn", "nc (netcat) does not support HTTPS; uploads may fail")
        end
        return true
    end

    -- BusyBox wget as last resort
    if has_wget then
        config.upload_tool = "busybox-wget"
        log_msg("warn", "BusyBox wget detected; binary files with NUL bytes may fail to upload")
        return true
    end

    return false
end

-- ==========================================================================
-- MULTIPART FORM-DATA CONSTRUCTION
-- ==========================================================================

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

-- ==========================================================================
-- UPLOAD BACKENDS
-- ==========================================================================

function get_curl_insecure_flag()
    if config.insecure then return "-k " else return "" end
end

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

    if not exec_ok(cmd) then
        return false
    end

    -- Check response for server-side rejection
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

function upload_with_nc(endpoint, filepath, filename)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    -- Parse URL: http://host:port/path?query
    local hostpath = endpoint:match("^https?://(.+)$")
    if not hostpath then return false end

    local hostport = hostpath:match("^([^/]+)")
    local path_rest = hostpath:match("^[^/]+/(.*)$")
    local path_query = "/" .. (path_rest or "")

    local host = hostport:match("^([^:]+)")
    local port = hostport:match(":(%d+)$")
    if not port then
        if config.ssl then port = "443" else port = "80" end
    end

    -- Build raw HTTP request
    local req_file = mktemp()
    local req_f = io.open(req_file, "wb")
    if not req_f then return false end

    req_f:write(string.format("POST %s HTTP/1.1\r\n", path_query))
    req_f:write(string.format("Host: %s\r\n", hostport))
    req_f:write(string.format("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))
    req_f:write(string.format("Content-Length: %d\r\n", body_len))
    req_f:write("Connection: close\r\n")
    req_f:write("\r\n")

    -- Append the body content
    local body_f = io.open(body_file, "rb")
    if body_f then
        req_f:write(body_f:read("*a"))
        body_f:close()
    end
    req_f:close()

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

function upload_with_busybox_wget(endpoint, filepath, filename)
    -- Same as wget but with known NUL byte truncation risk
    return upload_with_wget(endpoint, filepath, filename)
end

-- ==========================================================================
-- FILE SUBMISSION WITH RETRY
-- ==========================================================================

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

-- ==========================================================================
-- COLLECTION MARKERS
-- ==========================================================================

-- Escape a string for safe inclusion in JSON values
function json_escape(s)
    if not s then return "" end
    s = s:gsub('\\', '\\\\')
    s = s:gsub('"', '\\"')
    s = s:gsub('\n', '\\n')
    s = s:gsub('\r', '\\r')
    s = s:gsub('\t', '\\t')
    -- Escape remaining control characters (0x00-0x1F)
    s = s:gsub('%c', function(c)
        return string.format('\\u%04x', string.byte(c))
    end)
    return s
end

function send_collection_marker(base_url, marker_type, scan_id, stats_json)
    local url = base_url .. "/api/collection"

    -- Build JSON manually (no json library in Lua 5.1)
    local parts = {}
    parts[#parts + 1] = string.format('"type":"%s"', json_escape(marker_type))
    parts[#parts + 1] = string.format('"source":"%s"', json_escape(config.source))
    parts[#parts + 1] = string.format('"collector":"lua/%s"', json_escape(VERSION))
    parts[#parts + 1] = string.format('"timestamp":"%s"',
        os.date("!%Y-%m-%dT%H:%M:%SZ"))

    if scan_id and scan_id ~= "" then
        parts[#parts + 1] = string.format('"scan_id":"%s"', json_escape(scan_id))
    end

    local body = "{" .. table.concat(parts, ",")
    if stats_json and stats_json ~= "" then
        body = body .. "," .. stats_json
    end
    body = body .. "}"

    local resp = nil
    local resp_file = mktemp()
    local tool = config.upload_tool

    -- Use the already-detected upload tool; fall back to checking availability
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then tool = "wget"
        end
    end

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

    -- Extract scan_id from response
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id then return id end
    end
    return ""
end

-- ==========================================================================
-- FILE DISCOVERY
-- ==========================================================================

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

function scan_directory(dir, api_endpoint)
    -- Check directory exists
    if not exec_ok("test -d " .. shell_quote(dir)) then
        log_msg("warn", "Skipping non-directory path '" .. dir .. "'")
        return
    end

    log_msg("info", "Scanning '" .. dir .. "'")

    local cmd = build_find_command(dir)
    log_msg("debug", "find command: " .. cmd)

    local handle = io.popen(cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        return
    end

    -- Process line by line (memory efficient)
    for file_path in handle:lines() do
        if file_path ~= "" then
            counters.files_scanned = counters.files_scanned + 1

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
end

-- ==========================================================================
-- MAIN
-- ==========================================================================

function main()
    -- Parse args (before opening log file, so --log-file takes effect)
    parse_args(arg)

    -- Open log file (after arg parsing so --log-file / --no-log-file apply)
    if config.log_to_file then
        local err
        log_file_handle, err = io.open(config.log_file, "a")
        if not log_file_handle then
            io.stderr:write(string.format("[warn] Cannot open log file '%s': %s\n",
                config.log_file, err or "unknown"))
            config.log_to_file = false
        end
    end

    -- Validate
    validate_config()

    -- Detect source name
    detect_source_name()

    -- Banner
    print_banner()

    -- Warn if not root
    local whoami = exec_capture("id -u 2>/dev/null")
    if whoami and trim(whoami) ~= "0" then
        log_msg("warn", "Running without root privileges; some files may be inaccessible")
    end

    -- Parse dynamic mount exclusions
    parse_proc_mounts()

    -- Detect upload tool
    if not config.dry_run then
        if not detect_upload_tool() then
            die("Neither curl, wget, nor nc is installed; unable to upload samples")
        end
        log_msg("info", "Upload tool: " .. config.upload_tool)
    else
        if detect_upload_tool() then
            log_msg("info", "Dry-run mode (upload tool detected: " .. config.upload_tool .. ")")
        else
            log_msg("info", "Dry-run mode (no upload tool required)")
        end
    end

    -- Build endpoint URL
    local scheme = "http"
    if config.ssl then scheme = "https" end

    local endpoint_name = "checkAsync"
    if not config.async_mode then endpoint_name = "check" end

    local base_url = string.format("%s://%s:%d", scheme, config.server, config.port)
    local query_source = ""
    if config.source ~= "" then
        query_source = "?source=" .. urlencode(config.source)
    end
    local api_endpoint = string.format("%s/api/%s%s", base_url, endpoint_name, query_source)

    -- Log startup info
    log_msg("info", "Started Thunderstorm Collector (Lua) - Version " .. VERSION)
    log_msg("info", "Server: " .. config.server)
    log_msg("info", "Port: " .. tostring(config.port))
    log_msg("info", "API endpoint: " .. api_endpoint)
    log_msg("info", "Max age (days): " .. config.max_age)
    log_msg("info", "Max size (KB): " .. config.max_size_kb)
    log_msg("info", "Source: " .. config.source)
    local dirs_str = table.concat(config.scan_dirs, " ")
    log_msg("info", "Folders: " .. dirs_str)
    if config.dry_run then log_msg("info", "Dry-run mode enabled") end

    -- Record start time
    local start_time = os.time()

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

    -- Scan directories
    for _, dir in ipairs(config.scan_dirs) do
        scan_directory(dir, api_endpoint)
    end

    -- Calculate elapsed time
    local elapsed = os.difftime(os.time(), start_time)

    -- Log summary
    log_msg("info", string.format(
        "Run completed: scanned=%d submitted=%d skipped=%d failed=%d seconds=%d",
        counters.files_scanned, counters.files_submitted,
        counters.files_skipped, counters.files_failed, elapsed))

    -- Print summary to stdout
    io.write(string.format(
        "Run completed: scanned=%d submitted=%d skipped=%d failed=%d seconds=%d\n",
        counters.files_scanned, counters.files_submitted,
        counters.files_skipped, counters.files_failed, elapsed))

    -- Send end marker
    if not config.dry_run then
        local stats = string.format(
            '"stats":{"scanned":%d,"submitted":%d,"skipped":%d,"failed":%d,"elapsed_seconds":%d}',
            counters.files_scanned, counters.files_submitted,
            counters.files_skipped, counters.files_failed, elapsed)
        send_collection_marker(base_url, "end", scan_id, stats)
    end

    -- Cleanup
    cleanup_temp_files()
    if log_file_handle then log_file_handle:close() end
end

-- ==========================================================================
-- ENTRY POINT
-- ==========================================================================

main()

```


## Findings to Fix


### Finding 1. [CRITICAL] Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures
Location: die() / main()
Description: The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine but some uploads failed' (should be 1) and 'could not start at all' (should be 2), and a clean run with zero failures should exit 0.
Suggested fix: Change die() to call os.exit(2). At the end of main(), add: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end

### Finding 2. [CRITICAL] Shell injection via unsanitized filepath in curl --form argument
Location: upload_with_curl() ~line 290
Description: shell_quote wraps the entire --form value, but the filepath is interpolated raw into the format string before shell_quote sees it. A filename like /tmp/a'b would produce --form 'file=@/tmp/a'"'"'b;filename=...' which is correct for the outer shell quoting, BUT the curl --form parser itself sees the semicolon as a separator for curl options (e.g. ;type=...). A file at /tmp/evil;type=text/html would cause curl to set Content-Type to text/html instead of application/octet-stream, bypassing server-side type checks.
Suggested fix: Use curl's separate --form-string or pass filename via a separate -F field. Better: use the multipart body builder (build_multipart_body) for curl too, passing the body file with --data-binary @file and setting Content-Type header manually, eliminating the --form parsing issue entirely.

### Finding 3. [HIGH] Exit codes do not follow the documented collector contract
Location: die / main / parse_args / validate_config
Description: The script exits with status 1 for fatal configuration/runtime errors via die(), and main() never returns a non-zero status when uploads fail. The stated hardened behavior for sibling collectors is 0=clean, 1=partial failure, 2=fatal error. In this implementation, fatal errors are reported as 1, and runs with failed file uploads still exit 0 after printing the summary.
Suggested fix: Adopt the shared exit-code contract consistently: make die() use os.exit(2), and at the end of main() exit 1 when counters.files_failed > 0, else 0. Also ensure unknown-option and similar fatal parse failures use 2.

### Finding 4. [HIGH] Begin-marker retry hardening is missing
Location: main / send_collection_marker
Description: The script sends the initial "begin" collection marker only once. The prompt explicitly states the other collectors were hardened with a single retry after 2 seconds on initial begin-marker failure. Here, if the first marker request fails transiently, the run proceeds without a scan_id and without retrying.
Suggested fix: Wrap the initial begin marker send in retry logic: if the first call returns an empty scan_id, sleep 2 seconds and retry once before continuing. Log the retry and final failure clearly.

### Finding 5. [HIGH] --ca-cert support is missing despite required hardening parity
Location: print_help / parse_args / upload_with_curl / upload_with_wget / send_collection_marker
Description: The script supports --insecure but has no --ca-cert option and never passes a custom CA bundle to curl or wget. The prompt explicitly lists --ca-cert PATH as a hardened feature already implemented in the other collectors.
Suggested fix: Add a config.ca_cert field, parse --ca-cert PATH, validate the file exists, and pass it to curl (--cacert) and wget (--ca-certificate). Apply it to both file uploads and collection-marker requests.

### Finding 6. [HIGH] No interruption handling means end/interrupted markers and cleanup are skipped on SIGINT/SIGTERM
Location: main / overall process lifecycle
Description: The prompt requires signal handling parity, but this Lua 5.1 script has no mechanism to handle SIGINT/SIGTERM. The context explicitly notes native signal handling is unavailable and should use a shell-wrapper approach or be documented as a limitation. The current script neither implements a wrapper strategy nor emits an interrupted marker, and temp-file/log cleanup only happens on normal completion or die().
Suggested fix: At minimum, document this limitation clearly in help/output. Preferably provide a shell wrapper that traps INT/TERM, invokes the Lua collector, and sends an interrupted collection marker with current stats. If wrapper integration is out of scope, note the parity gap explicitly.

### Finding 7. [HIGH] Multipart body construction loads entire file into memory, risking OOM on embedded targets
Location: build_multipart_body / upload_with_wget / upload_with_nc
Description: build_multipart_body() reads the full file into a Lua string, concatenates multipart headers and payload into another large string, then writes that combined body to a temp file. For files up to the configured 2000 KB limit, this can transiently require multiple copies of the payload in memory. upload_with_nc() then reads the generated body file fully again when appending it to the request file.
Suggested fix: Stream multipart construction directly to the output file instead of assembling the whole body in memory. For nc, write headers to req_file and then copy the source file in chunks. For wget, write multipart preamble, stream file content in chunks, then write epilogue. Avoid read('*a') for payloads.

### Finding 8. [HIGH] begin-marker has no retry; a transient failure silently loses scan_id and all files are uploaded without association
Location: send_collection_marker() ~line 340
Description: The other 8 hardened collectors implement a single retry after 2 seconds on initial begin-marker failure. This script calls send_collection_marker() once with no retry. If the server is temporarily unavailable at startup, scan_id remains '' and all subsequent file uploads proceed without a scan_id, making them unassociated on the server side. There is no warning logged when scan_id comes back empty.
Suggested fix: After the first send_collection_marker call returns '', sleep 2 seconds and retry once. Log a warning if scan_id is still '' after the retry.

### Finding 9. [HIGH] nc response captured via exec_capture (io.popen) loads entire HTTP response into RAM and loses binary safety
Location: upload_with_nc() ~line 310
Description: exec_capture() uses io.popen and read('*a') to capture nc's stdout. For large responses this wastes RAM. More importantly, io.popen on some BusyBox Lua builds is not binary-safe and may truncate at NUL bytes. The HTTP response from the server is text, so this is usually fine, but the real bug is that exec_capture runs 'cat file | nc ...' — the cat+pipe means the request body (which IS binary) is piped through the shell. On BusyBox, the pipe buffer may be limited and large files may stall.
Suggested fix: Use 'nc -w 30 host port < req_file > resp_file' and read resp_file afterward, avoiding the pipe entirely. This also eliminates the useless cat process.

### Finding 10. [HIGH] find -prune logic is incorrect — pruned paths are also printed as files
Location: build_find_command() ~line 390
Description: The generated find command is: find DIR (-path P1 -prune -o -path P2 -prune -o) -type f -mtime -N -print. The -prune action prevents descending but does NOT prevent the pruned directory itself from being printed if it matches -type f (it won't since it's a dir), but more importantly the -o (OR) chain means: if the path matches a prune pattern, prune it (and implicitly print nothing for that node due to -prune's false return), otherwise if it's a regular file modified within N days, print it. This is actually the standard idiom and is correct for directories. HOWEVER, if a pruned path is itself a file (e.g. EXCLUDE_PATHS contains a file path), -prune on a file is a no-op and the file will still be printed if it matches -type f -mtime. More critically: the prune_str ends with ' -o ' and then '-type f -mtime -N -print' follows. If prune_parts is empty, prune_str is '' and the command is correct. But if prune_parts is non-empty, the structure is: '( -path P -prune -o -path Q -prune -o ) -type f ...' — the trailing -o before -type f means: if none of the prune patterns matched, evaluate '-type f'. This is correct. But the issue is that -path matching uses shell glob patterns, and paths like /proc will not match /proc/net/foo because -path matches the full path. The correct idiom requires the prune pattern to be -path '/proc' OR -path '/proc/*'. Currently only -path '/proc' is used, so files directly under /proc (if any) would be excluded but /proc/net/foo would NOT be pruned — find would still try to descend into /proc.
Suggested fix: Change the prune pattern to match both the directory and its contents: string.format('\( -path %s -o -path %s \) -prune', shell_quote(p), shell_quote(p .. '/*')). Or use: -path 'P' -prune -o -path 'P/*' -prune

### Finding 11. [HIGH] Backslash escaping in gsub pattern is wrong — literal backslash in filename not sanitized
Location: sanitize_filename() ~line 95
Description: The pattern '["\\;]' in Lua is the string '["\\ ;]' after Lua string escape processing, which becomes the pattern character class containing: double-quote, backslash, semicolon. Wait — let's be precise: in Lua source, '["\\;]' — the \\ is two backslashes in source which Lua processes to one backslash, so the pattern is ["\ ;] which in Lua pattern syntax means: double-quote, backslash, semicolon. Actually this looks correct at first glance. BUT: Lua patterns use % as escape, not backslash. A backslash in a Lua pattern character class is treated as a literal backslash. So the pattern '["\\;]' with Lua string escaping gives pattern string ["\;] which matches double-quote, backslash, or semicolon. This IS correct. However, the real bug is that sanitize_filename is used to produce the filename in the Content-Disposition header, which is embedded in a double-quoted string. The sanitization replaces backslash with underscore, but does NOT handle other characters that are problematic in Content-Disposition filename fields, such as forward slashes (a filename from filepath:match('([^/]+)$') shouldn't have slashes, but the function itself accepts arbitrary input). More importantly, the function is also applied to the full filepath in upload_with_curl's --form value, where the safe_name is embedded inside double-quotes in the curl argument — a filename containing a double-quote would be replaced with underscore, which is correct, but a filename containing a percent sign would not be escaped and could confuse some parsers.
Suggested fix: This is a minor issue; the function is adequate for its actual use case. Consider documenting its limitations.

### Finding 12. [HIGH] wget --post-data with shell_quote passes JSON/body as command-line argument — NUL bytes and very long bodies will fail
Location: upload_with_wget() / send_collection_marker() ~line 295, 340
Description: In send_collection_marker(), the JSON body is passed via --post-data=shell_quote(body). For wget, --post-data takes the data as a command-line argument. Command-line arguments on Linux are limited to ARG_MAX (typically 128KB-2MB) and cannot contain NUL bytes. For the collection marker this is fine (small JSON). But in upload_with_wget(), the multipart body is passed via --post-file which reads from a file — this is correct. However, the Content-Type header is passed via --header=shell_quote(...) which is also a command-line argument and is fine. The real issue in send_collection_marker is that if config.source contains special characters that survive json_escape but are problematic in shell context, shell_quote handles it. This is actually OK. The wget --post-data issue is real for large sources but the collection marker body is small.
Suggested fix: For send_collection_marker, write the JSON body to a temp file and use --post-file instead of --post-data to be consistent and avoid argument length limits.

### Finding 13. [HIGH] Missing --ca-cert option for custom CA bundle TLS validation
Location: main() — no --ca-cert support
Description: The other 8 hardened collectors all support --ca-cert PATH for TLS certificate validation with custom CA bundles. This script has --ssl and -k/--insecure but no --ca-cert. On embedded systems, the system CA bundle is often absent or outdated, making --ca-cert essential for secure HTTPS uploads to internal Thunderstorm servers with private CA certificates.
Suggested fix: Add config.ca_cert = '' and --ca-cert <path> CLI option. In upload_with_curl, add --cacert shell_quote(config.ca_cert) when ca_cert ~= ''. In upload_with_wget, add --ca-certificate=shell_quote(config.ca_cert). Document that nc does not support CA certs.

### Finding 14. [HIGH] io.popen handle for find is never checked for errors; find failures are silently ignored
Location: scan_directory() / handle:close() ~line 420
Description: handle:close() on an io.popen handle in Lua 5.2+ returns the exit status of the process, but in Lua 5.1 it always returns true. There is no check of find's exit status. More importantly, if find exits with an error (e.g., permission denied on the root scan dir itself), the loop simply processes zero lines with no error logged. The existing check 'if not handle' only catches the case where io.popen itself fails (extremely rare).
Suggested fix: After handle:close(), check if files_scanned for this directory is still 0 and log a warning. Alternatively, redirect find's stderr to a temp file and check it after the loop.

### Finding 15. [MEDIUM] os.tmpname() is unsafe/unreliable on embedded Unix targets
Location: mktemp
Description: mktemp() uses os.tmpname() and then opens the returned path. On Unix-like systems, os.tmpname() is historically race-prone because it may return a predictable name that is created in a separate step. On some minimal environments it can also return unusable paths. This is especially problematic because the script stores upload bodies and server responses in temp files.
Suggested fix: Prefer invoking a shell mktemp utility when available (e.g. `mktemp /tmp/thunderstorm.XXXXXX`) and fall back carefully if absent. Open the file immediately after creation and verify it is a regular file in a trusted temp directory.

### Finding 16. [MEDIUM] find pruning expression is malformed and may not exclude mounted/special paths reliably
Location: build_find_command
Description: The generated command has the form `find <dir> <prunes> -type f -mtime -N -print`, where `<prunes>` expands to repeated `-path X -prune -o ...`. Without grouping parentheses around the prune expression, operator precedence can produce unintended evaluation, and excluded paths may still be traversed or matched inconsistently across find implementations.
Suggested fix: Build the command using grouped prune logic, e.g. `find DIR \( -path P1 -o -path P2 ... \) -prune -o -type f -mtime -N -print`. Keep shell quoting around each path.

### Finding 17. [MEDIUM] Progress reporting options required for parity are missing
Location: parse_args / print_help / overall CLI
Description: The hardened collectors are described as supporting TTY-aware progress reporting with --progress / --no-progress. This Lua script implements neither option nor any TTY detection logic.
Suggested fix: Add config.progress with auto-detection based on whether stdout/stderr is a TTY, parse --progress and --no-progress, and emit lightweight periodic progress updates without flooding logs.

### Finding 18. [MEDIUM] Collection marker requests ignore transport failures and HTTP error status
Location: send_collection_marker
Description: send_collection_marker() executes curl/wget but does not check the command exit status. It simply reads the response file if present and returns an extracted scan_id or empty string. For curl it also omits --fail, so HTTP 4xx/5xx can still produce a body and appear superficially successful. This makes marker delivery failures silent.
Suggested fix: Use exec_ok() for marker commands, add curl --fail/--show-error, and log failures explicitly. Consider checking for expected HTTP success semantics before parsing scan_id.

### Finding 19. [MEDIUM] Mount point paths with spaces or escape sequences in /proc/mounts are not handled
Location: parse_proc_mounts() ~line 200
Description: /proc/mounts encodes spaces in paths as \040 and other special characters with octal escapes (e.g., \011 for tab). The current parser uses a simple %S+ pattern which will correctly read the encoded mountpoint string, but the resulting path stored in dynamic_excludes will contain the literal string '\040' instead of a space. When this path is later compared against file paths returned by find (which use real spaces), the exclusion will never match.
Suggested fix: After extracting mp, decode octal escapes: mp = mp:gsub('\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end)

### Finding 20. [MEDIUM] os.tmpname() race condition — TOCTOU between name generation and file creation
Location: mktemp() ~line 110
Description: os.tmpname() returns a filename but does not create it atomically on all platforms. The subsequent io.open(path, 'wb') creates the file, but between tmpname() and open() another process could create a file with the same name (symlink attack or race). On Linux with glibc, os.tmpname() calls tmpnam() which is documented as insecure for this reason. On BusyBox Lua, behavior varies.
Suggested fix: Use mktemp shell command: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). Fall back to os.tmpname() if mktemp is unavailable. This is atomic.

### Finding 21. [MEDIUM] Syslog injection via unsanitized log message passed to shell
Location: log_msg() ~line 155
Description: log_msg() passes the 'clean' message to logger via shell_quote(). shell_quote() correctly escapes single quotes, so shell injection is prevented. However, the message passed to logger can contain arbitrary content from file paths, server responses, etc. The logger command itself is safe due to shell_quote. BUT: the 'clean' variable only strips \r and \n — it does not strip other control characters (0x01-0x08, 0x0B-0x0C, 0x0E-0x1F) that could confuse syslog parsers or terminal emulators when written to stderr.
Suggested fix: In log_msg, strip or replace all control characters before output: clean = message:gsub('[%c]', function(c) if c == '\n' or c == '\r' then return ' ' else return string.format('<0x%02x>', string.byte(c)) end end)

### Finding 22. [MEDIUM] Missing progress reporting with TTY auto-detection
Location: main() — no --progress / --no-progress support
Description: The other 8 hardened collectors implement --progress / --no-progress flags with TTY auto-detection. This script has no progress reporting at all. On long-running scans of large directories, there is no feedback to the operator about how many files have been processed.
Suggested fix: Add a progress counter that prints to stderr every N files (e.g., every 100) when stderr is a TTY. TTY detection in Lua 5.1 can be approximated by checking if 'tty -s 2>/dev/null' exits 0.

### Finding 23. [MEDIUM] HTTP/1.1 request without proper chunked encoding or exact Content-Length may fail with some servers
Location: upload_with_nc() ~line 315
Description: The nc upload builds an HTTP/1.1 request with Content-Length set to body_len (the multipart body size). This is correct. However, HTTP/1.1 servers may send a 100-Continue response before the client sends the body, and nc will not handle this — it just dumps the full request. Most HTTP/1.1 servers accept this for small requests, but some strict servers require the Expect: 100-continue handshake. Additionally, using HTTP/1.0 would be simpler and more compatible with nc (no persistent connection complications).
Suggested fix: Change the request to use HTTP/1.0 instead of HTTP/1.1, or add 'Expect: ' (empty) header to suppress 100-continue behavior.

### Finding 24. [MEDIUM] Source name not JSON-escaped before use in collection markers
Location: detect_source_name() ~line 230
Description: config.source is set from hostname output and used directly in send_collection_marker() via json_escape(config.source), which is correct. However, config.source is also appended to the API endpoint URL via urlencode(config.source), which is correct. The issue is in the log output: log_msg('info', 'Source: ' .. config.source) — if the hostname contains control characters or terminal escape sequences, this could cause terminal injection (covered by F14). Additionally, config.source set via --source CLI arg is not validated for length or character set.
Suggested fix: Truncate config.source to a reasonable length (e.g., 253 chars for a valid FQDN) and validate it contains only printable characters.

### Finding 25. [MEDIUM] Exponential backoff implementation is O(n) loop instead of bit shift — minor but incorrect for large retry counts
Location: submit_file() — exponential backoff ~line 370
Description: The backoff delay is computed as: local delay = 1; for _ = 2, attempt do delay = delay * 2 end. For attempt=1, the loop runs 0 times (2 to 1 is empty), giving delay=1. For attempt=2, loop runs once, delay=2. For attempt=3, delay=4. This is correct for small values. However, with config.retries=10 and attempt=9, delay=256 seconds — the script will stall for over 4 minutes on a single file. There is no cap on the backoff delay.
Suggested fix: Cap the backoff: local delay = math.min(30, 2^(attempt-1)) — but since Lua 5.1 has no ** operator, use: local delay = math.min(30, math.pow and math.pow(2, attempt-1) or (1 * (2^(attempt-1)))). Actually in Lua 5.1, ^ is the power operator: local delay = math.min(30, 2^(attempt-1))

### Finding 26. [MEDIUM] Boundary string could theoretically appear in file content, corrupting the multipart body
Location: build_multipart_body() ~line 250
Description: The multipart boundary is 'ThunderstormBoundary' + timestamp + random(10000,99999). If the file being uploaded happens to contain this exact byte sequence, the multipart parser on the server will incorrectly split the body. The probability is low but non-zero, especially since the boundary is predictable (based on os.time() which has 1-second resolution).
Suggested fix: Use a longer, more random boundary. Since Lua 5.1 has no crypto random, combine multiple math.random() calls and include a counter: boundary = 'ThunderstormBoundary' .. os.time() .. math.random(100000000, 999999999) .. math.random(100000000, 999999999). Also consider checking if the boundary appears in the content and regenerating if so.

### Finding 27. [LOW] All variables are global — risk of accidental cross-contamination in embedded Lua environments
Location: main() — global variable namespace pollution
Description: VERSION, config, counters, EXCLUDE_PATHS, dynamic_excludes, temp_files, log_file_handle, and all functions are defined in the global namespace. On some embedded Lua environments that run multiple scripts in the same interpreter instance, or if this script is require()'d, these globals will pollute the shared namespace.
Suggested fix: Wrap everything in a local scope or use local variables where possible. At minimum, add 'local' to module-level variables that don't need to be global.

### Finding 28. [LOW] wget --version may not be available on all BusyBox wget builds
Location: wget_is_busybox() ~line 215
Description: BusyBox wget may not support --version and could print an error or return non-zero. The function uses exec_capture which captures both stdout and stderr (only stdout via io.popen). If BusyBox wget prints 'BusyBox' to stderr for --version, the check will fail to detect it.
Suggested fix: Also check 'wget --help 2>&1' output, or use 'busybox wget --help 2>&1' as a fallback detection method.


## Instructions

1. Fix each finding listed above
2. Make MINIMAL changes — do not refactor unrelated code
3. If a finding is a false positive, state SKIPPED with reason

## Output Format

Return your fixes as SEARCH/REPLACE blocks. Each block replaces an exact snippet of the original code.

For each fix, write:

```
### Finding N: FIXED|SKIPPED|PARTIAL

<<<SEARCH
exact lines from the original code
(must match exactly, including whitespace)
>>>REPLACE
the replacement lines
<<<END
```

Rules:
- The SEARCH block must match the original code EXACTLY (copy-paste, don't retype)
- Keep SEARCH blocks as small as possible — just the lines that need changing plus minimal context
- Multiple SEARCH/REPLACE blocks per finding are fine
- For new code that doesn't replace anything, use an empty SEARCH with a comment indicating where to insert
- Do NOT return the entire file — only the changed sections
