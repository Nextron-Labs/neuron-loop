# Code Fix Prompt

You are a senior engineer fixing issues found during code review. Your job is to apply precise, minimal fixes that address each finding without introducing new bugs.

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


### 1. [CRITICAL] Exit code always 1 regardless of failure type; no exit code 2 for fatal errors vs exit code 1 for partial failures
Location: die() / main()
Description: The other 8 collector scripts use exit code 0=clean, 1=partial failure (some files failed), 2=fatal error. This script calls os.exit(1) from die() for all fatal errors, and main() falls off the end with implicit exit code 0 even when counters.files_failed > 0. There is no differentiation between 'ran fine', 'some uploads failed', and 'fatal misconfiguration'.
Suggested fix: At the end of main(), use: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end. Change die() to os.exit(2) for fatal errors. Update --help to document exit codes.

### 2. [CRITICAL] Shell injection via filepath in curl --form argument
Location: upload_with_curl() / shell_quote()
Description: The form value string.format('file=@%s;filename="%s"', filepath, safe_name) embeds filepath raw. If filepath contains a double-quote character, it terminates the filename= value inside the curl form spec. While shell_quote wraps the whole thing in single quotes preventing shell injection, curl itself parses the semicolon-separated form spec, so a filepath with a semicolon would be misinterpreted by curl's form parser as a type= or filename= separator.
Suggested fix: Use curl's --form-string or pass the file path separately: curl -F 'file=@/path/to/file' with the filename set via a separate -F 'filename=...' or use --form with proper escaping. Alternatively, write the file path to a temp file and use curl's @filename syntax only for the actual file, keeping the display filename in a separate field.

### 3. [CRITICAL] Entire file content loaded into Lua memory — fatal on embedded systems with large files
Location: build_multipart_body()
Description: build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file (max_size_kb default), this creates at least 3 copies of the file in memory simultaneously: the raw content string, the parts table entry, and the body concatenation. On a 2-4 MB RAM embedded device this will cause OOM or Lua memory errors.
Suggested fix: Stream the multipart body directly to the temp file without holding it in memory: open the temp file for writing, write the headers, then copy the source file in chunks (e.g., 4096-byte reads in a loop), then write the closing boundary. Remove the in-memory body concatenation entirely. The body_len can be computed as header_len + file_size + footer_len without reading the file.

### 4. [HIGH] Exit codes do not follow the documented collector contract
Location: die / main / parse_args / process exit handling
Description: The script exits with status 1 for fatal configuration/runtime errors via die(), and otherwise falls off the end of main() with exit status 0 even when some file uploads failed. The hardened collectors are expected to use 0=clean, 1=partial failure, 2=fatal error. This implementation currently cannot distinguish partial upload failures from a clean run, and fatal errors are reported with the wrong code.
Suggested fix: Introduce a final exit-status computation and use 2 for fatal errors. For example: make die() call os.exit(2), and at the end of main() call os.exit(counters.files_failed > 0 and 1 or 0). Also ensure unknown-option/config-validation fatal paths use die() or os.exit(2).

### 5. [HIGH] Begin collection marker is not retried on initial failure
Location: main / send_collection_marker begin flow
Description: The script sends the begin marker exactly once: `scan_id = send_collection_marker(base_url, "begin", nil, nil)`. The hardening requirements explicitly call for a single retry after 2 seconds on initial failure. If the first marker request fails transiently, the run proceeds without a scan_id and without retrying.
Suggested fix: If the first begin marker call returns an empty scan_id, sleep 2 seconds and retry once before proceeding. Log both attempts. Example: call send_collection_marker() again after `os.execute("sleep 2")` when the first result is empty.

### 6. [HIGH] Custom CA bundle support is missing despite required hardening parity
Location: CLI parsing / upload_with_curl / upload_with_wget / send_collection_marker
Description: The script supports `--ssl` and `--insecure` but does not implement the required `--ca-cert PATH` option. As a result, users on embedded systems with private PKI or custom trust stores cannot validate TLS using a supplied CA bundle. The only workaround is `--insecure`, which disables verification entirely.
Suggested fix: Add `config.ca_cert`, parse `--ca-cert <path>`, validate the file exists, and pass it through to the selected backend: curl `--cacert`, wget `--ca-certificate`, and marker requests as well. If using nc, reject HTTPS when a CA bundle is required because nc cannot validate TLS.

### 7. [HIGH] Netcat backend cannot perform HTTPS uploads but is still selected for SSL mode
Location: upload_with_nc / detect_upload_tool
Description: When curl and wget are unavailable, detect_upload_tool() selects `nc` even if `config.ssl` is true, only logging a warning. However, upload_with_nc() always emits a plain HTTP request over a raw TCP socket and never performs a TLS handshake. For `https://...` endpoints this will fail or send invalid traffic to the server.
Suggested fix: Do not select nc when `config.ssl` is true unless an actual TLS-capable wrapper is available. Treat this as a fatal capability mismatch: `if config.ssl and only nc is available then die("HTTPS requires curl or wget; nc cannot upload over TLS")`.

### 8. [HIGH] Shell injection via --post-data with unquoted body containing shell metacharacters
Location: send_collection_marker() — wget branch
Description: In send_collection_marker(), the wget command uses --post-data=%s where the body is passed through shell_quote(). However, the wget command string itself uses single-quoted --header='Content-Type: application/json' hardcoded in the format string, which is fine. But --post-data=shell_quote(body) is correct only if shell_quote works. The real issue: the format string contains literal single quotes around --header='...' that are part of the Lua string passed to os.execute(). On some shells (dash, ash) this works, but the body JSON may contain characters that interact with the shell_quote escaping in edge cases. More critically, the body is built with string.format and json_escape, but if json_escape fails to escape a character (e.g., a NUL byte in source name), the shell command will be malformed.
Suggested fix: Write the JSON body to a temp file and use --post-file= instead of --post-data= to avoid any shell quoting issues with binary or special characters in the body.

### 9. [HIGH] find prune logic is incorrect — pruned paths are still printed
Location: build_find_command()
Description: The find command is built as: find DIR (-path P1 -prune -o -path P2 -prune -o ...) -type f -mtime -N -print. The prune_str ends with ' -o ' before '-type f'. This means the full expression is: (-path P1 -prune -o -path P2 -prune -o -type f -mtime -N -print). This is correct ONLY if the pruned directories themselves are not printed. However, the -prune action returns true but does not print, so the -o chain correctly skips to the next alternative. BUT: the issue is that -prune only prevents descending; the directory entry itself matches -path and gets pruned. The real bug is that when there are NO prune_parts, prune_str is empty and the command is 'find DIR -type f -mtime -N -print' which is correct. When there ARE prune parts, the expression needs explicit grouping with escaped parentheses: find DIR \( -path P1 -prune -o -path P2 -prune \) -o -type f -mtime -N -print. Without the grouping, operator precedence may cause -type f to bind to the last -prune's -o incorrectly on some find implementations.
Suggested fix: Wrap prune clauses in escaped parentheses: prune_str = '\( ' .. table.concat(prune_parts, ' -o ') .. ' \) -o '. This ensures correct precedence across all POSIX find implementations.

### 10. [HIGH] No retry on begin-marker failure; scan_id silently empty
Location: send_collection_marker() — begin marker retry missing
Description: The other 8 hardened collectors implement a single retry after 2 seconds if the begin marker fails (returns empty scan_id). This script sends the begin marker once and silently continues with scan_id='' if it fails. An empty scan_id means the server cannot correlate uploaded files with a collection session.
Suggested fix: After the first send_collection_marker call returns '', sleep 2 seconds and retry once: if scan_id == '' then os.execute('sleep 2'); scan_id = send_collection_marker(base_url, 'begin', nil, nil) end. Log a warning if still empty after retry.

### 11. [HIGH] nc response reading via exec_capture uses a pipe that may deadlock or truncate
Location: upload_with_nc()
Description: upload_with_nc() uses exec_capture() which calls io.popen() to run 'cat FILE | nc -w 30 HOST PORT'. The nc command sends the request and then reads the response. io.popen() captures stdout of the entire pipeline. However, nc's -w 30 timeout applies to inactivity, not total time. More critically, on BusyBox nc, the -w flag behavior varies. The response is read with handle:read('*a') which blocks until nc closes. If the server keeps the connection open (HTTP/1.1 keep-alive), nc will hang until the 30s timeout. The HTTP request correctly sends 'Connection: close' but the server may not honor it immediately.
Suggested fix: Add explicit timeout handling. Use nc -q 1 (if supported) or nc -w 5 for the response wait. Alternatively, parse the Content-Length from the HTTP response and read only that many bytes. Also consider using 'nc -w 10' with a shorter timeout.

### 12. [HIGH] Backslash escaping pattern is wrong — gsub pattern '["\\;]' does not escape backslash correctly in Lua
Location: sanitize_filename()
Description: The pattern '["\\;]' in Lua: the string literal '["%\\;]' — in Lua source, \\ is a single backslash, so the pattern is ["%\;] which is a character class containing double-quote, percent, backslash, semicolon. Wait — re-examining: the source has '["\\;]' which in Lua string is the 4 chars [, ", \, ;, ] — that's actually correct for matching backslash. BUT the comment says 'Proper JSON escaping for source names' requires escaping control chars, backslashes, and quotes. The sanitize_filename function replaces these with underscore, which is used for the curl filename= field. The issue is that the curl form spec uses semicolons as separators (filename=foo;type=bar), so a semicolon in the filename would be misinterpreted. The pattern does include semicolon, so that's handled. However, the function does NOT escape forward slashes, which in a filename= context are harmless but in a path context could cause issues. More importantly, this function is used for the curl --form filename display value, not for JSON — the json_escape function is separate and correct.
Suggested fix: Verify the pattern is correct for the use case. Consider also replacing null bytes (\0) which would truncate C-string processing in curl.

### 13. [HIGH] No --ca-cert option for custom CA bundle, parity gap with all other 8 collectors
Location: main() — ca-cert option missing
Description: All 8 other hardened collectors support --ca-cert PATH for TLS certificate validation with custom CA bundles. This Lua collector has no --ca-cert option. The only TLS option is --insecure (-k). On embedded systems with self-signed certificates (common in enterprise Thunderstorm deployments), users must either skip verification entirely or cannot use this collector.
Suggested fix: Add config.ca_cert = '' field. Add --ca-cert <path> CLI option. In upload_with_curl(), add: if config.ca_cert ~= '' then insecure = '--cacert ' .. shell_quote(config.ca_cert) .. ' ' end. In upload_with_wget(), add --ca-certificate=PATH. Document that nc does not support CA certs.

### 14. [HIGH] wget --post-file sends raw multipart body but --header only sets one Content-Type; wget may add its own Content-Type overriding the boundary
Location: upload_with_wget() / upload_with_busybox_wget()
Description: GNU wget with --post-file does not automatically set Content-Type. The script sets it via --header='Content-Type: multipart/form-data; boundary=...'. However, BusyBox wget's --post-file behavior varies: some versions ignore custom Content-Type headers when --post-file is used and set application/x-www-form-urlencoded instead, breaking the multipart upload. Additionally, wget's --header flag syntax requires the value to not contain newlines, which is satisfied here, but the boundary value could theoretically contain characters that confuse the header parser.
Suggested fix: Test BusyBox wget behavior explicitly. Consider using --header with explicit quoting. For BusyBox wget, consider falling back to a different upload strategy or documenting the limitation more prominently.

### 15. [MEDIUM] Collection markers are never sent when nc is the detected upload tool
Location: send_collection_marker / tool selection for markers
Description: send_collection_marker() only implements curl and wget/busybox-wget branches. If detect_upload_tool() selected `nc`, `tool` remains `nc`, no request is sent, and the function silently returns an empty scan_id. This means begin/end markers are skipped entirely on nc-only systems.
Suggested fix: Either implement JSON POST via nc for plain HTTP, or explicitly log that markers are unsupported with nc and treat missing marker support as a degraded/partial-failure condition. If SSL is enabled, fail earlier as noted in F4.

### 16. [MEDIUM] Required interruption marker handling is absent and not documented as a limitation
Location: main / signal handling parity gap
Description: The hardened collectors are expected to send an `interrupted` collection marker with stats on SIGINT/SIGTERM. This Lua implementation has no such handling, and although the prompt notes native signal handling is unavailable on minimal Lua 5.1, the script neither provides a shell-wrapper approach nor clearly documents the limitation in behavior.
Suggested fix: Because pure Lua 5.1 cannot reliably trap signals on the target, document this limitation explicitly and provide a companion shell wrapper that traps INT/TERM and invokes marker submission before terminating the Lua process, or at minimum update help/comments to state interruption markers are unsupported in pure Lua mode.

### 17. [MEDIUM] Progress reporting and TTY auto-detection are missing
Location: CLI / user interface parity
Description: The hardening baseline includes progress reporting with TTY auto-detection and `--progress` / `--no-progress`. This script has neither the CLI options nor any progress behavior. While not a security issue, it is a stated parity requirement for the collector family.
Suggested fix: Add `config.progress` with auto-detection based on whether stdout/stderr is a TTY, implement `--progress` and `--no-progress`, and emit lightweight periodic progress updates without excessive memory use.

### 18. [MEDIUM] Multipart body construction reads entire file into memory
Location: build_multipart_body / upload_with_wget / upload_with_nc
Description: build_multipart_body() reads the full sample into a Lua string (`content = f:read("*a")`) and then concatenates it into another full multipart body string before writing to a temp file. For files near the 2000 KB limit this can transiently consume multiple megabytes per upload, which is significant on the stated 2–16 MB RAM targets.
Suggested fix: Stream the multipart body directly to the temp file instead of materializing both the file content and full body in memory. Write the headers, then copy the file in chunks (e.g. 8–32 KB), then write the trailer. Compute Content-Length from file size plus header/trailer lengths.

### 19. [MEDIUM] os.tmpname() race condition — TOCTOU between name generation and file creation
Location: mktemp() / os.tmpname()
Description: os.tmpname() returns a filename but does not create the file atomically. The script then opens the file with io.open(path, 'wb') to create it. Between tmpname() returning and io.open() creating the file, another process could create a file or symlink at that path (classic TOCTOU). On embedded systems running as root (common), this could be exploited to redirect writes to arbitrary paths.
Suggested fix: Use mktemp shell command instead: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). This creates the file atomically. Fall back to os.tmpname() only if mktemp is unavailable.

### 20. [MEDIUM] io.popen() handle not closed on error paths; resource leak
Location: scan_directory() / io.popen()
Description: In scan_directory(), if handle:lines() iteration is interrupted by a Lua error (e.g., out of memory processing a file path), the popen handle is never closed. Lua's garbage collector will eventually close it, but on embedded systems with limited file descriptors, leaked handles from multiple scan_directory() calls could exhaust the fd limit.
Suggested fix: Wrap the iteration in pcall or use a manual loop with explicit handle:close() in a finally-equivalent pattern: local ok, err = pcall(function() for file_path in handle:lines() do ... end end); handle:close(); if not ok then log_msg('error', err) end

### 21. [MEDIUM] Mount point paths with spaces are not handled correctly
Location: parse_proc_mounts()
Description: The pattern '^(%S+)%s+(%S+)%s+(%S+)' matches non-whitespace tokens. In /proc/mounts, mount points with spaces are encoded as \040 (octal escape), not literal spaces. This is actually handled correctly by the pattern since \040 is not whitespace. However, the extracted mount point path will contain the literal string \040 instead of a space, while the actual filesystem path uses a real space. When this path is later used in find -path exclusions, the shell_quote() will quote \040 literally, which won't match the actual path with a space.
Suggested fix: After extracting mp, decode octal escapes: mp = mp:gsub('\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end). This converts \040 to actual space before using in exclusions.

### 22. [MEDIUM] Source name not JSON-escaped before use in collection markers
Location: detect_source_name()
Description: config.source is set from hostname command output via trim(). While json_escape() is called when building the collection marker JSON, the source is also used directly in the query string via urlencode(config.source) which is correct for URLs. However, if hostname returns a value with characters that survive urlencode but are semantically significant in the API (e.g., a hostname with a hash or question mark), the endpoint URL could be malformed. More critically, the source name is used in log messages without sanitization, which is minor but could cause log injection.
Suggested fix: urlencode() already handles this correctly for URL context. The json_escape() handles JSON context. This is mostly fine, but add a length limit on source name (e.g., truncate to 253 chars, max DNS name length) to prevent excessively long URLs.

### 23. [MEDIUM] No signal handling — SIGINT/SIGTERM leaves collection in 'begun' state with no end marker
Location: main() — signal handling
Description: The other 8 collectors implement signal handling to send an 'interrupted' collection marker with current stats when SIGINT/SIGTERM is received. Lua 5.1 has no native signal handling, but the script doesn't even document this limitation or suggest a workaround. If the user presses Ctrl+C, the script exits immediately, the begin marker was sent but no end marker is sent, and the server's collection session is left open indefinitely.
Suggested fix: Document this as a known limitation in the script header (already partially done). Optionally provide a shell wrapper script that traps SIGINT/SIGTERM and sends the end marker. Add a note in --help output. Consider registering an atexit-equivalent using pcall around main() to send the end marker even on Lua errors.

### 24. [MEDIUM] Boundary value could theoretically appear in binary file content
Location: build_multipart_body()
Description: The multipart boundary is 'ThunderstormBoundary' + os.time() + math.random(10000,99999). While collisions are unlikely for text files, binary files could contain this exact byte sequence. The multipart RFC requires that the boundary not appear in the body content. No check is performed to verify the boundary doesn't appear in the file content.
Suggested fix: After reading file content, verify the boundary doesn't appear: if content:find(boundary, 1, true) then regenerate boundary end. Or use a longer random boundary (add more random components) to make collision probability negligible. curl handles this automatically when using --form, which is another reason to prefer curl's native multipart handling.

### 25. [LOW] Timestamp not included in console output, only in file output
Location: log_msg()
Description: Console output format is '[level] message' without timestamp, while file output includes timestamp. This is inconsistent and makes it harder to correlate console output with log file entries during debugging.
Suggested fix: Add timestamp to console output: io.stderr:write(string.format('[%s] [%s] %s\n', ts, level, clean))

### 26. [LOW] HTTP/1.0 would be safer than HTTP/1.1 for nc-based uploads
Location: upload_with_nc()
Description: The nc upload sends 'POST %s HTTP/1.1' with 'Connection: close'. HTTP/1.1 requires the server to support chunked transfer encoding and other features. Using HTTP/1.0 would be simpler and more reliable for a raw nc implementation since HTTP/1.0 closes the connection after the response by default, eliminating the need for Connection: close and avoiding HTTP/1.1 compliance issues.
Suggested fix: Change to 'POST %s HTTP/1.0\r\n' and remove the 'Connection: close' header. HTTP/1.0 is universally supported and simpler for raw socket communication.


## Instructions

1. Fix each finding listed above
2. Make minimal changes — do not refactor unrelated code
3. Preserve the existing code style and conventions
4. If a finding is a false positive, explain why and skip it
5. If a fix would break something else, note the trade-off

## Output

Return the complete fixed file(s). Include a brief summary of what you changed and why.

For each finding, state: FIXED, SKIPPED (with reason), or PARTIAL (with explanation).
