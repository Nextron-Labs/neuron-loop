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
Suggested fix: At the end of main(), use: if counters.files_failed > 0 then os.exit(1) else os.exit(0) end. Change die() to os.exit(2) for fatal errors. Update parse_args unknown-option handler to also use os.exit(2).

### 2. [CRITICAL] Shell injection via filename in curl --form argument
Location: upload_with_curl() / shell_quote()
Description: upload_with_curl builds the --form argument as: 'file=@<filepath>;filename="<safe_name>"'. The filepath is passed through shell_quote() which wraps in single quotes and escapes embedded single quotes. However, safe_name (from sanitize_filename) only strips backslash, double-quote, semicolon, CR, LF — it does NOT strip NUL bytes or other characters. More critically, the entire --form value is a single shell_quote() call containing both the @ path and the filename= part. If filepath itself contains a double-quote (which shell_quote does not protect inside the form value string), the curl argument parsing could be confused. The real issue: the form value string is constructed with string.format and then shell_quote'd as a whole, so a filepath like /tmp/foo'bar would be escaped by shell_quote, but the inner filename= value uses double-quotes and safe_name only strips backslash/quote/semicolon — a filename with a double-quote is replaced with underscore, so that part is safe. However, the @ path is NOT sanitized — only shell_quote'd. A path with a newline (noted as unsupported) would break the shell command. This is a known limitation but not documented for the curl case specifically.
Suggested fix: For the filepath in the curl --form value, additionally validate that it contains no characters that could escape the shell_quote boundary. Consider using curl's --form-string for the filename part and a separate --form for the file reference.

### 3. [CRITICAL] Entire file loaded into Lua memory — catastrophic on embedded systems with large files
Location: build_multipart_body()
Description: build_multipart_body() reads the entire file with f:read('*a') into a Lua string, then concatenates it with headers into another string (body), then writes it to a temp file. For a 2000 KB file (max_size_kb default), this creates at least 3 copies of the file content in memory simultaneously: the raw content string, the parts table entry, and the body string from table.concat. On a 2–16 MB RAM embedded device, a 2 MB file would consume 6+ MB just for this operation, likely causing OOM.
Suggested fix: Write the multipart body directly to the temp file in chunks rather than building it in memory. Write the headers first, then copy the source file in chunks (e.g., 64KB at a time), then write the closing boundary. Calculate body_len separately using file_size_kb * 1024 + header/footer lengths.

### 4. [HIGH] Exit codes do not follow the documented collector contract
Location: die / function body; parse_args unknown-option branch; main exit path
Description: The script exits with `os.exit(1)` for fatal errors in `die()`, and also uses `os.exit(1)` for unknown CLI options. On successful completion it implicitly exits 0 even when some files failed to upload. The stated hardened behavior for the other collectors is `0=clean, 1=partial failure, 2=fatal error`, but this Lua collector does not implement that contract.
Suggested fix: Introduce explicit final exit status handling: use `os.exit(2)` for fatal errors in `die()` and argument/validation failures; after the scan, exit `1` if `counters.files_failed > 0`, otherwise `0`. Example: `local code = (counters.files_failed > 0) and 1 or 0; cleanup_temp_files(); if log_file_handle then log_file_handle:close() end; os.exit(code)`.

### 5. [HIGH] Missing required begin-marker retry on initial failure
Location: main / begin marker send block
Description: The script sends the `begin` collection marker exactly once via `send_collection_marker(base_url, "begin", nil, nil)`. If that initial request fails transiently, no retry is attempted, despite the documented hardening requirement of a single retry after 2 seconds on initial failure.
Suggested fix: If the first begin marker returns an empty `scan_id`, sleep 2 seconds and retry once before proceeding. Example: `scan_id = send_collection_marker(...); if scan_id == "" then os.execute("sleep 2"); scan_id = send_collection_marker(...) end`.

### 6. [HIGH] Custom CA bundle support (`--ca-cert`) is missing
Location: CLI parsing/help + upload_with_curl + upload_with_wget + send_collection_marker
Description: The hardened requirements explicitly include `--ca-cert PATH` for TLS validation with custom CA bundles, but the Lua collector neither parses this option nor passes a CA bundle to curl/wget. It only supports `--ssl` and `--insecure`.
Suggested fix: Add `config.ca_cert`, parse `--ca-cert <path>`, validate the file exists, and pass it to backends (`curl --cacert <path>`, `wget --ca-certificate=<path>` where supported). Reject incompatible combinations only where necessary.

### 7. [HIGH] No interruption handling or documented wrapper strategy for SIGINT/SIGTERM
Location: main / collection lifecycle; entire script
Description: The requirements call out signal handling parity via a shell-wrapper approach because Lua 5.1 lacks native signal handling on these targets. This script has neither in-process handling nor any documented/implemented wrapper mechanism to send an `interrupted` collection marker with stats on SIGINT/SIGTERM.
Suggested fix: Implement the documented shell-wrapper approach: have a small POSIX shell launcher trap `INT`/`TERM`, invoke the Lua collector in a way that persists state/stats, and send an `interrupted` marker before exit. If that is intentionally unsupported, document the limitation explicitly in the script/help and release notes.

### 8. [HIGH] Multipart body construction reads entire file into memory and duplicates it
Location: build_multipart_body / full function; upload_with_wget; upload_with_nc; upload_with_busybox_wget
Description: For wget/nc uploads, `build_multipart_body()` reads the whole sample with `f:read("*a")`, concatenates it into a Lua table, then `table.concat`s the full multipart body, and finally writes that body to a temp file. This creates multiple in-memory copies of the sample plus headers. On 2–16 MB embedded devices, a file near the 2000 KB limit can consume several megabytes transiently.
Suggested fix: Stream multipart construction directly to the temp file instead of materializing the whole body in memory. Write headers, then copy the source file in chunks (e.g. 8–32 KB), then write the closing boundary. Compute `Content-Length` from file size plus header/footer lengths if needed.

### 9. [HIGH] Shell injection via --post-data with unquoted body containing special characters
Location: send_collection_marker() / wget/busybox-wget branch
Description: In send_collection_marker(), the wget branch uses --post-data=<shell_quote(body)>. The body is a JSON string containing config.source which comes from hostname output or --source CLI argument. shell_quote() wraps in single quotes and escapes embedded single quotes. However, the wget command is built as a format string where --post-data=%s uses shell_quote(body). If body contains characters that interact with wget's own argument parsing (e.g., very long strings, or if shell_quote fails for some edge case), this could be problematic. More concretely: the --header option uses --header='Content-Type: ...' with literal single quotes in the format string, NOT through shell_quote. This means if the format string itself is passed to a shell that interprets it, the quoting is inconsistent. The --header value is hardcoded so this is low risk there, but --post-data uses shell_quote correctly.
Suggested fix: Write the JSON body to a temp file and use --post-file= instead of --post-data= for the wget marker call, consistent with how upload_with_wget works.

### 10. [HIGH] find prune logic is incorrect — pruned paths are still printed
Location: build_find_command()
Description: The find command is built as: find <dir> -path X -prune -o -path Y -prune -o ... -o -type f -mtime -N -print. This is the correct POSIX pattern. However, the prune_str is constructed as: table.concat(prune_parts, ' -o ') .. ' -o '. Each prune_part is '-path X -prune'. The final command becomes: find dir -path X -prune -o -path Y -prune -o -type f -mtime -N -print. This is actually correct POSIX find syntax. BUT: if a pruned directory itself matches -type f (it won't, it's a dir), or if the prune path is a prefix of the scan dir itself, find may behave unexpectedly. The real bug: -path matching in find uses glob patterns, and the paths in EXCLUDE_PATHS like '/proc' will match '/proc' exactly but NOT '/proc/something' unless the pattern is '/proc/*'. The correct pattern for pruning a directory tree is '-path /proc -prune -o -path /proc/* -prune'. As written, files directly inside /proc would be pruned (since /proc matches), but this depends on find implementation. On BusyBox find, -path /proc matches the directory /proc itself, so -prune prevents descent — this is actually correct behavior for directory pruning.
Suggested fix: Test the find prune behavior on BusyBox. Consider using '-path /proc -prune -o -path /proc/* -prune' for robustness, or use the pattern '-path "/proc*" -prune' to catch both the dir and its contents.

### 11. [HIGH] nc (netcat) upload reads entire response into memory and has no timeout on response reading
Location: upload_with_nc()
Description: exec_capture() uses io.popen() to run the nc command and reads the entire response with handle:read('*a'). The nc command has -w 30 (30s write timeout) but the response reading in Lua has no timeout. If the server sends a partial response and keeps the connection open, io.popen read will block indefinitely. Additionally, exec_capture captures stdout of the pipeline 'cat file | nc ...', which is the server's HTTP response — this could be megabytes if the server misbehaves.
Suggested fix: Add a timeout wrapper: use 'timeout 35 sh -c "cat ... | nc -w 30 ..."' or redirect nc output to a temp file with a timeout, then read the temp file. Also limit response reading to first 4KB.

### 12. [HIGH] Missing --ca-cert option for custom CA bundle (parity gap with other 8 collectors)
Location: main() — --ca-cert option missing
Description: The other 8 hardened collectors support --ca-cert PATH for TLS certificate validation with custom CA bundles. This script has no --ca-cert option. When --ssl is used on embedded systems that lack system CA stores, there is no way to provide a custom CA certificate, forcing users to use --insecure (-k) which disables all TLS validation.
Suggested fix: Add config.ca_cert = '' field, add --ca-cert <path> CLI option in parse_args(), and pass --cacert <path> to curl or --ca-certificate <path> to wget when config.ca_cert ~= ''.

### 13. [HIGH] Backslash escape pattern in gsub is incorrect — only strips backslash, not escaping it
Location: sanitize_filename()
Description: sanitize_filename() uses: r = s:gsub('["\\;]', '_'). In a Lua character class, \\ is a single backslash. So the pattern '["\\;]' matches double-quote, backslash, and semicolon. This appears correct. However, the intent is to sanitize for use in a Content-Disposition header filename= value which is double-quoted. The function replaces these with underscore, which is safe. BUT: it does not handle forward slashes in the basename. Since filename is extracted as filepath:match('([^/]+)$'), it won't contain slashes. It also doesn't handle NUL bytes (\0) which could truncate C-string processing in curl/wget. NUL bytes in filenames are extremely rare but possible on Linux.
Suggested fix: Add NUL byte stripping: r = r:gsub('%z', '_') (Lua pattern %z matches NUL). Also consider stripping other control characters.

### 14. [HIGH] io.popen handle not closed on early return paths; resource leak
Location: scan_directory() / io.popen()
Description: In scan_directory(), if handle:lines() iteration is interrupted by an error in a called function (e.g., submit_file throws an uncaught error via pcall boundary), the popen handle is never closed. More practically: if the script is killed (SIGTERM), the popen handle leaks. In Lua 5.1 on embedded systems, unclosed popen handles can leave zombie find processes running.
Suggested fix: Wrap the iteration in a pcall or use a pattern that ensures handle:close() is always called: local ok, err = pcall(function() for file_path in handle:lines() do ... end end); handle:close(); if not ok then log_msg('error', err) end

### 15. [MEDIUM] Use of `os.tmpname()` is unsafe/unreliable on embedded Unix targets
Location: mktemp / function body
Description: `mktemp()` relies on `os.tmpname()` and then opens the returned path. On Unix-like systems this is prone to race conditions because the name generation and file creation are separate operations. On some minimal environments `os.tmpname()` may also return unusable paths or fail unexpectedly.
Suggested fix: Prefer invoking a shell `mktemp` utility when available (`mktemp /tmp/thunderstorm.XXXXXX`) and fall back carefully only if absent. If keeping a Lua fallback, create files under a fixed writable temp dir with randomized names and retry on collision.

### 16. [MEDIUM] Collection marker requests ignore command success and can silently fail
Location: send_collection_marker / curl and wget command construction
Description: Both curl and wget branches in `send_collection_marker()` call `os.execute(cmd)` but do not check whether the command succeeded. The function then attempts to parse `resp_file` if present and otherwise returns an empty string. This suppresses transport failures and makes begin/end marker delivery failures indistinguishable from a valid empty response.
Suggested fix: Use `exec_ok(cmd)` and log failures to stderr/log file. Return a success flag plus optional `scan_id`, e.g. `return false, ""` on transport failure and `return true, id or ""` on HTTP success.

### 17. [MEDIUM] Unconditional stdout output breaks quiet/non-interactive behavior parity
Location: main / banner and summary output
Description: The script always prints the ASCII banner and final summary to stdout, even when `--quiet` is set. The hardened behavior described for the other collectors includes TTY-aware progress control and routing errors to stderr; this collector still emits normal-status output unconditionally to stdout.
Suggested fix: Suppress banner/summary unless stdout is a TTY and quiet mode is off, or add explicit `--progress/--no-progress` parity and gate human-oriented output behind it. Keep errors on stderr.

### 18. [MEDIUM] json_escape %c pattern also matches \n, \r, \t which are already escaped above it
Location: json_escape()
Description: json_escape() first replaces \n, \r, \t with their JSON escape sequences, then applies s:gsub('%c', ...) which matches ALL control characters including \n (0x0A), \r (0x0D), \t (0x09). Since gsub processes the string sequentially and the prior replacements have already converted these to multi-character escape sequences (e.g., \n becomes the two characters backslash+n), the %c pattern will NOT re-match them (backslash is 0x5C, not a control char; 'n' is 0x6E). So this is actually safe. However, it's fragile and confusing. More importantly: the %c pattern in Lua matches characters where iscntrl() is true, which includes 0x7F (DEL). DEL should also be escaped in JSON (it's not required by JSON spec but is good practice). This is a minor correctness issue.
Suggested fix: After the %c gsub, add: s = s:gsub('\x7f', '\\u007f'). Or rewrite json_escape to handle all cases in a single pass.

### 19. [MEDIUM] URL path extraction regex fails for URLs with no path component
Location: upload_with_nc() — path_rest extraction
Description: In upload_with_nc(), path_rest is extracted with: hostpath:match('^[^/]+/(.*)$'). If the URL is 'http://host:8080' (no trailing slash, no path), hostpath is 'host:8080' and path_rest is nil, so path_query becomes '/'. But the actual endpoint always has '/api/checkAsync?...' so this shouldn't occur in practice. However, if config.server contains a slash (e.g., user error), hostpath parsing breaks entirely. The host extraction host = hostport:match('^([^:]+)') would also fail if hostport is nil.
Suggested fix: Add nil checks: if not hostport then log_msg('error', 'Invalid endpoint URL for nc'); return false end. Validate config.server doesn't contain slashes in validate_config().

### 20. [MEDIUM] wget_is_busybox() spawns a subprocess even when wget is not available
Location: detect_upload_tool() / wget_is_busybox()
Description: detect_upload_tool() calls wget_is_busybox() only after confirming wget exists (has_wget is true), so this is actually fine. However, wget_is_busybox() uses exec_capture('wget --version 2>&1') which on some BusyBox systems causes wget to actually attempt a connection or print usage to stderr and exit non-zero. The 2>&1 redirect captures both, so the output check works. But on systems where 'wget --version' is not recognized (BusyBox wget may not support --version), it may print usage/error text that doesn't contain 'busybox', causing it to be misidentified as GNU wget.
Suggested fix: Also check if the output contains 'GNU Wget' to positively identify GNU wget, rather than relying solely on absence of 'busybox': if output:lower():find('gnu wget') then return false (it's GNU); elseif output:lower():find('busybox') then return true; else return true (assume busybox if unknown) end.

### 21. [MEDIUM] Syslog via os.execute('logger ...') called for every log message — severe performance issue
Location: main() — syslog logging in log_msg()
Description: When config.log_to_syslog is true, every call to log_msg() spawns a new shell process to run logger. For a scan of thousands of files with debug enabled, this spawns thousands of processes. On embedded systems with limited process table size and slow fork(), this can severely degrade performance or exhaust system resources.
Suggested fix: Rate-limit syslog calls (e.g., only log warn/error/info to syslog, not debug), or batch syslog writes. At minimum, document that --syslog with --debug is not recommended on embedded systems.

### 22. [MEDIUM] Boundary string not verified to be absent from file content
Location: build_multipart_body() — boundary generation
Description: The multipart boundary is generated as '----ThunderstormBoundary' + os.time() + math.random(10000,99999). This boundary is NOT checked against the file content. If a binary file happens to contain this exact byte sequence, the multipart body will be malformed, causing the server to reject or misparse the upload. While the probability is low for any single file, over millions of files it becomes a real risk.
Suggested fix: After reading file content, verify the boundary is not present: while content:find(boundary, 1, true) do boundary = regenerate() end. Or use a longer random boundary (e.g., 32 hex chars from os.time + multiple math.random calls).

### 23. [MEDIUM] Unknown options after valid options are silently ignored if they don't start with '-'
Location: parse_args() — unknown option handling
Description: parse_args() only checks a:sub(1,1) == '-' for unknown option detection. Positional arguments (non-flag tokens) are silently ignored. A user typo like 'lua collector.lua --server foo.com /tmp' would silently ignore '/tmp' instead of warning. This is a usability issue but could also mask misconfiguration.
Suggested fix: Add an else clause to the option parsing chain that warns about unrecognized non-flag arguments: else if a:sub(1,1) ~= '-' then io.stderr:write('[warn] Ignoring unexpected argument: ' .. a .. '\n') end

### 24. [MEDIUM] Race condition between file_size_kb() check and actual upload
Location: file_size_kb()
Description: file_size_kb() opens the file to seek to end for size, then closes it. The actual upload happens later in submit_file(). Between these two operations, the file could grow beyond max_size_kb (e.g., an active log file). The upload would then send a file larger than the configured limit.
Suggested fix: This is an inherent TOCTOU race on a live filesystem. Document it as a known limitation. Optionally, re-check file size in the upload function before sending, or use the Content-Length from the actual bytes read.

### 25. [MEDIUM] No signal handling — interrupted runs send no 'interrupted' collection marker (parity gap)
Location: main() — signal handling
Description: The other 8 collectors send an 'interrupted' collection marker with stats when receiving SIGINT/SIGTERM. This Lua script has no signal handling at all. When killed, it exits immediately without sending the end marker or interrupted marker, leaving the server-side collection in an unknown state.
Suggested fix: Document this as a known Lua 5.1 limitation (no native signal handling). Provide a shell wrapper that traps SIGINT/SIGTERM and calls the script with a flag, or use a trap in the calling shell. Add a note in the script header about this limitation.

### 26. [MEDIUM] GNU wget --post-file does not set Content-Length, causing chunked transfer issues
Location: upload_with_wget() — wget --post-file with multipart
Description: GNU wget's --post-file sends the file contents but does not automatically set Content-Length (it uses chunked transfer encoding or relies on the server to handle it). The --header only sets Content-Type. Some HTTP/1.0 servers or simple Thunderstorm implementations may not handle chunked transfer encoding, causing upload failures. The body_len variable is calculated but never used in the wget upload.
Suggested fix: Add --header='Content-Length: <body_len>' to the wget command. The body_len is already calculated by build_multipart_body() but unused in upload_with_wget().

### 27. [LOW] os.tmpname() on some systems returns a name without creating the file, creating a TOCTOU race
Location: mktemp()
Description: The code comments acknowledge this: 'os.tmpname may just return a name on some systems'. The workaround (opening and closing the file) is implemented. However, on systems where os.tmpname() returns a name in /tmp that doesn't exist yet, there's a brief window between the name generation and file creation where another process could create a file with the same name (symlink attack). On embedded systems this is very low risk but worth noting.
Suggested fix: On Linux, prefer using mktemp shell command: local path = trim(exec_capture('mktemp 2>/dev/null') or ''). Fall back to os.tmpname() if mktemp is unavailable.

### 28. [LOW] Console log output missing timestamp (inconsistency with file log)
Location: log_msg() — console output
Description: File log entries include timestamp: '%s %s %s\n' (ts, level, clean). Console (stderr) output only shows '[level] message' without timestamp. The other collectors consistently include timestamps in console output.
Suggested fix: Change console output to: io.stderr:write(string.format('[%s] [%s] %s\n', ts, level, clean))

### 29. [LOW] All variables are global — risk of accidental pollution and harder debugging
Location: global scope
Description: config, counters, EXCLUDE_PATHS, dynamic_excludes, temp_files, log_file_handle, and all functions are global. In Lua 5.1, this means any typo in a variable name silently creates a new global instead of erroring. On embedded systems with multiple Lua scripts, global pollution could cause subtle bugs if this script is require()'d.
Suggested fix: Add 'local' declarations for module-level variables. At minimum, add a comment that this script is designed to be run standalone, not require()'d.


## Instructions

1. Fix each finding listed above
2. Make minimal changes — do not refactor unrelated code
3. Preserve the existing code style and conventions
4. If a finding is a false positive, explain why and skip it
5. If a fix would break something else, note the trade-off

## Output

Return the complete fixed file(s). Include a brief summary of what you changed and why.

For each finding, state: FIXED, SKIPPED (with reason), or PARTIAL (with explanation).
