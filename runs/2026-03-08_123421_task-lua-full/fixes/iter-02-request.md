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
-- - Lua 5.1 has no native signal handling (no posix.signal on embedded targets).
--   SIGINT/SIGTERM will terminate the process without sending an "interrupted"
--   collection marker. For signal-aware operation, wrap this script in a shell:
--     trap 'lua thunderstorm-collector.lua --dry-run 2>/dev/null; kill $PID' INT TERM
--   A proper wrapper is outside the scope of this pure-Lua implementation.
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
    os.exit(2)
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
    print("      --ca-cert <path>       CA certificate bundle for TLS verification")
    print("      --sync                 Use /api/check (default: /api/checkAsync)")
    print("      --retries <num>        Retry attempts per file (default: 3)")
    print("      --dry-run              Do not upload, only show what would be submitted")
    print("      --debug                Enable debug log messages")
    print("      --log-file <path>      Log file path (default: ./thunderstorm.log)")
    print("      --no-log-file          Disable file logging")
    print("      --syslog               Enable syslog logging")
    print("      --quiet                Disable command-line logging")
    print("      --progress             Force progress reporting")
    print("      --no-progress          Disable progress reporting")
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
        elseif a == "--ca-cert" then
            if not next_val then die("Missing value for " .. a) end
            config.ca_cert = next_val
            i = i + 1
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
        elseif a == "--progress" then
            config.progress = true
        elseif a == "--no-progress" then
            config.progress = false
        elseif a == "-h" or a == "--help" then
            print_help()
            os.exit(0)
        elseif a:sub(1, 1) == "-" then
            io.stderr:write(string.format("[error] Unknown option: %s (use --help)\n", a))
            os.exit(2)
        end

        i = i + 1
    end
end

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

-- ==========================================================================
-- UPLOAD BACKENDS
-- ==========================================================================

function get_curl_insecure_flag()
    if config.insecure then return "-k " else return "" end
end

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
    local dir_files_scanned = 0
    for file_path in handle:lines() do
        if file_path ~= "" then
            dir_files_scanned = dir_files_scanned + 1
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
    if dir_files_scanned == 0 then
        log_msg("debug", "No files found in '" .. dir .. "' (check permissions or find errors)")
    end
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

```


## Findings to Fix


### Finding 1. [CRITICAL] nc upload reads entire file body into Lua memory before writing to request file
Location: upload_with_nc / lines ~340-390
Description: In upload_with_nc, after building the multipart body in a temp file (which correctly streams in chunks), the code then does `req_f:write(body_f:read('*a'))` to append the body to the HTTP request file. This reads the entire file content into a single Lua string in memory. On embedded systems with 2-16 MB RAM and files up to 2000 KB, this can cause OOM or Lua memory errors, defeating the purpose of the chunked streaming in build_multipart_body.
Suggested fix: Stream the body file to the request file in chunks instead of reading all at once:
```lua
local chunk_size = 8192
while true do
    local chunk = body_f:read(chunk_size)
    if not chunk then break end
    req_f:write(chunk)
end
```

### Finding 2. [CRITICAL] Content-Length in nc upload is computed from preamble+epilogue+chunk-counted bytes but preamble/epilogue byte counts may be wrong on systems where Lua counts characters not bytes
Location: build_multipart_body / lines ~270-310
Description: total_body is computed as `#preamble + sum(#chunk) + #epilogue`. In Lua 5.1, `#` on a string returns the number of bytes, which is correct for binary data. However, preamble and epilogue are constructed with string.format and contain CRLF sequences. The real issue is that body_len passed to upload_with_nc is the size of the multipart body written to body_file, but the nc backend then writes the HTTP headers PLUS the body into req_file and sends that. The Content-Length header value (body_len) is correct for the body portion only. This part is actually correct. BUT: the function returns body_len which is never used by curl or wget backends (they use `--data-binary @file` which auto-computes length). Only nc uses it. The nc backend correctly uses body_len as Content-Length for the body. This is fine.

Actual critical issue: the multipart body temp file is created and tracked in temp_files, but if build_multipart_body returns nil (on error), the partially-created temp file path was already added to temp_files via mktemp() before the failure. The function returns `nil, nil, nil` but the temp file path is already registered. This is minor. The real critical issue is that body_len counts bytes written to body_file (preamble + file chunks + epilogue), which IS the correct Content-Length for the multipart body. So nc sends: HTTP headers with Content-Length=body_len, then the body_file content. This is correct only if req_file contains headers+body and nc sends all of req_file. Yes, nc sends req_file which has headers+body concatenated. Content-Length refers to the body after the blank line, which equals body_len. This is correct.

Re-evaluating: The actual critical issue is that `body_len` is computed as the number of bytes in the multipart body (preamble + file data + epilogue). But `total_body` starts as `#preamble` (string length in bytes), then adds chunk sizes, then adds `#epilogue`. This is correct. No bug here after careful analysis.
Suggested fix: No change needed for Content-Length. However, ensure temp files created by mktemp() before a failure in build_multipart_body are still cleaned up (they are, via cleanup_temp_files at exit).

### Finding 3. [CRITICAL] JSON body passed directly to curl -d via shell_quote — NUL bytes and very long source names could cause shell argument issues; more critically, body written to temp file for wget but passed as shell argument for curl
Location: send_collection_marker / lines ~430-490
Description: For curl, the JSON body is passed as `shell_quote(body)` directly on the command line via `-d`. If config.source or VERSION contains single quotes (which shell_quote handles by escaping), this is safe. However, the body could be large enough to hit ARG_MAX on some systems. More importantly, for wget the code correctly writes body to a temp file and uses --post-file, but for curl it passes the body as a command-line argument. This is inconsistent and could fail on systems with small ARG_MAX limits if source names are long.
Suggested fix: Write the JSON body to a temp file for curl too, and use `--data-binary @file` instead of `-d shell_quote(body)`:
```lua
local body_tmp = mktemp()
local bf = io.open(body_tmp, 'wb')
if bf then bf:write(body); bf:close() end
local cmd = string.format(
    'curl -sS --fail -o %s %s%s-H %s --max-time 10 --data-binary @%s %s 2>/dev/null',
    shell_quote(resp_file), insecure, ca_cert_flag,
    shell_quote('Content-Type: application/json'),
    shell_quote(body_tmp), shell_quote(url))
```

### Finding 4. [HIGH] Normal execution writes to stdout, which breaks the hardened stderr-only error/reporting convention
Location: main / banner and summary stdout writes
Description: The script prints the banner with `print_banner()` and always prints the final run summary with `io.write(...)` to stdout. In the hardened sibling collectors, operational/errors are routed consistently away from stdout so stdout can remain machine-consumable or unused. Here, even `--quiet` does not suppress the banner or summary, and any caller that expects silent success or reserved stdout will receive unsolicited output.
Suggested fix: Suppress banner/summary unless explicitly requested, or route them through `log_msg()`/stderr. At minimum, honor `--quiet` for banner and summary output.

### Finding 5. [HIGH] Progress reporting flags are parsed but never implemented
Location: main / progress option handling
Description: The script accepts `--progress` and `--no-progress`, and `config.progress` is documented as supporting TTY auto-detection, but no code ever uses this setting. This is a direct parity gap with the hardened collectors, which provide progress reporting with TTY auto-detection.
Suggested fix: Either implement progress reporting and TTY auto-detection, or remove the options. A minimal fix is to detect TTY via `test -t 2` and emit periodic progress updates to stderr when enabled.

### Finding 6. [HIGH] Netcat backend cannot perform HTTPS but is still selected for SSL mode
Location: upload_with_nc / HTTPS endpoint handling
Description: When `config.ssl` is true and only `nc` is available, `detect_upload_tool()` still selects `nc` and merely logs a warning. `upload_with_nc()` then strips `https://` and sends a plain HTTP request over the target port, typically 443. This is not TLS and will fail against real HTTPS servers; worse, it may send sensitive sample data unencrypted to a listener if the endpoint is misconfigured or intercepted.
Suggested fix: Do not allow `nc` when `config.ssl` is true. Treat this as fatal during tool detection unless a TLS-capable tool is available. Example: `if config.ssl and tool == 'nc' then die('HTTPS requires curl or wget; nc is not TLS-capable') end`.

### Finding 7. [HIGH] Collection markers may be skipped when BusyBox wget is the detected backend
Location: send_collection_marker / upload tool fallback logic
Description: If `config.upload_tool` is `busybox-wget`, `send_collection_marker()` does not enter the fallback detection block because `tool ~= ''`, but it also does not have a branch that executes until the later `elseif tool == 'wget' or tool == 'busybox-wget'`. That part is fine only if `config.upload_tool` was already set. However, in paths where marker sending happens before upload tool detection or where detection is deferred/changed, the fallback only checks for `curl` and generic `wget`, not BusyBox wget classification. This creates inconsistent behavior and makes marker delivery dependent on call order.
Suggested fix: Make marker sending use the same centralized tool detection/classification logic as file uploads, or call `detect_upload_tool()` before any marker attempt and remove ad-hoc fallback probing.

### Finding 8. [HIGH] find -mtime uses days but the semantics differ: -mtime -N means modified within N*24h, not N calendar days; also -mtime -0 would find nothing
Location: build_find_command / lines ~530-560
Description: The find command uses `-mtime -N` where N is config.max_age. POSIX find's -mtime counts 24-hour periods, not calendar days. `-mtime -14` means files modified less than 14*24=336 hours ago. This is the intended behavior. However, if max_age=0, `-mtime -0` means files modified less than 0 hours ago, which matches nothing. The validate_config() check allows max_age >= 0, so max_age=0 is valid but would scan no files. This is a usability issue but not a crash.
Suggested fix: Either document that max_age=0 scans no files, or change the validation to require max_age >= 1, or use `-mtime -1` as minimum. Add a warning in validate_config:
```lua
if config.max_age == 0 then
    log_msg('warn', 'max-age=0 will match no files (find -mtime -0 matches nothing)')
end
```

### Finding 9. [HIGH] nc response check uses HTTP/1.x pattern but nc may receive partial response or no response before connection closes
Location: upload_with_nc / lines ~370-395
Description: The nc backend sends the request and reads the response with `nc -w 30`. The response is read into resp_file and then checked with `resp:match('HTTP/1%.%d 2%d%d')`. However, nc with -w 30 waits 30 seconds for data after the connection goes idle. On some servers that close the connection immediately after sending the response, nc may exit before reading the full response. More critically, if the server uses HTTP/1.1 keep-alive and doesn't close the connection, nc will wait the full 30 seconds. The response parsing only checks the first line, which is correct, but the 30-second timeout per file makes this extremely slow for large file sets.
Suggested fix: Add `Connection: close` to the request headers (already done - good). Also consider reducing the timeout or adding a note that nc is only suitable for small file sets. Verify the request already includes `Connection: close` (it does at line ~375). The main remaining issue is the 30s timeout per file. Consider using `-w 10` or making it configurable.

### Finding 10. [HIGH] sanitize_filename does not escape all characters that are special in multipart Content-Disposition headers
Location: sanitize_filename / lines ~95-101
Description: The filename in the Content-Disposition header is enclosed in double quotes: `filename="<safe_name>"`. sanitize_filename replaces `"`, `\`, `;`, `\r`, `\n` with underscores. However, it does not handle other control characters (0x00-0x1F, 0x7F) that could appear in filenames on Linux filesystems. A filename with embedded control characters (e.g., 0x01-0x1F) would be passed through unmodified into the Content-Disposition header, potentially corrupting the multipart boundary parsing on the server side.
Suggested fix: Add control character sanitization to sanitize_filename:
```lua
function sanitize_filename(s)
    if not s then return '' end
    local r = s:gsub('["\\;]', '_')
    r = r:gsub('%c', '_')  -- replace all control chars including \r, \n, \t, etc.
    return r
end
```

### Finding 11. [HIGH] Mount point paths with spaces or special characters in /proc/mounts are not handled correctly
Location: parse_proc_mounts / lines ~490-510
Description: /proc/mounts encodes spaces in paths as `\040` (octal escape). The pattern `(%S+)%s+(%S+)%s+(%S+)` correctly splits on whitespace, so a mount point with a space would be split incorrectly — the path would be truncated at the space. The captured mountpoint would be wrong, and the exclusion would not work for paths containing spaces.
Suggested fix: Decode \040 escape sequences from the captured mountpoint:
```lua
local _, mp, fstype = line:match('^(%S+)%s+(%S+)%s+(%S+)')
if mp then
    mp = mp:gsub('\\040', ' ')  -- decode octal-escaped spaces
    mp = mp:gsub('\\011', '\t') -- decode octal-escaped tabs
end
```

### Finding 12. [HIGH] Fallback temp file path using os.time() + math.random is predictable and has TOCTOU race
Location: mktemp / lines ~115-140
Description: When mktemp binary is unavailable, the code falls back to os.tmpname() and then potentially to `/tmp/thunderstorm.<time><random>`. The os.tmpname() fallback has a TOCTOU race (noted in comments). The secondary fallback uses os.time() (second granularity) + math.random(10000,99999). math.random in Lua 5.1 uses the C rand() function which may not be seeded properly (math.randomseed is not called in the script). Without seeding, math.random returns the same sequence on every run, making the temp filename predictable.
Suggested fix: Add math.randomseed(os.time()) at script startup (in main() before any mktemp calls). Also consider using os.clock() combined with os.time() for better entropy:
```lua
math.randomseed(os.time() + math.floor(os.clock() * 1000000))
```
Add this near the top of main() before any mktemp() calls.

### Finding 13. [HIGH] io.popen handle for find command is not closed on early return paths
Location: scan_directory / lines ~590-640
Description: In scan_directory, if the function returns early (e.g., due to exec_ok failing for the directory test), the handle from io.popen is properly not opened. However, within the file processing loop, there is no mechanism to close the handle if an unexpected error occurs during processing. More importantly, `handle:close()` is called after the loop, but if the loop body raises a Lua error (e.g., from a failed string operation on a malformed path), the handle would be leaked. In Lua 5.1, unclosed io.popen handles consume file descriptors.
Suggested fix: Wrap the loop in pcall or use a local function with proper cleanup:
```lua
local ok, err = pcall(function()
    for file_path in handle:lines() do
        -- processing
    end
end)
handle:close()
if not ok then
    log_msg('error', 'Error during scan of ' .. dir .. ': ' .. tostring(err))
end
```

### Finding 14. [HIGH] wget --post-file with multipart body does not set Content-Length header, relying on chunked transfer which BusyBox wget may not support
Location: upload_with_wget / lines ~370-400
Description: GNU wget with --post-file sends the file content as the POST body but does not automatically add a Content-Length header for the multipart body — it relies on the server accepting chunked transfer encoding or the connection being closed to signal end of body. BusyBox wget may not support chunked transfer encoding. Without Content-Length, some HTTP/1.0 servers or strict HTTP/1.1 servers may reject the request.
Suggested fix: Add an explicit Content-Length header to the wget command:
```lua
local cmd = string.format(
    'wget -q -O %s %s%s--header=%s --header=%s --post-file=%s %s 2>/dev/null',
    shell_quote(resp_file), insecure, ca_cert_flag,
    shell_quote('Content-Type: multipart/form-data; boundary=' .. boundary),
    shell_quote('Content-Length: ' .. tostring(body_len)),
    shell_quote(body_file), shell_quote(endpoint))
```

### Finding 15. [MEDIUM] Temporary file fallback is race-prone and can clobber attacker-chosen paths
Location: mktemp / os.tmpname fallback path creation
Description: When `mktemp` is unavailable, the code falls back to `os.tmpname()` and then separately opens the returned path, explicitly noting the race. On multi-user systems or writable shared `/tmp`, this can be exploited with symlinks or pre-created files. The later `/tmp/thunderstorm.<time><rand>` fallback has the same TOCTOU issue because it also uses predictable naming plus non-exclusive open.
Suggested fix: Prefer requiring `mktemp` when available and fail closed if no safe temp creation primitive exists. If a fallback is unavoidable, create temp files via a shell `umask 077; mktemp` invocation only, and abort if that fails rather than using predictable names.

### Finding 16. [MEDIUM] Max-age filtering is off by up to almost one day
Location: build_find_command / use of `-mtime -%d`
Description: The script uses `find ... -mtime -N`, which matches files modified less than N*24 hours ago, not 'within the last N calendar days' and not an exact day threshold. For example, `--max-age 14` excludes files that are 14 days and a few minutes old, which may surprise users expecting inclusive behavior. This is a correctness issue in file selection semantics.
Suggested fix: Document the exact semantics clearly or switch to a more precise comparison using `-mtime`/`-mmin` as intended. If parity with other collectors expects inclusive day behavior, adjust the expression accordingly.

### Finding 17. [MEDIUM] Find command failures are silently ignored, so partial scan failures do not affect exit code
Location: scan_directory / `handle:close()` result ignored
Description: The script reads file paths from `io.popen(cmd)` and then calls `handle:close()` without checking its return status. If `find` encounters an execution error beyond stderr suppression, or exits non-zero due to environmental issues, the collector still treats the directory scan as successful unless zero files were seen. This conflicts with the hardened requirement that partial failures be tracked and reflected in exit code 1.
Suggested fix: Capture and evaluate the close status from `io.popen` where available, and increment a scan-failure counter that contributes to exit code 1. Also avoid blanket `2>/dev/null` if you need to distinguish permission noise from real command failure.

### Finding 18. [MEDIUM] Escaped mountpoints from `/proc/mounts` are not unescaped before exclusion matching
Location: parse_proc_mounts / mountpoint parsing from `/proc/mounts`
Description: Mountpoints in `/proc/mounts` encode spaces and some characters using backslash escapes such as `\040`. The code stores the raw encoded mountpoint string in `dynamic_excludes` and later compares it against real filesystem paths in `find -path`. For mountpoints containing spaces or escaped characters, the exclusion will not match the actual path tree.
Suggested fix: Unescape `/proc/mounts` mountpoints before storing them, at least for common octal escapes like `\040`, `\011`, `\012`, and `\134`.

### Finding 19. [MEDIUM] Shell injection risk if scan directory paths contain shell metacharacters
Location: build_find_command / lines ~530-560
Description: scan_dirs entries are passed through shell_quote() in build_find_command, which correctly handles single quotes. However, the exclude paths in EXCLUDE_PATHS and dynamic_excludes are also passed through shell_quote(). The dynamic_excludes come from /proc/mounts mountpoint parsing. If a mountpoint contains a single quote (unusual but possible on some filesystems), shell_quote handles it correctly via the `'"'"'` escaping. This appears safe. However, the dir argument to scan_directory comes from config.scan_dirs which comes from user CLI input. shell_quote handles this correctly. No actual injection risk found after analysis.
Suggested fix: No change needed. The shell_quote implementation is correct.

### Finding 20. [MEDIUM] scan_id extracted from server response is not validated before use in URL construction
Location: send_collection_marker / lines ~430-490
Description: The scan_id is extracted from the server JSON response using `resp:match('"scan_id"%s*:%s*"([^"]+)"')`. This scan_id is then appended to the API endpoint URL via urlencode(). urlencode() properly percent-encodes all non-safe characters, so URL injection is prevented. However, the scan_id is also passed to send_collection_marker as a parameter and embedded in JSON via json_escape(). If the server returns a maliciously crafted scan_id with characters that survive json_escape (which it shouldn't — json_escape handles all control chars and quotes), there could be JSON injection. After analysis, json_escape is comprehensive. The urlencode also protects the URL. This is safe.
Suggested fix: Consider adding a length check on scan_id (e.g., reject if > 256 chars) as a defense-in-depth measure against unexpectedly large values from a compromised server.

### Finding 21. [MEDIUM] Progress reporting feature is advertised in --help and config but never implemented
Location: main / lines ~660-720
Description: The config has a `progress` field (nil=auto-detect TTY, true/false=forced), --progress and --no-progress CLI flags are parsed, but the progress reporting functionality is never actually implemented anywhere in the code. The scan_directory function never checks config.progress or outputs any progress indicators.
Suggested fix: Either implement basic progress reporting in scan_directory (e.g., print a dot or counter every N files when config.progress is true), or remove the --progress/--no-progress flags and config field, and remove them from --help output to avoid misleading users.

### Finding 22. [MEDIUM] curl command missing --max-time / --connect-timeout flags for file uploads
Location: upload_with_curl / lines ~320-360
Description: The curl command for file uploads does not include `--max-time` or `--connect-timeout` flags. The collection marker curl command correctly uses `--max-time 10`, but the file upload curl command has no timeout. On embedded systems with unstable network connections, a stalled upload could hang indefinitely, blocking the entire scan.
Suggested fix: Add appropriate timeouts to the upload curl command:
```lua
local cmd = string.format(
    'curl -sS --fail --show-error -X POST %s%s%s' ..
    ' --connect-timeout 30 --max-time 120' ..
    ' -H %s --data-binary @%s -o %s 2>%s',
    ...)
```
Consider making the timeout configurable.

### Finding 23. [MEDIUM] Cloud path detection suffix check uses hardcoded length that may be wrong for some entries
Location: is_cloud_path / lines ~500-515
Description: The suffix check `lower:sub(-(#name + 1)) == '/' .. name` correctly computes the length dynamically using `#name`. This is correct. However, the macOS cloud storage check `lower:sub(-20) == '/library/cloudstorage'` uses a hardcoded length of 20. The string '/library/cloudstorage' has 21 characters (including the leading slash), so `sub(-20)` would miss the leading slash and the comparison would fail for paths that end exactly with '/library/cloudstorage'. Let me count: /library/cloudstorage = 1+7+1+12 = 21 chars. sub(-20) returns the last 20 chars = 'library/cloudstorage'. The comparison is with '/library/cloudstorage' (21 chars). These can never be equal. The suffix check is broken.
Suggested fix: Fix the hardcoded length:
```lua
local cloud_suffix = '/library/cloudstorage'
if lower:sub(-(#cloud_suffix)) == cloud_suffix then return true end
```

### Finding 24. [MEDIUM] Syslog logging via os.execute('logger ...') spawns a shell process for every log message
Location: log_msg / lines ~175-205
Description: When syslog logging is enabled, every call to log_msg spawns a shell process via os.execute to run the logger command. In scan_directory, log_msg is called for every file (at debug level) and for every submission. With thousands of files, this spawns thousands of shell processes, which is extremely expensive on embedded systems with limited RAM and slow process creation.
Suggested fix: Batch syslog messages or use a pipe to a persistent logger process. At minimum, add a check to skip syslog for debug-level messages unless explicitly needed:
```lua
if config.log_to_syslog and level ~= 'debug' then
    -- spawn logger only for non-debug messages
end
```

### Finding 25. [MEDIUM] Temp files created by build_multipart_body accumulate throughout the run and are only cleaned at exit
Location: build_multipart_body / lines ~270-310
Description: Each call to build_multipart_body creates two temp files (via mktemp): one for the multipart body. Each call to upload_with_curl/wget/nc creates additional temp files (resp_file, err_file, req_file). These are all tracked in temp_files[] and only cleaned up at exit via cleanup_temp_files(). For a scan of 10,000 files with 3 retries each, this could create 30,000-60,000 temp file entries in temp_files[] and the same number of actual files on disk simultaneously.
Suggested fix: Clean up temp files after each file submission attempt rather than accumulating them. Track temp files per-upload and clean them immediately after the upload attempt:
```lua
-- After submit_file() returns, clean up files created during that submission
-- Use a separate 'current_upload_temps' list that's cleared after each file
```
Alternatively, reuse temp file paths across uploads (create them once, reuse, delete at end).

### Finding 26. [LOW] exec_capture does not check handle:close() return value for command exit status
Location: exec_capture / lines ~155-160
Description: io.popen returns a handle, and handle:close() in Lua 5.2+ returns the exit status of the command. In Lua 5.1, close() returns true/nil. The exec_capture function ignores the return value of handle:close(), so if the command fails (e.g., hostname -f returns non-zero), the output is still returned. This is intentional for exec_capture (we want the output regardless of exit code), but it means callers cannot distinguish between 'command succeeded with output' and 'command failed with partial output'.
Suggested fix: Document that exec_capture returns output regardless of exit code, and callers should validate the output content rather than relying on exit status.

### Finding 27. [LOW] validate_config allows retries=0 via the > 0 check but the submit_file loop uses 1-based indexing so retries=1 means one attempt with no retries
Location: validate_config / lines ~225-245
Description: validate_config requires `config.retries > 0` (so minimum is 1). The submit_file loop is `for attempt = 1, config.retries do`, so retries=1 means exactly one attempt. The --help says 'Retry attempts per file (default: 3)' which implies retries=3 means 3 retries (4 total attempts), but the implementation means retries=3 means 3 total attempts (2 retries). The semantics are inconsistent with the help text.
Suggested fix: Either rename the parameter to 'attempts' and update help text, or change the loop to `for attempt = 1, config.retries + 1 do` to make retries mean the number of retry attempts after the first failure.


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
