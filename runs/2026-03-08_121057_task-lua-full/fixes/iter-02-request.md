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
-- NOTE: This script is designed to be run standalone, not require()'d.
--       All module-level state is global for Lua 5.1 compatibility.
--
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
-- - No native signal handling in Lua 5.1; use the shell wrapper below or
--   trap SIGINT/SIGTERM in the calling shell to send an 'interrupted' marker.
--   Shell wrapper example:
--     #!/bin/sh
--     LUA_PID=""
--     cleanup() {
--       if [ -n "$LUA_PID" ]; then
--         kill "$LUA_PID" 2>/dev/null
--       fi
--       # Optionally send interrupted marker here via curl/wget
--     }
--     trap cleanup INT TERM
--     lua thunderstorm-collector.lua "$@" &
--     LUA_PID=$!
--     wait $LUA_PID
-- - TOCTOU race between file size check and upload is a known limitation on
--   live filesystems (e.g., active log files may grow between check and send).
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
    -- Strip NUL bytes (could truncate C-string processing in curl/wget)
    r = r:gsub("%z", "_")
    -- Strip remaining control characters
    r = r:gsub("%c", "_")
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

-- Return exact file size in bytes, or -1 on error
function file_size_bytes(path)
    local f = io.open(path, "rb")
    if not f then return -1 end
    local size = f:seek("end")
    f:close()
    if not size then return -1 end
    return size
end

-- Prefer the shell mktemp utility to avoid os.tmpname() TOCTOU races.
-- Falls back to os.tmpname() if mktemp is unavailable.
function mktemp()
    local path = nil

    -- Try shell mktemp first
    local handle = io.popen("mktemp 2>/dev/null")
    if handle then
        local result = handle:read("*l")
        handle:close()
        if result and trim(result) ~= "" then
            path = trim(result)
        end
    end

    -- Fall back to os.tmpname()
    if not path then
        path = os.tmpname()
        -- Ensure the file exists (os.tmpname may just return a name on some systems)
        local f = io.open(path, "wb")
        if f then f:close() end
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

    -- Console output (stderr), gated by --quiet
    -- Finding 17: respect --quiet for banner/summary; errors always shown
    if not config.quiet then
        io.stderr:write(string.format("[%s] [%s] %s\n", ts, level, clean))
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
    -- Finding 21: skip debug messages for syslog to avoid spawning thousands of processes
    if config.log_to_syslog and level ~= "debug" then
        local prio = level
        if prio == "warn" then prio = "warning"
        elseif prio == "error" then prio = "err" end
        os.execute(string.format("logger -p %s %s 2>/dev/null",
            shell_quote(config.syslog_facility .. "." .. prio),
            shell_quote("thunderstorm-collector: " .. clean)))
    end
end

-- Finding 1/4: die() now exits with code 2 (fatal error)
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
    -- Finding 17: only print banner when not in quiet mode
    if config.quiet then return end
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
    print("      --ca-cert <path>       CA certificate bundle for TLS validation")
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
    print("  Signal handling (SIGINT/SIGTERM) is not natively supported in Lua 5.1.")
    print("  Use the shell wrapper documented in the script header for signal support.")
    print("")
    print("Examples:")
    print("  lua thunderstorm-collector.lua --server thunderstorm.local")
    print("  lua thunderstorm-collector.lua --server 10.0.0.5 --dir /tmp --dir /home")
    print("  lua thunderstorm-collector.lua --server 10.0.0.5 --ssl --ca-cert /etc/ssl/ca.pem")
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
            -- Finding 6/12: custom CA bundle support
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
        elseif a == "-h" or a == "--help" then
            print_help()
            os.exit(0)
        elseif a:sub(1, 1) == "-" then
            -- Finding 1/4: unknown option is a fatal error → exit 2
            io.stderr:write(string.format("[error] Unknown option: %s (use --help)\n", a))
            os.exit(2)
        else
            -- Finding 23: warn about unexpected positional arguments
            io.stderr:write(string.format("[warn] Ignoring unexpected argument: %s\n", a))
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
    -- Finding 19: validate server doesn't contain slashes (breaks nc URL parsing)
    if config.server:find("/") then
        die("Server must be a hostname or IP address, not a URL path")
    end
    if #config.scan_dirs == 0 then
        die("At least one scan directory is required")
    end
    -- Finding 6/12: validate ca_cert file exists if specified
    if config.ca_cert ~= "" then
        if not exec_ok("test -f " .. shell_quote(config.ca_cert)) then
            die("CA certificate file not found: " .. config.ca_cert)
        end
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
    if not output then return true end  -- unknown, assume BusyBox
    local lower = output:lower()
    -- Positively identify GNU wget; anything else is treated as BusyBox
    if lower:find("gnu wget") then return false end
    if lower:find("busybox") then return true end
    -- Unknown wget variant — treat as BusyBox (conservative)
    return true
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
-- TLS HELPER FLAGS
-- ==========================================================================

-- Finding 6/12: build curl TLS flags (insecure or ca-cert)
function get_curl_tls_flags()
    if config.insecure then
        return "-k "
    elseif config.ca_cert ~= "" then
        return "--cacert " .. shell_quote(config.ca_cert) .. " "
    end
    return ""
end

-- Finding 6/12: build wget TLS flags
function get_wget_tls_flags()
    if config.insecure then
        return "--no-check-certificate "
    elseif config.ca_cert ~= "" then
        return "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "
    end
    return ""
end

-- ==========================================================================
-- MULTIPART FORM-DATA CONSTRUCTION (streaming, memory-efficient)
-- ==========================================================================

-- Finding 3/8: stream multipart body directly to temp file instead of
-- materializing the entire body in memory. Returns boundary, tmp_path,
-- body_len or nil, nil, nil on error.
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)
    local boundary = "----ThunderstormBoundary" .. tostring(os.time())
        .. tostring(math.random(10000, 99999))

    -- Get file size for Content-Length calculation and boundary check
    local src_size = file_size_bytes(filepath)
    if src_size < 0 then return nil, nil, nil end

    -- Finding 22: verify boundary is not present in file content by reading
    -- a small sample. For large files we use a longer unique boundary instead
    -- of reading the whole file just for the check. We regenerate up to 5 times.
    -- For files <= 64KB we do a full check; for larger files we rely on the
    -- long random boundary being sufficiently unique.
    if src_size <= 65536 then
        local src_f = io.open(filepath, "rb")
        if src_f then
            local sample = src_f:read("*a")
            src_f:close()
            local attempts = 0
            while sample:find(boundary, 1, true) and attempts < 5 do
                boundary = "----ThunderstormBoundary" .. tostring(os.time())
                    .. tostring(math.random(100000, 999999))
                    .. tostring(math.random(100000, 999999))
                attempts = attempts + 1
            end
        end
    else
        -- For large files, use a longer boundary to reduce collision probability
        boundary = "----ThunderstormBoundary" .. tostring(os.time())
            .. tostring(math.random(100000, 999999))
            .. tostring(math.random(100000, 999999))
    end

    -- Build header and footer strings
    local header = "--" .. boundary .. "\r\n"
        .. string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n', safe_name)
        .. "Content-Type: application/octet-stream\r\n"
        .. "\r\n"
    local footer = "\r\n--" .. boundary .. "--\r\n"

    local body_len = #header + src_size + #footer

    -- Write multipart body to temp file in chunks (memory-efficient)
    local tmp = mktemp()
    local out = io.open(tmp, "wb")
    if not out then return nil, nil, nil end

    -- Write header
    out:write(header)

    -- Stream file content in 32KB chunks
    local src_f = io.open(filepath, "rb")
    if not src_f then
        out:close()
        return nil, nil, nil
    end

    local CHUNK = 32768
    while true do
        local chunk = src_f:read(CHUNK)
        if not chunk then break end
        out:write(chunk)
    end
    src_f:close()

    -- Write footer
    out:write(footer)
    out:close()

    return boundary, tmp, body_len
end

-- ==========================================================================
-- UPLOAD BACKENDS
-- ==========================================================================

function upload_with_curl(endpoint, filepath, filename)
    local safe_name = sanitize_filename(filename)
    local tls_flags = get_curl_tls_flags()
    local resp_file = mktemp()

    -- Finding 2: document that filepath is shell_quote'd (single-quote safe).
    -- Paths with literal newlines are unsupported (documented limitation).
    -- The form value uses double-quotes around filename= which is safe because
    -- sanitize_filename() replaces double-quotes, backslashes, semicolons,
    -- NUL bytes, and control chars with underscores.
    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s%s --form %s -o %s 2>%s",
        tls_flags,
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
    local tls_flags = get_wget_tls_flags()

    -- Finding 26: include Content-Length header so HTTP/1.0 servers work correctly
    local cmd = string.format(
        "wget -q -O %s %s--header=%s --header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        tls_flags,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote("Content-Length: " .. tostring(body_len)),
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
    if not hostpath then
        log_msg("error", "Invalid endpoint URL for nc: " .. endpoint)
        return false
    end

    -- Finding 19: add nil checks for URL component extraction
    local hostport = hostpath:match("^([^/]+)")
    if not hostport then
        log_msg("error", "Cannot parse host from endpoint URL: " .. endpoint)
        return false
    end

    local path_rest = hostpath:match("^[^/]+/(.*)$")
    local path_query = "/" .. (path_rest or "")

    local host = hostport:match("^([^:]+)")
    if not host then
        log_msg("error", "Cannot parse host from hostport: " .. hostport)
        return false
    end
    local port = hostport:match(":(%d+)$")
    if not port then
        if config.ssl then port = "443" else port = "80" end
    end

    -- Build raw HTTP request header in a temp file, then append body
    local req_file = mktemp()
    local req_f = io.open(req_file, "wb")
    if not req_f then return false end

    req_f:write(string.format("POST %s HTTP/1.1\r\n", path_query))
    req_f:write(string.format("Host: %s\r\n", hostport))
    req_f:write(string.format("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))
    req_f:write(string.format("Content-Length: %d\r\n", body_len))
    req_f:write("Connection: close\r\n")
    req_f:write("\r\n")

    -- Append the body content in chunks (memory-efficient)
    local body_f = io.open(body_file, "rb")
    if body_f then
        local CHUNK = 32768
        while true do
            local chunk = body_f:read(CHUNK)
            if not chunk then break end
            req_f:write(chunk)
        end
        body_f:close()
    end
    req_f:close()

    -- Finding 11: use timeout wrapper and redirect nc output to temp file
    -- to avoid blocking indefinitely on partial server responses
    local resp_file = mktemp()
    local cmd = string.format(
        "timeout 35 sh -c %s >%s 2>/dev/null",
        shell_quote(string.format("cat %s | nc -w 30 %s %s",
            shell_quote(req_file), shell_quote(host), shell_quote(port))),
        shell_quote(resp_file)
    )
    exec_ok(cmd)  -- ignore exit code; check response below

    -- Read first 4KB of response only (Finding 11)
    local resp = nil
    local resp_f = io.open(resp_file, "rb")
    if resp_f then
        resp = resp_f:read(4096)
        resp_f:close()
    end

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

-- Finding 18: rewrite json_escape as a single-pass function to avoid
-- %c pattern re-matching issues and handle DEL (0x7F) correctly.
function json_escape(s)
    if not s then return "" end
    local result = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        if b == 0x22 then          -- double-quote
            result[#result + 1] = '\\"'
        elseif b == 0x5C then      -- backslash
            result[#result + 1] = '\\\\'
        elseif b == 0x0A then      -- newline
            result[#result + 1] = '\\n'
        elseif b == 0x0D then      -- carriage return
            result[#result + 1] = '\\r'
        elseif b == 0x09 then      -- tab
            result[#result + 1] = '\\t'
        elseif b < 0x20 or b == 0x7F then  -- control chars + DEL
            result[#result + 1] = string.format('\\u%04x', b)
        else
            result[#result + 1] = s:sub(i, i)
        end
    end
    return table.concat(result)
end

-- Finding 9/16: write JSON body to temp file and use --post-file for wget;
-- check exec_ok() result and log failures.
-- Returns scan_id string (may be empty on failure).
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

    -- Finding 9: write body to temp file to avoid shell quoting issues with
    -- special characters in --post-data
    local body_file = mktemp()
    local bf = io.open(body_file, "wb")
    if not bf then
        log_msg("warn", "Could not write marker body to temp file")
        return ""
    end
    bf:write(body)
    bf:close()

    local resp = nil
    local resp_file = mktemp()
    local tool = config.upload_tool

    -- Use the already-detected upload tool; fall back to checking availability
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then tool = "wget"
        end
    end

    -- Finding 16: check exec_ok() and log failures
    if tool == "curl" then
        local tls_flags = get_curl_tls_flags()
        local cmd = string.format(
            "curl -s -o %s %s-H 'Content-Type: application/json' --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), tls_flags,
            shell_quote(body_file), shell_quote(url))
        if not exec_ok(cmd) then
            log_msg("warn", "Failed to send collection marker (" .. marker_type .. ") via curl")
        else
            local f = io.open(resp_file, "r")
            if f then resp = f:read("*a"); f:close() end
        end
    elseif tool == "wget" or tool == "busybox-wget" then
        local tls_flags = get_wget_tls_flags()
        -- Finding 9: use --post-file instead of --post-data to avoid shell injection
        local cmd = string.format(
            "wget -q -O %s %s--header='Content-Type: application/json' --post-file=%s --timeout=10 %s 2>/dev/null",
            shell_quote(resp_file), tls_flags,
            shell_quote(body_file), shell_quote(url))
        if not exec_ok(cmd) then
            log_msg("warn", "Failed to send collection marker (" .. marker_type .. ") via wget")
        else
            local f = io.open(resp_file, "r")
            if f then resp = f:read("*a"); f:close() end
        end
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
    -- Build prune clauses for excluded paths.
    -- Finding 10: use both "-path X -prune" and "-path X/* -prune" for
    -- robustness across find implementations (BusyBox and GNU find).
    local prune_parts = {}
    for _, p in ipairs(EXCLUDE_PATHS) do
        prune_parts[#prune_parts + 1] = string.format("-path %s -prune", shell_quote(p))
        prune_parts[#prune_parts + 1] = string.format("-path %s -prune", shell_quote(p .. "/*"))
    end
    for _, p in ipairs(dynamic_excludes) do
        prune_parts[#prune_parts + 1] = string.format("-path %s -prune", shell_quote(p))
        prune_parts[#prune_parts + 1] = string.format("-path %s -prune", shell_quote(p .. "/*"))
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

    -- Finding 14: wrap iteration in pcall to ensure handle is always closed
    local ok, err = pcall(function()
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
    end)

    -- Always close the handle (Finding 14)
    handle:close()

    if not ok then
        log_msg("error", "Error during directory scan of '" .. dir .. "': " .. tostring(err))
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

    -- Banner (Finding 17: gated by quiet mode inside print_banner)
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

    -- Send begin marker (Finding 5: single retry after 2s on initial failure)
    local scan_id = ""
    if not config.dry_run then
        scan_id = send_collection_marker(base_url, "begin", nil, nil)
        if scan_id == "" then
            log_msg("warn", "Begin marker failed; retrying in 2 seconds...")
            os.execute("sleep 2")
            scan_id = send_collection_marker(base_url, "begin", nil, nil)
        end
        if scan_id ~= "" then
            log_msg("info", "Collection scan_id: " .. scan_id)
            -- Append scan_id to endpoint
            local sep = "&"
            if not api_endpoint:find("?") then sep = "?" end
            api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
        else
            log_msg("warn", "Could not obtain scan_id from server; continuing without it")
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

    -- Finding 17: print summary to stdout only when not in quiet mode
    if not config.quiet then
        io.write(string.format(
            "Run completed: scanned=%d submitted=%d skipped=%d failed=%d seconds=%d\n",
            counters.files_scanned, counters.files_submitted,
            counters.files_skipped, counters.files_failed, elapsed))
    end

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

    -- Finding 1/4: exit 0=clean, 1=partial failure (some files failed)
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


### 1. [CRITICAL] Shell injection via filepath in curl --form argument
Location: upload_with_curl / build around line 330
Description: The curl command constructs the --form value as `file=@<filepath>;filename="<safe_name>"`. The `filepath` is wrapped in `shell_quote()` (single-quote escaping), but the entire string passed to `shell_quote()` is `string.format('file=@%s;filename="%s"', filepath, safe_name)`. The `filepath` is interpolated into the format string BEFORE shell_quote is applied to the whole thing. So if `filepath` contains a single-quote, the shell_quote wrapping of the outer string will be broken because `filepath` itself is not shell-quoted at the inner level — it's just string-concatenated. Example: a file path like `/tmp/a'b` would produce `file=@/tmp/a'b;filename="..."` inside the outer single-quoted string, which breaks the quoting. The correct fix is to shell_quote filepath separately and build the form value differently, or use curl's `--form-string` / `-F` with a file reference that avoids embedding the path in a quoted string.
Suggested fix: Use `shell_quote(filepath)` separately and pass it as a curl variable, or write the form spec to a temp file and use `--config`. Alternatively: `local form_val = 'file=@' .. filepath .. ';filename="' .. safe_name .. '"'` then pass `shell_quote(form_val)` — but this still embeds the raw filepath. The safest fix is to use curl's `-F` with a file reference written to a curl config file, or to use the multipart body builder (like wget/nc backends do) and pass `--data-binary @tmpfile` with explicit Content-Type.

### 2. [CRITICAL] body_len calculation uses pre-read src_size but file may be re-read with different size
Location: build_multipart_body / ~line 270
Description: The function reads `src_size = file_size_bytes(filepath)` (via seek), then for small files reads the entire content into `sample` for boundary checking, then opens the file AGAIN to stream it into the temp file. Between the size measurement and the second open, the file could change size (TOCTOU). More critically, the `body_len` is computed as `#header + src_size + #footer`, but the actual bytes written to the temp file may differ if the file changed. This causes an incorrect `Content-Length` header, which will cause HTTP servers to reject or misparse the request. Additionally, after the boundary-collision check reads the whole file into `sample` (up to 64KB), the file is opened a third time for streaming — the boundary may have changed after the sample read, so the boundary used in `header` and `footer` may differ from what was checked against `sample`.
Suggested fix: After streaming the file to the temp file, seek to end of the temp file to get the actual body size, then update body_len. Or: compute body_len from the actual temp file size after writing. Also, fix the boundary regeneration logic to regenerate `header` and `footer` after changing the boundary.

### 3. [CRITICAL] Boundary regenerated but header/footer not rebuilt with new boundary
Location: build_multipart_body / boundary regeneration block ~line 285
Description: When a boundary collision is detected in the file sample, the code regenerates `boundary` up to 5 times. However, `header` and `footer` are computed AFTER the boundary-check block, so they will use the final boundary value. But `body_len` is computed using `#header + src_size + #footer` which also comes after. So the header/footer/body_len are consistent with the final boundary. HOWEVER: for the large-file path (src_size > 65536), the boundary is regenerated unconditionally at the bottom of the else-branch, but `header` and `footer` haven't been built yet at that point either — they're built after. So this is actually fine for header/footer. The real bug is: after the small-file boundary collision loop, `body_len` uses `#header` and `#footer` which haven't been computed yet at that point in the code. Wait — re-reading: header and footer ARE computed after the boundary block. So body_len = #header + src_size + #footer is computed with the correct final boundary. This is actually OK. Retracting — marking as medium for the confusing flow.
Suggested fix: Restructure so boundary finalization happens before header/footer construction, with a clear comment.

### 4. [HIGH] os.execute success detection is wrong on many Lua 5.1 builds
Location: exec_ok / utility function used throughout uploads and marker sending
Description: The helper assumes Lua 5.1 returns numeric 0 on success and Lua 5.2+ returns true. On many real Lua 5.1/5.1-derived environments, especially embedded builds, os.execute may return values that are not exactly 0/true (for example a platform-dependent status code, or multiple return values in patched runtimes). As written, successful commands can be treated as failures, breaking tool detection, CA file validation, directory checks, uploads, and marker delivery.
Suggested fix: Normalize os.execute handling more defensively. In Lua 5.1, treat both numeric 0 and true as success, and if multiple returns are available, accept true or an exit code of 0. A compatibility wrapper like `local a,b,c = os.execute(cmd); if a == true then return true elseif type(a) == 'number' then return a == 0 elseif b == 'exit' and c == 0 then return true else return false end` is safer.

### 5. [HIGH] nc backend is effectively broken due to double shell-quoting of host and port
Location: upload_with_nc / command construction for timeout + sh -c
Description: The command passed to `sh -c` is built as `cat <req> | nc -w 30 'host' 'port'`, where `host` and `port` are already shell-quoted before being embedded into another shell command string that is itself shell-quoted. Those literal quote characters survive into the inner shell and become part of the arguments, so nc receives a hostname like `'example.com'` instead of `example.com`.
Suggested fix: Do not pre-quote host/port inside the inner command string. Quote only once at the shell boundary, or avoid `sh -c` entirely. For example, build the inner command as `string.format("cat %s | nc -w 30 %s %s", shell_quote(req_file), host, port)` and then shell-quote that whole string for `sh -c`, or better: `timeout 35 nc -w 30 ... < req_file > resp_file`.

### 6. [HIGH] Collection markers are never sent when nc is the selected upload tool
Location: send_collection_marker / tool fallback logic
Description: The marker sender only implements curl and wget/busybox-wget branches. If runtime detection selected `nc`, `tool` remains `nc`, no upload branch executes, and the function silently returns an empty scan_id. That means begin/end markers are skipped on exactly the minimal environments where nc is chosen.
Suggested fix: Implement JSON POST via nc as a third backend, or explicitly fall back to curl/wget only if available and otherwise log a clear warning that markers are unsupported with nc. Given the stated target constraints, adding an nc JSON POST path is the correct fix.

### 7. [HIGH] Max-age filter is off by almost a full day
Location: build_find_command / use of `-mtime -%d`
Description: The script interprets `--max-age <days>` as a day-based age limit, but uses `find -mtime -N`. In POSIX/GNU/BusyBox find semantics, `-mtime -14` means strictly less than 14*24 hours, not 'within the last 14 calendar days'. Files that are 14 days old plus a few minutes are excluded, even though users typically expect them to be included under a 14-day limit.
Suggested fix: Use minute granularity for an exact threshold, e.g. `-mmin -<days*1440>`, or document the strict `find` semantics clearly. If parity matters, match the behavior of the other collectors exactly.

### 8. [HIGH] nc command uses cat piped to nc, which may not work on all BusyBox nc variants; also no SSL support warning is insufficient
Location: upload_with_nc / ~line 390
Description: The nc backend uses `cat <req_file> | nc -w 30 <host> <port>`. On some BusyBox nc implementations, `-w` sets the timeout for connection establishment only, not for the full transfer. More importantly, the response reading relies on nc closing after the server closes the connection (`Connection: close`), but some nc variants exit immediately after stdin closes without waiting for the server response. This means `resp` will often be empty, causing the function to return false even on successful uploads.
Suggested fix: After writing the request, use `nc -w 30 host port < req_file > resp_file` (redirect, not pipe) which is more portable. Also consider using `timeout` around the entire nc invocation. The current code already uses timeout 35 but the inner nc -w 30 may not honor it on all implementations.

### 9. [HIGH] wget marker command uses single-quoted --header flag which breaks on some BusyBox wget
Location: send_collection_marker / ~line 460
Description: The wget command for sending the collection marker uses `--header='Content-Type: application/json'` with single quotes embedded in the format string, not via shell_quote. The format string is: `"wget -q -O %s %s--header='Content-Type: application/json' --post-file=%s --timeout=10 %s"`. The single quotes here are literal characters in the Lua string, passed directly to `os.execute()` via a shell. This works in bash/sh but on some minimal BusyBox sh implementations the quoting may be interpreted differently. More critically, `tls_flags` is inserted between `%s` and `--header=` without any separator guarantee — if tls_flags is non-empty and doesn't end with a space, the flags will be concatenated. Looking at `get_wget_tls_flags()`, it does append a trailing space, so this is OK. But the hardcoded single quotes in the format string (not going through shell_quote) is inconsistent with the rest of the code.
Suggested fix: Use `shell_quote('Content-Type: application/json')` and pass it via `--header=` with proper quoting: `'--header=' .. shell_quote('Content-Type: application/json')`.

### 10. [HIGH] find prune logic is incorrect — -prune without -o -false causes find to print pruned dirs
Location: build_find_command / ~line 510
Description: The find command is built as: `find <dir> ( -path X -prune -o -path X/* -prune -o ... ) -o -type f -mtime -N -print`. The prune_str ends with ` -o ` and then `-type f -mtime -N -print` follows. This means the full expression is: `(-path X -prune) -o (-path X/* -prune) -o ... -o (-type f -mtime -N -print)`. When a pruned directory matches, `-prune` returns true and the `-o` short-circuits, so the directory itself is NOT printed (because `-print` is only in the last clause). This is actually correct behavior for GNU find. However, on BusyBox find, the behavior of `-prune` with `-o` can differ. More importantly: the pruned directory entry itself will match the first clause and return true without printing — but subdirectories won't be descended into. This is the intended behavior. Actually this is fine for GNU find. For BusyBox find, `-path X/* -prune` may not work as expected because BusyBox find may not support glob patterns in `-path`. This is a real portability issue.
Suggested fix: Test with BusyBox find. Consider using `-path 'X' -prune -o -path 'X/*' -prune` but also add a fallback: after getting each file path from find, do a prefix check in Lua against the exclude list as a second line of defense.

### 11. [HIGH] io.popen handle not closed on early return paths
Location: scan_directory / ~line 545
Description: In `scan_directory`, `handle = io.popen(cmd)` is opened, then a `pcall` wraps the iteration. If `handle:lines()` itself throws (which it can on some Lua implementations when the process has already exited), the pcall catches it and `handle:close()` is called after. This part is OK. However, if `exec_ok("test -d " .. shell_quote(dir))` returns false, the function returns early without ever opening a handle — that's fine. The real issue: `io.popen` on Lua 5.1 returns a file handle even if the command fails to start (the shell itself starts). The `handle:lines()` iterator will simply return no lines. This is acceptable. The pcall + handle:close() pattern is correct. This finding is a false positive.
Suggested fix: N/A

### 12. [HIGH] scan_id appended to api_endpoint inside the directory loop causes double-appending on second iteration
Location: main / scan_id append to api_endpoint ~line 610
Description: The scan_id is appended to `api_endpoint` once before the directory scan loop: `api_endpoint = api_endpoint .. sep .. 'scan_id=' .. urlencode(scan_id)`. This happens once, outside the loop, so it's fine — `api_endpoint` is modified once and then used for all directories. This is not a bug. Retracting.
Suggested fix: N/A

### 13. [HIGH] wget --post-file sends multipart body but wget may add its own Content-Length incorrectly
Location: upload_with_wget / ~line 355
Description: GNU wget with `--post-file` reads the file and sends it, but it computes Content-Length from the file size automatically. The script also adds an explicit `--header='Content-Length: N'` header. This results in a duplicate Content-Length header being sent (one from wget's automatic calculation, one from the explicit header). RFC 7230 says duplicate Content-Length headers with differing values are an error. If wget's auto-calculated size matches the manually computed `body_len`, there's no problem. But if the file changed between size measurement and sending (TOCTOU), the two Content-Length values will differ, causing the server to reject the request or behave unpredictably.
Suggested fix: Remove the explicit `Content-Length` header from the wget command and rely on wget's automatic calculation, OR compute body_len from the actual temp file size after writing (which eliminates the TOCTOU issue for the temp file itself).

### 14. [HIGH] Mount point paths with spaces are not handled correctly
Location: parse_proc_mounts / ~line 175
Description: The /proc/mounts parser uses `line:match("^(%S+)%s+(%S+)%s+(%S+)")` which splits on whitespace. Mount points with spaces in their names (encoded as `\040` in /proc/mounts) will be split incorrectly. The raw /proc/mounts format encodes spaces as `\040`, so the pattern would actually capture `\040` as part of the mount point string rather than splitting on it. However, the captured mount point string would then contain the literal `\040` escape sequence rather than a space, meaning the exclusion path won't match actual filesystem paths that contain spaces. This is a correctness issue for mount points with spaces.
Suggested fix: After extracting `mp`, decode `\040` to space: `mp = mp:gsub('\\040', ' ')`. Also handle `\011` (tab) and `\012` (newline) for completeness.

### 15. [MEDIUM] Dynamic mount exclusions fail for escaped mountpoints in /proc/mounts
Location: parse_proc_mounts / parsing `/proc/mounts`
Description: Mountpoints in `/proc/mounts` encode spaces and some special characters as escape sequences such as `\040`. The parser stores the raw escaped text into `dynamic_excludes`, but `find` emits real filesystem paths, so exclusion checks built from those mountpoints will not match actual paths containing spaces or escaped characters.
Suggested fix: Unescape mountpoint fields from `/proc/mounts` before storing them, at least handling `\040`, `\011`, `\012`, and `\\` per fstab/proc mount escaping rules.

### 16. [MEDIUM] nc backend depends on external `timeout` despite stated minimal-tool constraints
Location: upload_with_nc / unconditional use of `timeout`
Description: The nc uploader shells out to `timeout 35 ...`, but `timeout` is not one of the declared runtime requirements and is absent on many BusyBox deployments unless specifically enabled. If nc exists but timeout does not, the command fails and uploads never work.
Suggested fix: Probe for `timeout` before using it and fall back to plain `nc -w` if unavailable, or structure the command so nc's own timeout is sufficient. If an outer timeout is truly required, include it in documented prerequisites and detection logic.

### 17. [MEDIUM] Error and warn messages suppressed by --quiet flag
Location: log_msg / ~line 130
Description: The `log_msg` function gates ALL console output (including `error` and `warn` level messages) behind `if not config.quiet`. The comment says 'errors always shown' but the code does not implement this — errors are suppressed in quiet mode just like info messages. This means fatal errors and warnings are silently swallowed when `--quiet` is used.
Suggested fix: Change the condition to: `if not config.quiet or level == 'error' or level == 'warn' then` to always show errors and warnings regardless of quiet mode.

### 18. [MEDIUM] Exponential backoff calculation is O(n) loop instead of bit shift, and produces wrong values
Location: submit_file / exponential backoff ~line 430
Description: The backoff delay is computed as: `local delay = 1; for _ = 2, attempt do delay = delay * 2 end`. For attempt=1: loop runs 0 times (2 to 1 is empty), delay=1. For attempt=2: loop runs once, delay=2. For attempt=3: loop runs twice, delay=4. This gives delays of 1, 2, 4 seconds for attempts 1, 2, 3. The comment says '2^(attempt-1)' which matches. However, with default retries=3, the maximum delay is 4 seconds between attempt 2 and 3. This is fine functionally. The loop-based power calculation is just inefficient (though negligible for small retry counts). Not a real bug.
Suggested fix: Use `math.pow(2, attempt-1)` or `2^(attempt-1)` (Lua supports `^` operator) for clarity: `local delay = math.floor(2^(attempt-1))`.

### 19. [MEDIUM] wget_is_busybox() spawns a subprocess and reads output but doesn't handle io.popen failure
Location: detect_upload_tool / ~line 230
Description: `wget_is_busybox()` calls `exec_capture("wget --version 2>&1")`. If `io.popen` fails (returns nil), `exec_capture` returns nil, and `wget_is_busybox()` returns `true` (assumes BusyBox). This is the safe/conservative fallback. However, `exec_capture` itself doesn't handle the case where `handle:read("*a")` returns nil (possible if the process was killed). In that case it returns nil, and `wget_is_busybox()` correctly returns true. This is acceptable behavior. Minor issue: `wget --version` may not exist on all BusyBox wget builds (some only support `--help`), causing wget to print an error to stderr (redirected to stdout via 2>&1) and exit non-zero. The output would contain 'BusyBox' or similar, so the detection still works.
Suggested fix: Also check for `wget -V` as an alternative version flag for completeness.

### 20. [MEDIUM] nc response check uses HTTP/1.x pattern but server may respond with HTTP/2 or malformed status
Location: upload_with_nc / HTTP response parsing ~line 415
Description: The response success check is `resp:match("HTTP/1%.%d 2%d%d")`. This correctly matches HTTP/1.0 and HTTP/1.1 2xx responses. However, if the server sends HTTP/1.1 200 OK with a space before the status code (non-standard but seen in some embedded servers), or if the response is truncated (only 4096 bytes read), the match may fail. More practically: if the nc connection succeeds but the server sends a redirect (301/302), the upload is treated as a failure even though the file was received. This is correct behavior (redirects should be failures for API endpoints), but worth noting.
Suggested fix: The pattern is reasonable. Consider also matching `HTTP/2 2` for HTTP/2 cleartext responses, though nc-based HTTP/2 is unlikely.

### 21. [MEDIUM] config.retries validation allows retries=0 to pass if --retries 0 is given
Location: validate_config / ~line 205
Description: The validation checks `if config.retries <= 0 then die(...)`. The `is_integer` check only accepts `^%d+$` (digits only, no sign), so negative values are rejected at parse time. However, `--retries 0` passes `is_integer` (returns true for '0') and `tonumber('0') = 0`, which then fails the `<= 0` check and calls `die()`. So retries=0 is correctly rejected. This is fine. Not a real bug.
Suggested fix: N/A

### 22. [MEDIUM] Boundary collision check reads entire file into memory for files up to 64KB
Location: build_multipart_body / small file boundary check ~line 278
Description: For files up to 65536 bytes, the function reads the entire file content into `sample` (a Lua string) to check for boundary collisions. This is done in addition to the streaming copy that follows. So for small files, the file is read twice: once into memory for the boundary check, and once streamed to the temp file. On a system with 2MB RAM scanning many small files, this doubles memory pressure for the boundary check phase. The `sample` string is not explicitly freed (Lua GC will collect it eventually). On embedded systems with tight memory, this could cause GC pressure.
Suggested fix: Either skip the boundary check entirely (the random boundary is sufficiently unique in practice) or do the boundary check during the streaming copy to avoid the double-read.

### 23. [MEDIUM] api_endpoint has scan_id appended with urlencode but scan_id from server may already be URL-safe
Location: main / ~line 590
Description: The scan_id extracted from the server response via `resp:match('"scan_id"%s*:%s*"([^"]+)"')` could theoretically contain characters that need URL encoding (e.g., if the server returns a UUID with `+` or special chars, though UUIDs are URL-safe). The `urlencode(scan_id)` call handles this correctly. However, the `sep` logic checks `if not api_endpoint:find('?')` — but `api_endpoint` already has `?source=...` appended if source is non-empty. The `find('?')` check is correct. This is fine.
Suggested fix: N/A

### 24. [MEDIUM] curl response file and error file are registered in temp_files but resp_file itself is also registered via mktemp — double registration
Location: upload_with_curl / ~line 330
Description: `resp_file = mktemp()` registers `resp_file` in `temp_files`. Then `temp_files[#temp_files + 1] = resp_file .. '.err'` manually adds the `.err` file. The `.err` file is never created via `mktemp()` so it won't be cleaned up unless the manual addition works. This is correct. However, if `upload_with_curl` is called multiple times (retries), a new `resp_file` and `.err` file are created each time and all are registered. With 3 retries across many files, this could accumulate many temp file entries. On a scan of 10,000 files with 3 retries each, that's 60,000 entries in the `temp_files` table. This is a memory concern on embedded systems.
Suggested fix: Reuse a single resp_file per upload session (pass it in or create it once in submit_file), or clean up resp_file immediately after each upload attempt rather than deferring to cleanup_temp_files.

### 25. [LOW] sanitize_filename uses Lua pattern '["\\;]' which has incorrect escaping
Location: sanitize_filename / ~line 85
Description: The pattern `'["\\;]'` in Lua: the `\\` in a Lua string literal is a single backslash `\`, so the character class is `["\ ;]` — double-quote, backslash, semicolon. This is the intended behavior (replace these three characters). However, the Lua pattern `["\;]` would also work since inside a character class `\` doesn't need escaping in Lua patterns (it's not a magic character there). The current code works correctly but is confusing.
Suggested fix: Add a comment: `-- character class: double-quote, backslash, semicolon` to clarify intent.

### 26. [LOW] nc is not used as a fallback for collection markers even though it's a supported upload tool
Location: send_collection_marker / ~line 460
Description: The `send_collection_marker` function only handles `curl`, `wget`, and `busybox-wget` upload tools. If `config.upload_tool == 'nc'`, the function silently does nothing (no marker is sent, empty string is returned). This means on nc-only systems, begin/end markers are never sent, and the server has no collection tracking.
Suggested fix: Add an `elseif tool == 'nc' then` branch that uses the nc backend to POST the JSON body, similar to `upload_with_nc` but for JSON content-type. Or at minimum, log a warning: `log_msg('warn', 'Collection markers not supported with nc upload tool')`.

### 27. [LOW] api_endpoint query string separator logic has off-by-one: scan_id separator check uses api_endpoint which already has ?source= but the check is correct
Location: main / ~line 570
Description: After appending `?source=...` to `api_endpoint`, the code checks `if not api_endpoint:find('?') then sep = '?' else sep = '&' end` before appending `scan_id`. Since `?source=` was already appended, `find('?')` returns non-nil and `sep = '&'` is used. This is correct. However, if `config.source == ''`, then `query_source = ''` and `api_endpoint` has no `?`. Then `sep = '?'` is used for scan_id. This is also correct. No bug here.
Suggested fix: N/A

### 28. [LOW] math.randomseed not called before math.random usage in build_multipart_body
Location: global scope
Description: `build_multipart_body` uses `math.random(10000, 99999)` to generate boundary components. Without calling `math.randomseed()`, Lua 5.1 uses a fixed seed (implementation-defined, often 1), meaning the same sequence of random numbers is generated on every run. Combined with `os.time()` in the boundary, this provides some uniqueness, but if two processes start within the same second, they will generate identical boundaries.
Suggested fix: Add `math.randomseed(os.time())` near the top of `main()` before any `math.random()` calls.


## Instructions

1. Fix each finding listed above
2. Make minimal changes — do not refactor unrelated code
3. Preserve the existing code style and conventions
4. If a finding is a false positive, explain why and skip it
5. If a fix would break something else, note the trade-off

## Output

Return the complete fixed file(s). Include a brief summary of what you changed and why.

For each finding, state: FIXED, SKIPPED (with reason), or PARTIAL (with explanation).
