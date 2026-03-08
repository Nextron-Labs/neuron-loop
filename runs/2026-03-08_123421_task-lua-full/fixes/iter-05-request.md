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
(move randomseed to top of main)

    -- Send begin marker (with single retry after 2s on transient failure)
>>>REPLACE
    -- Send begin marker (with single retry after 2s on transient failure)#!/usr/bin/env lua
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
    -- Replace characters unsafe in Content-Disposition filename="..." header values:
    -- double-quote (would break the header), backslash (escape prefix), semicolon (param separator)
    local r = s:gsub('[";\\]', "_")
    -- Replace all control characters (0x00-0x1F, 0x7F) including \r, \n, \t, etc.
    r = r:gsub("%c", "_")
    r = r:gsub("\127", "_")
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
    -- Verify the path is in a sane location
    if path == "" or (not path:match("^/tmp/") and not path:match("^/var/tmp/")) then
        die("mktemp returned unexpected path '" .. tostring(path) .. "'; aborting for safety")
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
    print("      --retries <num>        Total upload attempts per file (default: 3)")
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
    if config.server:sub(1, 1) == "-" then
        die("Server hostname must not start with '-'")
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
    if config.max_age == 0 then
        die("max-age=0 will match no files (find -mtime -0 matches nothing); use at least 1")
    end
    if config.max_size_kb <= 0 then
        die("max-size-kb must be > 0")
    end
    if config.max_age > 3650 then
        log_msg("warn", "max-age > 3650 days; this will scan very old files and may take a long time")
    end
    if config.retries < 1 then
        die("retries must be >= 1 (minimum 1 attempt)")
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
    f:close()
end

function is_cloud_path(path)
    local lower = path:lower()
    -- Use pre-computed pattern tables (populated by _init_cloud_patterns at startup)
    for _, pat in ipairs(_cloud_mid_patterns) do
        if lower:find(pat, 1, true) then return true end
    end
    for _, suf in ipairs(_cloud_end_suffixes) do
        if lower:sub(-(#suf)) == suf then return true end
    end
    -- macOS cloud storage (/Library/CloudStorage/ or ending with /Library/CloudStorage)
    if lower:find("/library/cloudstorage/", 1, true) then return true end
    local cloud_suffix = "/library/cloudstorage"
    if lower:sub(-(#cloud_suffix)) == cloud_suffix then return true end
    return false
end

-- ==========================================================================
-- UPLOAD TOOL DETECTION
-- ==========================================================================

local _wget_is_busybox_cache = nil
function wget_is_busybox()
    if _wget_is_busybox_cache ~= nil then return _wget_is_busybox_cache end
    local output = exec_capture("wget --version 2>&1")
    _wget_is_busybox_cache = (output and output:lower():find("busybox") ~= nil) or false
    return _wget_is_busybox_cache
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

-- ==========================================================================
-- MULTIPART FORM-DATA CONSTRUCTION
-- ==========================================================================

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
        "curl -sS --fail --show-error -X POST %s%s" ..
        " --connect-timeout 30 --max-time 120" ..
        " -H %s --data-binary @%s -o %s 2>%s %s",
        insecure,
        ca_cert_flag,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote(body_file),
        shell_quote(resp_file),
        shell_quote(err_file),
        shell_quote(endpoint)
    )

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
        "wget -q -O %s %s%s--header=%s --header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        insecure,
        ca_cert_flag,
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
    if not hostpath then return false end

    local hostport = hostpath:match("^([^/]+)")
    local path_rest = hostpath:match("^[^/]+/(.*)$") or ""
    local path_query = "/" .. path_rest
>>>REPLACE
    local hostpath = endpoint:match("^https?://(.+)$")
    if not hostpath then return false end

    local hostport = hostpath:match("^([^/]+)")
    local path_rest = hostpath:match("^[^/]+/(.*)$") or ""
    local path_query = "/" .. path_rest

    local host = hostport:match("^([^:]+)")
    local port = hostport:match(":(%d+)$")
    if not port then
        if config.ssl then port = "443" else port = "80" end
    end

    -- Build raw HTTP request
    local req_file = mktemp()
    local req_f = io.open(req_file, "wb")
    if not req_f then return false end

    req_f:write(string.format("POST %s HTTP/1.0\r\n", path_query))
    req_f:write(string.format("Host: %s\r\n", hostport))
    req_f:write(string.format("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))
    req_f:write(string.format("Content-Length: %d\r\n", body_len))
    req_f:write("Connection: close\r\n")
    req_f:write("\r\n")

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
    req_f:close()

    -- Send via nc using redirect (avoids pipe buffer limits and useless cat process)
    -- Use -w 10 timeout; Connection: close header ensures server closes after response
    local resp_file = mktemp()
    -- Timeout: base 30s + 1s per 10KB to accommodate slow servers on large files
    local nc_timeout = math.max(30, 30 + math.floor(body_len / 10240))
    local cmd = string.format(
        "nc -w %d %s %s <%s >%s 2>/dev/null",
        nc_timeout,
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

    -- Check for HTTP 2xx success (anchored to start of response to avoid false matches in body)
    if resp:match("^HTTP/1%.%d 2%d%d") then return true end

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
        -- Capture temps_before inside the loop so each retry cleans up its own temp files
        local temps_before = #temp_files
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

        -- Clean up temp files created during this attempt (combined into one reverse loop)
        for i = #temp_files, temps_before + 1, -1 do
            os.remove(temp_files[i])
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
    local temps_before = #temp_files

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
        -- stats_json must be a pre-validated JSON fragment (caller's responsibility).
        -- Verify it contains only safe characters: digits, letters, quotes, colons,
        -- braces, brackets, commas, dots, underscores, spaces, and minus signs.
        if stats_json:match('[^%w%s":{},%.%[%]_%-]') then
            log_msg("warn", "stats_json contains unexpected characters; omitting from marker")
        else
            body = body .. "," .. stats_json
        end
    end
    body = body .. "}"

    local resp = nil
    local resp_file = mktemp()
    local tool = config.upload_tool

    -- Use the already-detected upload tool; fall back to full detection if not set
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then
            tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then
            if wget_is_busybox() then tool = "busybox-wget"
            else tool = "wget" end
        elseif exec_ok("which nc >/dev/null 2>&1") then
            if not config.ssl then
                tool = "nc"
            else
                log_msg("debug", "nc skipped for marker: does not support HTTPS")
            end
        end
    end

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

    -- Clean up temp files created during this marker send
    for i = #temp_files, temps_before + 1, -1 do
        os.remove(temp_files[i])
        table.remove(temp_files, i)
    end

    -- Extract scan_id from response.
    -- Only accept simple alphanumeric/UUID values to avoid using escaped JSON fragments.
    -- If the server returns a scan_id with special characters, it will be ignored safely.
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([A-Za-z0-9_%.%-]+)"')
        if id and id ~= "" then return id end
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

    -- Wrap find to capture its exit status in a temp file
    local find_status_file = mktemp()
    local wrapped_cmd = string.format("sh -c %s",
        shell_quote(cmd .. "; echo $? >" .. shell_quote(find_status_file)))
    local handle = io.popen(wrapped_cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        counters.files_failed = counters.files_failed + 1
        os.remove(find_status_file)
        return
    end
>>>REPLACE
    local cmd = build_find_command(dir)
    log_msg("debug", "find command: " .. cmd)

    local handle = io.popen(cmd)
    if not handle then
        log_msg("error", "Could not start find for '" .. dir .. "'")
        counters.files_failed = counters.files_failed + 1
        return
    end

    -- Determine whether to show progress
    local show_progress = config.progress
    if show_progress == nil then
        -- Auto-detect: check if stderr is a TTY
        show_progress = exec_ok("test -t 2")
    end

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
>>>REPLACE
    handle:close()
    if not ok then
        log_msg("error", "Error during scan of '" .. dir .. "': " .. tostring(scan_err))
        counters.files_failed = counters.files_failed + 1
    end
    if show_progress and progress_counter > 0 then
        -- Clear progress line
        io.stderr:write("\r" .. string.rep(" ", 60) .. "\r")
        io.stderr:flush()
    end
    if dir_files_scanned == 0 then
        log_msg("debug", "No files found in '" .. dir .. "' (check permissions or find errors)")
    end
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

-- ==========================================================================
-- MAIN
-- ==========================================================================

function main()
    -- Seed RNG immediately (before any mktemp() fallback calls)
    math.randomseed(os.time() + math.floor(os.clock() * 1000000))

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

    -- Banner (suppressed in quiet mode)
    if not config.quiet then
        print_banner()
    end

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
>>>REPLACE
(move randomseed to top of main)

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

    -- Print summary to stderr (consistent with other collectors; honors --quiet via log_msg)
    if not config.quiet then
        io.stderr:write(string.format(
            "Run completed: scanned=%d submitted=%d skipped=%d failed=%d seconds=%d\n",
            counters.files_scanned, counters.files_submitted,
            counters.files_skipped, counters.files_failed, elapsed))
    end

    -- Send end marker; treat failure as partial failure (exit code 1)
    if not config.dry_run then
        local stats = string.format(
            '"stats":{"scanned":%d,"submitted":%d,"skipped":%d,"failed":%d,"elapsed_seconds":%d}',
            counters.files_scanned, counters.files_submitted,
            counters.files_skipped, counters.files_failed, elapsed)
        local end_id = send_collection_marker(base_url, "end", scan_id, stats)
        if end_id == "" and scan_id ~= "" then
            -- end marker failed (scan_id was known, so server should have accepted it)
            log_msg("warn", "End collection marker failed to send; collection state on server may be incomplete")
            counters.files_failed = counters.files_failed + 1
        end
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


### Finding 1. [CRITICAL] Dead code attempts to re-run find after output already consumed; find exit status never actually checked
Location: scan_directory / find_status_file block after pcall
Description: After the pcall loop consumes all find output via io.popen, the code creates a new `status_file` temp file and builds a `status_cmd` string but never executes it (no `exec_ok(status_cmd)` call). The comment even acknowledges this: 'We already ran the find via popen above'. The `status_file` is created via `mktemp()` (registered in `temp_files`) and then immediately removed with `os.remove(status_file)`, but the `table.remove` from `temp_files` never happens, leaving a dangling entry. More importantly, find permission errors (non-zero exit) are silently ignored — the exit code is never captured, so partial scans due to permission errors are not reflected in `counters.files_failed` as the comment claims they will be.
Suggested fix: Either (a) use the wrapped sh -c approach that was in the original REPLACE block (write find status to a temp file, read it after popen closes) or (b) accept that popen exit status is unavailable in Lua 5.1 and remove the dead status-checking code entirely. Remove the mktemp()/os.remove() pair for status_file since it serves no purpose. If find exit status matters, use: `local wrapped = string.format('sh -c \'%s; echo $? >%s\'', cmd, status_file)` and open that file after `handle:close()`.

### Finding 2. [CRITICAL] shell_quote applied to nc host and port arguments breaks nc invocation on BusyBox
Location: upload_with_nc / nc command construction
Description: The nc command is built as: `nc -w %d %s %s <%s >%s` where host and port are passed through `shell_quote()`, producing e.g. `nc -w 30 'hostname' '8080' <...`. BusyBox nc (the target platform) does not accept quoted tokens as separate arguments when the shell expands them — the shell does strip the quotes, so this is actually fine in a shell context. However the real bug is that `shell_quote(port)` where port is a string like `"80"` produces `'80'` which is valid. The actual critical issue is that `nc_timeout` can be astronomically large: `body_len` is the total multipart body size in bytes, and `math.floor(body_len / 10240)` for a 2 MB file gives 200, so timeout = 230 seconds. For the maximum allowed file (2000 KB = ~2 MB) this is acceptable, but `body_len` is the size of the temp file written to disk, not validated against `config.max_size_kb` at this layer — if `max_size_kb` is very large (user override) the timeout could be thousands of seconds, effectively hanging the collector on a failed connection.
Suggested fix: Cap nc_timeout to a reasonable maximum: `local nc_timeout = math.min(300, math.max(30, 30 + math.floor(body_len / 10240)))`. Also add a sanity check that body_len is reasonable before computing the timeout.

### Finding 3. [HIGH] find exit status is no longer captured, so partial scan failures are silently ignored
Location: scan_directory / wrapped find execution and handle close
Description: The hardened behavior requires failed scans to be reflected in the exit code. The current replacement removes the earlier wrapper that wrote find's exit status to a temp file and falls back to plain io.popen(cmd). As a result, permission errors, traversal failures, and other non-zero find exits are suppressed by `2>/dev/null` and never propagated into `counters.files_failed`. The later comment acknowledges this gap but does not actually detect it.
Suggested fix: Restore the wrapped execution that records find's exit status during the same run, then increment `files_failed` when the recorded status is non-zero. For example, keep the `sh -c 'find ...; echo $? >statusfile'` approach and read the status after `handle:close()`.

### Finding 4. [HIGH] End marker failures are not counted when no scan_id was obtained
Location: send_collection_marker / end marker failure handling
Description: The script intends to treat end-marker send failures as partial failures, but it only increments `counters.files_failed` when `end_id == "" and scan_id ~= ""`. If the begin marker failed twice and `scan_id` is empty, the end marker may still fail, yet that failure is ignored for exit-code purposes. This is inconsistent with the stated hardening goal that marker failures should affect reliability reporting.
Suggested fix: Track marker send success explicitly instead of inferring it from returned scan_id. For example, make `send_collection_marker` return `(ok, scan_id)` and increment `files_failed` whenever the end marker POST fails, regardless of whether a scan_id exists.

### Finding 5. [HIGH] Boundary collision check reads file twice: once for collision check, once for body writing — TOCTOU and double I/O cost
Location: build_multipart_body / boundary collision check
Description: The function opens `filepath` once to check for boundary collisions, closes it, then opens it again to stream into the temp file. Between these two opens, the file content could change (TOCTOU). More practically, on embedded systems with slow flash storage, reading a 2 MB file twice doubles I/O cost and time. Additionally, if the file is deleted or becomes unreadable between the collision check and the body-writing open, `src` will be nil and the function returns `nil, nil, nil` silently — the caller in `submit_file` treats this as a transient failure and retries, wasting retry budget.
Suggested fix: Open the file once, read it into the temp file, then scan the temp file for boundary collisions (or generate the boundary first using /dev/urandom which makes collisions astronomically unlikely and skip the collision check entirely — a 128-bit random boundary has collision probability of ~2^-128 per file byte). If the collision check is kept, do it in a single pass while writing to the temp file.

### Finding 6. [HIGH] curl --data-binary @file sends the multipart body but Content-Length header is not set, relying on curl's chunked or server-determined length
Location: upload_with_curl / cmd construction
Description: Unlike the wget backend which explicitly sets `Content-Length`, the curl backend uses `--data-binary @file` without setting Content-Length. curl will set it automatically from the file size, which is correct. However, the `body_len` return value from `build_multipart_body` is computed as `#preamble + file_content_bytes + #epilogue` which is correct. The real issue: curl is invoked with `--fail --show-error` but the error output is captured to `err_file` via `2>err_file`. If curl fails with exit code 22 (HTTP error), the response body (which may contain the server's error message) is written to `resp_file` via `-o resp_file`. The code then checks `resp_file` for `'reason'` to detect server-side rejection. But `--fail` causes curl to exit non-zero on HTTP 4xx/5xx, so the `if not exec_ok(cmd)` branch fires first and returns false before the response body check is reached. This means server-side rejection messages are never logged — only the curl error line is logged.
Suggested fix: Remove `--fail` and instead check the HTTP status code separately, or use `--fail-with-body` (curl 7.76+, not available on embedded systems). Alternative: remove `--fail`, always read resp_file, check for HTTP error status in the response, and log the reason. Or keep `--fail` but also log the resp_file content when exec_ok returns false.

### Finding 7. [HIGH] The REPLACE block removes the find exit-status wrapper but the replacement code references the old `cmd` variable in dead status-checking code, creating confusion and a broken status check
Location: scan_directory / wrapped_cmd (original) vs io.popen(cmd) (replacement)
Description: The original code used a `wrapped_cmd` with `sh -c` to capture find's exit status. The REPLACE block switches to plain `io.popen(cmd)`. Then after the pcall, the dead code block references `cmd` again in `status_cmd` but never runs it. The variable `find_status_file` from the original code is gone (replaced by `status_file` in the dead block). The net result is that the replacement code is internally inconsistent: it claims to check find exit status but doesn't, and the dead code references `cmd` which is defined earlier in the function — so it's not a compile error, just dead/misleading code that will confuse maintainers into thinking exit status is being checked.
Suggested fix: Remove the entire dead status-checking block (from `-- Note: find exits non-zero...` to `os.remove(status_file)`). Add a comment: `-- Note: io.popen() in Lua 5.1 does not expose the child exit status; find permission errors are not detectable. Use the sh wrapper for exit-status-aware operation.`

### Finding 8. [HIGH] mktemp fallback uses exec_capture with sh -c mktemp, but if mktemp binary doesn't exist in sh's PATH either, die() is called — however the primary check already tried sh-accessible mktemp via exec_ok('which mktemp'), making the fallback redundant and the die() message misleading
Location: mktemp / fallback path
Description: `_check_mktemp()` runs `which mktemp` to detect mktemp. If not found, `_has_mktemp = false`. Then `mktemp()` tries `exec_capture('mktemp /tmp/thunderstorm.XXXXXX')` (which will fail since mktemp isn't in PATH), gets empty result, then tries `exec_capture("sh -c 'mktemp /tmp/thunderstorm.XXXXXX 2>/dev/null'")` which will also fail for the same reason. Then `die()` is called with message about permissions. The die message says 'check permissions' but the real issue is mktemp not being installed. More critically: on systems where mktemp IS available but /tmp is full or unwritable, the first exec_capture returns empty string, the second also returns empty, and die() fires with a misleading message. The `_urandom_suffix()` fallback is defined but never used in the mktemp() function — it's only used in `_make_boundary()`. The comment in mktemp() says 'Fallback: use shell mktemp via sh' but there's no pure-Lua fallback for when mktemp truly isn't available.
Suggested fix: Add a pure-Lua fallback in mktemp(): if both mktemp attempts fail, generate a path using `_urandom_suffix()` and create the file with `io.open()`. Accept the TOCTOU risk with a comment, or use a loop to find an unused name. Fix the die() message to say 'mktemp not found or /tmp not writable'.

### Finding 9. [HIGH] nc response check anchors to start of string but HTTP/1.0 responses may have leading \r\n or server banners on some implementations
Location: upload_with_nc / HTTP response parsing
Description: `resp:match("^HTTP/1%.%d 2%d%d")` anchors to the very start of the response. RFC 7230 requires the status line to be the first line, so this is correct for compliant servers. However, some embedded HTTP servers (lighttpd on OpenWrt, for example) may prepend a blank line or the response may have a BOM. More practically: the nc command reads the full response including headers and body into resp_file. If the server sends `HTTP/1.0 200 OK
...`, the match works. If the server sends `HTTP/1.1 200 OK
...`, the pattern `HTTP/1%.%d` matches `HTTP/1.1` correctly. This is actually fine. The real issue: if nc exits with error (connection refused) and resp is empty, the code returns false with a debug log — but if nc exits successfully (connected) and the server closes the connection immediately without sending a response (e.g., firewall RST after connect), resp will be empty and the code logs a warn but returns false. This is correct behavior. Actually this finding is lower severity than initially assessed.
Suggested fix: Change the match to `resp:match('HTTP/1[%.%d]+ 2%d%d')` without the `^` anchor, or use `resp:find('HTTP/1%.%d 2%d%d')` to be more lenient about leading content.

### Finding 10. [HIGH] find -mtime -N semantics: -mtime -14 finds files modified less than 14*24 hours ago, not 'within 14 days' as intended for max_age=14
Location: build_find_command
Description: The find command uses `-mtime -%d` with `config.max_age`. POSIX `find -mtime -N` means 'modified less than N*24 hours ago'. For `max_age=14`, this finds files modified in the last 14 days, which is correct. However, `max_age=1` finds files modified in the last 24 hours (not 'today'). The validation rejects `max_age=0` with a correct message. This is actually correct behavior and matches the intent. The real issue: the find command uses `shell_quote(dir)` for the directory argument, which is correct. But the prune expressions use `shell_quote(p)` and `shell_quote(p .. "/*")` — if an exclude path contains spaces (decoded from /proc/mounts \040 sequences), the shell_quote handles this correctly. This is fine. Actually the find command construction is correct.
Suggested fix: No change needed. The -mtime semantics are correct.

### Finding 11. [MEDIUM] nc backend misparses bracketed IPv6 endpoints
Location: upload_with_nc / URL parsing
Description: The nc uploader extracts host and port using `hostport:match("^([^:]+)")` and `hostport:match(":(%d+)$")`. This works for IPv4/hostnames but fails for valid URLs like `http://[2001:db8::1]:8080/...`, where the host contains multiple colons and brackets. The parsed host becomes incorrect and the connection command is malformed.
Suggested fix: Add explicit parsing for bracketed IPv6 literals, e.g. detect `^%[(.-)%](?::(%d+))?$` before the hostname/IPv4 path, and pass the unbracketed address to `nc` while preserving the correct Host header.

### Finding 12. [MEDIUM] Collection markers are silently skipped if no upload tool was detected earlier and only nc is available with HTTPS
Location: send_collection_marker / tool selection
Description: When `config.upload_tool` is empty, marker sending performs ad-hoc tool detection. In the HTTPS + nc-only case it logs a debug message and leaves `tool` unset, causing the function to return `""` without a clear warning unless debug logging is enabled. This is especially relevant for begin markers before any uploads occur or in edge cases where detection state is not set.
Suggested fix: Emit a warning, not debug-only output, whenever marker delivery is impossible due to backend limitations. Better yet, return an explicit failure status and reason so callers can surface it consistently.

### Finding 13. [MEDIUM] Temp file cleanup in submit_file uses table.remove in a reverse loop but removes from temp_files while iterating, which is correct — however body_file from build_multipart_body is registered in temp_files AND the cleanup loop removes it, but if build_multipart_body itself calls mktemp() for the output file, that file is also in temp_files and will be cleaned up by the loop — this is correct. The actual issue: if config.retries > 1 and the first attempt fails, the body_file temp is cleaned up, but on the next retry build_multipart_body re-reads the source file and creates a new temp. If the source file was deleted between retries (e.g., /tmp cleanup), build_multipart_body returns nil and submit_file returns false. This is correct behavior. However, the exponential backoff delay is computed incorrectly.
Location: submit_file / temp file cleanup loop
Description: The exponential backoff loop: `local delay = 1; for _ = 2, attempt do delay = delay * 2 end`. For attempt=1 (first failure, sleeping before attempt 2): the loop runs from 2 to 1, which in Lua means zero iterations (since 2 > 1), so delay stays 1. For attempt=2: loop runs once (2 to 2), delay = 2. For attempt=3: loop runs twice (2 to 3), delay = 4. So delays are 1, 2, 4 seconds for attempts 1, 2, 3. This is correct exponential backoff. BUT: the sleep happens `if attempt < config.retries`, so for the last attempt there's no sleep (correct). The actual bug: for `config.retries = 1`, the loop body never executes (attempt goes 1 to 1, then `if 1 < 1` is false), so no sleep and no retry — correct. For `config.retries = 2`: attempt 1 fails, sleeps 1s, attempt 2 fails, returns false. This is correct. The backoff is actually correct.
Suggested fix: No change needed for backoff. However, document that retries=1 means exactly one attempt (no retries), which may surprise users who expect retries=1 to mean 'retry once' (2 total attempts).

### Finding 14. [MEDIUM] sanitize_filename uses Lua pattern %c which in Lua 5.1 matches bytes 0x01-0x1F but NOT 0x00 (NUL byte), leaving NUL bytes in Content-Disposition filename
Location: sanitize_filename
Description: The comment says 'Replace all control characters (0x00-0x1F, 0x7F)'. The pattern `%c` in Lua 5.1 matches characters for which `iscntrl()` returns true, which typically includes 0x01-0x1F and 0x7F but behavior for 0x00 (NUL) is implementation-defined and often excluded because NUL terminates C strings. The separate `r:gsub("\127", "_")` handles 0x7F. But NUL bytes in filenames (rare but possible on Linux) would pass through into the Content-Disposition header, potentially truncating the header at the NUL when processed by C-based HTTP parsers on the server side.
Suggested fix: Add explicit NUL handling: `r = r:gsub('%z', '_')` (Lua pattern `%z` matches NUL in Lua 5.1). Add this before or after the `%c` substitution.

### Finding 15. [MEDIUM] scan_id regex allows dots and hyphens but the character class is anchored incorrectly for UUIDs with uppercase hex
Location: send_collection_marker / scan_id extraction regex
Description: The regex `'"scan_id"%s*:%s*"([A-Za-z0-9_%.%-]+)"'` correctly allows alphanumeric, underscore, dot, and hyphen. UUID format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` uses only hex digits and hyphens, all covered. This is correct. However, the regex uses `%s*` between `scan_id` and `:` and between `:` and `"`, which handles pretty-printed JSON. The issue: if the server returns the scan_id embedded in a larger JSON object where the value contains a `+` or `/` (e.g., base64-encoded IDs), the regex won't match and scan_id will be empty, causing the end marker to be sent without a scan_id. This means the server cannot correlate begin and end markers. This is a silent failure with no warning logged.
Suggested fix: Log a debug message when the response contains `scan_id` but the regex doesn't match: `if resp:find('"scan_id"') and id == nil then log_msg('debug', 'scan_id present in response but format not recognized') end`. Consider widening the character class to `[A-Za-z0-9_%.%-%+%/%=]+` to cover base64.

### Finding 16. [MEDIUM] parse_proc_mounts only decodes \040, \011, \012, \134 but /proc/mounts can encode any byte as \NNN octal
Location: parse_proc_mounts
Description: The code handles the four most common octal escapes in /proc/mounts. However, /proc/mounts can encode any special character as `\NNN` octal. For example, a mountpoint with a tab character other than \011 won't occur (\011 IS tab), but mountpoints with characters like `#` (\043), `(` (\050), `)` (\051), or non-ASCII bytes in UTF-8 paths would be encoded as octal sequences that are not decoded. The undecoded path (e.g., `/mnt/my\040share` decoded to `/mnt/my share`) would be compared against file paths from find, which returns actual paths. If the decoded path doesn't match the actual mountpoint, the exclusion won't work.
Suggested fix: Implement a general octal decoder: `mp = mp:gsub('\\(%d%d%d)', function(oct) return string.char(tonumber(oct, 8)) end)`. Apply this after the specific substitutions or replace them all with this general approach.

### Finding 17. [MEDIUM] wget --ca-certificate flag uses shell_quote but the = separator means the quoted value includes the = sign inside the quotes, which is wrong
Location: upload_with_wget / ca_cert_flag
Description: `ca_cert_flag = "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "` produces `--ca-certificate='/path/to/cert.pem' `. The shell will see `--ca-certificate=` as one token and `'/path/to/cert.pem'` as a separate token. wget expects `--ca-certificate=/path/to/cert.pem` as a single argument. The shell_quote wraps only the path, not the `--ca-certificate=` prefix, so the argument is split incorrectly. Compare with the curl backend: `"--cacert " .. shell_quote(config.ca_cert)` which correctly passes `--cacert` and the path as separate arguments (curl accepts both `--cacert FILE` and `--cacert=FILE` forms).
Suggested fix: Change to: `ca_cert_flag = shell_quote("--ca-certificate=" .. config.ca_cert) .. " "` — quote the entire argument including the `=` and path. Or use: `"--ca-certificate " .. shell_quote(config.ca_cert) .. " "` if wget accepts space-separated form (it does for most options).

### Finding 18. [MEDIUM] scan_id appended to api_endpoint with urlencode but api_endpoint may already have a query string with source parameter, and the separator logic is wrong
Location: main / api_endpoint scan_id append
Description: The code: `local sep = "&"; if not api_endpoint:find("?") then sep = "?" end; api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)`. The `api_endpoint` is built as `base_url .. "/api/" .. endpoint_name .. query_source` where `query_source` is either `""` or `"?source=" .. urlencode(config.source)`. So if source is set, api_endpoint already has `?`, and `sep = "&"` is correct. If source is empty, `query_source = ""` and `sep = "?"` is correct. This logic is actually correct. However: `api_endpoint:find("?")` — the `?` character is a Lua pattern wildcard (matches any character). This should be `api_endpoint:find("?", 1, true)` to use plain string search. With pattern matching, `find("?")` will always find a match (since `?` matches any single character) as long as the string is non-empty, so `sep` will always be `"&"` even when there's no actual `?` in the URL.
Suggested fix: Change `api_endpoint:find("?")` to `api_endpoint:find("?", 1, true)` to use plain string matching. Same fix needed in any other place where literal `?` is searched in a URL.

### Finding 19. [MEDIUM] syslog logger command uses shell_quote for the message but the facility.priority argument is also shell_quoted — however the format string concatenates them without proper quoting of the combined argument
Location: log_msg / syslog path
Description: `os.execute(string.format("logger -p %s %s 2>/dev/null", shell_quote(config.syslog_facility .. "." .. prio), shell_quote("thunderstorm-collector: " .. clean)))`. This produces e.g. `logger -p 'user.info' 'thunderstorm-collector: message'`. This is correct — both arguments are properly shell-quoted. However, `clean` is derived from `message:gsub("[\r\n]", " ")` which removes newlines but not other shell-special characters. Since `shell_quote` wraps in single quotes and escapes embedded single quotes, this is safe. The actual issue: `config.syslog_facility` is never validated. A user could set it to a value containing shell metacharacters via... wait, syslog_facility is only set by `--syslog` flag which doesn't take a value; the facility is hardcoded as `"user"` in config. So this is not exploitable. The finding is low severity.
Suggested fix: No immediate fix needed. If syslog_facility becomes user-configurable in the future, validate it against an allowlist of valid syslog facility names.

### Finding 20. [MEDIUM] total_body counter counts preamble bytes but file content bytes are counted as Lua string lengths which may differ from actual bytes written for binary files in text mode
Location: build_multipart_body / total_body calculation
Description: The preamble and epilogue are written with `out:write()` and their lengths counted with `#preamble` and `#epilogue`. The source file is opened with `io.open(filepath, "rb")` (binary mode) and read in chunks — correct. But `total_body = total_body + #chunk` counts Lua string bytes, which for binary data is the actual byte count. The output file is opened with `io.open(tmp, "wb")` (binary mode). On Linux, binary and text mode are identical, so this is fine. The `total_body` value is used as `Content-Length` in the wget and nc backends. If `total_body` is wrong, the server will reject the request or truncate the body. The calculation appears correct for Linux. This is not a bug on the target platform.
Suggested fix: No change needed for the target platform. Add a comment noting that binary mode is required for correct Content-Length calculation.

### Finding 21. [LOW] detect_upload_tool calls 'which nc' twice: once to skip it for SSL, and once at the end to report a warning
Location: detect_upload_tool
Description: When `config.ssl = true` and nc is the only available tool, the function: (1) checks `which nc` and skips it with a debug log, (2) `has_wget` is false (wget not found), so falls through to the final block, (3) checks `which nc` again to log a warning. This is two `exec_ok` calls (two shell forks) for the same check. Minor inefficiency.
Suggested fix: Cache the nc availability: `local has_nc = exec_ok('which nc >/dev/null 2>&1')` at the top of the function, then use `has_nc` throughout.


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
