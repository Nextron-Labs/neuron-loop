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
    for _, name in ipairs(CLOUD_DIR_NAMES) do
        -- Match /name/ in the middle or /name at the end
        if lower:find("/" .. name .. "/", 1, true) then return true end
        if lower:sub(-(#name + 1)) == "/" .. name then return true end
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
        body = body .. "," .. stats_json
    end
    body = body .. "}"

    local resp = nil
    local resp_file = mktemp()
    local tool = config.upload_tool

    -- Use the already-detected upload tool; fall back to checking availability
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then
            if wget_is_busybox() then tool = "busybox-wget"
            else tool = "wget" end
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


### Finding 1. [CRITICAL] Duplicate code block causes scan_directory to never execute file processing
Location: scan_directory / progress detection block (duplicated before pcall)
Description: The source file contains a literal '>>>REPLACE' marker and a duplicated block of code starting with 'local show_progress = config.progress'. The first copy of the block (before '>>>REPLACE') is never closed with a pcall/end, and the second copy (after '>>>REPLACE') contains the actual pcall with the file-processing loop. As written, the Lua parser will encounter the duplicate local declarations and the stray '>>>REPLACE' text, causing a syntax error that prevents the entire script from loading. Even if the marker were removed, the duplicate variable declarations would shadow each other and the first block would fall through without processing any files.
Suggested fix: Remove the first (incomplete) copy of the show_progress/progress_counter block and the '>>>REPLACE' marker, keeping only the version inside the pcall. The function should read:

```lua
function scan_directory(dir, api_endpoint)
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
        counters.files_failed = counters.files_failed + 1
        return
    end
    local show_progress = config.progress
    if show_progress == nil then
        show_progress = exec_ok("test -t 2")
    end
    local dir_files_scanned = 0
    local progress_counter = 0
    local ok, scan_err = pcall(function()
        for file_path in handle:lines() do
            -- ... processing ...
        end
    end)
    handle:close()
    -- ... rest of function
end
```

### Finding 2. [CRITICAL] Second stray '>>>REPLACE' marker causes syntax error in main()
Location: main / second '>>>REPLACE' marker
Description: There is a second '>>>REPLACE\n(move randomseed to top of main)' comment block inserted in the middle of the main() function body, between the 'Record start time' block and the 'Send begin marker' block. This is not valid Lua syntax and will cause a parse error, preventing the script from running.
Suggested fix: Remove the '>>>REPLACE\n(move randomseed to top of main)' lines. The math.randomseed call is already correctly placed at the top of main(), so no code movement is needed—just delete the marker.

### Finding 3. [HIGH] Script contains unresolved patch markers and duplicated code, making it syntactically invalid
Location: scan_directory / duplicated block around the >>>REPLACE marker
Description: The file still includes literal `>>>REPLACE` markers and replacement notes such as `(move randomseed to top of main)`. These are not Lua comments and will cause a parse error before execution. In addition, the surrounding code is duplicated in `scan_directory`, so the checked-in file is not runnable as-is.
Suggested fix: Remove the patch markers and keep only the intended final code. Ensure `scan_directory` contains a single progress-detection block and that `main()` contains only valid Lua statements. Run `lua -p thunderstorm-collector.lua` or equivalent syntax validation before release.

### Finding 4. [HIGH] Temporary-file fallback is vulnerable to symlink clobbering and races
Location: mktemp / fallback branch using io.open(path, "wb")
Description: When `mktemp` is unavailable, the code generates `/tmp/thunderstorm.<suffix>` and creates it with `io.open(..., "wb")`. On multi-user or adversarial systems, an attacker can pre-create that path as a symlink to another file. Opening with `wb` follows symlinks and truncates the target. The random suffix reduces predictability but does not provide atomic creation or symlink protection.
Suggested fix: Do not implement a non-atomic temp-file fallback with plain `io.open`. Prefer requiring a real `mktemp` utility, or create a private temp directory with restrictive permissions and use shell `mktemp` inside it. If no safe primitive exists in pure Lua 5.1, fail closed with a fatal error instead of creating insecure temp files.

### Finding 5. [HIGH] Find command failures are silently ignored, so partial scans can exit as clean
Location: scan_directory / after handle:close()
Description: The code reads `find` output via `io.popen(cmd)` and then calls `handle:close()`, but it never inspects the close status. `find` commonly exits non-zero on traversal errors, I/O errors, or permission problems even when some paths were emitted. The comment explicitly says partial results are treated as valid, but the hardened behavior requested for the other collectors is to reflect partial failures in the exit code. As written, a directory scan can miss files due to runtime errors and still return exit code 0 if uploads succeeded.
Suggested fix: Capture and evaluate the `find` exit status. If it is non-zero, log to stderr and increment a partial-failure counter so the process exits 1. If BusyBox/Lua version differences make `popen():close()` status awkward, redirect `find` exit code to a temp file or wrap the command in `sh -c 'find ...; echo $? >status'`.

### Finding 6. [HIGH] Boundary collision check misses the preamble and epilogue themselves
Location: build_multipart_body / boundary collision check
Description: The collision check searches the file content for '\r\n--' .. candidate, but the actual boundary delimiter that appears at the very start of the body is '--' .. boundary (no leading \r\n). If the file begins with bytes that match '--<boundary>', the preamble delimiter will collide with file content and corrupt the multipart message. The check should also cover '--' .. candidate at position 1 (start of body) and '--' .. candidate .. '--' (epilogue).
Suggested fix: Also check for the plain '--' .. candidate pattern (without leading \r\n) to cover the opening delimiter:
```lua
local needle1 = "\r\n--" .. candidate
local needle2 = "--" .. candidate  -- covers opening delimiter
if search_buf:find(needle1, 1, true) or search_buf:find(needle2, 1, true) then
    collision = true
    break
end
```

### Finding 7. [HIGH] nc upload silently succeeds on HTTP error responses that contain a 2xx line elsewhere
Location: upload_with_nc / HTTP response check
Description: The response check uses `resp:match("HTTP/1%.%d 2%d%d")` which searches anywhere in the response body. A server that returns HTTP 400 with a JSON body containing the string 'HTTP/1.1 200' (e.g., in an error description or echoed request) would be incorrectly treated as a success. The status line must be anchored to the beginning of the response.
Suggested fix: Anchor the match to the start of the response:
```lua
if resp:match("^HTTP/1%.%d 2%d%d") then return true end
```

### Finding 8. [HIGH] Temp file list truncation uses table.remove in reverse but leaves holes after partial removal
Location: submit_file / temp file cleanup loop
Description: After each upload attempt the code removes temp files created during that attempt and then truncates the `temp_files` table by calling `table.remove(temp_files, i)` in a reverse loop from `#temp_files` down to `temps_before + 1`. However, `temps_before` is captured once before the retry loop. On the second and subsequent attempts, new temp files are appended starting at index `temps_before + 1` again (since the list was truncated), so the cleanup is correct for the indices—but if `build_multipart_body` or an upload function fails mid-way and leaves fewer entries than expected, the loop bounds may be wrong. More critically, the `os.remove` loop and the `table.remove` loop are separate: if `os.remove` succeeds but the script is interrupted between the two loops, entries remain in `temp_files` and will be double-removed by `cleanup_temp_files()` at exit (harmless but indicative of fragile design). The real bug is that `temps_before` is not updated between retries, so if a retry creates a different number of temp files than the first attempt, the truncation index is wrong.
Suggested fix: Reset `temps_before` at the start of each retry iteration:
```lua
for attempt = 1, config.retries do
    local temps_before = #temp_files  -- capture inside loop
    local success = false
    -- ... upload ...
    -- cleanup
    for i = #temp_files, temps_before + 1, -1 do
        os.remove(temp_files[i])
        table.remove(temp_files, i)
    end
    if success then return true end
    -- ...
end
```

### Finding 9. [HIGH] Missing -X POST flag in curl upload command causes GET request
Location: upload_with_curl / cmd construction
Description: The curl command in `upload_with_curl` uses `--data-binary @file` which implicitly sets the method to POST in modern curl versions, but the explicit `-X POST` flag present in the collection marker curl command is absent here. Some older curl versions (common on embedded/OpenWrt systems) require the explicit flag when combined with `--fail --show-error`. More importantly, the format string has `%s%s%s` for insecure+ca_cert+endpoint but the endpoint is shell_quote'd as the third %s while the Content-Type header (-H) comes after—this means the endpoint URL appears before the -H flag, which is valid, but the `-X POST` is missing entirely.
Suggested fix: Add `-X POST` explicitly:
```lua
local cmd = string.format(
    "curl -sS --fail --show-error -X POST %s%s" ..
    " --connect-timeout 30 --max-time 120" ..
    " -H %s --data-binary @%s -o %s 2>%s %s",
    insecure, ca_cert_flag,
    shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
    shell_quote(body_file),
    shell_quote(resp_file),
    shell_quote(err_file),
    shell_quote(endpoint)
)
```
Note also that the endpoint argument should come last in curl invocations.

### Finding 10. [HIGH] find -mtime predicate semantics: -mtime -N finds files modified less than N*24h ago, not N days
Location: build_find_command
Description: The command uses `-mtime -<max_age>` which on POSIX find means files modified less than max_age*24 hours ago (rounded down to whole days). With max_age=14 this finds files modified in the last 13-14 days depending on the current time of day. This is the standard behavior and matches the other collectors, so it is not a bug per se—but the validate_config check `max_age == 0` correctly rejects 0. However, the comment 'Max file age in days' in the config is slightly misleading since -mtime -1 finds files modified less than 24h ago (i.e., today only). This is a documentation issue rather than a code bug, so severity is noted but the real issue is that `-mtime -0` is explicitly rejected but `-mtime -1` finds files from the last 24h which may surprise users expecting 'last 1 day' to mean 'yesterday and today'.
Suggested fix: This is acceptable behavior matching POSIX find semantics. Update the help text to say 'Max file age in days (uses find -mtime; -mtime -N finds files modified less than N×24h ago)'.

### Finding 11. [HIGH] nc collection marker path uses #body (byte count) but body may contain multi-byte sequences
Location: send_collection_marker / nc path
Description: The Content-Length header is set to `#body` where body is a Lua string. In Lua 5.1, `#` on a string returns the number of bytes, which is correct for Content-Length. However, `json_escape` can produce `\uXXXX` sequences for control characters, and the source name could contain UTF-8 multi-byte sequences that are passed through unescaped (json_escape only escapes control chars 0x00-0x1F, not high bytes). The byte count will still be correct since Lua strings are byte arrays. This is actually fine—marking as high only because the interaction with the nc HTTP/1.0 raw request is fragile: if the body string contains a NUL byte (impossible here since JSON values are escaped) it would truncate. Since json_escape is applied, this is safe.
Suggested fix: No code change needed; add a comment confirming that #body is byte-accurate in Lua 5.1.

### Finding 12. [MEDIUM] Fallback scan_id parser can return escaped JSON fragments instead of the real value
Location: send_collection_marker / scan_id extraction
Description: The strict pattern only accepts `[A-Za-z0-9_%.%-]+`. If the server returns a valid JSON string containing any escaped character, the fallback pattern `"scan_id"%s*:%s*"([^"]*)"` stops at the first embedded escaped quote sequence and returns the raw escaped fragment rather than the decoded string. That malformed value is then appended to the upload endpoint as `scan_id=...`.
Suggested fix: Either constrain the server contract and reject non-simple scan IDs explicitly, or implement minimal JSON string parsing for this field that honors backslash escapes before using the value.

### Finding 13. [MEDIUM] Begin/end markers are skipped when only nc is available and upload tool was not pre-detected
Location: send_collection_marker / tool fallback logic
Description: Inside `send_collection_marker`, if `config.upload_tool` is empty, the fallback detection checks only `curl` and `wget`; it does not consider `nc`. Today `main()` usually calls `detect_upload_tool()` first in non-dry-run mode, but this function is written as a general fallback and will incorrectly skip marker sending in any path where the upload tool was not pre-populated and only `nc` exists.
Suggested fix: Reuse `detect_upload_tool()` or mirror its full logic, including `nc` selection for non-SSL URLs. Avoid maintaining a second, incomplete tool-detection path.

### Finding 14. [MEDIUM] End marker delivery failures do not affect exit status
Location: main / end-marker send result ignored
Description: The script sends the final `end` collection marker but ignores whether it succeeded. The hardened behavior described for the other collectors emphasizes partial-failure reporting. If all file uploads succeed but the end marker fails, the script still exits 0, even though the server-side collection state is incomplete.
Suggested fix: Have `send_collection_marker` return success separately from `scan_id`, and treat begin/end marker failures as partial failures that produce exit code 1 (unless you intentionally document a different contract).

### Finding 15. [MEDIUM] Pre-computed cloud pattern tables (_cloud_mid_patterns, _cloud_end_suffixes) are never used
Location: is_cloud_path
Description: The function `_init_cloud_patterns()` populates `_cloud_mid_patterns` and `_cloud_end_suffixes` at module load time, but `is_cloud_path()` ignores these tables entirely and re-constructs the patterns inline by iterating `CLOUD_DIR_NAMES` and doing string concatenation on every call. The optimization is dead code.
Suggested fix: Either use the pre-computed tables in is_cloud_path:
```lua
function is_cloud_path(path)
    local lower = path:lower()
    for _, pat in ipairs(_cloud_mid_patterns) do
        if lower:find(pat, 1, true) then return true end
    end
    for _, suf in ipairs(_cloud_end_suffixes) do
        if lower:sub(-(#suf)) == suf then return true end
    end
    -- macOS check ...
    return false
end
```
or remove `_init_cloud_patterns` and the two tables if the optimization is not desired.

### Finding 16. [MEDIUM] nc upload URL path parsing drops query string when path_rest is nil
Location: upload_with_nc / URL parsing
Description: The path extraction uses `hostpath:match("^[^/]+/(.*)$")` which captures everything after the first slash. If the URL is `http://host:8080/api/checkAsync?source=foo`, path_rest will be `api/checkAsync?source=foo` and path_query will be `/api/checkAsync?source=foo`—this is correct. However, if the URL has no path component at all (e.g., `http://host:8080`), path_rest is nil and path_query becomes `/`, which would POST to the wrong endpoint. While the endpoint is always constructed with a path in main(), this is a latent fragility.
Suggested fix: Add a guard:
```lua
local path_rest = hostpath:match("^[^/]+/(.*)$") or ""
local path_query = "/" .. path_rest
```
This is already done but the `or ""` should be verified to handle the no-path case correctly.

### Finding 17. [MEDIUM] sanitize_filename does not handle DEL character (0x7F) correctly via %c pattern
Location: sanitize_filename
Description: The code applies `r:gsub("%c", "_")` to replace control characters, then separately `r:gsub("\127", "_")` for DEL. In Lua 5.1, `%c` in patterns matches characters for which `isctype(c, ctype_cntrl)` is true. On most C libraries this includes 0x7F (DEL), making the second gsub redundant but harmless. However, on some minimal libc implementations (uClibc, musl) `%c` may not match 0x7F. The explicit second gsub is the correct defensive approach, but the comment says 'Replace all control characters (0x00-0x1F, 0x7F)' while the first gsub comment says '0x00-0x1F'—the intent is clear but the implementation order is correct (belt-and-suspenders).
Suggested fix: Combine into a single pattern or add a comment explaining the belt-and-suspenders approach. No functional change needed.

### Finding 18. [MEDIUM] stats_json is concatenated into JSON body without validation, allowing injection
Location: send_collection_marker / JSON body construction
Description: The stats_json parameter is appended directly into the JSON body: `body = body .. "," .. stats_json`. In main(), stats_json is constructed from integer counters via string.format, so the values are safe. However, the function signature accepts arbitrary strings, and if a caller passes a malformed or attacker-influenced stats_json, it would produce invalid or injected JSON. This is a defense-in-depth concern since all current callers are internal.
Suggested fix: Either document that stats_json must be a pre-validated JSON fragment, or validate that it contains only expected characters (digits, quotes, colons, braces, commas).

### Finding 19. [MEDIUM] SSL + nc detection runs 'which nc' twice unnecessarily and logs misleading warning
Location: detect_upload_tool
Description: When SSL is enabled and nc is the only available tool, the function first calls `exec_ok("which nc ...")` inside the nc block (skipping it with a debug log), then at the end calls `exec_ok("which nc ...")` again to emit a warning. This spawns two extra shell processes. More importantly, the final warning block is only reached if `has_wget` is false (since busybox-wget would have returned true), but the condition `if config.ssl and exec_ok("which nc ...")` is evaluated even when the function is about to return false—the warning is correct but the double-check is wasteful on embedded systems.
Suggested fix: Track nc availability in a local variable:
```lua
local has_nc = exec_ok("which nc >/dev/null 2>&1")
if has_nc then
    if config.ssl then
        log_msg("debug", "nc skipped: does not support HTTPS")
    else
        config.upload_tool = "nc"
        return true
    end
end
-- ...
if config.ssl and has_nc then
    log_msg("warn", "nc is available but cannot be used for HTTPS")
end
```

### Finding 20. [MEDIUM] total_body size calculation is incorrect: preamble length counted but file bytes not streamed to variable
Location: build_multipart_body / total_body calculation
Description: The variable `total_body` is initialized to `#preamble` and incremented by `#chunk` for each chunk read from the source file, then incremented by `#epilogue`. This correctly computes the total byte count of the multipart body written to the temp file. The value is returned as `body_len` and used by wget's Content-Length header. However, `total_body` is computed correctly only if all chunks are read without error. If `src:read(chunk_size)` returns a partial chunk due to an I/O error mid-file, `total_body` will be less than the actual bytes written (since `out:write(chunk)` may have already written the partial data). The Content-Length will then be wrong, causing wget to send a truncated or malformed request.
Suggested fix: After writing the temp file, use `file_size_kb` or seek to determine the actual written size rather than computing it incrementally, or check for write errors:
```lua
local written, werr = out:write(chunk)
if not written then
    src:close(); out:close()
    return nil, nil, nil
end
```

### Finding 21. [MEDIUM] Octal escape decoding in /proc/mounts is incomplete: only \040, \011, \012, \134 handled
Location: parse_proc_mounts
Description: The /proc/mounts format encodes special characters as octal escapes (\NNN). The code handles space (\040), tab (\011), newline (\012), and backslash (\134). However, other characters can appear in mount points, such as \043 (#), \073 (;), or any other byte. If a mount point contains such characters, the exclusion path will not match the actual filesystem path returned by find, and files under that mount point will not be excluded.
Suggested fix: Use a general octal decoder:
```lua
mp = mp:gsub("\\(%d%d%d)", function(oct)
    return string.char(tonumber(oct, 8))
end)
```
This handles all octal escapes in a single pass.

### Finding 22. [LOW] syslog logger command uses shell_quote for facility.priority but logger -p expects unquoted argument on some BusyBox versions
Location: log_msg / syslog path
Description: The syslog call uses `shell_quote(config.syslog_facility .. "." .. prio)` which wraps the priority in single quotes. GNU logger and most implementations accept quoted arguments via the shell, but BusyBox logger on some versions passes the literal quoted string (including the quotes) as the priority, resulting in an invalid priority and the message being dropped or logged with default priority.
Suggested fix: Since syslog_facility and prio are controlled internal values (not user input that needs quoting), use them directly after validating they contain only safe characters:
```lua
local prio_arg = config.syslog_facility .. "." .. prio
-- prio_arg contains only [a-z0-9.] so no quoting needed
os.execute(string.format("logger -p %s %s 2>/dev/null",
    prio_arg, shell_quote("thunderstorm-collector: " .. clean)))
```

### Finding 23. [LOW] scan_id appended to api_endpoint with incorrect separator detection
Location: main / api_endpoint scan_id append
Description: The code checks `if not api_endpoint:find("?")` to decide whether to use '?' or '&' as the separator. `string.find` with a single-character argument treats '?' as a Lua pattern metacharacter (matches any character). This means the condition is always true (any string contains 'any character'), so '?' is always used as the separator even when the URL already has a query string (e.g., `?source=foo`), producing `?source=foo?scan_id=...` which is an invalid URL.
Suggested fix: Use the plain=true flag for find:
```lua
local sep = "&"
if not api_endpoint:find("?", 1, true) then sep = "?" end
api_endpoint = api_endpoint .. sep .. "scan_id=" .. urlencode(scan_id)
```


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
