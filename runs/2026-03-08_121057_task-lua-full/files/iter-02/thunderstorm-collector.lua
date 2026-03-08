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

-- Whether the `timeout` command is available (detected once at startup)
has_timeout_cmd = nil

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
    -- character class: double-quote, backslash, semicolon
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
-- Finding 4: more defensive handling of os.execute return values
function exec_ok(cmd)
    local a, b, c = os.execute(cmd)
    if a == true then return true end           -- Lua 5.2+ success
    if a == false or a == nil then              -- Lua 5.2+ failure
        -- but check if it's the 3-return form
        if b == "exit" and c == 0 then return true end
        return false
    end
    -- Lua 5.1: numeric return
    if type(a) == "number" then return a == 0 end
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

-- Detect whether the `timeout` shell command is available (cached).
-- Finding 16: probe for timeout before using it in nc backend.
function detect_timeout_cmd()
    if has_timeout_cmd ~= nil then return has_timeout_cmd end
    has_timeout_cmd = exec_ok("which timeout >/dev/null 2>&1")
    return has_timeout_cmd
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

    -- Console output (stderr).
    -- Finding 17: always show error and warn regardless of --quiet;
    -- only suppress info/debug in quiet mode.
    if not config.quiet or level == "error" or level == "warn" then
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
    print("      --quiet                Disable info/debug command-line logging")
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

-- Decode /proc/mounts octal escape sequences (\040 = space, \011 = tab,
-- \012 = newline, \\ = backslash). Finding 14/15.
function decode_mounts_field(s)
    if not s then return s end
    return s:gsub("\\(%d%d%d)", function(oct)
        return string.char(tonumber(oct, 8))
    end):gsub("\\\\", "\\")
end

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
            -- Finding 14/15: decode octal escape sequences in mountpoint
            mp = decode_mounts_field(mp)
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

-- Lua-level prefix check against all excluded paths (Finding 10: second line
-- of defense for BusyBox find which may not support glob patterns in -path).
function is_excluded_path(path)
    for _, p in ipairs(EXCLUDE_PATHS) do
        if path == p or path:sub(1, #p + 1) == p .. "/" then return true end
    end
    for _, p in ipairs(dynamic_excludes) do
        if path == p or path:sub(1, #p + 1) == p .. "/" then return true end
    end
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

-- Finding 2/3: stream multipart body directly to temp file. Returns
-- boundary, tmp_path, actual_body_len (from temp file size) or nil on error.
-- The boundary is finalized BEFORE header/footer are built so they are
-- always consistent. body_len is measured from the actual temp file to
-- avoid TOCTOU skew between size measurement and streaming.
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)

    -- Finding 3: finalize boundary first, then build header/footer once.
    -- Use a long random boundary; for files <= 64KB do a collision check.
    -- Finding 22: avoid double-reading large files; rely on long random
    -- boundary being sufficiently unique for files > 64KB.
    local src_size = file_size_bytes(filepath)
    if src_size < 0 then return nil, nil, nil end

    -- Generate initial boundary
    local boundary = "----ThunderstormBoundary"
        .. tostring(os.time())
        .. tostring(math.random(100000, 999999))
        .. tostring(math.random(100000, 999999))

    -- For small files, check for boundary collision and regenerate if needed
    if src_size <= 65536 then
        local src_f = io.open(filepath, "rb")
        if src_f then
            local sample = src_f:read("*a")
            src_f:close()
            local attempts = 0
            while sample:find(boundary, 1, true) and attempts < 5 do
                boundary = "----ThunderstormBoundary"
                    .. tostring(os.time())
                    .. tostring(math.random(100000, 999999))
                    .. tostring(math.random(100000, 999999))
                attempts = attempts + 1
            end
            -- sample goes out of scope here; GC will collect it
        end
    end

    -- Finding 3: build header and footer AFTER boundary is finalized
    local header = "--" .. boundary .. "\r\n"
        .. string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n', safe_name)
        .. "Content-Type: application/octet-stream\r\n"
        .. "\r\n"
    local footer = "\r\n--" .. boundary .. "--\r\n"

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

    -- Finding 2: measure actual body length from the temp file after writing,
    -- so Content-Length is always accurate regardless of TOCTOU file changes.
    local actual_body_len = out:seek("end")
    out:close()

    if not actual_body_len then return nil, nil, nil end

    return boundary, tmp, actual_body_len
end

-- ==========================================================================
-- UPLOAD BACKENDS
-- ==========================================================================

-- Finding 1: curl backend now uses the multipart body builder (same as
-- wget/nc) and passes the body via --data-binary @tmpfile with an explicit
-- Content-Type header. This avoids embedding the raw filepath inside a
-- shell-quoted --form string, eliminating the shell injection vector.
function upload_with_curl(endpoint, filepath, filename, resp_file)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    local tls_flags = get_curl_tls_flags()
    local err_file = resp_file .. ".err"
    temp_files[#temp_files + 1] = err_file

    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s"
        .. "-H %s "
        .. "-H %s "
        .. "--data-binary @%s "
        .. "-o %s 2>%s",
        tls_flags,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
        shell_quote("Content-Length: " .. tostring(body_len)),
        shell_quote(body_file),
        shell_quote(resp_file),
        shell_quote(err_file)
    )
    -- Append endpoint as last positional argument
    cmd = cmd .. " " .. shell_quote(endpoint)

    if not exec_ok(cmd) then
        -- Read stderr for error details
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

-- Finding 13: remove explicit Content-Length header from wget command;
-- wget computes it automatically from --post-file, avoiding duplicate headers.
-- body_len from build_multipart_body is the actual temp file size (Finding 2).
function upload_with_wget(endpoint, filepath, filename, resp_file)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    local tls_flags = get_wget_tls_flags()

    -- Finding 13: omit explicit Content-Length; wget calculates it from the
    -- post file automatically, avoiding duplicate/conflicting headers.
    local cmd = string.format(
        "wget -q -O %s %s--header=%s --post-file=%s %s 2>/dev/null",
        shell_quote(resp_file),
        tls_flags,
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

function upload_with_nc(endpoint, filepath, filename, resp_file)
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

    -- Finding 5/8: use input redirect instead of pipe so nc waits for server
    -- response before exiting. Finding 16: use timeout only if available.
    -- Finding 5: do NOT double-quote host/port inside the inner command.
    local cmd
    if detect_timeout_cmd() then
        -- timeout is available: wrap nc with it
        cmd = string.format(
            "timeout 35 nc -w 30 %s %s <%s >%s 2>/dev/null",
            shell_quote(host), shell_quote(port),
            shell_quote(req_file), shell_quote(resp_file)
        )
    else
        -- No timeout command; rely on nc's own -w flag
        cmd = string.format(
            "nc -w 30 %s %s <%s >%s 2>/dev/null",
            shell_quote(host), shell_quote(port),
            shell_quote(req_file), shell_quote(resp_file)
        )
    end
    exec_ok(cmd)  -- ignore exit code; check response below

    -- Read first 4KB of response only
    local resp = nil
    local resp_f = io.open(resp_file, "rb")
    if resp_f then
        resp = resp_f:read(4096)
        resp_f:close()
    end

    if not resp or resp == "" then return false end

    -- Finding 20: check for HTTP/1.x and HTTP/2 2xx success
    if resp:match("HTTP/1%.%d 2%d%d") then return true end
    if resp:match("HTTP/2%.?%d? 2%d%d") then return true end
    if resp:match("HTTP/2 2%d%d") then return true end

    -- Any non-2xx is a failure
    local status = resp:match("^([^\r\n]+)") or "unknown"
    log_msg("error", "Server error for '" .. filepath .. "': " .. status)
    return false
end

function upload_with_busybox_wget(endpoint, filepath, filename, resp_file)
    -- Same as wget but with known NUL byte truncation risk
    return upload_with_wget(endpoint, filepath, filename, resp_file)
end

-- ==========================================================================
-- FILE SUBMISSION WITH RETRY
-- ==========================================================================

-- Finding 24: create resp_file once per submit_file call and reuse across
-- retry attempts to avoid accumulating temp file entries.
function submit_file(endpoint, filepath)
    local filename = filepath:match("([^/]+)$") or filepath

    -- Single resp_file reused across all retry attempts
    local resp_file = mktemp()

    for attempt = 1, config.retries do
        local success = false

        if config.upload_tool == "curl" then
            success = upload_with_curl(endpoint, filepath, filename, resp_file)
        elseif config.upload_tool == "wget" then
            success = upload_with_wget(endpoint, filepath, filename, resp_file)
        elseif config.upload_tool == "nc" then
            success = upload_with_nc(endpoint, filepath, filename, resp_file)
        elseif config.upload_tool == "busybox-wget" then
            success = upload_with_busybox_wget(endpoint, filepath, filename, resp_file)
        else
            log_msg("error", "No upload tool available")
            return false
        end

        if success then return true end

        log_msg("warn", string.format("Upload failed for '%s' (attempt %d/%d)",
            filepath, attempt, config.retries))

        if attempt < config.retries then
            -- Finding 18: use ^ operator for clarity: 2^(attempt-1) seconds
            local delay = math.floor(2 ^ (attempt - 1))
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
-- Finding 6/26: implement nc branch so markers work on nc-only systems.
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
        elseif exec_ok("which nc >/dev/null 2>&1") then tool = "nc"
        end
    end

    -- Finding 16: check exec_ok() and log failures
    if tool == "curl" then
        local tls_flags = get_curl_tls_flags()
        local cmd = string.format(
            "curl -s -o %s %s-H %s --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), tls_flags,
            shell_quote("Content-Type: application/json"),
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
        -- Finding 9: use shell_quote for the Content-Type header value
        local cmd = string.format(
            "wget -q -O %s %s--header=%s --post-file=%s --timeout=10 %s 2>/dev/null",
            shell_quote(resp_file), tls_flags,
            shell_quote("Content-Type: application/json"),
            shell_quote(body_file), shell_quote(url))
        if not exec_ok(cmd) then
            log_msg("warn", "Failed to send collection marker (" .. marker_type .. ") via wget")
        else
            local f = io.open(resp_file, "r")
            if f then resp = f:read("*a"); f:close() end
        end
    elseif tool == "nc" then
        -- Finding 6/26: implement nc branch for collection markers
        -- Parse URL components
        local hostpath = url:match("^https?://(.+)$")
        if not hostpath then
            log_msg("warn", "Cannot parse URL for nc marker: " .. url)
            return ""
        end
        local hostport = hostpath:match("^([^/]+)")
        local path_rest = hostpath:match("^[^/]+/(.*)$")
        local path_query = "/" .. (path_rest or "")
        local host = hostport and hostport:match("^([^:]+)")
        local port = hostport and hostport:match(":(%d+)$")
        if not host then
            log_msg("warn", "Cannot parse host for nc marker")
            return ""
        end
        if not port then
            if config.ssl then port = "443" else port = "80" end
        end

        -- Build HTTP request in a temp file
        local req_file = mktemp()
        local req_f = io.open(req_file, "wb")
        if not req_f then
            log_msg("warn", "Cannot create temp file for nc marker request")
            return ""
        end
        local body_len = #body
        req_f:write(string.format("POST %s HTTP/1.1\r\n", path_query))
        req_f:write(string.format("Host: %s\r\n", hostport))
        req_f:write("Content-Type: application/json\r\n")
        req_f:write(string.format("Content-Length: %d\r\n", body_len))
        req_f:write("Connection: close\r\n")
        req_f:write("\r\n")
        req_f:write(body)
        req_f:close()

        -- Finding 16: use timeout if available, else rely on nc -w
        local nc_cmd
        if detect_timeout_cmd() then
            nc_cmd = string.format(
                "timeout 15 nc -w 10 %s %s <%s >%s 2>/dev/null",
                shell_quote(host), shell_quote(port),
                shell_quote(req_file), shell_quote(resp_file))
        else
            nc_cmd = string.format(
                "nc -w 10 %s %s <%s >%s 2>/dev/null",
                shell_quote(host), shell_quote(port),
                shell_quote(req_file), shell_quote(resp_file))
        end
        if not exec_ok(nc_cmd) then
            log_msg("warn", "Failed to send collection marker (" .. marker_type .. ") via nc")
        else
            local f = io.open(resp_file, "rb")
            if f then
                local raw = f:read(4096)
                f:close()
                -- Strip HTTP response headers to get body
                if raw then
                    local body_start = raw:find("\r\n\r\n", 1, true)
                    if body_start then
                        resp = raw:sub(body_start + 4)
                    end
                end
            end
        end
    else
        log_msg("warn", "No upload tool available to send collection marker (" .. marker_type .. ")")
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

    -- Finding 7: use -mmin for minute-granularity age filtering so that files
    -- exactly at the max_age boundary are included. -mtime -N excludes files
    -- that are exactly N*24h old; -mmin -N*1440 is equivalent but precise.
    local max_age_min = config.max_age * 1440

    -- Build the full find command
    return string.format("find %s %s-type f -mmin -%d -print 2>/dev/null",
        shell_quote(dir), prune_str, max_age_min)
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

                -- Finding 10: Lua-level prefix exclusion check as second line
                -- of defense (handles BusyBox find glob portability issues)
                if is_excluded_path(file_path) then
                    counters.files_skipped = counters.files_skipped + 1
                    log_msg("debug", "Skipping excluded path '" .. file_path .. "'")
                -- Cloud path exclusion
                elseif is_cloud_path(file_path) then
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
    -- Finding 28: seed RNG before any math.random() calls
    math.randomseed(os.time())

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

    -- Probe for timeout command availability (cached for nc backend)
    detect_timeout_cmd()

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
