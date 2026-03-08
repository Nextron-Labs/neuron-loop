#!/usr/bin/env lua
-- ==========================================================================
-- THOR Thunderstorm Collector — Lua 5.1+ Edition
-- Florian Roth / Nextron Systems
--
-- Pure Lua implementation of the Thunderstorm file collector.
-- Target: OpenWrt, embedded Linux, BusyBox+Lua systems, industrial gateways.
-- Requires: Lua 5.1+ standard library + one of: curl, wget, nc
--
-- Exit codes:
--   0 = clean run (all files submitted successfully or dry-run)
--   1 = partial failure (some file uploads failed)
--   2 = fatal error (misconfiguration, missing tools, etc.)
--
-- Limitations:
-- - Filenames containing literal newlines are not supported
-- - Symlink cycles not auto-detected (could cause infinite recursion in find)
-- - Signal handling (SIGINT/SIGTERM) is NOT available in pure Lua 5.1 on
--   embedded targets (no posix.signal). If interrupted, the begin marker
--   will have been sent but no end/interrupted marker will be sent.
--   Use the companion shell wrapper (thunderstorm-collector-wrapper.sh) for
--   signal-aware operation.
-- - nc (netcat) does not support HTTPS/TLS; use curl or wget for SSL.
-- - nc does not support custom CA bundles; --ca-cert requires curl or wget.
-- ==========================================================================

VERSION = "0.1.1"

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

-- TTY detection result (cached)
_is_tty = nil

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
    -- Replace characters that are problematic in curl form specs or HTTP headers
    local r = s:gsub('["%\\;%z]', "_")
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

function file_size_bytes(path)
    local f = io.open(path, "rb")
    if not f then return -1 end
    local size = f:seek("end")
    f:close()
    if not size then return -1 end
    return size
end

-- Use the shell mktemp command for atomic temp file creation (avoids TOCTOU race)
function mktemp()
    local path = trim(exec_capture("mktemp 2>/dev/null") or "")
    if path == "" then
        -- Fallback to os.tmpname() if mktemp is unavailable
        path = os.tmpname()
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

-- Detect whether stderr is a TTY (for progress reporting)
function is_tty()
    if _is_tty ~= nil then return _is_tty end
    -- Use test -t 2 to check if stderr (fd 2) is a TTY
    _is_tty = exec_ok("test -t 2 2>/dev/null")
    return _is_tty
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
    if config.log_to_syslog then
        local prio = level
        if prio == "warn" then prio = "warning"
        elseif prio == "error" then prio = "err" end
        os.execute(string.format("logger -p %s %s 2>/dev/null",
            shell_quote(config.syslog_facility .. "." .. prio),
            shell_quote("thunderstorm-collector: " .. clean)))
    end
end

-- Fatal error: log, cleanup, exit with code 2
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
    print("      --ca-cert <path>       CA bundle for TLS verification (curl/wget only)")
    print("      --sync                 Use /api/check (default: /api/checkAsync)")
    print("      --retries <num>        Retry attempts per file (default: 3)")
    print("      --dry-run              Do not upload, only show what would be submitted")
    print("      --debug                Enable debug log messages")
    print("      --progress             Force progress reporting")
    print("      --no-progress          Disable progress reporting")
    print("      --log-file <path>      Log file path (default: ./thunderstorm.log)")
    print("      --no-log-file          Disable file logging")
    print("      --syslog               Enable syslog logging")
    print("      --quiet                Disable command-line logging")
    print("  -h, --help                 Show this help text")
    print("")
    print("Exit codes:")
    print("  0 = clean run (all files submitted or dry-run)")
    print("  1 = partial failure (some file uploads failed)")
    print("  2 = fatal error (misconfiguration, missing tools, etc.)")
    print("")
    print("Notes:")
    print("  Requires Lua 5.1+ and one of: curl, wget, or nc for uploads.")
    print("  Filenames containing literal newline characters are not supported.")
    print("  nc (netcat) does not support HTTPS or custom CA bundles.")
    print("  Signal handling (SIGINT/SIGTERM) is not available in pure Lua 5.1;")
    print("  use the companion shell wrapper for signal-aware operation.")
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
            -- Truncate to 253 chars (max DNS name length) to prevent excessively long URLs
            config.source = next_val:sub(1, 253)
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
        elseif a == "--progress" then
            config.progress = true
        elseif a == "--no-progress" then
            config.progress = false
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
            os.exit(2)
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
    -- Validate ca_cert file exists if specified
    if config.ca_cert ~= "" then
        if not exec_ok("test -f " .. shell_quote(config.ca_cert)) then
            die("CA certificate file not found: " .. config.ca_cert)
        end
    end
    -- Warn if ca_cert is set but insecure is also set (contradictory)
    if config.ca_cert ~= "" and config.insecure then
        log_msg("warn", "--ca-cert and --insecure are both set; --insecure takes precedence")
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
                -- Truncate to 253 chars (max DNS name length)
                config.source = trim(result):sub(1, 253)
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
            -- Decode octal escapes (e.g. \040 for space) used in /proc/mounts
            mp = mp:gsub("\\(%d%d%d)", function(oct)
                return string.char(tonumber(oct, 8))
            end)
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
        -- nc cannot do HTTPS/TLS — fatal if SSL is required
        if config.ssl then
            log_msg("error", "HTTPS (--ssl) requires curl or wget; nc cannot perform TLS uploads")
            return false
        end
        -- nc cannot use custom CA bundles
        if config.ca_cert ~= "" then
            log_msg("error", "--ca-cert requires curl or wget; nc does not support TLS")
            return false
        end
        config.upload_tool = "nc"
        return true
    end

    -- BusyBox wget as last resort
    if has_wget then
        config.upload_tool = "busybox-wget"
        log_msg("warn", "BusyBox wget detected; binary files with NUL bytes may fail to upload")
        log_msg("warn", "BusyBox wget may ignore custom Content-Type headers with --post-file")
        return true
    end

    return false
end

-- ==========================================================================
-- TLS FLAGS HELPERS
-- ==========================================================================

-- Returns the curl TLS flags string (insecure or ca-cert or empty)
function get_curl_tls_flags()
    if config.insecure then
        return "-k "
    elseif config.ca_cert ~= "" then
        return "--cacert " .. shell_quote(config.ca_cert) .. " "
    end
    return ""
end

-- Returns the wget TLS flags string
function get_wget_tls_flags()
    if config.insecure then
        return "--no-check-certificate "
    elseif config.ca_cert ~= "" then
        return "--ca-certificate=" .. shell_quote(config.ca_cert) .. " "
    end
    return ""
end

-- ==========================================================================
-- MULTIPART FORM-DATA CONSTRUCTION (streaming, low-memory)
-- ==========================================================================

-- Build a multipart body by streaming directly to a temp file.
-- Returns: boundary (string), body_file (path), body_len (number)
-- Does NOT load the entire file into memory.
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)

    -- Generate a sufficiently random boundary to avoid collisions with binary content
    math.randomseed(os.time())
    local boundary = string.format(
        "ThunderstormBoundary%d%d%d",
        os.time(),
        math.random(100000, 999999),
        math.random(100000, 999999)
    )

    -- Build header and footer parts
    local header = "--" .. boundary .. "\r\n"
        .. string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n', safe_name)
        .. "Content-Type: application/octet-stream\r\n"
        .. "\r\n"
    local footer = "\r\n--" .. boundary .. "--\r\n"

    -- Get file size without reading content
    local fsize = file_size_bytes(filepath)
    if fsize < 0 then return nil, nil, nil end

    local body_len = #header + fsize + #footer

    -- Write multipart body to temp file in chunks (memory-efficient)
    local tmp = mktemp()
    local out = io.open(tmp, "wb")
    if not out then return nil, nil, nil end

    -- Write header
    out:write(header)

    -- Stream file content in 8 KB chunks
    local src = io.open(filepath, "rb")
    if not src then
        out:close()
        return nil, nil, nil
    end

    local CHUNK = 8192
    while true do
        local chunk = src:read(CHUNK)
        if not chunk then break end
        out:write(chunk)
    end
    src:close()

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
    local err_file = mktemp()

    -- Use separate -F fields to avoid semicolon injection in curl's form spec parser.
    -- file=@PATH uploads the file content; filename= sets the display name separately.
    -- This avoids embedding filepath inside a semicolon-delimited form spec value.
    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s%s -F %s -F %s -o %s 2>%s",
        tls_flags,
        shell_quote(endpoint),
        shell_quote("file=@" .. filepath),
        shell_quote("filename=" .. safe_name),
        shell_quote(resp_file),
        shell_quote(err_file)
    )

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

function upload_with_wget(endpoint, filepath, filename)
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then return false end

    local resp_file = mktemp()
    local tls_flags = get_wget_tls_flags()

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
        -- nc is only used for plain HTTP (SSL check is in detect_upload_tool)
        port = "80"
    end

    -- Build raw HTTP/1.0 request (simpler than 1.1 for raw nc; no keep-alive issues)
    local req_file = mktemp()
    local req_f = io.open(req_file, "wb")
    if not req_f then return false end

    req_f:write(string.format("POST %s HTTP/1.0\r\n", path_query))
    req_f:write(string.format("Host: %s\r\n", hostport))
    req_f:write(string.format("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))
    req_f:write(string.format("Content-Length: %d\r\n", body_len))
    req_f:write("\r\n")

    -- Append the body content in chunks (memory-efficient)
    local body_f = io.open(body_file, "rb")
    if body_f then
        local CHUNK = 8192
        while true do
            local chunk = body_f:read(CHUNK)
            if not chunk then break end
            req_f:write(chunk)
        end
        body_f:close()
    end
    req_f:close()

    -- Send via nc with a 10-second timeout (shorter than 30s to avoid long hangs)
    -- HTTP/1.0 causes server to close connection after response, so nc will exit cleanly
    local cmd = string.format(
        "cat %s | nc -w 10 %s %s 2>/dev/null",
        shell_quote(req_file), shell_quote(host), shell_quote(port)
    )
    local resp = exec_capture(cmd)

    if not resp or resp == "" then return false end

    -- Check for HTTP 2xx success
    if resp:match("HTTP/1%.[01] 2%d%d") then return true end

    -- Any non-2xx is a failure
    local status = resp:match("^([^\r\n]+)") or "unknown"
    log_msg("error", "Server error for '" .. filepath .. "': " .. status)
    return false
end

function upload_with_busybox_wget(endpoint, filepath, filename)
    -- Same as wget but with known NUL byte truncation risk and possible
    -- Content-Type override by BusyBox wget when using --post-file
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

    -- Write JSON body to a temp file to avoid shell quoting issues with special chars
    local body_file = mktemp()
    local bf = io.open(body_file, "wb")
    if not bf then return "" end
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

    if tool == "curl" then
        local tls_flags = get_curl_tls_flags()
        local cmd = string.format(
            "curl -s -o %s %s-H 'Content-Type: application/json' --max-time 10 --data-binary @%s %s 2>/dev/null",
            shell_quote(resp_file), tls_flags,
            shell_quote(body_file), shell_quote(url))
        os.execute(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
    elseif tool == "wget" or tool == "busybox-wget" then
        local tls_flags = get_wget_tls_flags()
        local cmd = string.format(
            "wget -q -O %s %s--header='Content-Type: application/json' --post-file=%s --timeout=10 %s 2>/dev/null",
            shell_quote(resp_file), tls_flags,
            shell_quote(body_file), shell_quote(url))
        os.execute(cmd)
        local f = io.open(resp_file, "r")
        if f then resp = f:read("*a"); f:close() end
    elseif tool == "nc" then
        -- nc only for plain HTTP (SSL check already done in detect_upload_tool)
        local hostpath = url:match("^https?://(.+)$")
        if hostpath then
            local hostport = hostpath:match("^([^/]+)")
            local path_rest = hostpath:match("^[^/]+/(.*)$")
            local path_query = "/" .. (path_rest or "")
            local host = hostport:match("^([^:]+)")
            local port = hostport:match(":(%d+)$") or "80"

            local req_file = mktemp()
            local req_f = io.open(req_file, "wb")
            if req_f then
                req_f:write(string.format("POST %s HTTP/1.0\r\n", path_query))
                req_f:write(string.format("Host: %s\r\n", hostport))
                req_f:write("Content-Type: application/json\r\n")
                req_f:write(string.format("Content-Length: %d\r\n", #body))
                req_f:write("\r\n")
                req_f:write(body)
                req_f:close()

                local cmd = string.format(
                    "cat %s | nc -w 10 %s %s 2>/dev/null",
                    shell_quote(req_file), shell_quote(host), shell_quote(port))
                resp = exec_capture(cmd)
            end
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
        -- Wrap in escaped parentheses for correct operator precedence across all
        -- POSIX find implementations
        prune_str = "\\( " .. table.concat(prune_parts, " -o ") .. " \\) -o "
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

    -- Process line by line (memory efficient); wrap in pcall to ensure handle is closed
    local ok, err = pcall(function()
        for file_path in handle:lines() do
            if file_path ~= "" then
                counters.files_scanned = counters.files_scanned + 1

                -- Progress reporting
                local show_progress = config.progress
                if show_progress == nil then show_progress = is_tty() end
                if show_progress and counters.files_scanned % 100 == 0 then
                    io.stderr:write(string.format(
                        "\r[progress] scanned=%d submitted=%d skipped=%d failed=%d",
                        counters.files_scanned, counters.files_submitted,
                        counters.files_skipped, counters.files_failed))
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

    -- Always close the handle, even if iteration raised an error
    handle:close()

    -- Clear progress line if we were showing progress
    local show_progress = config.progress
    if show_progress == nil then show_progress = is_tty() end
    if show_progress then
        io.stderr:write("\r\027[K")  -- CR + clear-to-EOL (works on most terminals)
        io.stderr:flush()
    end

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
    if config.ca_cert ~= "" then log_msg("info", "CA cert: " .. config.ca_cert) end

    -- Record start time
    local start_time = os.time()

    -- Send begin marker (with single retry after 2s on failure)
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

    -- Exit with appropriate code:
    --   0 = clean run
    --   1 = partial failure (some uploads failed)
    if counters.files_failed > 0 then
        os.exit(1)
    else
        os.exit(0)
    end
end

-- ==========================================================================
-- ENTRY POINT
-- Wrap main() in pcall so that Lua errors still attempt to send an end marker
-- and produce a proper exit code 2 (fatal error).
-- Note: SIGINT/SIGTERM cannot be trapped in pure Lua 5.1 on embedded targets.
-- If the process is killed, the begin marker will have been sent but no
-- end/interrupted marker will be sent. Use the companion shell wrapper for
-- signal-aware operation.
-- ==========================================================================

local ok, err = pcall(main)
if not ok then
    io.stderr:write(string.format("[error] Fatal Lua error: %s\n", tostring(err)))
    -- Attempt to send an interrupted marker if we have enough state
    if config and config.upload_tool and config.upload_tool ~= "" and not config.dry_run then
        local scheme = config.ssl and "https" or "http"
        local base_url = string.format("%s://%s:%d", scheme, config.server, config.port)
        local stats = string.format(
            '"stats":{"scanned":%d,"submitted":%d,"skipped":%d,"failed":%d}',
            counters.files_scanned or 0, counters.files_submitted or 0,
            counters.files_skipped or 0, counters.files_failed or 0)
        pcall(send_collection_marker, base_url, "interrupted", nil, stats)
    end
    cleanup_temp_files()
    if log_file_handle then pcall(function() log_file_handle:close() end) end
    os.exit(2)
end
