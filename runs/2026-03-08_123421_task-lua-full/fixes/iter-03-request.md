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
        log_msg("warn", "max-age=0 will match no files (find -mtime -0 matches nothing)")
    end
    if config.max_size_kb <= 0 then
        die("max-size-kb must be > 0")
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

    req_f:write(string.format("POST %s HTTP/1.1\r\n", path_query))
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
        local cmd = string.format(
            "curl -sS --fail -o %s %s%s-H %s --max-time 10 --data-binary @%s %s 2>/dev/null",
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
    for file_path in handle:lines() do
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

    -- Seed random number generator for temp file name generation
    math.randomseed(os.time() + math.floor(os.clock() * 1000000))

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


### Finding 1. [CRITICAL] Malformed script: `>>>REPLACE` marker left in production code
Location: scan_directory / for file_path in handle:lines() loop
Description: The source file contains a literal `>>>REPLACE` token followed by a duplicated block of code (the progress-detection and pcall-wrapped scan loop appears twice). The `>>>REPLACE` line is not valid Lua and will cause a syntax error, making the entire script fail to load. The code between the first `for file_path in handle:lines() do` and the `>>>REPLACE` marker is an incomplete, unclosed loop body.
Suggested fix: Remove the first (incomplete) copy of the loop and the `>>>REPLACE` marker, keeping only the pcall-wrapped version that follows it. The final scan_directory function should contain exactly one progress-detection block and one pcall-wrapped loop.

### Finding 2. [CRITICAL] shell_quote does not protect against filenames starting with a dash being interpreted as options
Location: shell_quote / all upload functions
Description: shell_quote wraps the string in single quotes, which correctly handles most special characters. However, when the quoted value is passed as a positional argument to tools like `nc`, a filename like `-e /bin/sh` stored in a path such as `/tmp/-e /bin/sh` would be single-quoted correctly. The real risk is in `upload_with_nc` where `shell_quote(host)` and `shell_quote(port)` are passed directly as arguments to `nc`. If the server hostname parsed from the URL were attacker-controlled and began with `-`, it could inject nc options. More critically, `shell_quote(req_file)` and `shell_quote(resp_file)` use mktemp paths that are under attacker influence via symlink attacks (see F3), but the option-injection risk exists for the host/port fields derived from config.
Suggested fix: Prepend `--` before positional arguments where the tool supports it, or validate that `config.server` does not start with `-` in `validate_config()`.

### Finding 3. [HIGH] Patched block leaves a stray `for` and breaks the function syntactically
Location: scan_directory / replaced loop body
Description: The file shows an original `for file_path in handle:lines() do` immediately followed by a replacement block that introduces another `for file_path in handle:lines() do` inside a `pcall`. If applied literally, the outer loop is never closed and the function becomes invalid Lua. This is not just a merge artifact concern: the target file as presented is not executable.
Suggested fix: Remove the original loop header entirely and keep only the wrapped version. The function should contain exactly one iteration over `handle:lines()`, e.g. `local ok, scan_err = pcall(function() for file_path in handle:lines() do ... end end)`.

### Finding 4. [HIGH] Missing space before `-H` corrupts curl command when no CA cert is used
Location: send_collection_marker / curl command construction
Description: The curl marker upload command is built with `"... %s%s-H %s ..."`. When `ca_cert_flag` is empty, this expands to something like `curl ... -k -H ...`, which works only if `insecure` ends with a space. But when `config.insecure` is false and `ca_cert_flag` is empty, it becomes `curl ... <respfile> -H ...` only because the previous placeholder may or may not provide spacing; the formatting is fragile and can produce malformed concatenation such as `--cacert 'x'-H` when flags are changed. This differs from the file upload curl path, which inserts spaces explicitly between arguments.
Suggested fix: Build the command with explicit spaces between every optional segment, e.g. `"curl -sS --fail -o %s %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null"` and let empty flags collapse harmlessly.

### Finding 5. [HIGH] No `nc` implementation for collection markers causes marker loss on minimal systems
Location: send_collection_marker
Description: The script supports `nc` for file uploads, but `send_collection_marker` only implements curl and wget paths. On systems where `detect_upload_tool()` selected `nc` (a stated supported environment on BusyBox/OpenWrt), begin/end markers are silently skipped because `tool == "nc"` is never handled and the function just returns an empty string.
Suggested fix: Add an `nc` JSON POST path similar to `upload_with_nc`, or explicitly document and surface this as a warning/error when `config.upload_tool == "nc"` so operators know markers are unavailable.

### Finding 6. [HIGH] TOCTOU race on temp file fallback path; symlink attack possible
Location: mktemp / build_multipart_body / upload_with_nc / submit_file
Description: When `mktemp` (the system binary) is unavailable, the code falls back to `os.tmpname()` and then opens the returned path. `os.tmpname()` in Lua 5.1 calls C `tmpnam()`, which is documented as unsafe due to the race between name generation and file creation. An attacker with write access to `/tmp` can create a symlink at the returned path between `os.tmpname()` and `io.open()`, causing the script to write multipart body data (including file contents) to an attacker-chosen destination. The secondary fallback (`/tmp/thunderstorm.<time><random>`) is also predictable because `os.time()` has 1-second granularity and `math.random` is seeded with `os.time()` — the seed is set in `main()` after `mktemp` may already be called during `send_collection_marker` for the begin marker.
Suggested fix: Always prefer the `mktemp` binary. If unavailable, use `/dev/urandom` via `io.open('/dev/urandom','rb'):read(8)` to generate an unpredictable suffix. Also call `math.randomseed` before the first `mktemp()` call (move it before `send_collection_marker`).

### Finding 7. [HIGH] Boundary collision: file content containing the boundary string causes malformed multipart body
Location: build_multipart_body
Description: The multipart boundary is generated as `----ThunderstormBoundary` + two 9-digit random numbers. If the binary content of the uploaded file happens to contain this exact byte sequence preceded by `\r\n--`, the HTTP server will interpret it as a premature boundary, truncating the file data and potentially causing the server to parse a malformed request. The boundary is not checked against the file content before use.
Suggested fix: After generating the boundary, read the file once to verify the boundary does not appear in it, regenerating if necessary. Alternatively, use a cryptographically derived boundary (e.g., hex-encode bytes from `/dev/urandom`). Since the file is already being streamed to a temp file, a pre-scan pass is feasible.

### Finding 8. [HIGH] nc upload silently succeeds even on connection failure when resp is empty
Location: upload_with_nc / send_collection_marker
Description: In `upload_with_nc`, if `nc` fails to connect (e.g., server unreachable), it exits non-zero but the script ignores the exit code (`exec_ok(cmd)` result is discarded). The response file will be empty, and the check `if not resp or resp == ''` returns `false` — correctly. However, if nc connects but the server closes the connection before sending a response (e.g., TLS mismatch, server crash mid-transfer), `resp` will also be empty and the function returns `false`. The issue is that the nc exit code is never checked, so a partial upload (nc connected, sent data, server closed without responding) is indistinguishable from a clean failure. More importantly, `exec_ok(cmd)` return value is thrown away — this is intentional per the comment, but means retry logic in `submit_file` will always retry even when nc itself reports success (exit 0) with an empty body.
Suggested fix: Capture nc's exit code: `local nc_ok = exec_ok(cmd)`. If `nc_ok` is false AND resp is empty, treat as connection failure. If `nc_ok` is true but resp is empty, log a warning about missing response but consider it a potential success (or retry once).

### Finding 9. [HIGH] Temp file list truncation uses table.remove in reverse but leaves gaps if upload functions add non-contiguous entries
Location: submit_file / temp file cleanup loop
Description: After each upload attempt, `submit_file` removes temp files created during that attempt by iterating `temp_files` from `#temp_files` down to `temps_before + 1` using `table.remove`. This is correct for a simple stack. However, `build_multipart_body` calls `mktemp()` which appends to `temp_files`, and the upload functions (curl, wget, nc) also call `mktemp()` for resp_file and err_file. If an upload function returns early (e.g., `build_multipart_body` returns nil and the function returns false before creating resp_file), `temps_before` was captured before the attempt, so the cleanup loop correctly removes whatever was added. This part is actually correct. The real bug is: `send_collection_marker` also calls `mktemp()` and adds to `temp_files`, but never cleans up those entries — it relies on `cleanup_temp_files()` at the end of `main()`. If the script is killed (SIGKILL) or crashes, those temp files leak. This is a minor resource leak but on embedded systems with limited `/tmp` space it matters.
Suggested fix: In `send_collection_marker`, track the temp_files index before the call and clean up immediately after, similar to the pattern in `submit_file`. Or use a dedicated cleanup wrapper.

### Finding 10. [HIGH] sanitize_filename uses a Lua pattern class that does not correctly escape backslash
Location: sanitize_filename
Description: The pattern `'["\\;]'` in Lua source is the string `["%\;]` at runtime (Lua string escaping: `\\` → `\`). In a Lua character class `[...]`, `%\` means literal `%` followed by `\` — but `%` inside `[]` is not a magic character in Lua patterns, so this matches `%`, `\`, `"`, and `;`. The intent was to match `"`, `\`, and `;`. The accidental inclusion of `%` is harmless for the sanitization purpose, but the backslash IS correctly matched here (since `\` inside `[]` is just a literal backslash in Lua patterns). So the backslash replacement works. However, the function is used to sanitize the filename in the Content-Disposition header. The header value is placed inside double quotes: `filename="%s"`. If `sanitize_filename` replaces `"` with `_` but a filename contains `\"` (backslash then quote), the backslash is replaced with `_` and the quote is replaced with `_`, so the output is safe. This is actually correct but the pattern comment is misleading. The real issue: `sanitize_filename` is NOT applied to the boundary string or to the endpoint URL — only to the filename in the Content-Disposition header.
Suggested fix: Rewrite the pattern clearly: `s:gsub('["\\;%%]', '_')` if `%` should be included, or `s:gsub('["\\;]', '_')` if not. Add a comment explaining why each character is excluded.

### Finding 11. [HIGH] find -mtime -N semantics: -mtime -0 matches no files, and -mtime -1 only matches files modified in the last 24 hours, not 'today'
Location: build_find_command
Description: The find command uses `-mtime -N` where N is `config.max_age`. The `find -mtime -N` predicate matches files modified less than N*24 hours ago. With `max_age=14`, this correctly finds files modified in the last 14 days. However, the validation in `validate_config` warns about `max_age=0` but allows it through (the warning says it matches nothing, which is correct). More importantly, `max_age=1` matches files modified less than 24 hours ago — not 'today' as users might expect. This is documented behavior of find, but there's no warning for `max_age=1`. This is a minor UX issue. The more significant issue: if `config.max_age` is very large (e.g., 36500 for 100 years), the find command will scan all files, which could be millions of files on a system, causing memory exhaustion in the popen pipe buffer or extremely long runtime.
Suggested fix: Add an upper bound check in `validate_config`: `if config.max_age > 3650 then log_msg('warn', 'max-age > 3650 days; this will scan very old files') end`.

### Finding 12. [HIGH] wget --post-file with multipart body: Content-Length header may be wrong if body_len is nil
Location: upload_with_wget / upload_with_busybox_wget
Description: In `upload_with_wget`, `body_len` comes from `build_multipart_body` as the third return value. `build_multipart_body` returns `nil, nil, nil` on failure, and the caller checks `if not boundary then return false end`. However, `body_len` is computed as `total_body` which counts bytes written. If the source file is empty (0 bytes), `body_len` will equal `#preamble + #epilogue`, which is correct. The issue is that `body_len` counts Lua string lengths in bytes, which is correct for binary data. BUT: on systems where `io.seek('end')` returns a size that differs from the actual bytes read (e.g., due to text-mode translation on non-Linux systems), the Content-Length could be wrong. Since the target is Linux/embedded, this is low risk. The actual bug: `body_len` is the size of the multipart body written to the temp file, but wget's `--post-file` will send the actual file size regardless of the Content-Length header. If they differ (shouldn't happen on Linux), the server may reject the request. This is not a real bug on the target platform.
Suggested fix: After writing the temp file, verify its size matches body_len using `file_size_kb` or a seek, and log a warning if they differ.

### Finding 13. [MEDIUM] Marker upload success is inferred only from response body, not transport status
Location: send_collection_marker / response parsing
Description: For both curl and wget marker uploads, the code ignores the return value of `exec_ok(cmd)` and proceeds to parse the response file. If the command fails or writes no response, the function just returns an empty string without logging why. This makes begin/end marker failures opaque and undermines the retry logic.
Suggested fix: Check `exec_ok(cmd)` and log stderr or at least a warning on failure before returning `""`. For curl, capture stderr to a temp file as done in `upload_with_curl`.

### Finding 14. [MEDIUM] `--max-age 0` is accepted even though the generated `find -mtime -0` matches nothing
Location: build_find_command / validate_config
Description: The script warns that `max-age=0` will match no files, but still accepts it. The surrounding context says the other collectors were hardened for correctness and consistent behavior; silently running a scan that can never submit anything is a correctness trap rather than a useful mode.
Suggested fix: Reject `max-age == 0` in `validate_config()` with a fatal error, or translate it to a meaningful behavior such as `-mtime 0`/`-mmin` semantics if that is intended.

### Finding 15. [MEDIUM] Fallback temp-file creation is race-prone and may overwrite attacker-chosen files
Location: mktemp
Description: When `mktemp` is unavailable, the function falls back to `os.tmpname()` and then to a predictable `/tmp/thunderstorm.<time><random>` path opened with `io.open(..., "wb")`. On multi-user systems or compromised devices, this is vulnerable to symlink races because Lua's standard library cannot request exclusive creation. The comment acknowledges TOCTOU risk, but the code still uses these files for request bodies and responses.
Suggested fix: Prefer failing closed when no safe temp-file mechanism exists, or invoke a shell helper that performs atomic creation (`umask 077; mktemp`) and abort if unavailable. At minimum, set restrictive permissions and avoid predictable fallback names.

### Finding 16. [MEDIUM] No practical interrupted-marker support despite hardened collector requirement
Location: main / signal handling limitation
Description: The script explicitly states that Lua 5.1 lacks native signal handling and suggests a shell wrapper, but no wrapper is provided and the example trap runs `--dry-run`, which would not send an `interrupted` marker at all. The prompt states the other collectors send an `interrupted` collection marker with stats on SIGINT/SIGTERM and notes that Lua should use a shell-wrapper approach or clearly note the limitation. The current note is misleading because the sample wrapper does not achieve the stated behavior.
Suggested fix: Either provide a real wrapper script that traps signals and posts an `interrupted` marker using the same transport tools, or remove the incorrect example and clearly document that interrupted markers are unsupported in pure Lua mode.

### Finding 17. [MEDIUM] wget_is_busybox() is called twice: once during detection and potentially again in send_collection_marker
Location: detect_upload_tool / wget_is_busybox
Description: In `detect_upload_tool`, `wget_is_busybox()` is called when wget is found. In `send_collection_marker`, if `config.upload_tool` is empty (which shouldn't happen after detection but is a fallback), `wget_is_busybox()` is called again. Each call spawns a subprocess (`io.popen`). On embedded systems, subprocess spawning is expensive. More importantly, `wget_is_busybox()` is not memoized — if called multiple times it re-executes `wget --version` each time. This is wasteful but not a correctness bug.
Suggested fix: Memoize the result of `wget_is_busybox()` similar to `_check_mktemp()`.

### Finding 18. [MEDIUM] scan_id extracted from JSON response using a fragile pattern that can be fooled by nested JSON
Location: send_collection_marker
Description: The scan_id is extracted with `resp:match('"scan_id"%s*:%s*"([^"]+)"')`. This pattern will match the first occurrence of `"scan_id":"..."` in the response. If the response JSON contains a nested object or array where a string value contains `"scan_id":"fake"`, the pattern would match the wrong value. Additionally, if the scan_id itself contains escaped quotes (valid JSON: `"scan_id":"abc\"def"`), the pattern `[^"]+` would stop at the escaped quote, returning a truncated ID. While Thunderstorm server responses are likely well-controlled, this is a robustness issue.
Suggested fix: Use a more specific pattern that anchors to the beginning of the JSON object, or validate that the extracted ID matches an expected format (alphanumeric/UUID). At minimum, document the assumption that scan_ids don't contain escaped quotes.

### Finding 19. [MEDIUM] math.randomseed called after mktemp() is first used, so early temp files use uninitialized RNG
Location: main / math.randomseed
Description: `math.randomseed(os.time() + ...)` is called in `main()` after `validate_config()`, `detect_source_name()`, and before `parse_proc_mounts()`. However, `send_collection_marker` (the begin marker) is called after `detect_upload_tool()` which is after the seed call — so that's fine. BUT: `mktemp()` is called from `build_multipart_body` which is called from upload functions. The seed IS set before any uploads. However, if `_check_mktemp()` fails and the fallback path is used, `math.random(10000,99999)` is called. In Lua 5.1, the default RNG state before `randomseed` is implementation-defined but typically produces the same sequence on every run. The seed IS set before uploads, so this is actually fine for the upload path. The issue is if `mktemp()` is called before `math.randomseed` — checking the code flow: `parse_args` → `validate_config` → `detect_source_name` → `parse_proc_mounts` → `detect_upload_tool` → `math.randomseed` → `send_collection_marker` (which calls `mktemp`). So the seed IS set before the first `mktemp` call that uses `math.random`. This finding is lower severity than initially assessed.
Suggested fix: Move `math.randomseed` to the very top of `main()` before any function calls, as a defensive measure.

### Finding 20. [MEDIUM] curl error output captured from err_file but only logged at debug level, hiding upload failures
Location: upload_with_curl
Description: When curl fails, the error message from stderr (captured in `err_file`) is logged at `debug` level: `log_msg('debug', 'curl error: ' .. ...)`. This means that unless `--debug` is enabled, curl errors (e.g., 'Connection refused', 'SSL certificate problem') are silently swallowed. The caller (`submit_file`) logs a generic 'Upload failed' warning, but the specific curl error is lost in non-debug mode.
Suggested fix: Log curl errors at `warn` level (not `debug`) so they appear in normal operation. The specific error message is valuable for diagnosis.

### Finding 21. [MEDIUM] find prune expression uses -path which matches on the full path, but the pattern P/* may not prune correctly on all find implementations
Location: build_find_command
Description: The prune expression uses `-path /proc -o -path /proc/*`. On GNU find, `-path /proc/*` correctly matches any path under `/proc`. On BusyBox find, `-path` behavior with wildcards may differ — specifically, BusyBox find's `-path` uses `fnmatch()` which should work correctly. However, the expression structure `\( -path P -o -path P/* -o -path Q -o -path Q/* ... \) -prune -o -type f -print` has a subtle issue: the `-prune` action only prevents descending into matched directories, but if `find` is given a start path that IS one of the excluded paths (e.g., `find /proc ...`), the prune won't help because find has already entered it. This is handled by the `test -d` check before scanning, but if a scan_dir is `/` (root), the prune expressions need to work correctly. The `-path P/*` pattern requires the path to contain a `/` after P, which means the directory P itself is matched by `-path P` (without the slash). This is correct.
Suggested fix: Add a test with BusyBox find to verify prune behavior. As a fallback, consider using `-name` based exclusions for known special directories, or add a runtime check of the find version.

### Finding 22. [MEDIUM] HTTP/1.1 request without proper chunked encoding or guaranteed Content-Length may cause server to hang
Location: upload_with_nc
Description: The nc upload sends an HTTP/1.1 request with `Connection: close` and a `Content-Length` header. This should work correctly. However, if `body_len` (the Content-Length) is computed incorrectly (e.g., due to the boundary collision scenario in F4 where the body is truncated), the server will wait for more data than is sent, causing a timeout. Additionally, HTTP/1.1 with `Connection: close` requires the server to close the connection after the response, which nc handles via `-w 10` timeout. If the server is slow to respond (e.g., scanning a large file), the 10-second timeout may cause nc to close the connection before reading the full response, resulting in a false failure.
Suggested fix: Increase the nc timeout (`-w`) based on file size, or use HTTP/1.0 instead of HTTP/1.1 (which has simpler connection semantics). Consider using `Connection: close` with HTTP/1.0 to avoid keep-alive complications.

### Finding 23. [LOW] syslog via os.execute('logger ...') is called synchronously and blocks the scan loop
Location: log_msg
Description: When `config.log_to_syslog` is true, every non-debug log message spawns a shell process via `os.execute`. The comment notes that debug messages are skipped to avoid this overhead. However, info-level messages (logged for every submitted file in debug mode, and for errors/warnings) still spawn a shell. On embedded systems with slow process creation, this can significantly slow down the scan loop.
Suggested fix: Batch syslog messages or use a pipe to a persistent logger process. Alternatively, document that syslog should only be enabled when performance is not critical.

### Finding 24. [LOW] Cloud path detection uses case-insensitive matching but path:lower() is called on every file
Location: is_cloud_path
Description: For every file processed, `is_cloud_path` calls `path:lower()` and then iterates through all cloud directory names. On embedded systems scanning millions of files, this creates unnecessary string allocations. This is a minor performance issue.
Suggested fix: Pre-compute lowercased versions of CLOUD_DIR_NAMES at startup. The `path:lower()` call per file is unavoidable but the name comparisons could be optimized.

### Finding 25. [LOW] validate_config does not validate that scan directories exist or are accessible
Location: validate_config
Description: The validation checks server, port, ca_cert, max_age, max_size_kb, retries, and source, but does not check whether the configured scan directories exist. Non-existent directories are handled gracefully in `scan_directory` with a warning, but a typo in a directory path would silently result in no files being scanned with exit code 0 (if no other failures occur).
Suggested fix: In `validate_config`, warn (not die) if a configured scan directory does not exist: `if not exec_ok('test -d ' .. shell_quote(dir)) then log_msg('warn', 'Scan directory does not exist: ' .. dir) end`.


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
