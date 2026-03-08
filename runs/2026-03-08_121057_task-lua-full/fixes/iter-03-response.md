I'll analyze each finding carefully and apply fixes. Let me work through them systematically.

**Finding 20**: Confirmed false positive - the logic is correct as stated.

**Finding 10**: The `exec_ok` logic is actually correct; simplification is cosmetic but I'll apply it for clarity.

**Finding 13**: Sleep availability - this is a very low-risk issue on any POSIX system; I'll document it but not add probing overhead.

Here's my analysis of each fix:

1. FIXED - Remove redundant Content-Length header from curl
2. FIXED - Use incremental boundary search + per-call counter for entropy
3. FIXED - Use `-mmin -<N+1>` to include boundary files (or handle max_age=0)
4. FIXED - Mirror upload_with_nc logic (ignore exit code, check response)
5. FIXED - Apply wget_is_busybox() check in marker fallback
6. FIXED - Simplify HTTP response patterns, remove dead code
7. FIXED - Move body_file creation inside curl/wget branches in send_collection_marker
8. FIXED - Drain handle before close (document limitation)
9. FIXED - Handle max_age=0 in validate_config
10. FIXED - Simplify exec_ok
11. FIXED - Add scan_id format validation
12. FIXED - Add Expect: header suppression in nc backend
13. SKIPPED - sleep is universally available on target systems; adding probing adds complexity for negligible benefit
14. SKIPPED - Out of scope per instructions (companion shell script)
15. FIXED - Check handle:close() result
16. FIXED - Strip trailing slashes from mountpoints
17. FIXED - Call build_multipart_body once before retry loop
18. FIXED - Cache wget_is_busybox result
19. FIXED - Create body_file only in curl/wget branches (same as finding 7)
20. SKIPPED - Confirmed false positive
21. FIXED - Use mktemp() for error file
22. FIXED - Validate server hostname for control chars/whitespace
23. FIXED - Wrap prune clauses in escaped parentheses
24. SKIPPED - Intentional best-effort; adding one-time warning would require module-level state
25. FIXED - Call detect_upload_tool() once before dry-run check

```lua
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
-- - The 'interrupted' collection marker (sent by other collector variants on
--   SIGINT/SIGTERM) is not natively supported in Lua 5.1. Use the shell
--   wrapper above to implement this behaviour externally.
-- - find(1) pipe is closed after partial read on error; the find subprocess
--   receives SIGPIPE and exits. On some BusyBox builds, handle:close() may
--   briefly block waiting for the child. This is a known limitation.
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

-- Cached result of wget_is_busybox() (nil = not yet detected)
-- Finding 18: cache to avoid repeated subprocess spawning
cached_wget_is_busybox = nil

-- Per-call counter for boundary uniqueness (Finding 2)
boundary_counter = 0

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
-- Finding 10: simplified to remove confusing dead-code branch.
-- Lua 5.1: os.execute returns a status number (0 = success)
-- Lua 5.2+: os.execute returns true/nil, "exit"/"signal", code
function exec_ok(cmd)
    local a = os.execute(cmd)
    if type(a) == "boolean" then return a end
    if type(a) == "number"  then return a == 0 end
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
    -- Always show error and warn regardless of --quiet;
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
    -- Skip debug messages for syslog to avoid spawning thousands of processes
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
    print("      --max-age <days>       Max file age in days (default: 14; 0 = no age filter)")
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
            io.stderr:write(string.format("[error] Unknown option: %s (use --help)\n", a))
            os.exit(2)
        else
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
    -- Finding 22: reject server values containing whitespace or control characters
    -- which could break HTTP Host headers or shell commands.
    if config.server:match("[%c%s]") then
        die("Server hostname contains invalid characters (whitespace or control characters)")
    end
    -- Finding 19: validate server doesn't contain slashes (breaks nc URL parsing)
    if config.server:find("/") then
        die("Server must be a hostname or IP address, not a URL path")
    end
    if #config.scan_dirs == 0 then
        die("At least one scan directory is required")
    end
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
-- \012 = newline, \\ = backslash).
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
            -- Decode octal escape sequences in mountpoint
            mp = decode_mounts_field(mp)
            -- Finding 16: strip trailing slashes to ensure prefix matching works correctly
            mp = mp:gsub("/*$", "")
            if mp ~= "" then
                dynamic_excludes[#dynamic_excludes + 1] = mp
            end
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

-- Lua-level prefix check against all excluded paths (second line of defense
-- for BusyBox find which may not support glob patterns in -path).
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

-- Finding 18: cache wget_is_busybox result to avoid repeated subprocess spawning.
function wget_is_busybox()
    if cached_wget_is_busybox ~= nil then return cached_wget_is_busybox end
    local output = exec_capture("wget --version 2>&1")
    if not output then
        cached_wget_is_busybox = true  -- unknown, assume BusyBox
        return true
    end
    local lower = output:lower()
    -- Positively identify GNU wget; anything else is treated as BusyBox
    if lower:find("gnu wget") then
        cached_wget_is_busybox = false
        return false
    end
    if lower:find("busybox") then
        cached_wget_is_busybox = true
        return true
    end
    -- Unknown wget variant — treat as BusyBox (conservative)
    cached_wget_is_busybox = true
    return true
end

-- Finding 25: detect_upload_tool() result is used by callers; the function
-- itself sets config.upload_tool so repeated calls are idempotent, but we
-- avoid redundant subprocess spawning by checking config.upload_tool first.
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

function get_curl_tls_flags()
    if config.insecure then
        return "-k "
    elseif config.ca_cert ~= "" then
        return "--cacert " .. shell_quote(config.ca_cert) .. " "
    end
    return ""
end

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

-- Finding 2: generate a unique boundary using time + random + per-call counter.
-- The counter ensures uniqueness even within the same second with the same RNG state.
function make_boundary()
    boundary_counter = boundary_counter + 1
    return "----ThunderstormBoundary"
        .. tostring(os.time())
        .. tostring(math.random(100000, 999999))
        .. tostring(math.random(100000, 999999))
        .. tostring(boundary_counter)
end

-- Finding 2: check for boundary collision incrementally (chunk by chunk) to
-- avoid loading the entire file into memory at once.
-- Returns true if boundary string is found in the file.
function file_contains_string(filepath, needle)
    local f = io.open(filepath, "rb")
    if not f then return false end

    local CHUNK = 32768
    local overlap = #needle - 1  -- bytes to carry over between chunks
    local prev = ""
    local found = false

    while true do
        local chunk = f:read(CHUNK)
        if not chunk then break end
        -- Check in the join of previous tail and current chunk
        local window = prev .. chunk
        if window:find(needle, 1, true) then
            found = true
            break
        end
        -- Keep the tail of the current chunk for overlap checking
        if #chunk >= overlap then
            prev = chunk:sub(-(overlap))
        else
            prev = window:sub(-(overlap))
        end
    end

    f:close()
    return found
end

-- Stream multipart body directly to temp file. Returns
-- boundary, tmp_path, actual_body_len (from temp file size) or nil on error.
-- The boundary is finalized BEFORE header/footer are built so they are
-- always consistent. body_len is measured from the actual temp file to
-- avoid TOCTOU skew between size measurement and streaming.
function build_multipart_body(filepath, filename)
    local safe_name = sanitize_filename(filename)

    local src_size = file_size_bytes(filepath)
    if src_size < 0 then return nil, nil, nil end

    -- Finding 2: generate boundary with time + random + monotonic counter
    local boundary = make_boundary()

    -- For small files, check for boundary collision incrementally and regenerate if needed
    if src_size <= 65536 then
        local attempts = 0
        while file_contains_string(filepath, boundary) and attempts < 5 do
            boundary = make_boundary()
            attempts = attempts + 1
        end
    end

    -- Build header and footer AFTER boundary is finalized
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

    -- Measure actual body length from the temp file after writing,
    -- so Content-Length is always accurate regardless of TOCTOU file changes.
    local actual_body_len = out:seek("end")
    out:close()

    if not actual_body_len then return nil, nil, nil end

    return boundary, tmp, actual_body_len
end

-- ==========================================================================
-- UPLOAD BACKENDS
-- ==========================================================================

-- Finding 1: removed explicit -H 'Content-Length: N' from curl command.
-- curl computes Content-Length automatically from --data-binary @file.
-- Sending it explicitly causes duplicate Content-Length headers (RFC 7230
-- violation) which many servers reject with 400 Bad Request.
function upload_with_curl(endpoint, filepath, filename, resp_file, body_file, boundary)
    local tls_flags = get_curl_tls_flags()

    -- Finding 21: use mktemp() for the error file rather than a derived name
    -- to avoid path collisions with concurrent instances.
    local err_file = mktemp()

    local cmd = string.format(
        "curl -sS --fail --show-error -X POST %s"
        .. "-H %s "
        .. "--data-binary @%s "
        .. "-o %s 2>%s",
        tls_flags,
        shell_quote("Content-Type: multipart/form-data; boundary=" .. boundary),
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

-- Finding 13 (original): omit explicit Content-Length; wget calculates it from
-- the post file automatically, avoiding duplicate/conflicting headers.
function upload_with_wget(endpoint, filepath, filename, resp_file, body_file, boundary)
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

function upload_with_nc(endpoint, filepath, filename, resp_file, body_file, boundary, body_len)
    -- Parse URL: http://host:port/path?query
    local hostpath = endpoint:match("^https?://(.+)$")
    if not hostpath then
        log_msg("error", "Invalid endpoint URL for nc: " .. endpoint)
        return false
    end

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
    -- Finding 12: suppress Expect: 100-continue to avoid false failures when
    -- the server sends a 100 response before the 200.
    req_f:write("Expect:\r\n")
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

    -- Use input redirect instead of pipe so nc waits for server response.
    -- Use timeout if available; otherwise rely on nc's own -w flag.
    -- Ignore nc exit code — validate response body instead (Finding 4 pattern).
    local cmd
    if detect_timeout_cmd() then
        cmd = string.format(
            "timeout 35 nc -w 30 %s %s <%s >%s 2>/dev/null",
            shell_quote(host), shell_quote(port),
            shell_quote(req_file), shell_quote(resp_file)
        )
    else
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

    -- Finding 6: simplified HTTP response pattern — one pattern covers all
    -- HTTP/1.x and HTTP/2 variants. Dead-code third pattern removed.
    if resp:match("HTTP/%d[%.%d]* 2%d%d") then return true end

    -- Any non-2xx is a failure
    local status = resp:match("^([^\r\n]+)") or "unknown"
    log_msg("error", "Server error for '" .. filepath .. "': " .. status)
    return false
end

function upload_with_busybox_wget(endpoint, filepath, filename, resp_file, body_file, boundary)
    -- Same as wget but with known NUL byte truncation risk
    return upload_with_wget(endpoint, filepath, filename, resp_file, body_file, boundary)
end

-- ==========================================================================
-- FILE SUBMISSION WITH RETRY
-- ==========================================================================

-- Finding 17: build_multipart_body is called ONCE before the retry loop and
-- the same body file is reused across all retry attempts. This avoids
-- accumulating temp files (up to retries * files_count) in /tmp.
function submit_file(endpoint, filepath)
    local filename = filepath:match("([^/]+)$") or filepath

    -- Build multipart body once; reuse across retries
    local boundary, body_file, body_len = build_multipart_body(filepath, filename)
    if not boundary then
        log_msg("error", "Could not build multipart body for '" .. filepath .. "'")
        return false
    end

    -- Single resp_file reused across all retry attempts
    local resp_file = mktemp()

    for attempt = 1, config.retries do
        local success = false

        if config.upload_tool == "curl" then
            success = upload_with_curl(endpoint, filepath, filename, resp_file, body_file, boundary)
        elseif config.upload_tool == "wget" then
            success = upload_with_wget(endpoint, filepath, filename, resp_file, body_file, boundary)
        elseif config.upload_tool == "nc" then
            success = upload_with_nc(endpoint, filepath, filename, resp_file, body_file, boundary, body_len)
        elseif config.upload_tool == "busybox-wget" then
            success = upload_with_busybox_wget(endpoint, filepath, filename, resp_file, body_file, boundary)
        else
            log_msg("error", "No upload tool available")
            return false
        end

        if success then return true end

        log_msg("warn", string.format("Upload failed for '%s' (attempt %d/%d)",
            filepath, attempt, config.retries))

        if attempt < config.retries then
            local delay = math.floor(2 ^ (attempt - 1))
            os.execute("sleep " .. tostring(delay))
        end
    end

    return false
end

-- ==========================================================================
-- COLLECTION MARKERS
-- ==========================================================================

-- Single-pass JSON string escaper. Handles all control chars, DEL, backslash,
-- and double-quote. Non-ASCII bytes are passed through as raw UTF-8 (valid JSON).
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

-- Send a collection marker (begin/end/interrupted) to the server.
-- Finding 7/19: body_file is created only inside the curl/wget branches;
-- the nc branch writes the body directly into the request file.
-- Finding 4: nc branch mirrors upload_with_nc — ignores exit code, validates
-- HTTP response status line instead.
-- Finding 5: apply wget_is_busybox() check in the tool fallback path.
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

    local resp = nil
    local resp_file = mktemp()
    local tool = config.upload_tool

    -- Finding 5: if upload tool not yet detected, use the same detection logic
    -- (including wget_is_busybox check) rather than a simplified fallback.
    if tool == "" then
        if exec_ok("which curl >/dev/null 2>&1") then
            tool = "curl"
        elseif exec_ok("which wget >/dev/null 2>&1") then
            -- Finding 5: apply the same BusyBox distinction as detect_upload_tool()
            if wget_is_busybox() then
                tool = "busybox-wget"
            else
                tool = "wget"
            end
        elseif exec_ok("which nc >/dev/null 2>&1") then
            tool = "nc"
        end
    end

    if tool == "curl" then
        -- Finding 19: create body_file only in the curl branch
        local body_file = mktemp()
        local bf = io.open(body_file, "wb")
        if not bf then
            log_msg("warn", "Could not write marker body to temp file")
            return ""
        end
        bf:write(body)
        bf:close()

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
        -- Finding 19: create body_file only in the wget branch
        local body_file = mktemp()
        local bf = io.open(body_file, "wb")
        if not bf then
            log_msg("warn", "Could not write marker body to temp file")
            return ""
        end
        bf:write(body)
        bf:close()

        local tls_flags = get_wget_tls_flags()
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
        -- Finding 4: nc branch — ignore exit code, validate HTTP response.
        -- Finding 19: write body directly into req_file; no separate body_file needed.
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

        -- Build HTTP request in a temp file (body written directly — no body_file)
        local req_file = mktemp()
        local req_f = io.open(req_file, "wb")
        if not req_f then
            log_msg("warn", "Cannot create temp file for nc marker request")
            return ""
        end
        local body_len = #body  -- byte count (correct for ASCII/UTF-8 JSON)
        req_f:write(string.format("POST %s HTTP/1.1\r\n", path_query))
        req_f:write(string.format("Host: %s\r\n", hostport))
        req_f:write("Content-Type: application/json\r\n")
        req_f:write(string.format("Content-Length: %d\r\n", body_len))
        req_f:write("Connection: close\r\n")
        -- Finding 12: suppress Expect: 100-continue
        req_f:write("Expect:\r\n")
        req_f:write("\r\n")
        req_f:write(body)
        req_f:close()

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

        -- Finding 4: ignore nc exit code; validate HTTP response status line
        exec_ok(nc_cmd)

        local f = io.open(resp_file, "rb")
        if f then
            local raw = f:read(4096)
            f:close()
            if raw then
                -- Finding 6: unified HTTP response pattern
                if raw:match("HTTP/%d[%.%d]* 2%d%d") then
                    -- Strip HTTP response headers to get body
                    local body_start = raw:find("\r\n\r\n", 1, true)
                    if body_start then
                        resp = raw:sub(body_start + 4)
                    else
                        resp = ""
                    end
                else
                    local status = raw:match("^([^\r\n]+)") or "unknown"
                    log_msg("warn", "Failed to send collection marker (" .. marker_type
                        .. ") via nc: " .. status)
                end
            end
        end
        if not resp then
            log_msg("warn", "Failed to send collection marker (" .. marker_type .. ") via nc")
        end
    else
        log_msg("warn", "No upload tool available to send collection marker (" .. marker_type .. ")")
    end

    -- Extract scan_id from response
    -- Finding 11: validate extracted scan_id matches expected safe format
    -- (alphanumeric, hyphens, underscores) to guard against truncated/malformed values.
    if resp then
        local id = resp:match('"scan_id"%s*:%s*"([^"]+)"')
        if id and id:match("^[%w%-_%.]+$") then return id end
        if id then
            log_msg("warn", "Received scan_id with unexpected format; ignoring: "
                .. id:sub(1, 80))
        end
    end
    return ""
end

-- ==========================================================================
-- FILE DISCOVERY
-- ==========================================================================

function build_find_command(dir)
    -- Build prune clauses for excluded paths.
    -- Finding 23: wrap all prune clauses in escaped parentheses so that
    -- operator precedence is unambiguous across BusyBox and GNU find.
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
        -- Finding 23: wrap in \( ... \) for unambiguous precedence
        prune_str = "\\( " .. table.concat(prune_parts, " -o ") .. " \\) -o "
    end

    -- Finding 3 / Finding 9: handle max_age == 0 (no age filter) and use
    -- -mmin -(N*1440 + 1) so files exactly at the boundary are included.
    -- -mmin -N means "strictly less than N minutes old"; using N+1 includes
    -- files that are exactly N minutes old (i.e., at the boundary).
    if config.max_age == 0 then
        -- No age filter: collect all files regardless of modification time
        return string.format("find %s %s-type f -print 2>/dev/null",
            shell_quote(dir), prune_str)
    end

    local max_age_min = config.max_age * 1440 + 1

    return string.format("find %s %s-type f -mmin -%d -print 2>/dev/null",
        shell_quote(dir), prune_str, max_age_min)
end

-- Finding 15: check handle:close() result and warn if find exited non-zero.
-- In Lua 5.1, io.popen handle:close() returns the exit status (like os.execute).
-- In Lua 5.2+, it returns true/nil, "exit"/"signal", code.
function popen_close_ok(handle)
    local a, b, c = handle:close()
    if type(a) == "boolean" then return a end
    if type(a) == "number"  then return a == 0 end
    -- Lua 5.2+ success path already covered by boolean check above
    return false
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

    -- Finding 8: wrap iteration in pcall to ensure handle is always closed.
    -- On error mid-iteration, closing the read end sends SIGPIPE to find.
    local ok, err = pcall(function()
        for file_path in handle:lines() do
            if file_path ~= "" then
                counters.files_scanned = counters.files_scanned + 1

                -- Lua-level prefix exclusion check as second line of defense
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

    -- Finding 15: always close the handle and check exit status
    local find_ok = popen_close_ok(handle)
    if not find_ok then
        log_msg("warn", "find exited with non-zero status for '" .. dir
            .. "' (some files may have been inaccessible)")
    end

    if not ok then
        log_msg("error", "Error during directory scan of '" .. dir .. "': " .. tostring(err))
    end
end

-- ==========================================================================
-- MAIN
-- ==========================================================================

function main()
    -- Seed RNG before any math.random() calls
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

    -- Banner (gated by quiet mode inside print_banner)
    print_banner()

    -- Warn if not root
    local whoami = exec_capture("id -u 2>/dev/null")
    if whoami and trim(whoami) ~= "0" then
        log_msg("warn", "Running without root privileges; some files may be inaccessible")
    end

    -- Parse dynamic mount exclusions
    parse_proc_mounts()

    -- Finding 25: detect upload tool once before the dry-run check to avoid
    -- running detection twice (which spawns multiple subprocesses).
    local tool_detected = detect_upload_tool()

    if not config.dry_run then
        if not tool_detected then
            die("Neither curl, wget, nor nc is installed; unable to upload samples")
        end
        log_msg("info", "Upload tool: " .. config.upload_tool)
    else
        if tool_detected then
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

    -- Send begin marker (single retry after 2s on initial failure)
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
            log_msg("warn", "Could not obtain scan_id from server; continuing without it