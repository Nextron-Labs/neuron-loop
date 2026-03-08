[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "exec_ok / utility function used throughout uploads and marker sending",
    "title": "os.execute success detection is wrong on many Lua 5.1 builds",
    "description": "The helper assumes Lua 5.1 returns numeric 0 on success and Lua 5.2+ returns true. On many real Lua 5.1/5.1-derived environments, especially embedded builds, os.execute may return values that are not exactly 0/true (for example a platform-dependent status code, or multiple return values in patched runtimes). As written, successful commands can be treated as failures, breaking tool detection, CA file validation, directory checks, uploads, and marker delivery.",
    "impact": "The collector can falsely conclude that curl/wget/nc are missing, that directories or CA bundles do not exist, or that uploads failed. This can turn healthy runs into fatal errors or partial-failure exits in production.",
    "suggestion": "Normalize os.execute handling more defensively. In Lua 5.1, treat both numeric 0 and true as success, and if multiple returns are available, accept true or an exit code of 0. A compatibility wrapper like `local a,b,c = os.execute(cmd); if a == true then return true elseif type(a) == 'number' then return a == 0 elseif b == 'exit' and c == 0 then return true else return false end` is safer.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "upload_with_nc / command construction for timeout + sh -c",
    "title": "nc backend is effectively broken due to double shell-quoting of host and port",
    "description": "The command passed to `sh -c` is built as `cat <req> | nc -w 30 'host' 'port'`, where `host` and `port` are already shell-quoted before being embedded into another shell command string that is itself shell-quoted. Those literal quote characters survive into the inner shell and become part of the arguments, so nc receives a hostname like `'example.com'` instead of `example.com`.",
    "impact": "On systems where nc is the only available upload tool, file uploads will fail consistently, making the collector unusable on a key target platform class (minimal BusyBox systems).",
    "suggestion": "Do not pre-quote host/port inside the inner command string. Quote only once at the shell boundary, or avoid `sh -c` entirely. For example, build the inner command as `string.format(\"cat %s | nc -w 30 %s %s\", shell_quote(req_file), host, port)` and then shell-quote that whole string for `sh -c`, or better: `timeout 35 nc -w 30 ... < req_file > resp_file`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "send_collection_marker / tool fallback logic",
    "title": "Collection markers are never sent when nc is the selected upload tool",
    "description": "The marker sender only implements curl and wget/busybox-wget branches. If runtime detection selected `nc`, `tool` remains `nc`, no upload branch executes, and the function silently returns an empty scan_id. That means begin/end markers are skipped on exactly the minimal environments where nc is chosen.",
    "impact": "This breaks parity with the hardened collectors: no begin marker retry can succeed, no scan_id is obtained, and no end/interrupted-style accounting is possible. Server-side correlation and collection lifecycle tracking are lost on nc-only devices.",
    "suggestion": "Implement JSON POST via nc as a third backend, or explicitly fall back to curl/wget only if available and otherwise log a clear warning that markers are unsupported with nc. Given the stated target constraints, adding an nc JSON POST path is the correct fix.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "build_find_command / use of `-mtime -%d`",
    "title": "Max-age filter is off by almost a full day",
    "description": "The script interprets `--max-age <days>` as a day-based age limit, but uses `find -mtime -N`. In POSIX/GNU/BusyBox find semantics, `-mtime -14` means strictly less than 14*24 hours, not 'within the last 14 calendar days'. Files that are 14 days old plus a few minutes are excluded, even though users typically expect them to be included under a 14-day limit.",
    "impact": "Suspicious files near the age threshold are silently skipped, reducing collection coverage and causing inconsistent behavior versus other hardened collectors if they use a more exact cutoff.",
    "suggestion": "Use minute granularity for an exact threshold, e.g. `-mmin -<days*1440>`, or document the strict `find` semantics clearly. If parity matters, match the behavior of the other collectors exactly.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "parse_proc_mounts / parsing `/proc/mounts`",
    "title": "Dynamic mount exclusions fail for escaped mountpoints in /proc/mounts",
    "description": "Mountpoints in `/proc/mounts` encode spaces and some special characters as escape sequences such as `\\040`. The parser stores the raw escaped text into `dynamic_excludes`, but `find` emits real filesystem paths, so exclusion checks built from those mountpoints will not match actual paths containing spaces or escaped characters.",
    "impact": "Network/special filesystems mounted under paths with spaces or escaped characters may be scanned unexpectedly, causing hangs, slow scans, or collection from locations that were meant to be excluded.",
    "suggestion": "Unescape mountpoint fields from `/proc/mounts` before storing them, at least handling `\\040`, `\\011`, `\\012`, and `\\\\` per fstab/proc mount escaping rules.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "upload_with_nc / unconditional use of `timeout`",
    "title": "nc backend depends on external `timeout` despite stated minimal-tool constraints",
    "description": "The nc uploader shells out to `timeout 35 ...`, but `timeout` is not one of the declared runtime requirements and is absent on many BusyBox deployments unless specifically enabled. If nc exists but timeout does not, the command fails and uploads never work.",
    "impact": "On constrained embedded systems, the collector may detect nc as available and then fail every upload at runtime, producing partial failures or making the tool unusable.",
    "suggestion": "Probe for `timeout` before using it and fall back to plain `nc -w` if unavailable, or structure the command so nc's own timeout is sufficient. If an outer timeout is truly required, include it in documented prerequisites and detection logic.",
    "false_positive_risk": "low"
  }
]