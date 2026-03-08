[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "die / main / parse_args / validate_config",
    "title": "Exit codes do not follow the documented collector contract",
    "description": "The script exits with status 1 for fatal configuration/runtime errors via die(), and main() never returns a non-zero status when uploads fail. The stated hardened behavior for sibling collectors is 0=clean, 1=partial failure, 2=fatal error. In this implementation, fatal errors are reported as 1, and runs with failed file uploads still exit 0 after printing the summary.",
    "impact": "Supervisors, wrappers, and automation cannot reliably distinguish fatal startup/configuration failures from partial collection failures. A run that failed to upload some files may be treated as fully successful.",
    "suggestion": "Adopt the shared exit-code contract consistently: make die() use os.exit(2), and at the end of main() exit 1 when counters.files_failed > 0, else 0. Also ensure unknown-option and similar fatal parse failures use 2.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "main / send_collection_marker",
    "title": "Begin-marker retry hardening is missing",
    "description": "The script sends the initial \"begin\" collection marker only once. The prompt explicitly states the other collectors were hardened with a single retry after 2 seconds on initial begin-marker failure. Here, if the first marker request fails transiently, the run proceeds without a scan_id and without retrying.",
    "impact": "Transient network failures at startup can cause the entire collection session to lose correlation metadata, reducing server-side traceability and parity with other collectors.",
    "suggestion": "Wrap the initial begin marker send in retry logic: if the first call returns an empty scan_id, sleep 2 seconds and retry once before continuing. Log the retry and final failure clearly.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "print_help / parse_args / upload_with_curl / upload_with_wget / send_collection_marker",
    "title": "--ca-cert support is missing despite required hardening parity",
    "description": "The script supports --insecure but has no --ca-cert option and never passes a custom CA bundle to curl or wget. The prompt explicitly lists --ca-cert PATH as a hardened feature already implemented in the other collectors.",
    "impact": "On embedded systems using private PKI or custom trust stores, HTTPS uploads and collection markers may fail unless verification is disabled entirely with --insecure, weakening transport security.",
    "suggestion": "Add a config.ca_cert field, parse --ca-cert PATH, validate the file exists, and pass it to curl (--cacert) and wget (--ca-certificate). Apply it to both file uploads and collection-marker requests.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "main / overall process lifecycle",
    "title": "No interruption handling means end/interrupted markers and cleanup are skipped on SIGINT/SIGTERM",
    "description": "The prompt requires signal handling parity, but this Lua 5.1 script has no mechanism to handle SIGINT/SIGTERM. The context explicitly notes native signal handling is unavailable and should use a shell-wrapper approach or be documented as a limitation. The current script neither implements a wrapper strategy nor emits an interrupted marker, and temp-file/log cleanup only happens on normal completion or die().",
    "impact": "If the collector is interrupted, the server never receives the required interrupted marker with stats, and temporary files may be left behind. Operational monitoring will see incomplete sessions with no terminal state.",
    "suggestion": "At minimum, document this limitation clearly in help/output. Preferably provide a shell wrapper that traps INT/TERM, invokes the Lua collector, and sends an interrupted collection marker with current stats. If wrapper integration is out of scope, note the parity gap explicitly.",
    "false_positive_risk": "low"
  },
  {
    "id": "F5",
    "severity": "HIGH",
    "location": "build_multipart_body / upload_with_wget / upload_with_nc",
    "title": "Multipart body construction loads entire file into memory, risking OOM on embedded targets",
    "description": "build_multipart_body() reads the full file into a Lua string, concatenates multipart headers and payload into another large string, then writes that combined body to a temp file. For files up to the configured 2000 KB limit, this can transiently require multiple copies of the payload in memory. upload_with_nc() then reads the generated body file fully again when appending it to the request file.",
    "impact": "On 2-16 MB RAM devices, scanning near-limit files can trigger memory pressure or process termination, especially when Lua string duplication and temporary tables are considered.",
    "suggestion": "Stream multipart construction directly to the output file instead of assembling the whole body in memory. For nc, write headers to req_file and then copy the source file in chunks. For wget, write multipart preamble, stream file content in chunks, then write epilogue. Avoid read('*a') for payloads.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "mktemp",
    "title": "os.tmpname() is unsafe/unreliable on embedded Unix targets",
    "description": "mktemp() uses os.tmpname() and then opens the returned path. On Unix-like systems, os.tmpname() is historically race-prone because it may return a predictable name that is created in a separate step. On some minimal environments it can also return unusable paths. This is especially problematic because the script stores upload bodies and server responses in temp files.",
    "impact": "An attacker on the same system could potentially pre-create or replace temp paths, causing data corruption, disclosure, or writes to unintended locations. Reliability also suffers on BusyBox/OpenWrt variants where os.tmpname() behavior is inconsistent.",
    "suggestion": "Prefer invoking a shell mktemp utility when available (e.g. `mktemp /tmp/thunderstorm.XXXXXX`) and fall back carefully if absent. Open the file immediately after creation and verify it is a regular file in a trusted temp directory.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F7",
    "severity": "MEDIUM",
    "location": "build_find_command",
    "title": "find pruning expression is malformed and may not exclude mounted/special paths reliably",
    "description": "The generated command has the form `find <dir> <prunes> -type f -mtime -N -print`, where `<prunes>` expands to repeated `-path X -prune -o ...`. Without grouping parentheses around the prune expression, operator precedence can produce unintended evaluation, and excluded paths may still be traversed or matched inconsistently across find implementations.",
    "impact": "The collector may descend into /proc, /sys, network mounts, or other excluded trees, causing hangs, permission noise, or scanning of paths that should be skipped.",
    "suggestion": "Build the command using grouped prune logic, e.g. `find DIR \\( -path P1 -o -path P2 ... \\) -prune -o -type f -mtime -N -print`. Keep shell quoting around each path.",
    "false_positive_risk": "low"
  },
  {
    "id": "F8",
    "severity": "MEDIUM",
    "location": "parse_args / print_help / overall CLI",
    "title": "Progress reporting options required for parity are missing",
    "description": "The hardened collectors are described as supporting TTY-aware progress reporting with --progress / --no-progress. This Lua script implements neither option nor any TTY detection logic.",
    "impact": "Behavior diverges from the other collectors and from operator expectations. On interactive runs there is no progress visibility; in non-interactive runs there is no way to explicitly suppress or enable progress output consistently.",
    "suggestion": "Add config.progress with auto-detection based on whether stdout/stderr is a TTY, parse --progress and --no-progress, and emit lightweight periodic progress updates without flooding logs.",
    "false_positive_risk": "low"
  },
  {
    "id": "F9",
    "severity": "MEDIUM",
    "location": "send_collection_marker",
    "title": "Collection marker requests ignore transport failures and HTTP error status",
    "description": "send_collection_marker() executes curl/wget but does not check the command exit status. It simply reads the response file if present and returns an extracted scan_id or empty string. For curl it also omits --fail, so HTTP 4xx/5xx can still produce a body and appear superficially successful. This makes marker delivery failures silent.",
    "impact": "Begin/end marker loss is hard to diagnose, and the collector may proceed as if marker submission were attempted successfully when the request actually failed at transport or HTTP level.",
    "suggestion": "Use exec_ok() for marker commands, add curl --fail/--show-error, and log failures explicitly. Consider checking for expected HTTP success semantics before parsing scan_id.",
    "false_positive_risk": "low"
  }
]