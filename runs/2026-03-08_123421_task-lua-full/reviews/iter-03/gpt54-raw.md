[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "scan_directory / replaced loop body",
    "title": "Patched block leaves a stray `for` and breaks the function syntactically",
    "description": "The file shows an original `for file_path in handle:lines() do` immediately followed by a replacement block that introduces another `for file_path in handle:lines() do` inside a `pcall`. If applied literally, the outer loop is never closed and the function becomes invalid Lua. This is not just a merge artifact concern: the target file as presented is not executable.",
    "impact": "The collector will fail to start at all, turning the script into a fatal error on embedded targets.",
    "suggestion": "Remove the original loop header entirely and keep only the wrapped version. The function should contain exactly one iteration over `handle:lines()`, e.g. `local ok, scan_err = pcall(function() for file_path in handle:lines() do ... end end)`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "send_collection_marker / curl command construction",
    "title": "Missing space before `-H` corrupts curl command when no CA cert is used",
    "description": "The curl marker upload command is built with `\"... %s%s-H %s ...\"`. When `ca_cert_flag` is empty, this expands to something like `curl ... -k -H ...`, which works only if `insecure` ends with a space. But when `config.insecure` is false and `ca_cert_flag` is empty, it becomes `curl ... <respfile> -H ...` only because the previous placeholder may or may not provide spacing; the formatting is fragile and can produce malformed concatenation such as `--cacert 'x'-H` when flags are changed. This differs from the file upload curl path, which inserts spaces explicitly between arguments.",
    "impact": "Begin/end collection markers can fail intermittently depending on option combinations, causing loss of scan tracking and parity gaps with the hardened collectors.",
    "suggestion": "Build the command with explicit spaces between every optional segment, e.g. `\"curl -sS --fail -o %s %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null\"` and let empty flags collapse harmlessly.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "send_collection_marker",
    "title": "No `nc` implementation for collection markers causes marker loss on minimal systems",
    "description": "The script supports `nc` for file uploads, but `send_collection_marker` only implements curl and wget paths. On systems where `detect_upload_tool()` selected `nc` (a stated supported environment on BusyBox/OpenWrt), begin/end markers are silently skipped because `tool == \"nc\"` is never handled and the function just returns an empty string.",
    "impact": "On devices that only have `nc`, the collector cannot send begin/end markers, so scan correlation and lifecycle tracking break. This is a real parity gap versus the hardened collectors, especially because begin-marker retry is implemented but ineffective under `nc`.",
    "suggestion": "Add an `nc` JSON POST path similar to `upload_with_nc`, or explicitly document and surface this as a warning/error when `config.upload_tool == \"nc\"` so operators know markers are unavailable.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "MEDIUM",
    "location": "send_collection_marker / response parsing",
    "title": "Marker upload success is inferred only from response body, not transport status",
    "description": "For both curl and wget marker uploads, the code ignores the return value of `exec_ok(cmd)` and proceeds to parse the response file. If the command fails or writes no response, the function just returns an empty string without logging why. This makes begin/end marker failures opaque and undermines the retry logic.",
    "impact": "Operational troubleshooting becomes difficult, and transient network/TLS failures are indistinguishable from server responses without `scan_id`. In production this can hide real connectivity problems.",
    "suggestion": "Check `exec_ok(cmd)` and log stderr or at least a warning on failure before returning `\"\"`. For curl, capture stderr to a temp file as done in `upload_with_curl`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "build_find_command / validate_config",
    "title": "`--max-age 0` is accepted even though the generated `find -mtime -0` matches nothing",
    "description": "The script warns that `max-age=0` will match no files, but still accepts it. The surrounding context says the other collectors were hardened for correctness and consistent behavior; silently running a scan that can never submit anything is a correctness trap rather than a useful mode.",
    "impact": "Operators can believe a system is clean when in reality the collector was configured to scan zero eligible files. On unattended deployments this can lead to false assurance.",
    "suggestion": "Reject `max-age == 0` in `validate_config()` with a fatal error, or translate it to a meaningful behavior such as `-mtime 0`/`-mmin` semantics if that is intended.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "mktemp",
    "title": "Fallback temp-file creation is race-prone and may overwrite attacker-chosen files",
    "description": "When `mktemp` is unavailable, the function falls back to `os.tmpname()` and then to a predictable `/tmp/thunderstorm.<time><random>` path opened with `io.open(..., \"wb\")`. On multi-user systems or compromised devices, this is vulnerable to symlink races because Lua's standard library cannot request exclusive creation. The comment acknowledges TOCTOU risk, but the code still uses these files for request bodies and responses.",
    "impact": "An attacker with local filesystem access could cause the collector to overwrite arbitrary writable files or read/write through symlinks, which is especially risky if the script runs as root.",
    "suggestion": "Prefer failing closed when no safe temp-file mechanism exists, or invoke a shell helper that performs atomic creation (`umask 077; mktemp`) and abort if unavailable. At minimum, set restrictive permissions and avoid predictable fallback names.",
    "false_positive_risk": "low"
  },
  {
    "id": "F7",
    "severity": "MEDIUM",
    "location": "main / signal handling limitation",
    "title": "No practical interrupted-marker support despite hardened collector requirement",
    "description": "The script explicitly states that Lua 5.1 lacks native signal handling and suggests a shell wrapper, but no wrapper is provided and the example trap runs `--dry-run`, which would not send an `interrupted` marker at all. The prompt states the other collectors send an `interrupted` collection marker with stats on SIGINT/SIGTERM and notes that Lua should use a shell-wrapper approach or clearly note the limitation. The current note is misleading because the sample wrapper does not achieve the stated behavior.",
    "impact": "Interrupted scans terminate without lifecycle closure, leaving incomplete server-side state and breaking parity with the hardened collectors. The misleading wrapper example can also cause operators to think interruption reporting exists when it does not.",
    "suggestion": "Either provide a real wrapper script that traps signals and posts an `interrupted` marker using the same transport tools, or remove the incorrect example and clearly document that interrupted markers are unsupported in pure Lua mode.",
    "false_positive_risk": "low"
  }
]