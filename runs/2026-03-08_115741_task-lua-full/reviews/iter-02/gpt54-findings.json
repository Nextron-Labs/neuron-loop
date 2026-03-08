[
  {
    "id": "F1",
    "severity": "CRITICAL",
    "location": "send_collection_marker / curl command construction",
    "title": "Malformed curl command breaks JSON marker delivery when TLS flags are empty",
    "description": "The curl command for collection markers is built as `\"curl -s -o %s %s-H 'Content-Type: application/json' ...\"`. When `get_curl_tls_flags()` returns an empty string (the normal HTTP case, or HTTPS with default CA validation), the resulting command becomes `curl -s -o <file> -H 'Content-Type: application/json' ...` only if spacing is correct. Here the `-H` is concatenated directly to `%s`, so with an empty TLS flag string it becomes `... -o <file> -H ...`? Actually because `%s-H` is used, the command becomes `... -o <file> -H ...` only when `%s` includes trailing space; if `%s` is empty, it becomes `... -o <file> -H ...`? No: the format literally emits `%s-H`, so empty flags produce `... -o <file> -H ...` only if there is a preceding space in the format. In this string the separator relies on `tls_flags` always ending with a space. That is brittle and fails if helper behavior changes; more importantly it already creates malformed output symmetry unlike the wget path and is easy to break. The marker path is critical because begin/end/interrupted reporting depends on it.",
    "impact": "Collection begin/end/interrupted markers may fail to send, causing missing scan tracking and broken server-side correlation (`scan_id`). This directly violates the hardened parity requirement for reliable begin-marker retry and interruption reporting.",
    "suggestion": "Do not rely on helper-returned trailing spaces. Build arguments with explicit separators, e.g. `\"curl -s -o %s %s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null\"` and pass `tls_flags` without embedded trailing spaces, or append flags conditionally. Example: `local cmd = string.format(\"curl -s -o %s%s -H %s --max-time 10 --data-binary @%s %s 2>/dev/null\", shell_quote(resp_file), tls_flags ~= \"\" and (\" \" .. tls_flags) or \"\", shell_quote(\"Content-Type: application/json\"), shell_quote(body_file), shell_quote(url))`.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "parse_args / unknown-option handling",
    "title": "Non-option positional arguments are silently ignored",
    "description": "The argument parser only errors on tokens starting with `-`. Any unexpected positional argument is ignored because there is no final `else` branch to reject it. For example, `lua thunderstorm-collector.lua /tmp --server x` will silently ignore `/tmp` instead of treating it as invalid input.",
    "impact": "Operators can believe they configured scan paths or other inputs when they were actually ignored, leading to incomplete collection with a success exit code. On embedded incident-response tooling, silent misconfiguration is a correctness problem.",
    "suggestion": "Add a final `else` branch in `parse_args` that rejects unexpected positional arguments: `else die(\"Unexpected argument: \" .. a .. \" (use --help)\") end`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "build_find_command / use of `-mtime -%d`",
    "title": "Max-age filter is off by almost a full day and mishandles `--max-age 0`",
    "description": "The script uses `find ... -mtime -N`, which matches files modified less than N*24 hours ago, not 'within the last N calendar days' as users typically expect. More importantly, `-mtime -0` is effectively unsatisfiable on standard `find`, so `--max-age 0` will scan nothing even though validation allows 0. This is a real behavioral bug, not just semantics.",
    "impact": "Files can be incorrectly excluded from collection, especially for `--max-age 0`, which becomes a silent no-op scan. This undermines reliability and can cause missed suspicious files during incident response.",
    "suggestion": "Either reject `--max-age 0` explicitly, or implement age filtering with `-mmin`/shell-side timestamp comparison. If keeping `find`, map days to minutes and use `-mmin -<minutes>` where supported, or document and enforce `max-age >= 1`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F4",
    "severity": "HIGH",
    "location": "upload_with_curl / multipart form construction",
    "title": "curl upload sends filename as a separate form field instead of the file part filename",
    "description": "The curl path uses `-F 'file=@<path>' -F 'filename=<safe_name>'`. That creates two multipart fields: one file field named `file` and one text field named `filename`. It does not set the multipart filename parameter on the `file` part. The wget/nc implementations do set `Content-Disposition: ... name=\"file\"; filename=\"...\"`. If the server expects the uploaded file part's filename metadata, curl uploads will behave differently from wget/nc and may report the local basename or omit the intended sanitized name.",
    "impact": "Server-side processing may mislabel samples, reject uploads, or lose filename context depending on API expectations. This is a cross-backend correctness inconsistency in the primary upload path.",
    "suggestion": "Use curl's `filename=` attribute on the same form part, while still avoiding injection by quoting safely: `-F 'file=@/path;filename=<safe_name>;type=application/octet-stream'`. If semicolon parsing concerns remain, validate/sanitize `safe_name` more strictly and keep the filename on the same part rather than as a separate field.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "build_multipart_body / boundary generation",
    "title": "Boundary generation reseeds PRNG on every upload, increasing collision risk",
    "description": "Each call to `build_multipart_body` executes `math.randomseed(os.time())` and then draws two random numbers. Multiple uploads started within the same second will reuse the same seed and therefore generate identical boundaries. While multipart boundaries only need to avoid appearing in the body, repeated predictable boundaries reduce that safety margin and defeat the stated intent of generating a 'sufficiently random boundary'.",
    "impact": "On fast scans, many requests can share the same boundary value. If a file happens to contain that boundary sequence, the multipart body can be malformed and the upload may fail or be parsed incorrectly.",
    "suggestion": "Seed the PRNG once at startup, not per upload. Better, include monotonic uniqueness such as a counter plus time and temp path: `boundary = string.format(\"ThunderstormBoundary_%d_%d_%d\", os.time(), os.clock()*1000000, upload_seq)`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "main / banner and summary output to stdout",
    "title": "Normal stdout output violates hardened parity expectation that errors go to stderr and can pollute automation",
    "description": "The script always prints the banner and final summary to stdout. The hardened sibling collectors were updated for cleaner automation behavior, and this script already routes logs to stderr. Emitting banner/summary on stdout makes machine consumption harder and differs from the rest of the toolchain.",
    "impact": "Wrapper scripts or orchestration that expect stdout to be reserved for structured output or to remain quiet may mis-handle collector output. This is especially problematic on embedded systems where scripts are chained together.",
    "suggestion": "Suppress the banner by default in non-interactive mode, or send it to stderr. Likewise, send the summary to stderr unless an explicit `--json`/reporting mode is added.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F7",
    "severity": "MEDIUM",
    "location": "entry point pcall(main) / interrupted marker logic",
    "title": "Fatal-error path cannot include the real scan_id in interrupted marker",
    "description": "The top-level `pcall(main)` handler sends an `interrupted` marker with `scan_id = nil` because `scan_id` is local to `main` and never persisted globally. If a fatal Lua error occurs after a successful begin marker, the server cannot correlate the interrupted marker with the started collection.",
    "impact": "Server-side collection state can remain orphaned or ambiguous after runtime failures, weakening the intended hardened behavior for interruption/failure reporting.",
    "suggestion": "Store `scan_id` in a global/runtime state table once obtained, and reuse it in the top-level error handler: e.g. `runtime = { scan_id = \"\" }` and set `runtime.scan_id = scan_id` in `main`, then pass it to `send_collection_marker` on failure.",
    "false_positive_risk": "low"
  }
]