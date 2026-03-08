[
  {
    "id": "F1",
    "severity": "HIGH",
    "location": "upload_with_curl / form_value construction",
    "title": "curl upload breaks for file paths containing commas or leading parser metacharacters",
    "description": "The curl backend builds a single `-F` argument as `file=@<path>;filename=<name>;type=...`. While semicolons in `filepath` are replaced, other characters significant to curl's form parser are not handled. In particular, commas can split multiple files in a single `@...` spec, and parser-sensitive leading characters can change interpretation. Because the path is embedded inside curl's own `-F` mini-language rather than passed as a raw filename parameter, shell quoting alone does not make it safe.",
    "impact": "Legitimate files with uncommon names may fail to upload or upload the wrong content/metadata. On hostile filesystems, crafted filenames can interfere with submission behavior and cause missed samples.",
    "suggestion": "Avoid embedding the raw path in curl's `-F` mini-language. The safest fix on minimal systems is to copy the file to a temp path with a controlled name before calling curl, then use that temp path in `@...;filename=...`. Alternatively, use curl features that separate filename metadata from the local path if available on target versions. Example approach: create `tmp_upload = mktemp()`, stream-copy `filepath` to it, then build `file=@<tmp_upload>;filename=<safe_name>;type=application/octet-stream`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F2",
    "severity": "HIGH",
    "location": "send_collection_marker / curl branch",
    "title": "Collection marker uploads with curl do not fail on HTTP error status",
    "description": "The curl path for collection markers uses `curl -s -o ... --data-binary ...` without `--fail` or any explicit HTTP status check. `exec_ok()` therefore treats HTTP 4xx/5xx responses as success because curl exits 0 when the transfer itself succeeded. The function may report `upload_ok = true` even when the server rejected the marker.",
    "impact": "Begin/end/interrupted markers can be silently lost while the script believes they were delivered. This breaks server-side correlation, scan accounting, and the intended retry behavior for the begin marker.",
    "suggestion": "Add `--fail --show-error` and/or capture `%{http_code}` with `-w` and require a 2xx status. For example: `curl -sS --fail -o resp_file ...` or `curl -sS -o resp_file -w '%{http_code}' ...` and validate the returned code before setting `upload_ok = true`.",
    "false_positive_risk": "low"
  },
  {
    "id": "F3",
    "severity": "HIGH",
    "location": "send_collection_marker / wget and busybox-wget branches",
    "title": "Collection marker uploads with wget treat HTTP error pages as success",
    "description": "The wget marker path relies only on `exec_ok(cmd)`. Depending on wget variant and server behavior, an HTTP error response can still leave a response body in the output file while the command path is not validated against the actual HTTP status or response semantics. Unlike the file-upload paths, marker submission does not inspect the response for rejection or parse status lines.",
    "impact": "The script can incorrectly believe begin/end markers were accepted, causing missing scan lifecycle events and making the single begin-marker retry ineffective.",
    "suggestion": "Capture and validate the HTTP status explicitly. On GNU wget, use `--server-response` and parse the final status code from stderr, or prefer curl when available for marker submission. At minimum, reject non-2xx responses before returning `upload_ok = true`.",
    "false_positive_risk": "medium"
  },
  {
    "id": "F4",
    "severity": "MEDIUM",
    "location": "scan_directory / find stderr handling and final exit logic",
    "title": "Permission and traversal errors during scanning do not affect exit code",
    "description": "The script captures `find` stderr and logs it only at debug level, but does not mark the run as partially failed when directory traversal encounters permission denied or similar errors. The hardened behavior described in the prompt requires partial failures to be reflected in exit code 1. Currently, a scan can miss files due to access errors and still exit 0 as long as uploads succeeded.",
    "impact": "Automation may treat incomplete collections as clean/successful, hiding coverage gaps on real systems with mixed permissions or transient filesystem errors.",
    "suggestion": "Track scan errors separately, e.g. `counters.scan_errors = counters.scan_errors + 1` when `find` emits stderr or exits unsuccessfully, and return exit code 1 when any scan errors occurred. Consider logging such errors at warn level, not only debug.",
    "false_positive_risk": "low"
  },
  {
    "id": "F5",
    "severity": "MEDIUM",
    "location": "build_multipart_body / boundary collision check",
    "title": "Multipart boundary collision detection only scans file head and tail",
    "description": "The multipart builder checks for `--<boundary>` only in the first and last 64 KB of the file for large inputs. A collision in the middle of the file remains possible. While unlikely with a long random boundary, the code comment claims the boundary is verified against file content, which is not fully true.",
    "impact": "A rare but real collision can corrupt the multipart body and cause server-side parse failures for affected uploads.",
    "suggestion": "Either scan the entire file in chunks for the boundary string, or weaken the comment and rely on a sufficiently strong random boundary without claiming full verification. A streaming chunked search can be implemented with bounded memory.",
    "false_positive_risk": "low"
  },
  {
    "id": "F6",
    "severity": "MEDIUM",
    "location": "mktemp / os.tmpname fallback",
    "title": "Fallback temporary-file creation remains vulnerable to races and predictable names",
    "description": "If `mktemp` is unavailable, the fallback uses `os.tmpname()` and then a process-specific `/tmp/thunderstorm-<time>-<random>` path. Both approaches are non-atomic and can be pre-created or replaced between checks and opens. The symlink check after creation reduces one case but does not eliminate TOCTOU issues, especially for the second fallback path which is opened directly without exclusive creation.",
    "impact": "On multi-user systems or hostile environments, temp files used for request bodies and responses can be clobbered, redirected, or read by other processes, leading to failed uploads or data exposure.",
    "suggestion": "Prefer requiring the external `mktemp` utility when temp files are needed, and fail fatally if it is unavailable on systems where secure temp creation cannot be guaranteed. If a fallback is unavoidable, create files via a shell `umask 077; mktemp` invocation only, rather than predictable Lua-generated names.",
    "false_positive_risk": "low"
  }
]