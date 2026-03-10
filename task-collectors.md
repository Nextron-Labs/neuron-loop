Review and improve the THOR Thunderstorm Collector scripts.

These are file collectors that scan directories on endpoints and upload suspicious files to a Thunderstorm server for malware analysis via THOR.

## What each script does

1. Contacts Thunderstorm server to get a "begin" session marker (`POST /api/collection`)
2. Walks configured directories collecting files matching criteria (extensions, size limits, age)
3. Uploads each file via multipart HTTP POST with metadata (hostname, source path)
4. Sends an "end" collection marker with stats (files scanned, uploaded, errors)
5. Reports results and exits with appropriate code

## Required features (all scripts unless noted in Allowed Limitations)

- **Exit codes:** 0 = clean/success, 1 = partial failure (some files failed), 2 = fatal error (cannot connect, missing dependencies)
- **Failed file tracking:** `num_failed` / equivalent counter, reflected in exit code (exit 1 if any uploads failed)
- **Begin-marker retry:** Single retry after 2s on initial connection failure to `/api/collection`
- **Signal handling:** SIGINT/SIGTERM → sends "interrupted" collection marker with stats before exit
- **TLS:** `--ca-cert PATH` for custom CA bundle validation; `--insecure` / `-k` to skip verification
- **JSON escaping:** Proper escaping of source names (control chars, backslashes, quotes) in JSON payloads
- **Error routing:** `[ERROR]` output goes to stderr, not stdout
- **Progress reporting:** `[N/total] X%` with TTY auto-detection; `--progress` / `--no-progress` overrides
- **503 back-pressure:** Respect `Retry-After` header, capped at reasonable maximum
- **Retry with backoff:** Configurable retries with exponential backoff on upload failure
- **Collection markers:** Begin marker (with source, hostname) and end marker (with stats, scan_id)
- **URL-encoded source:** Source identifier properly URL-encoded in API calls

## Allowed limitations by platform

### Batch (.bat) — cmd.exe limitations

The following features are **NOT required** for the batch collector due to cmd.exe platform constraints.
Do NOT attempt to implement these — accept them as known limitations:

1. **No signal handling** — cmd.exe cannot trap SIGINT/SIGTERM. No interrupted marker on Ctrl+C.
2. **No TTY detection / progress reporting** — cmd.exe has no mechanism to detect interactive terminals.
3. **No full JSON escaping** — cmd.exe lacks JSON-capable tools. Basic backslash/quote escaping is sufficient. Control character escaping is not required.
4. **No --ca-cert** — While curl supports `--cacert`, the batch script's limited argument parsing makes this impractical. Document as unsupported.
5. **No --insecure / -k** — Same argument parsing limitation.
6. **Limited exit code 2** — Only for missing curl dependency. Other fatal errors may use exit code 1.
7. **Locale-dependent FORFILES date** — `FORFILES /D` date format depends on system locale. Documented limitation, no fix in batch.

### PowerShell 2 (.ps2.ps1) — PS 2.0 limitations

1. **No `ConvertFrom-Json`** — Not available in PS 2.0. Manual JSON parsing is acceptable.
2. **No `-File` parameter on `Get-ChildItem`** — Must use `Where-Object { -not $_.PSIsContainer }`.

## Review focus

When reviewing and improving these scripts, focus on:

- Logic errors, off-by-one, race conditions
- Security issues (command injection, path traversal, unsafe temp files)
- Correctness of HTTP handling, JSON construction, error propagation
- Platform-specific gotchas for the target runtime
- Implementing missing required features from the list above
- Consistency across all collectors (same flags, same behavior, same exit codes)

## What NOT to do

- Do NOT rewrite entire scripts — make targeted improvements
- Do NOT change the CLI interface (flag names, defaults) unless fixing a bug
- Do NOT attempt to add features listed under "Allowed limitations"
- Do NOT add external dependencies (all scripts must remain stdlib/single-file)
- Preserve the script's style and structure where possible
