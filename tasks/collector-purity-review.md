# Task: Collector Script Purity & Robustness Review

## Objective
Review the Thunderstorm collector script for correctness, robustness, and **language purity**.

## Critical Constraint: Language Purity

**Each collector script MUST use ONLY its own language and standard OS utilities.**

- **Batch (.bat)**: cmd.exe built-ins + curl ONLY. No PowerShell, no VBScript, no Python.
- **Bash (.sh)**: Bash built-ins + standard POSIX utilities (curl/wget, grep, sed, awk, find, date, etc.) ONLY. No Python, no Perl, no Ruby.
- **Ash (.ash.sh)**: POSIX sh built-ins + BusyBox/POSIX utilities ONLY. No Bash-isms, no Python, no Perl.
- **PowerShell (.ps1)**: PowerShell cmdlets + .NET framework ONLY. No calling Python, no cmd.exe workarounds.
- **PowerShell 2.0 (.ps2.ps1)**: PowerShell 2.0 compatible cmdlets + .NET 3.5 ONLY.
- **Python 3 (.py)**: Python 3 standard library ONLY. No subprocess calls to curl or shell commands.
- **Python 2.7 (.py2.py)**: Python 2.7 standard library ONLY.
- **Perl (.pl)**: Perl core modules ONLY. No shelling out to curl or Python.

**Why**: Each script variant exists because users lack access to other runtimes. A Batch script that calls PowerShell is useless — if PowerShell were available, the user would run the .ps1 collector. Same logic applies to all variants.

## What to Review

1. **Language purity violations** — Flag any cross-language calls as CRITICAL
2. **Error handling** — Proper HTTP error handling, retry logic, graceful degradation
3. **Security** — No command injection, safe temp file handling, input validation
4. **Platform compatibility** — Does it work on the target platforms?
   - Batch: Windows 7+ / Server 2008 R2+
   - Bash: Linux, macOS, WSL
   - Ash: BusyBox/Alpine, embedded Linux
   - PowerShell: Windows with PS 3.0+
   - PowerShell 2.0: Windows 7 / Server 2008 R2
   - Python 3: Any OS with Python 3.6+
   - Python 2.7: Legacy systems
   - Perl: Any OS with Perl 5.8+
5. **Correctness** — Logic errors, off-by-one, missing edge cases

## What NOT to Flag

- Missing features that are impossible in the target language (e.g., collection markers in Batch). Document these as known limitations instead.
- Style preferences or minor formatting issues (LOW severity — will not be fixed)
- Performance optimizations unless they fix actual bugs

## Severity Guide

- **CRITICAL**: Language purity violation, security vulnerability, data loss risk
- **HIGH**: Broken functionality, incorrect error handling that hides failures
- **MEDIUM**: Missing validation, poor error messages, edge cases that cause silent failures
- **LOW**: Style, naming, comments, minor improvements (will NOT be fixed)

## Known Limitations (do NOT flag these)

- **Batch**: No collection markers, no scan_id, no signal handling, no progress reporting, no TLS cert options — these are cmd.exe platform constraints
- **Ash**: No arrays, no C-style for loops, limited string manipulation
- **Python 2.7**: No `urllib3`, limited SSL options
