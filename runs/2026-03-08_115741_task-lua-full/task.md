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
