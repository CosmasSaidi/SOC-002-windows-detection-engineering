#!/usr/bin/env python3
"""SOC-002 Phase 7 - run the read-only telemetry collector on a lab host.

usage: collect_via_winrm.py <host> <ws001-local|dc1-forwarded> <startUtc> <endUtc>

Mechanism (identical on both hosts, and identical to the mechanism used for the
controlled test itself):
  1. the collector body is staged on the host as a .ps1 file;
  2. WinRS carries a SHORT payload that sets three environment variables and
     hands the staged body to a plainly started powershell.exe via -Command.

Two lab constraints forced this shape, neither of which is worked around:
  * WS001's effective execution policy is Restricted (every scope Undefined), so
    a .ps1 file cannot be executed directly there - and Phase 7 must not weaken
    any security control, so no -ExecutionPolicy switch is used;
  * a WinRS transport command line is bounded (~8 KB), so the 6 KB body cannot
    be sent inline the way Phase 5 sent its smaller collectors.

This script is strictly READ-ONLY against the event logs. It changes no
configuration and writes nothing on the target.
"""
import os, sys, winrm

BODY = r"C:\Windows\Temp\soc002-phase7\collect_phase7_telemetry.ps1"

def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    host, source, start_utc, end_utc = sys.argv[1:5]
    user, pwd = os.environ.get("WINRM_USER"), os.environ.get("WINRM_PASS")
    if not user or not pwd:
        sys.exit("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)")

    payload = (
        "$env:PHASE7_START_UTC='%s';$env:PHASE7_END_UTC='%s';$env:PHASE7_SOURCE='%s';"
        "$c=[IO.File]::ReadAllText('%s');"
        "powershell.exe -NoProfile -NonInteractive -Command $c"
        % (start_utc, end_utc, source, BODY)
    )
    sess = winrm.Session("http://%s:5985/wsman" % host,
                         auth=(user, pwd), transport="ntlm",
                         server_cert_validation="ignore",
                         read_timeout_sec=300, operation_timeout_sec=290)
    r = sess.run_ps(payload)
    sys.stdout.write(r.std_out.decode("utf-8", "replace"))
    err = r.std_err.decode("utf-8", "replace")
    if err.strip():
        sys.stdout.write("\n[STDERR]\n" + err)
    sys.stdout.write("\n[RC]=%d\n" % r.status_code)
    return 0 if r.status_code == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
