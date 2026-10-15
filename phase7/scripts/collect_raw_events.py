#!/usr/bin/env python3
"""SOC-002 Phase 7 - raw telemetry sampler (READ-ONLY).

usage: collect_raw_events.py <host> <ws001-local|dc1-forwarded> <startUtc> <endUtc>

Why this shape (all three constraints were hit and none is worked around):
  * WS001's effective execution policy is Restricted, so a staged .ps1 cannot be
    executed there, and Phase 7 must not weaken a control to make it runnable;
  * a WinRS transport command line is bounded (~8 KB), so a 6 KB script cannot
    be sent inline;
  * handing a multi-line script to powershell.exe as a native argument round-
    trips its double quotes and corrupts it.

So this sampler sends a SHORT, self-contained, read-only query that emits the raw
EventData XML for the three required sources. All interpretation happens offline
on the operator workstation against that raw XML.

Nothing is written on the target; no configuration is changed.
"""
import os, sys, winrm

TEMPLATE = """$s=[datetime]::Parse('%(start)s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AdjustToUniversal)
$e=[datetime]::Parse('%(end)s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AdjustToUniversal)
'%(header)s'
function D($log,$id,$prov){
Get-WinEvent -FilterHashtable @{LogName=$log;Id=$id;StartTime=$s.ToLocalTime();EndTime=$e.ToLocalTime()} -EA SilentlyContinue |
Where-Object{$_.TimeCreated.ToUniversalTime() -ge $s -and $_.TimeCreated.ToUniversalTime() -le $e -and (-not $prov -or $_.ProviderName -match $prov)} |
Sort-Object TimeCreated | ForEach-Object{'EVXML|'+$_.ToXml().Replace("`r","").Replace("`n","")}
}
D '%(log4688)s' 4688 ''
D '%(logsysmon)s' 1 'Sysmon'
D '%(logps)s' 4104 ''
D '%(logsysmon)s' 3 'Sysmon'
'%(footer)s'
"""

def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    host, source, start_utc, end_utc = sys.argv[1:5]
    user, pwd = os.environ.get("WINRM_USER"), os.environ.get("WINRM_PASS")
    if not user or not pwd:
        sys.exit("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)")
    if source == "ws001-local":
        l4688, lsys, lps = "Security", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational"
    else:
        l4688 = lsys = lps = "ForwardedEvents"
    q = TEMPLATE % dict(start=start_utc, end=end_utc,
                        header="### RAW COLLECT host=%s source=%s window=%s..%s ###" % (host, source, start_utc, end_utc),
                        footer="### END RAW COLLECT ###",
                        log4688=l4688, logsysmon=lsys, logps=lps)
    sess = winrm.Session("http://%s:5985/wsman" % host, auth=(user, pwd),
                         transport="ntlm", server_cert_validation="ignore",
                         read_timeout_sec=300, operation_timeout_sec=290)
    r = sess.run_ps(q)
    sys.stdout.write(r.std_out.decode("utf-8", "replace"))
    err = r.std_err.decode("utf-8", "replace")
    if err.strip():
        sys.stdout.write("\n[STDERR]\n" + err)
    sys.stdout.write("\n[RC]=%d\n" % r.status_code)
    return 0 if r.status_code == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
