#!/usr/bin/env python3
"""SOC-002 Phase 8 - raw telemetry sampler (READ-ONLY).

usage: collect_raw_events.py <host> <ws001-local|dc1-forwarded> <startUtc> <endUtc>

Read-only: sends a short self-contained query that emits raw EventData XML for
Security 4688, Sysmon Event 1, PowerShell 4104 and Sysmon Event 3. Nothing is
written on the target and no configuration is changed. (Same shape as the Phase 7
collector; Phase 8 keeps its own copy so phase7/ stays untouched.)
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
