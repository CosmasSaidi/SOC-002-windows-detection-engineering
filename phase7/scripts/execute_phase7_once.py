#!/usr/bin/env python3
"""SOC-002 Phase 7 - ONE-SHOT controlled execution driver.

Sends the Phase 7 blind-spot command to SOC002-WS001 exactly once over the
existing authorised WinRM administrator channel, then prints the raw result.

The command is a literal in this file so the evidence can quote the exact
bytes that crossed the wire. It contains NO encoded-command CLI switch:
the transport loader just reads the staged body and hands it to a plainly
started powershell.exe via -Command.

Refuses to run without --confirm. There is intentionally no loop and no retry.
"""
import os, sys, datetime
import winrm

WS001 = os.environ.get("SOC002_WS001", "192.168.56.102")
BODY  = r"C:\Windows\Temp\soc002-phase7\phase7_child_command.txt"

# The exact remote line. No -EncodedCommand / -enc / -e / -en anywhere.
LOADER = (
    "$c=[IO.File]::ReadAllText('" + BODY + "'); "
    "powershell.exe -NoProfile -NonInteractive -Command $c"
)

def main():
    if "--confirm" not in sys.argv:
        sys.exit("refusing to execute without --confirm (this is the single controlled run)")
    user, pwd = os.environ.get("WINRM_USER"), os.environ.get("WINRM_PASS")
    if not user or not pwd:
        sys.exit("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)")

    print("### PHASE 7 :: SINGLE CONTROLLED EXECUTION ###")
    print("Target          = %s (SOC002-WS001)" % WS001)
    print("Account         = %s" % user)
    print("Staged body     = %s" % BODY)
    print("TRANSPORT LINE  = %s" % LOADER)
    print("CHILD STARTS    = powershell.exe -NoProfile -NonInteractive -Command <staged body>")
    print("Encoded switch? = %s" % ("YES" if __import__("re").search(r"(?i)\s-(e|en|enc|encodedcommand)(\s|$)", LOADER) else "NO"))
    t0 = datetime.datetime.now(datetime.timezone.utc)
    print("OperatorUtcBefore = %s" % t0.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
    print("-" * 67)

    sess = winrm.Session(
        "http://%s:5985/wsman" % WS001,
        auth=(user, pwd), transport="ntlm", server_cert_validation="ignore",
        read_timeout_sec=120, operation_timeout_sec=110,
    )
    r = sess.run_ps(LOADER)
    t1 = datetime.datetime.now(datetime.timezone.utc)

    print("--- child/transport stdout ---")
    sys.stdout.write(r.std_out.decode("utf-8", "replace"))
    err = r.std_err.decode("utf-8", "replace")
    if err.strip():
        print("--- stderr ---")
        sys.stdout.write(err)
    print("-" * 67)
    print("RC                = %d" % r.status_code)
    print("OperatorUtcAfter  = %s" % t1.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
    print("### END SINGLE CONTROLLED EXECUTION ###")

if __name__ == "__main__":
    main()
