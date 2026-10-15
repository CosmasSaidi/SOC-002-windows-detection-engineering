#!/usr/bin/env python3
"""SOC-002 Phase 8 - ONE-SHOT harmless DET-003 live validation on SOC002-WS001.

Runs exactly ONE controlled, benign execution over the existing authorised WinRM
administrator channel. A plainly-started powershell.exe reconstructs a harmless
marker with [Convert]::FromBase64String(...). There is NO encoded-command switch
in the payload process, no network connection, no persistence, no configuration
change and no permanent file (the temp body is removed at the end).

Nothing decoded is ever executed - only printed.

Refuses to run without --confirm. No loop, no retry.
"""
import base64, datetime, hashlib, os, re, sys

try:
    import winrm
except ImportError:
    sys.exit("pywinrm not installed")

WS001 = os.environ.get("SOC002_WS001", "192.168.56.102")
HERE = os.path.dirname(os.path.abspath(__file__))
TMPDIR = r"C:\Windows\Temp\soc002-phase8"
BODY_REMOTE = TMPDIR + r"\phase8_child_command.txt"
MARKER = "SOC002-PHASE8-DET003-TEST"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def clean_err(err):
    if "CLIXML" not in err:
        return err.strip()
    keep = [l for l in err.splitlines()
            if l.strip() and "CLIXML" not in l and not l.strip().startswith("<Objs")
            and not l.strip().startswith("<")]
    return "\n".join(keep).strip()


def main():
    if "--confirm" not in sys.argv:
        sys.exit("refusing to execute without --confirm (this is the single controlled run)")

    user, pwd = os.environ.get("WINRM_USER"), os.environ.get("WINRM_PASS")
    if not user or not pwd:
        sys.exit("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)")

    body = open(os.path.join(HERE, "phase8_child_command.txt"), encoding="utf-8").read()
    blob = re.search(r"\$b='([A-Za-z0-9+/=]+)'", body).group(1)
    decoded = base64.b64decode(blob).decode("utf-8")
    child_cmd = 'powershell.exe -NoProfile -NonInteractive -Command "' + body + '"'
    enc_switch = bool(re.search(r"(?i)\s-(e|en|enc|encodedcommand)(\s|$)", child_cmd))
    if MARKER not in decoded:
        sys.exit("refusing: decoded content does not contain the harmless marker")
    if enc_switch:
        sys.exit("refusing: the payload child command line contains an encoded-command switch")

    print("### PHASE 8 :: SINGLE CONTROLLED LIVE VALIDATION (DET-003) ###")
    print("Target            = %s (SOC002-WS001)" % WS001)
    print("Account           = %s" % user)
    print("Payload body sha256 = %s" % hashlib.sha256(body.encode()).hexdigest().upper())
    print("Payload child cmd = %s" % child_cmd)
    print("Encoded switch?   = %s" % ("YES" if enc_switch else "NO"))
    print("Reconstructs with = [Convert]::FromBase64String")
    print("Decoded content   = %s" % repr(decoded[:60]))
    print("=" * 72)

    sess = winrm.Session(
        "http://%s:5985/wsman" % WS001,
        auth=(user, pwd), transport="ntlm", server_cert_validation="ignore",
        read_timeout_sec=120, operation_timeout_sec=110,
    )

    t_before = utc()
    print("OperatorUtcBefore = %s" % t_before)

    # --- stage the body WITHOUT any base64 in the transport (no DET-003 self-noise)
    stage_script = (
        "New-Item -ItemType Directory -Force -Path '%s' | Out-Null; "
        "Set-Content -LiteralPath '%s' -Value '%s' -NoNewline -Encoding ASCII; "
        "'STAGED='+(Get-Item '%s').Length"
    ) % (TMPDIR, BODY_REMOTE, body.replace("'", "''"), BODY_REMOTE)
    # The staging script necessarily carries the payload text as a LITERAL string
    # (the payload body itself contains the decode call). That is data being
    # written, not a decode being executed; it is expected and documented, and the
    # staging transport is separable from the payload process in the telemetry.
    if re.search(r"(?i)\[convert\]::frombase64string", stage_script) and "Set-Content" not in stage_script:
        sys.exit("refusing: staging script unexpectedly decodes base64 itself")
    t_stage0 = utc()
    r = sess.run_ps(stage_script)
    t_stage1 = utc()
    print("OperatorUtcStage  = %s .. %s" % (t_stage0, t_stage1))
    print("  stage rc=%d out=%s" % (r.status_code, r.std_out.decode("utf-8", "replace").strip()))

    # --- execute the payload (child powershell.exe, no encoded-command switch)
    loader = ("$c=[IO.File]::ReadAllText('%s'); "
              "powershell.exe -NoProfile -NonInteractive -Command $c") % BODY_REMOTE
    t_exec0 = utc()
    r = sess.run_ps(loader)
    t_exec1 = utc()
    print("OperatorUtcExec   = %s .. %s" % (t_exec0, t_exec1))
    out = r.std_out.decode("utf-8", "replace")
    print("--- payload stdout ---")
    sys.stdout.write(out)
    err = clean_err(r.std_err.decode("utf-8", "replace"))
    if err:
        print("--- payload stderr ---")
        print(err)
    print("--- end payload stdout ---")
    print("RC                = %d" % r.status_code)
    print("MARKER_PRESENT    = %s" % (MARKER in out))

    # --- cleanup: remove ONLY this phase's temp directory
    t_clean0 = utc()
    r = sess.run_ps("Remove-Item -Recurse -Force '%s' -ErrorAction SilentlyContinue; "
                    "'TMP_REMOVED='+(-not (Test-Path '%s'))" % (TMPDIR, TMPDIR))
    t_clean1 = utc()
    print("OperatorUtcCleanup= %s .. %s" % (t_clean0, t_clean1))
    print("  cleanup out=%s" % r.std_out.decode("utf-8", "replace").strip())
    print("OperatorUtcAfter  = %s" % utc())
    print("### END SINGLE CONTROLLED LIVE VALIDATION ###")
    return 0 if (r.status_code == 0 and MARKER in out) else 1


if __name__ == "__main__":
    sys.exit(main())
