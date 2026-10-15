#!/usr/bin/env python3
"""SOC-002 Phase 8 - run SOC002-DET-003 LIVE on the WEF collector SOC002-DC1.

Pushes the Phase 8 detection files (plus the Phase 6 library, read-only) into a
Phase 8 temp directory on DC1 and runs the detector against ForwardedEvents.
Then removes the temp directory. Nothing else on DC1 is touched.

This exercises the production-shaped path: the detector reads the same forwarded
telemetry the SOC would read, using the same trigger that was replayed offline.
"""
import base64, datetime, hashlib, os, sys

try:
    import winrm
except ImportError:
    sys.exit("pywinrm not installed")

HOST = os.environ.get("SOC002_DC1", "192.168.56.10")
TMPDIR = r"C:\Windows\Temp\soc002-phase8-det003"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # phase8/
PUSH = [
    (os.path.join(ROOT, "detections", "lib_soc002_phase8.ps1"), TMPDIR + r"\lib_soc002_phase8.ps1"),
    (os.path.join(ROOT, "detections", "detect_base64_reconstruction.ps1"), TMPDIR + r"\detect_base64_reconstruction.ps1"),
    (os.path.join(ROOT, "..", "phase6", "detections", "lib_soc002_v2.ps1"), TMPDIR + r"\lib_soc002_v2.ps1"),
    (os.path.join(ROOT, "..", "phase6", "detections", "lib_soc002_windows.ps1"), TMPDIR + r"\lib_soc002_windows.ps1"),
]


def clean_err(err):
    if "CLIXML" not in err:
        return err.strip()
    return "\n".join(l for l in err.splitlines()
                     if l.strip() and "CLIXML" not in l and not l.strip().startswith("<Objs")
                     and not l.strip().startswith("<")).strip()


def run_ps(sess, ps):
    r = sess.run_ps(ps)
    return r.status_code, r.std_out.decode("utf-8", "replace"), clean_err(r.std_err.decode("utf-8", "replace"))


def main():
    user, pwd = os.environ.get("WINRM_USER"), os.environ.get("WINRM_PASS")
    if not user or not pwd:
        sys.exit("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)")
    sess = winrm.Session("http://%s:5985/wsman" % HOST, auth=(user, pwd), transport="ntlm",
                         server_cert_validation="ignore", read_timeout_sec=300, operation_timeout_sec=290)

    print("### PHASE 8 :: DET-003 LIVE RUN ON SOC002-DC1 (ForwardedEvents) ###")
    print("Collector = %s   Temp = %s" % (HOST, TMPDIR))
    run_ps(sess, "New-Item -ItemType Directory -Force -Path '%s' | Out-Null; 'dir-ready'" % TMPDIR)
    for local, remote in PUSH:
        data = open(local, "rb").read()
        b64 = base64.b64encode(data).decode("ascii")
        tmp = remote + ".b64"
        run_ps(sess, "Remove-Item -Force '%s' -ErrorAction SilentlyContinue; 'ok'" % tmp)
        for i in range(0, len(b64), 1400):
            rc, _, err = run_ps(sess, "[IO.File]::AppendAllText('%s','%s')" % (tmp, b64[i:i + 1400]))
            if rc != 0:
                sys.exit("chunk push failed: %s" % err[:200])
        rc, out, err = run_ps(sess, ("$b=[IO.File]::ReadAllText('{0}');"
                                     "[IO.File]::WriteAllBytes('{1}',[Convert]::FromBase64String($b));"
                                     "Remove-Item -Force '{0}';"
                                     "'PUSHED {2} bytes='+(Get-Item '{1}').Length+' sha256='+"
                                     "(Get-FileHash -Algorithm SHA256 '{1}').Hash"
                                     ).format(tmp, remote, os.path.basename(remote)))
        print("  " + out.strip().replace("\n", "\n  "))
        local_sha = hashlib.sha256(data).hexdigest().upper()
        if local_sha not in out:
            sys.exit("HASH MISMATCH after push of %s (local %s)" % (remote, local_sha))

    print("-" * 70)
    detector = TMPDIR + r"\detect_base64_reconstruction.ps1"
    cmd = ("& '%s' -LogName ForwardedEvents -Minutes 60 -LibPath '%s' -LegacyLibPath '%s'")
    rc, out, err = run_ps(sess, cmd % (detector, TMPDIR, TMPDIR))
    sys.stdout.write(out)
    if err:
        print("--- stderr ---")
        print(err)
    print("detector rc = %d" % rc)
    print("-" * 70)
    rc, out, err = run_ps(sess, "Remove-Item -Recurse -Force '%s' -ErrorAction SilentlyContinue; 'TMP_REMOVED='+(-not (Test-Path '%s'))" % (TMPDIR, TMPDIR))
    print("cleanup: " + out.strip())
    print("### END DET-003 LIVE RUN ###")
    return 0 if rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
