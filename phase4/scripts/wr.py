#!/usr/bin/env python3
"""SOC-002 Phase 4 WinRM runner.
Usage: wr.py <host> (<ps-inline> | @<ps-file>) [--inline]
Reads WINRM_USER / WINRM_PASS from env. Never prints credentials.
stdout = raw output; final line [RC]=<n>. Non-zero exit on failure.
"""
import os, sys, winrm

def main():
    if len(sys.argv) < 3:
        print("usage: wr.py <host> <ps> [--inline]", file=sys.stderr); sys.exit(2)
    host = sys.argv[1]
    if "--inline" in sys.argv:
        ps = sys.argv[2]
    else:
        path = sys.argv[2][1:] if sys.argv[2].startswith("@") else sys.argv[2]
        with open(path, "r", encoding="utf-8") as f:
            ps = f.read()
    user = os.environ.get("WINRM_USER"); pwd = os.environ.get("WINRM_PASS")
    if not user or not pwd:
        print("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)", file=sys.stderr); sys.exit(3)
    last = None
    for ep in (f"http://{host}:5985/wsman", f"https://{host}:5986/wsman"):
        try:
            s = winrm.Session(ep, auth=(user, pwd), transport="ntlm",
                              server_cert_validation="ignore",
                              read_timeout_sec=90, operation_timeout_sec=80)
            r = s.run_ps(ps)
            sys.stdout.write(r.std_out.decode("utf-8", "replace"))
            err = r.std_err.decode("utf-8", "replace")
            if err.strip():
                sys.stdout.write("\n[STDERR]\n" + err)
            sys.stdout.write(f"\n[RC]={r.status_code}\n[EP]={ep}\n")
            sys.exit(0 if r.status_code == 0 else 1)
        except Exception as e:
            last = f"{ep}: {type(e).__name__}: {str(e)[:200]}"; continue
    print(f"[ALL ENDPOINTS FAILED] {last}", file=sys.stderr); sys.exit(4)

if __name__ == "__main__":
    main()
