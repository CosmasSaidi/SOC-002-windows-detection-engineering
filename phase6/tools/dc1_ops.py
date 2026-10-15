#!/usr/bin/env python3
"""SOC-002 Phase 6 - read-only WinRM operations against SOC002-DC1.

Subcommands
  push <local> <remote> [...]   upload files (b64 chunks, session reused)
  run  <remote-ps1> [args...]   run a pushed script and print its output
  ps   <inline-powershell>      run an inline command (no file needed)
  rm   <remote-path>            delete a pushed artefact (cleanup)

Credentials come from the environment (WINRM_USER / WINRM_PASS) and are never
printed. Only read-only queries plus writes inside the Phase 6 temp directory
are used; no lab configuration is touched.
"""
import base64, hashlib, os, sys

try:
    import winrm
except ImportError:
    sys.exit("pywinrm not installed")

HOST = os.environ.get("SOC002_DC1", "192.168.56.10")
TMPDIR = r"C:\Windows\Temp\soc002-phase6"


def session():
    user, pwd = os.environ.get("WINRM_USER"), os.environ.get("WINRM_PASS")
    if not user or not pwd:
        sys.exit("MISSING CREDENTIALS (WINRM_USER/WINRM_PASS not set)")
    ep = f"http://{HOST}:5985/wsman"
    return winrm.Session(ep, auth=(user, pwd), transport="ntlm",
                         server_cert_validation="ignore",
                         read_timeout_sec=180, operation_timeout_sec=170)


def clean_err(err):
    """Drop pywinrm's CLIXML progress stream (pure noise) but keep real errors."""
    if "CLIXML" not in err:
        return err.strip()
    keep = [l for l in err.splitlines()
            if l.strip() and "CLIXML" not in l and not l.strip().startswith("<Objs")
            and not l.strip().startswith("<")]
    return "\n".join(keep).strip()


def run_ps(s, ps):
    r = s.run_ps(ps)
    out = r.std_out.decode("utf-8", "replace")
    err = clean_err(r.std_err.decode("utf-8", "replace"))
    return r.status_code, out, err


def cmd_push(s, local, remote):
    data = open(local, "rb").read()
    b64 = base64.b64encode(data).decode("ascii")
    rdir = remote.rsplit("\\", 1)[0]
    tmp = remote + ".b64"
    run_ps(s, f"New-Item -ItemType Directory -Force -Path '{rdir}' | Out-Null; 'dir-ready'")
    run_ps(s, f"Remove-Item -Force '{tmp}' -ErrorAction SilentlyContinue; 'tmp-cleared'")
    chunk = int(os.environ.get('SOC002_CHUNK', '1400'))
    n = 0
    for i in range(0, len(b64), chunk):
        part = b64[i:i + chunk]
        rc, _, err = run_ps(s, f"[IO.File]::AppendAllText('{tmp}','{part}')")
        if rc != 0:
            sys.exit(f"chunk {n} failed: {err[:200]}")
        n += 1
    rc, out, err = run_ps(s, ("$b=[IO.File]::ReadAllText('{0}');"
                              "[IO.File]::WriteAllBytes('{1}',[Convert]::FromBase64String($b));"
                              "Remove-Item -Force '{0}';"
                              "'LEN='+(Get-Item '{1}').Length;"
                              "'SHA256='+(Get-FileHash -Algorithm SHA256 '{1}').Hash").format(tmp, remote))
    print(f"push {os.path.basename(local)} chunks={n} local_bytes={len(data)} "
          f"local_sha256={hashlib.sha256(data).hexdigest().upper()}")
    print("  " + out.strip().replace("\n", "\n  "))


def cmd_pushgz(s, local, remote):
    """Upload a gzip-compressed file: fewer WinRM commands (and therefore fewer
    self-observation process-create events) than a raw push."""
    import gzip
    raw = open(local, "rb").read()
    gz = gzip.compress(raw, 9)
    b64 = base64.b64encode(gz).decode("ascii")
    rdir = remote.rsplit("\\", 1)[0]
    tmp = remote + ".b64"
    run_ps(s, f"New-Item -ItemType Directory -Force -Path '{rdir}' | Out-Null; 'dir-ready'")
    run_ps(s, f"Remove-Item -Force '{tmp}' -ErrorAction SilentlyContinue; 'tmp-cleared'")
    chunk = int(os.environ.get("SOC002_CHUNK", "1400"))
    n = 0
    for i in range(0, len(b64), chunk):
        rc, _, err = run_ps(s, f"[IO.File]::AppendAllText('{tmp}','{b64[i:i+chunk]}')")
        if rc != 0:
            sys.exit(f"chunk {n} failed: {err[:200]}")
        n += 1
    ps = ("$b=[IO.File]::ReadAllText('{0}'); "
          "$g=[Convert]::FromBase64String($b); "
          "$ms=New-Object IO.MemoryStream(,$g); "
          "$zs=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); "
          "$o=New-Object IO.MemoryStream; $zs.CopyTo($o); $zs.Dispose(); "
          "[IO.File]::WriteAllBytes('{1}',$o.ToArray()); Remove-Item -Force '{0}'; "
          "'LEN='+(Get-Item '{1}').Length; 'SHA256='+(Get-FileHash -Algorithm SHA256 '{1}').Hash").format(tmp, remote)
    rc, out, err = run_ps(s, ps)
    print(f"pushgz {os.path.basename(local)} chunks={n} raw={len(raw)} gz={len(gz)} "
          f"local_sha256={hashlib.sha256(raw).hexdigest().upper()}")
    print("  " + out.strip().replace("\n", "\n  "))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    op = sys.argv[1]
    s = session()
    if op == "pushgz":
        pairs = sys.argv[2:]
        for i in range(0, len(pairs), 2):
            cmd_pushgz(s, pairs[i], pairs[i + 1])
    elif op == "push":
        pairs = sys.argv[2:]
        for i in range(0, len(pairs), 2):
            cmd_push(s, pairs[i], pairs[i + 1])
    elif op == "run":
        script = sys.argv[2]
        args = " ".join(sys.argv[3:])
        rc, out, err = run_ps(s, f"& '{script}' {args}")
        sys.stdout.write(out)
        if err.strip():
            sys.stdout.write("\n[STDERR]\n" + err)
        sys.stdout.write(f"\n[RC]={rc}\n")
    elif op == "ps":
        rc, out, err = run_ps(s, sys.argv[2])
        sys.stdout.write(out)
        if err.strip():
            sys.stdout.write("\n[STDERR]\n" + err)
        sys.stdout.write(f"\n[RC]={rc}\n")
    elif op == "rm":
        rc, out, err = run_ps(s, f"Remove-Item -Recurse -Force '{sys.argv[2]}' -ErrorAction SilentlyContinue; Test-Path '{sys.argv[2]}'")
        sys.stdout.write(out + f"\n[RC]={rc}\n")
    else:
        sys.exit(f"unknown subcommand {op}")


if __name__ == "__main__":
    main()
