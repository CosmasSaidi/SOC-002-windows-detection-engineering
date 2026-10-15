#!/usr/bin/env python3
"""Push a local file to a Windows host over WinRM in base64 chunks.
Usage: push.py <host> <local-path> <remote-path>
Prints remote length + SHA256 for verification against local sha256sum."""
import base64, hashlib, os, subprocess, sys

def run(host, ps):
    p = subprocess.run(['python3', 'scripts/wr.py', host, ps, '--inline'],
                       capture_output=True, text=True)
    return p.stdout

def main():
    host, local, remote = sys.argv[1], sys.argv[2], sys.argv[3]
    data = open(local, 'rb').read()
    b64 = base64.b64encode(data).decode('ascii')
    rdir = remote.rsplit('\\', 1)[0]
    tmp = remote + '.b64'
    run(host, f"New-Item -ItemType Directory -Force -Path '{rdir}' | Out-Null; Remove-Item -Force '{tmp}' -EA SilentlyContinue; 'ready'")
    n = 0
    for i in range(0, len(b64), 1500):
        chunk = b64[i:i+1500]
        run(host, f"[IO.File]::AppendAllText('{tmp}','{chunk}')")
        n += 1
    out = run(host, ("$b=[IO.File]::ReadAllText('%s');"
                     "[IO.File]::WriteAllBytes('%s',[Convert]::FromBase64String($b));"
                     "Remove-Item -Force '%s';"
                     "'LEN='+(Get-Item '%s').Length;"
                     "'SHA256='+(Get-FileHash -Algorithm SHA256 '%s').Hash") % (tmp, remote, tmp, remote, remote))
    print(f"chunks={n} local_len={len(data)} local_sha256={hashlib.sha256(data).hexdigest().upper()}")
    print(out.strip())

if __name__ == '__main__':
    main()
