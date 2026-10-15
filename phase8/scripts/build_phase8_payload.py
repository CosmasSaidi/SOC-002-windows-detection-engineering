#!/usr/bin/env python3
"""SOC-002 Phase 8 - build the harmless DET-003 validation payload (offline).

Writes scripts/phase8_child_command.txt (the exact PowerShell body that will run
in the payload process) and scripts/phase8_payload_metadata.json.

The body reconstructs a harmless marker from a base64 blob with
[Convert]::FromBase64String(...). It uses NO encoded-command switch, makes no
network connection, writes no file, creates no persistence and only prints text.
The decoded content is plain text and is never executed.
"""
import base64, hashlib, json, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
MARKER = "SOC002-PHASE8-DET003-TEST"

DECODED = (
    MARKER + "\n"
    "SOC002 PHASE 8 CONTROLLED DET-003 VALIDATION\n"
    "Marker: " + MARKER + "\n"
    "Purpose: harmless marker reconstruction only.\n"
)

BODY = ("$b='{b64}';"
        "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));"
        "Write-Output $t")

def main():
    blob = base64.b64encode(DECODED.encode("utf-8")).decode("ascii")
    body = BODY.format(b64=blob)
    body_path = os.path.join(HERE, "phase8_child_command.txt")
    with open(body_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(body)
    child_cmdline = 'powershell.exe -NoProfile -NonInteractive -Command "%s"' % body
    meta = {
        "phase": "SOC-002 Phase 8",
        "detection": "SOC002-DET-003",
        "marker": MARKER,
        "delivery": "WinRM/WinRS as SOC002\\Administrator (existing authorised lab admin context)",
        "loader_line": "$c=[IO.File]::ReadAllText('C:\\Windows\\Temp\\soc002-phase8\\phase8_child_command.txt'); powershell.exe -NoProfile -NonInteractive -Command $c",
        "payload_process_command": child_cmdline,
        "uses_encoded_command_switch": bool(re.search(r"(?i)\s-(e|en|enc|encodedcommand)(\s|$)", child_cmdline)),
        "reconstructs_with": "[Convert]::FromBase64String",
        "decodes_to": "plain text only (marker + purpose line); never executed",
        "decoded_bytes": len(DECODED.encode("utf-8")),
        "decoded_sha256": hashlib.sha256(DECODED.encode("utf-8")).hexdigest().upper(),
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest().upper(),
        "base64_len": len(blob),
        "executions": 1,
        "persistence": False,
        "config_change": False,
        "network_contact_by_payload": False,
        "file_writes_by_payload": False,
        "permanent_files": False,
    }
    with open(os.path.join(HERE, "phase8_payload_metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")
    print("body   :", body_path)
    print("marker :", MARKER)
    print("b64len :", len(blob))
    print("uses -EncodedCommand in child:", meta["uses_encoded_command_switch"])
    print("body sha256:", meta["body_sha256"])

if __name__ == "__main__":
    main()
