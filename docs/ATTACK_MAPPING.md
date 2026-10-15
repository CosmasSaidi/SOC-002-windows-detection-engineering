# SOC-002 — MITRE ATT&CK Mapping

This mapping uses **only** techniques already established in the project
artifacts (`phase5/evidence/ATTACK_MAPPING.txt`,
`phase9/sigma/SOC002-DET-001-encoded-powershell.yml` and the phase reports). No
additional techniques are introduced.

The rule the lab applies to itself: *map only what the telemetry actually shows,
and label how confident that mapping is.* Because only Sysmon Event 1/3 and a
limited Security/PowerShell event set are forwarded, the absence of a technique is
"not observed", not "disproved".

## Summary

| Technique | Name | Maps to | Evidence basis | Label |
|---|---|---|---|---|
| `T1059.001` | Command and Scripting Interpreter: PowerShell | The controlled activity | `powershell.exe` is the executing image (Sysmon Ev1 RecId 3535, Security 4688 RecId 15141, PowerShell 4104 RecId 72974) | **Observed / validated** |
| `T1027` | Obfuscated Files or Information | The controlled activity | The command was supplied as a base64 `-EncodedCommand`; a base64-encoded script block is a standard encoding/obfuscation form | **Observed / validated** (encoding is PowerShell's own parameter, not a custom packer) |
| `T1021.006` | Remote Services: Windows Remote Management | How the lab is *operated* | The process-ancestry root is `winrshost.exe`; delivery was over a WinRM session (Sysmon Ev1 ancestry + 4688 chain) | **Contextual only** |

## Observed / validated behaviour

These mappings are directly supported by the preserved telemetry for the
controlled executions:

- **`T1059.001` — PowerShell.** The executing image is `powershell.exe`, confirmed
  independently by three sources with matching PID/`ProcessGuid`/`ScriptBlockId`.
  This held for all three controlled cases (Phase 5, 7 and 8 payloads).
- **`T1027` — Obfuscated/Encoded Information.** In `CASE-0001` the command was
  supplied as a base64 `-EncodedCommand`; in `CASE-0002` and `CASE-0003` the
  payload reconstructed base64 in-process via `[Convert]::FromBase64String`. The
  mapping is to the *encoding form*, not to any packer or custom obfuscation.

Labelling caveats:

- ATT&CK maps **behaviour, not intent**. The same `T1059.001` covers a benign
  administrator one-liner and a malicious stager. The mapping says nothing about
  intent on its own.
- The controlled activity is **benign and authorised**; the techniques describe
  the *shape* of the activity, not a real attack.

## Simulated / controlled behaviour

The techniques above were produced by **controlled, benign, self-directed
activity** in a lab — not by an adversary. The project never executed malware, did
not download or stage malicious tooling, did not establish persistence, did not
access credentials, and did not perform lateral movement. The value of the mapping
is that it describes the same *behavioural shape* a real activity would exhibit,
which is what a detection must key on.

## Contextual mapping

- **`T1021.006` — Remote Services: Windows Remote Management.** The process
  ancestry root is `winrshost.exe`, i.e. the execution was delivered through a
  WinRM session. In this lab that channel is the **authorised operator access**,
  not adversary behaviour, so `T1021.006` is recorded as **observed context**, not
  as an attack technique. In an environment where WinRM is *not* the sanctioned
  management path, the same observation would be genuine adversary mapping.
- `SOC002-DET-002` exists specifically to surface this delivery context. It is a
  **context** detection ("how was this PowerShell created?"), not a verdict.

## Detection mapping

`SOC002-DET-001` is a detector for the **`T1059.001` + `T1027` pattern**: a
PowerShell process with an encoded command line. The detection is deliberately
written to fire on the *pattern* and to require human interpretation, so it must
**not** be reported as "`T1059.001` = compromised". The Sigma representation
carries `attack.execution`, `attack.t1059.001`, `attack.defense_evasion` and
`attack.t1027`.

`SOC002-DET-003` is not itself mapped to a distinct ATT&CK technique in the
project artifacts; it detects a **behavioural form** (in-process base64
reconstruction) that can occur in benign scripting as readily as in malicious
activity. No additional technique is asserted for it.

## Deliberately not mapped

No evidence supported these, so they are excluded rather than implied:

- **Persistence** (`T1547` / `T1053` / `T1543`): none observed — TaskScheduler
  106 = 0 and System 7045 = 0 in the window; 4697/4698 are set to *No Auditing*,
  so their absence proves nothing.
- **Privilege escalation** (`T1068` / `T1548`): the token was already elevated
  (High integrity, Full token) inherited from the Administrator logon.
- **Credential access** (`T1003` / `T1555`): no access to credential material was
  observed.
- **Lateral movement from WS001** (`T1021.x` to other hosts): no network from the
  payload process (Sysmon Ev3 = 0 for its `ProcessGuid`).
- **Defence evasion specific to logging** (`T1562`): no logging/config change was
  made.
- **`T1140` (Deobfuscate/Decode Files or Information):** the Phase 5 script
  decoded nothing for effect; the decode in Phase 7/8 was read-only and printed.
  The lab does not claim `T1140` for a plain printed marker.

## Limitations of this mapping

- ATT&CK maps behaviour, not intent; a benign one-liner and a malicious stager can
  share a technique.
- `T1021.006` describes how this lab is operated; it would only be *adversary*
  mapping where WinRM is not the sanctioned management path.
- Because only a limited set of event IDs is forwarded, the absence of other
  techniques is "not observed", not "disproved".
- The mapping was produced against **controlled lab activity**; it makes no claim
  about a real intrusion.
