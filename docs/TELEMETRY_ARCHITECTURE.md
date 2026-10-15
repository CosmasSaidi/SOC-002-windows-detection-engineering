# SOC-002 — Telemetry Architecture

This document describes the telemetry the lab actually collected and the
pipeline that centralised it. Everything below is drawn from the preserved Phase
4–8 artifacts; nothing is claimed beyond what those artifacts prove.

## Topology

```
Operator (Kali, 192.168.56.1)
   │  WinRM / NTLM over HTTP 5985 (authorised management channel)
   ▼
SOC002-WS001.soc002.local (192.168.56.102)   Windows 10 Pro, domain-joined
   │  Sysmon Operational, PowerShell Operational, Security
   │  Windows Event Forwarding (pull)
   ▼
SOC002-DC1 (192.168.56.10)                   Windows Server 2022
      AD DS + DNS + WEF Collector -> ForwardedEvents
```

The two VMs run in an isolated VirtualBox lab. `SOC002-DC1` deliberately has
**no Sysmon** (verified: `phase4/evidence/final_snapshot_dc1.txt` records
`Sysmon64: ABSENT (as required)`), so all Sysmon events in the project originate
on `SOC002-WS001`.

## SOC002-WS001 — endpoint

| Element | Value | Evidence |
|---|---|---|
| Platform | Windows 10 Pro | `PHASE5_PROMPT.txt` / phase reports |
| Domain | `soc002.local` | process/account fields in raw events |
| Address | `192.168.56.102` | `phase4/evidence/final_snapshot_ws001.txt` |
| Collectors active | Sysmon64 + SysmonDrv (Running), PowerShell Operational, Security | final snapshot |

- **Sysmon** — running with the Phase 4 config (see below).
- **PowerShell Script Block Logging** — enabled (`ScriptBlockLogging = 1`), which
  produces Event ID 4104.
- **Windows Security auditing** — process creation with command line enabled
  (`ProcessCreationIncludeCmdLine_Enabled = 1`), producing 4688 records with a
  populated `CommandLine`; logons produce 4624 / 4625.

Retention observed on WS001 (`phase4/evidence/final_snapshot_ws001.txt`):

```
Security: mode=Circular maxKB=20480 count=15066
Sysmon:   mode=Circular maxKB=65536 count=3468
```

Retention is **bounded**, which is why long-window absence is "not observed"
rather than "disproved".

## SOC002-DC1 — collector / domain controller

| Element | Value |
|---|---|
| Platform | Windows Server 2022 |
| Roles | AD DS, DNS, WEF collector (Windows Event Collector) |
| Address | `192.168.56.10` |
| Central log | `ForwardedEvents` |
| Sysmon | Absent by design |

Working directory for the Phase 4 change-set was `C:\Temp`, and the WEF
subscription was created/updated from the collector side. `phase4/evidence/t3_*`
records the before/after subscription state and the fact that centralised events
retain their `EventData` (used by the detection layer).

## Windows Event Forwarding (WEF)

Source → collector → `ForwardedEvents`:

| Field | Value |
|---|---|
| Subscription ID | `SOC002-WS001-Security` |
| Type | CollectorInitiated, `ConfigurationMode = Custom`, Delivery `Mode = Pull` |
| Transport | HTTP, port 5985 |
| Content format | `RenderedText` |
| Log file | `ForwardedEvents` |
| Event source | `SOC002-WS001.soc002.local` |
| Runtime status | Active, `LastError = 0` |
| Description | `SOC-002 Phase 4: Security 4624/4625/4688, PowerShell 4104, Sysmon 1/3` |

Subscription query (verbatim, `phase4/configs/wef_subscription.phase4.xml`):

```xml
<QueryList><Query Id="0">
  <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]</Select>
  <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select>
  <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=1 or EventID=3)]]</Select>
</Query></QueryList>
```

`ForwardedEvents` coverage measured during Phase 4
(`phase4/evidence/final_snapshot_dc1.txt`, a point-in-time snapshot):

| Provider | Event ID | Count | Newest |
|---|---|---|---|
| Microsoft-Windows-Security-Auditing | 4624 | 47 | 00:48:01 |
| Microsoft-Windows-Security-Auditing | 4625 | 1 | 00:46:54 |
| Microsoft-Windows-Security-Auditing | 4688 | 225 | 00:48:01 |
| Microsoft-Windows-PowerShell | 4104 | 270 | 00:48:15 |
| Microsoft-Windows-Sysmon | 1 | 1673 | 00:48:01 |
| Microsoft-Windows-Sysmon | 3 | 83 | 00:48:02 |

**WEF limitation (measured):** forwarded events in `ForwardedEvents` carry **no
rendered `Message` text**; any rule that filters on `$_.Message` silently matches
nothing centrally. Detection logic must parse the `EventData` XML. Phase 4
discovered this (`phase4/evidence/t3_dest_pair_dc1.txt`, `t3_dest_debug_dc1.txt`)
and the Phase 5 detector was reworked accordingly.

## Sysmon

Configuration: `phase4/configs/soc002_sysmon_phase4.xml`
(schema version 4.90; `HashAlgorithms = SHA256`; config hash
`SHA256=D3A8A1F81BC5CA12A0E2DC3071F07DDD91CBD75290C519DB364376B2EDEC77F6`).

Filtering is intentionally narrow — process creation and network connect only:

```xml
<ProcessCreate onmatch="include"><Image condition="contains">\</Image></ProcessCreate>
<NetworkConnect onmatch="include"><DestinationPort condition="more than">0</DestinationPort></NetworkConnect>
```

### Sysmon Event ID 1 — Process Create

The primary signal for `SOC002-DET-001`. Fields used by the project: `Image`,
`CommandLine`, `ProcessGuid`, `ProcessId`, `User`, `LogonId`, `ParentImage`,
`ParentCommandLine`, `Hashes`. Raw example:
`phase5/evidence/raw/sysmon1-recid3535-ws001.xml`.

### Sysmon Event ID 3 — Network Connect

Used to check whether a payload process made network connections. In
`CASE-0001`, filtering Event 3 on the payload's `ProcessGuid` over a 2-hour window
returned **0 events**; in `CASE-0002`, the three Event 3 records in the window were
transport traffic (inbound `WS001:5985` and an `lsass.exe` → DC1 authentication
socket), not payload connections.

### Sysmon limitations (measured)

- **Continuity gap.** Phase 6 measured a **2012-second hole** in the Sysmon Event 1
  stream at the collector (00:07:38 → 00:41:10 local) while Security 4688 kept
  recording. Root cause is `NOT VERIFIED` (local log rollover vs collector-side
  drop); establishing it would require changing logging configuration.
  Evidence: `phase6/evidence/t7_fm_live_probe_dc1.txt` (largest gap = 2012 s).
- **No `ParentProcessGuid` equivalent from 4688.** When lineage is resolved from
  Security 4688, PID joins can mis-attribute a parent; the Phase 6 library
  refuses a PID candidate whose image name does not match what the child recorded.
- **Only Events 1 and 3 are collected.** File writes, registry changes, driver
  loads and other Sysmon events are **not** available.
- **DC1 has no Sysmon**, so Sysmon events exist only for WS001.

## PowerShell

### Event ID 4104 — Script Block Logging

Enabled via Script Block Logging and forwarded by the WEF subscription. Used as
**corroboration** for the Sysmon process-creation signal, matched by executing PID
(or by known marker text), and independently as a source for DET-003's text
search. Fields used: `ScriptBlockText`, `ScriptBlockId`, `MessageNumber` /
`MessageTotal`, and the executing process ID from the event system data.

Limitations (`phase5/evidence/DETECTION_LIMITATIONS.txt`,
`phase6/evidence/t7_failure_modes.txt`):

- **Not mandatory** for DET-001: when 4104 is absent, the detector reports
  `Corroboration = NONE FOUND` but the Sysmon alert stands.
- **Not always present:** the Phase 6 failure-mode probe found that, of 39
  candidates, **33 had a binding 4104 block and 6 had none** (a strict
  executing-PID match). Phase 5's own corroboration step differed slightly (8
  without). Either way, the "what did it actually do" view is not guaranteed.
- **Fragmentation:** long scripts are split across `MessageNumber`/`MessageTotal
  > 1` and would need reassembly. In CASE-0001 the block was 1/1 (unfragmented).
- **Noise:** 142 of the window's 4104 blocks bound to no candidate executing PID.
- **Content boundary:** the Phase 7 payload's 4104 block contained the base64 blob
  and the reconstruction call, **not** the reconstructed marker (which existed
  only in process stdout).

## Windows Security (Security log)

| Event ID | Meaning | Use in the project |
|---|---|---|
| 4624 | Successful logon | Pipeline-verified in Phase 4; logon context |
| 4625 | Failed logon | Pipeline-verified with a controlled failed auth (Phase 4) |
| 4688 | Process creation (with `CommandLine`) | Optional fallback source for DET-001 and a DET-003 input |

Phase 4 verified all three reach `ForwardedEvents` with `EventData` preserved and
`RecordId` semantics intact (`phase4/evidence/t3_preserve_check_dc1.txt`), and
proved a fresh 4625 from a controlled failed authentication arrives centrally with
the same RecordID (`phase4/evidence/t4_dest4625_dc1.txt`).

Limitations:

- 4688 carries **no `ParentProcessGuid`**, so its lineage is weaker than Sysmon's.
- The audit subcategories **Security System Extension** and **Other Object Access
  Events** are set to **No Auditing** on WS001, so Security 4697/4698 cannot be
  used as evidence about service/task creation.
- `CommandLine` is only present while the command-line audit policy
  (`ProcessCreationIncludeCmdLine_Enabled = 1`) remains enabled; if it is disabled
  the trigger cannot evaluate at all (and the failure is silent).

## Enablers the detections depend on

The whole detection chain depends on the Phase 4 enablers staying in place:
4688 command-line auditing, PowerShell Script Block Logging, the Sysmon config,
and the WEF subscription. If any is removed, the corresponding evidence
disappears. That is a **collection** problem, not a detection result. Phase 7 and
Phase 8 verified the enablers were in place and left them untouched.

## What is deliberately out of scope

- No firewall, EDR, Sysmon file/registry/process-access events, or AD-specific
  auditing beyond the logon/process events listed above.
- No network packet capture or network-flow telemetry.
- No production estate, no internet-facing assets, no adversary telemetry.
