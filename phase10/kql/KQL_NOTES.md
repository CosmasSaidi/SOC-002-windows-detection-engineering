# KQL_NOTES — SOC002-DET-001 (Encoded PowerShell) translated to KQL

Companion notes for `SOC002-DET-001-encoded-powershell.kql` (portable form) and
`SOC002-DET-001-encoded-powershell-regex.kql` (regex form).

Phase 10 is a **closure / translation** artefact set. It expresses an existing,
already-validated detection in KQL for a Microsoft Sentinel / Microsoft Defender-style
environment. **No new detection logic was developed here, no detection was modified, and
no Phase 5–9 artefact was touched.** Nothing in this directory has been run against a live
workspace.

---

## 1. Source table assumption

Both queries target the Microsoft Sentinel **`Event`** table. This is an **assumption** about
the collection pipeline, stated explicitly because the lab's own evidence was collected from
a Windows Event Forwarding collector's `ForwardedEvents` log, *not* from Sentinel:

| Assumed element | Value used in the query |
|---|---|
| Table | `Event` (Microsoft Sentinel / Log Analytics) |
| Event identity | `EventID == 1` |
| Sysmon source | `Source == "Microsoft-Windows-Sysmon"` **or** `EventLog == "Microsoft-Windows-Sysmon/Operational"` |
| Process image | `EventData.Image` (dynamic → `tostring(...)`) |
| Command line | `EventData.CommandLine` (dynamic → `tostring(...)`) |
| Collector | Log Analytics agent (MMA) or Azure Monitor Agent, Windows event channel `Microsoft-Windows-Sysmon/Operational` |

The `Event` table is used because it is the canonical Sentinel landing table for **Windows
Event Log data collected verbatim** — which is exactly what Sysmon Event ID 1 is. The
alternative for EDR-shaped data is `DeviceProcessEvents`, which is **Defender for Endpoint
telemetry, not the lab's Sysmon Event 1**. A separate optional equivalent for that table is
given in section 9 and is explicitly labelled as a different source model.

**Field-shape caveat.** The query assumes the modern **AMA/MMA** shape where `EventData` is a
dynamic (JSON) column, so `EventData.Image` / `EventData.CommandLine` resolve directly. Some
older/legacy ingestion paths for Sysmon put the event in `ParameterXml` (a raw XML string) or
render the whole event into a single field. If a workspace uses that shape, the `extend` stage
must be replaced with a `parse_xml` / `parse` projection of the same two fields:

```kql
| extend Xml = parse_xml(ParameterXml)
| extend Image = tostring(Xml.Event.EventData.Data[0]), CommandLine = tostring(Xml.Event.EventData.Data[1])
```

The **predicate** is unchanged in either shape: Event ID 1 ∧ Sysmon source ∧ `Image` ends with
a PowerShell image ∧ `CommandLine` carries the encoded-command switch. Only the projection of
`Image`/`CommandLine` is shape-dependent.

## 2. Why the `Event` table, and what `Event ID 1` means

- **Why `Event`:** it is the verbatim Windows-event table. DET-001 is a Windows event-log
  detection (Sysmon), not an EDR-model detection, so the honest translation uses the table
  that stores the event as the operating system emitted it.
- **`Event ID 1` = Sysmon "Process Create".** Provider `Microsoft-Windows-Sysmon`, channel
  `Microsoft-Windows-Sysmon/Operational`. It is emitted once, at process creation, and carries
  the created process `Image` (full path) and the full `CommandLine`. These are precisely the
  two fields the existing DET-001 reads (confirmed against the preserved evidence
  `phase5/evidence/raw/sysmon1-recid3535-ws001.xml`).
- DET-001 is a **triage** signal. `Event ID 1` + an encoded-command switch says *an analyst
  should look at this process*; it does **not** say the process is malicious and does **not**
  prove compromise. The original detector prints "INVESTIGATION REQUIRED" for that reason, and
  the KQL translation keeps the same MEDIUM triage severity.

## 3. Portable Sigma → KQL representation

The Sigma rule (`phase9/sigma/SOC002-DET-001-encoded-powershell.yml`) encodes:

```yaml
selection_image:
  Image|endswith: ['\powershell.exe', '\pwsh.exe']
selection_encoded_switch:
  CommandLine|contains: ['-EncodedCommand', '-encodedcommand']
condition: selection_image and selection_encoded_switch
```

`SOC002-DET-001-encoded-powershell.kql` is the **faithful, one-to-one** KQL rendering of that
portable representation:

| Sigma | KQL |
|---|---|
| `category: process_creation` + `service: sysmon` | `EventID == 1` + `Source`/`EventLog` = Microsoft-Windows-Sysmon |
| `Image\|endswith '\powershell.exe'` / `'\pwsh.exe'` | `Image endswith @"\powershell.exe" or Image endswith @"\pwsh.exe"` |
| `CommandLine\|contains '-EncodedCommand'` | `CommandLine contains "-EncodedCommand"` |
| case-insensitive default matching | KQL `endswith` / `contains` are already case-insensitive |

Notes on operator choice:

- `endswith` is the correct operator for the Sigma `|endswith` modifier — it is a suffix test,
  not a regex or a substring scan. The leading backslash is kept (`@"\powershell.exe"`) so the
  KQL match is exactly as wide as the Sigma match; it will not fire on a hypothetical
  `C:\tools\mypowershell.exe`.
- `contains` is the correct operator for the Sigma `|contains` modifier: it is an unanchored,
  case-insensitive substring test. It is used deliberately instead of `has` because `has`
  matches whole *terms* delimited by non-alphanumerics, and the leading `-` of the switch makes
  term semantics fragile. `contains` reproduces the Sigma meaning exactly.
- Because KQL string comparison is case-insensitive, the single literal `"-EncodedCommand"`
  covers the `-encodedcommand` / `-EncodedCommand` / `-ENCODEDCOMMAND` spellings that Sigma
  listed twice. That is a *representation* equivalence, not a broadening.

## 4. Regex representation of the original detector's short-switch logic

The original PowerShell detector's switch test is **not** the Sigma `contains`; it is a
token-exact, case-insensitive regex:

```powershell
$encRx = '(?i)\s-(e|en|enc|encodedcommand)(\s|$)'
```

`SOC002-DET-001-encoded-powershell-regex.kql` reproduces that regex directly:

```kql
| where CommandLine matches regex @"(?i)\s-(e|en|enc|encodedcommand)(\s|$)"
```

Properties carried over faithfully:

- **Case-insensitive** — KQL `matches regex` is case-sensitive by default, so the original
  `(?i)` inline flag is retained explicitly.
- **Token-exact** — a whitespace must precede the switch and the switch token must be followed
  by whitespace or end-of-string. This is what makes the short forms safe to match:

| Command-line text | `-e` | `-en` | `-enc` | verdict |
|---|---|---|---|---|
| `-ErrorAction` | 'e' then 'r' → no boundary | — | — | no match |
| `-ExecutionPolicy` | 'e' then 'x' → no boundary | — | — | no match |
| `-Enabled` | 'e' then 'n' → no boundary | 'en' then 'a' → no boundary | — | no match |
| `-Encoding` | — | — | 'enc' then 'o' → no boundary | no match |
| `-e <b64>` | match | — | — | **match** |
| `-en <b64>` | — | match | — | **match** |
| `-enc <b64>` | — | — | match | **match** |
| `-EncodedCommand <b64>` | — | — | — | **match** (via `encodedcommand`) |

The `(?i)` flag is what allows the single lowercase alternation to match `-E`, `-Enc`, and
`-EncodedCommand` as Windows PowerShell accepts them.

## 5. Difference between the Sigma form and the original detector regex

This is the point of having **two** query files, and the difference must not be glossed over:

| Aspect | Original PowerShell detector | Sigma rule | Portable KQL (`...encoded-powershell.kql`) | Regex KQL (`...encoded-powershell-regex.kql`) |
|---|---|---|---|---|
| Switch matched | `-e` \| `-en` \| `-enc` \| `-encodedcommand`, token-exact | `-EncodedCommand` only | `-EncodedCommand` only | `-e` \| `-en` \| `-enc` \| `-encodedcommand`, token-exact |
| Short forms | covered | **not covered** | **not covered** | **covered** |
| Boundary enforcement | yes (whitespace / end) | no (substring) | no (substring) | yes (whitespace / end) |
| Image match | unanchored substring `(?i)(powershell\|pwsh)\.exe` | `endswith '\powershell.exe'` / `'\pwsh.exe'` | same as Sigma | same as Sigma |

Consequences, stated plainly:

- The **portable KQL file is narrower** than the original detector: it misses `-e`, `-en`, `-enc`.
  It is also *marginally broader* in one edge case — plain substring `contains` would fire on a
  command line that merely *quotes* the literal text `-EncodedCommand`.
- The **regex KQL file is the closer translation** of the original detector for the switch
  semantics, because it restores the short forms *and* the token-boundary behaviour.
- Neither file changes the **Image** test relative to Sigma. Sigma itself narrowed the original
  detector's unanchored `(powershell|pwsh)\.exe` substring match to the standard
  `endswith` idiom; that narrowing was inherited unchanged from Phase 9 and is documented here
  rather than silently altered.

Both files are provided precisely so the trade-off is explicit rather than hidden: a team that
wants maximum portability with minimum false-positive risk uses the portable file; a team that
wants the original detector's short-switch coverage uses the regex file.

## 6. Why the Phase 6 baseline (`BASE-01`) is NOT a KQL exclusion

- `BASE-01` is **lab-specific contextual tuning**, not part of DET-001's trigger. It is the
  narrow WinRS-transport baseline added in Phase 6
  (`phase6/evidence/TUNING_RATIONALE.txt`, section 2.1) — and even there it is the *only*
  suppression, and the general `powershell.exe` / `-EncodedCommand` suppressions are reported
  as 0.
- It is **not portable and not universal.** `BASE-01` requires data a single-event
  process-creation query does not have: the parent command line and the decoded payload. Two of
  its own conditions depend on the enrichment/correlation layers that are out of scope here.
- Encoding it as a global KQL exclusion would **suppress exactly the transport a real operator's
  tooling uses** — `cmd.exe /C powershell -encodedcommand <b64>` is how WinRM delivers *every*
  remote command, so "cmd.exe parent ⇒ benign" silently blinds the rule to the most common real
  delivery path.
- Therefore, per the closure requirements, **no `BASE-01`-style suppression appears in either
  KQL file.** Suppressing the lab's own administration pattern is a per-environment tuning
  decision that must be made (and documented) by the deploying team, not baked into the
  translation artefact. The validator enforces this: the token `BASE-01` does not appear in
  either query file at all.

## 7. Why Event ID 4104 is corroboration only

- 4104 (PowerShell **Script Block Logging**) is used by the original detector as a
  **corroborating/enrichment** source: it shows *what the encoded block actually did*, correlated
  to the Sysmon process by executing PID and a small time window.
- It is **not** a mandatory primary trigger, and it is deliberately absent from these queries.
  Reasons: 4104 is high-volume and noisy; it can be missing entirely (ScriptBlockLogging off, or
  the log not forwarded — the Phase 5 evidence contains hits where corroboration was
  `NONE FOUND` while the Sysmon alert still stood); and long scripts are fragmented across
  `MessageNumber/MessageTotal > 1`, which a single-event rule would have to reassemble.
- Consequence: **the KQL queries fire on the Sysmon Event ID 1 evidence alone**, exactly as
  DET-001's primary trigger does. Adding a 4104 join would narrow (and couple) coverage, not
  faithfully translate it. The validator confirms the primary query contains no 4104 dependency.

## 8. Blind spot: the other detection's reconstruction case

- DET-001 (and therefore this translation) only covers an **encoded-command switch on the command
  line**. PowerShell that rebuilds a payload *inside* the process —
  `powershell.exe -Command "$b='<base64>'; ...GetString(...FromBase64String($b))"` — carries **no
  encoded-command switch** and is **not** matched here. Phase 7 confirmed this blind spot.
- The lab addressed it with a **separate** detection, `SOC002-DET-003`
  (`phase8/detections/detect_base64_reconstruction.ps1`), built in Phase 8. It answers a
  different question with a different indicator.
- **It is deliberately not merged into these queries.** Merging it would silently broaden
  DET-001 and destroy the independent auditability of the two detections. The validator enforces
  this: neither the `FromBase64String` family nor a Base64-extraction regex appears anywhere in
  either query file. This is an acknowledged coverage gap, not an oversight.

## 9. Optional Defender XDR equivalent (separate source model)

`DeviceProcessEvents` is offered below **only** as a labelled alternative for teams whose
telemetry is Defender for Endpoint rather than collected Windows Event logs. It represents
**Defender for Endpoint process telemetry, not the lab's Sysmon Event ID 1 directly** — treat it
as a *different source model*, not as an equivalent rendering of the same evidence:

```kql
// OPTIONAL / DIFFERENT SOURCE MODEL - Defender for Endpoint, NOT Sysmon Event ID 1.
// Not part of the DET-001 translation and not statically validated here.
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "-EncodedCommand"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessFileName
```

This is intentionally left **outside** the two validated query files. Mixing EDR-model telemetry
into a Sysmon-evidence translation would misrepresent where the local evidence came from.

## 10. Lab false-positive history (measured, not theoretical)

- In a 60-minute window on a single workstation, DET-001 fired **39 times**
  (`phase5/evidence/t6_detection_broad60_dc1.txt`, `Total alerts = 39`).
- **38 of those 39 were the lab operator's own legitimate WinRM administration**: the WinRS client
  delivers every remote command as `cmd.exe /C powershell -encodedcommand <base64>`, so one
  administrator generates alert-per-command volume. The remaining single hit was the controlled
  test.
- All hits shared the same user, host and Microsoft binary hash — which is exactly why Phase 6
  refused to tune on user/host/hash/time, and why no such suppression is present in these KQL
  files.
- Practical reading: **expect volume before precision.** Scope the rule per environment and pair
  it with process-lineage context and payload decoding before treating a hit as suspicious.

## 11. What was preserved, and claim boundaries

Preserved: the primary telemetry (Sysmon Event ID 1 / Process Create), the two fields read
(`Image`, `CommandLine`), the process scope (`powershell.exe` / `pwsh.exe`), the trigger (an
encoded-command switch on the command line), and the MEDIUM triage interpretation.

Claim boundaries:

- This is a **static, offline translation** derived by reading the preserved Phase 5/6/9 sources
  and evidence. It is not a new detection, not a coverage measurement and not a performance test.
- **No production or live Sentinel validation was performed.** No KQL parser, backend or
  workspace exists in this environment, so the queries were **not executed** and their syntax was
  **not** checked by a KQL engine — only by the deterministic static validator in
  `validate_kql.ps1`.
- The source table, the `Source`/`EventLog` values and the `EventData` field shape are the
  documented **assumptions** of section 1; a real workspace may require the alternative
  projection shown there.
- No credentials or secrets are stored anywhere in this tree.

## 12. Final status

**PASS** — see `KQL_VALIDATION_REPORT.md`. Both KQL forms exist and are clearly distinguished as
portable vs original-regex; no other detection's logic and no environment-specific baseline
suppression is merged in; the Phase 5–9 files are provably byte-identical; the static validator
passes; and all assumptions and limitations are stated without any live-Sentinel or production
claim.
