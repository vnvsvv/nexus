# Sysmon for NEXUS: laptop development profile and lab VM profile

> **Status.** The dev laptop profile (`nexus-sysmon-dev.xml`) is **`VALIDATED 2026-11-18`** on a physical
> Windows 11 laptop with Sysmon 15.22 (schema 4.91); §3.3 records what was and was not verified. The lab
> VM profile (`nexus-sysmon.xml`) has **not** been loaded by a real Sysmon and stays `UNVALIDATED`. Both
> configs were written from Microsoft's documentation and general Sysmon knowledge and are also checked
> statically by `tools/lint_sysmon_config.py` (which does not prove Sysmon accepts a file). Treat the lab
> profile's first install as an experiment: run the pre-install checks, install, run the verification
> matrix, and uninstall if anything unexpected is logged. When it has passed on a real machine, replace
> `UNVALIDATED` in its header comment with `VALIDATED YYYY-MM-DD` (lint requires exactly one of the two)
> and note the date in `STATUS.md`.

Facts this README relies on (from Microsoft's Sysmon page, v15.22): all filter conditions are
case-insensitive; rules on the same field are ORed and rules on different fields are ANDed unless a
`RuleGroup groupRelation` says otherwise; include and exclude may both exist for an event and exclude
wins; an include filter with no rules logs nothing; EID 3 is off by default; EID 23 saves a copy of every
deleted file that matches into the archive directory (default `C:\Sysmon`); EID 26 logs the deletion
without saving the file. Field names per event are **not** on that page: confirm them with `Sysmon64.exe -s`.

## 1. Which profile, where

| | **Dev laptop profile** | **Lab VM profile** |
|---|---|---|
| File | `nexus-sysmon-dev.xml` | `nexus-sysmon.xml` |
| Machine | Anas's physical laptop (8 GB, personal data) | `windows-vm-01` only (disposable, isolated) |
| Purpose | Develop and unit-test the Windows adapter against real Sysmon XML | Integration, W1/W2/N1 scenarios, evaluation numbers, demo |
| Logging model | **Include only**: nothing is logged unless it touches `C:\Lab\` or a test marker | **Exclude noise**: log nearly everything, as the evaluation needs |
| EID 1 | Command line, parent command line, image or parent image mentions `C:\Lab\`, or command line contains `NEXUS_TEST` | All except a few system sources |
| EID 3 | Only cmd, powershell, pwsh, python, curl, `C:\Lab\*`; never loopback, link-local, ports 80/443 | All except loopback, link-local, svchost, gateway addresses |
| EID 5 | Same tool images only (no command line is recorded) | All |
| EID 11 | `C:\Lab\` except `C:\Lab\manifests\` | `C:\Lab\`, `C:\Users\Public\`, user Temp, `*.ps1`, `*.exe` (except manifests) |
| EID 22 | Only `*.nexus.test` | All except reverse lookups, `nexus-server`, Windows service noise |
| EID 26 | `C:\Lab\` | `C:\Lab\` |
| EID 23 | **off** | **off** |
| Everything else | off | off |

Do not install the lab profile on the laptop. It logs every process start, every DNS name and most
connections, which on a personal machine means your browsing and application activity.

**Integration and the numbers in the report come from the lab VM.** The laptop's IP is not on the
gateway subnets, so it cannot be correlated, and its Sysmon profile is intentionally thin.

### Why EID 26 and not EID 23
EID 23 copies every deleted file it matches into `C:\Sysmon` (SYSTEM-only ACL, no size limit by default).
On the laptop that is a way of silently collecting copies of files; on the VM it is disk growth with no
benefit, because no NEXUS rule or evidence field needs the file *content* of a deleted file. EID 26 gives
the same "this file was deleted by this process" fact, with the hash, and keeps nothing. The adapter maps
26 and tolerates 23 if somebody enables it later (§6).

## 2. Pre-install checks (read-only; nothing is installed)

1. Download Sysmon from Microsoft Sysinternals. In PowerShell: `Get-AuthenticodeSignature .\Sysmon64.exe`
   must show `Valid` and a Microsoft signer.
2. `.\Sysmon64.exe -? config` printed 15.22 / schema 4.91 on the laptop (already done). Both configs use 4.91.
3. Save the field list of your version outside the repo and run the weak name check:
   ```powershell
   .\Sysmon64.exe -s > $env:USERPROFILE\sysmon-schema.txt
   python tools\lint_sysmon_config.py --schema-dump $env:USERPROFILE\sysmon-schema.txt
   ```
   The `-s` output format is not documented on the Microsoft page; the check just looks for each event and
   field name as a word. If it reports `ParentCommandLine` (or anything else) as missing, delete those
   lines from the config and from the lint table before installing. Sysmon refuses to load a config that
   uses an unknown name, so this fails safe: the install stops with an error.
4. `python tools\lint_sysmon_config.py` and `pytest tests/test_sysmon_configs.py` (static only).
5. Read the XML once. Every rule is short.

## 3. Laptop: development profile

Prerequisites: Windows Defender stays **on**, and no Defender exclusions are added on the laptop. `C:\Lab`
must not be inside OneDrive. The agent's SQLite database (`NEXUS_DB_PATH`) must live outside `C:\Lab`,
for example `C:\ProgramData\nexus\agent.db`, or the agent would observe itself.

Elevated PowerShell:
```powershell
New-Item -ItemType Directory -Force C:\Lab\protected,C:\Lab\staging,C:\Lab\bin,C:\Lab\scenarios,C:\Lab\manifests,C:\Lab\receiver,C:\Lab\noise | Out-Null
cd <folder that contains Sysmon64.exe>        # not C:\Lab
.\Sysmon64.exe -accepteula -i C:\dev\nexus\lab\sysmon\nexus-sysmon-dev.xml
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List Id, TimeCreated, Message
.\Sysmon64.exe -c            # prints the configuration Sysmon actually loaded; compare it with the file
```
Expected right after install: service `Running`; only EID 4 (service started) and EID 16 (configuration
changed) in the log. To change the config later: `.\Sysmon64.exe -c C:\dev\nexus\lab\sysmon\nexus-sysmon-dev.xml`.

### 3.1 Verification matrix (run before the agent is ever started)
Run these from an ordinary PowerShell window. `Get-WinEvent` reads below use the channel name above.

| # | Action | Expected | Why |
|---|---|---|---|
| P1 | `cmd /c echo NEXUS_TEST` | EID 1 for `cmd.exe` with the marker; EID 5 for `cmd.exe` | marker path |
| P2 | `New-Item C:\Lab\probe.txt -Force; Remove-Item C:\Lab\probe.txt` | EID 11 then EID 26, `Image` = powershell.exe | file events |
| P3 | `Resolve-DnsName probe.nexus.test` | EID 22 with `QueryName` `probe.nexus.test` (a failed lookup is still logged per the docs) | DNS |
| P4 | Copy `lab\scenarios\w1_stage.ps1` to `C:\Lab\scenarios\`, put any file in `C:\Lab\protected\`, start a receiver (see `lab/scenarios/README.md`, "W1 on the laptop"), run W1 | EID 1 cmd and powershell; EID 11 `report.zip`; EID 3 `Initiated=true` from powershell to your LAN IP and port 8080; EID 3 `Initiated=false` and EID 1 for the python receiver | the real scenario |
| N1 | Open your browser for 30 s and browse normally | **zero** events whose `Image` is a browser | privacy |
| N2 | `Invoke-WebRequest https://example.com -UseBasicParsing \| Out-Null` | **no** EID 3 (port 443 excluded) and no EID 22 | include plus exclude on the same event works as intended |
| N3 | `Resolve-DnsName example.com` | no EID 22 | DNS include is narrow |
| N4 | `New-Item $env:TEMP\x.txt -Force; Remove-Item $env:TEMP\x.txt` | no EID 11, no EID 26 | file include is narrow |
| N5 | `Start-Process notepad; Start-Sleep 2; Stop-Process -Name notepad` | no EID 1, no EID 5 | process include is narrow |
| H | `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" \| Group-Object Id \| Sort-Object { [int]$_.Name } \| Format-Table Name, Count` | only Ids 1, 3, 5, 11, 22, 26 plus 4 and 16 | nothing else is on |

Note that EID 5 also appears when any PowerShell, cmd, python or curl window on the laptop exits, with the
image path, user and time, but no command line. That is intentional: it exercises the "exit for a process
never seen starting" path of the adapter. If you do not want it, delete the tool images from
`ProcessTerminate` and keep only `C:\Lab\`.

**Stop and roll back** if any N-row shows events, if H shows another Id, or if the service does not start.
Then send the output of `Sysmon64.exe -c` and the offending event to the team before changing anything.
If N2 fails, the likely cause is that include and exclude filters inside one `RuleGroup` do not combine as
assumed; the fix is to split `NetworkConnect` into two `RuleGroup`s, which the lint tool would then need
to learn.

### 3.2 Rollback and uninstall
```powershell
.\Sysmon64.exe -u            # add `force` if it refuses
Test-Path C:\Sysmon          # with EID 23 off this folder should be empty or absent
wevtutil cl "Microsoft-Windows-Sysmon/Operational"   # may say the channel no longer exists: then nothing is left
```
Do not use `Sysmon64.exe -c --`: that resets to Sysmon's built-in defaults, which log far more than this profile.
If `C:\Sysmon` exists and is empty but cannot be deleted (SYSTEM-only ACL), leave it.

### 3.3 Verification record: dev profile, 2026-11-18
Run by Anas on the physical laptop (Windows 11, Sysmon 15.22, schema 4.91). `Sysmon64.exe -c` showed the
intended dev profile and no EID 23 events or `C:\Sysmon` folder appeared. Raw logs are not stored in this
repository; only the outcomes below are.

| Row | Result |
|---|---|
| P1 | Pass: EID 1 and EID 5 for `cmd.exe` with the `NEXUS_TEST` marker. |
| P2 | Pass: EID 11 and EID 26 for a file under `C:\Lab\`. |
| P3 | Pass: EID 22 for `probe.nexus.test`. |
| P4 | Pass: W1 run with a temporary own-IP-only receiver (not in the repository; it discarded the upload). EID 1 for `cmd.exe`, `powershell.exe` and `python.exe`; EID 3 `powershell.exe` to port 8080 with `Initiated=true`; EID 3 `python.exe` on port 8080 with `Initiated=false`; EID 5 for all three; EID 11 for `report.zip` and for the `staging` and `manifests` directories. The receiver took one 153-byte upload and its SHA-256 matched the local `report.zip`. |
| N2, N3, N4, N5 | Pass: no EID 3 for HTTPS (port 443), no EID 22 for `example.com`, no EID 11 for a temp file outside `C:\Lab\`, no EID 1 for Notepad. |
| N1 | **Partial**: no EID 1 or EID 3 for Edge, but already-running browser processes may have been reused, so a freshly started browser was not conclusively tested. |
| H | Pass: only Ids 1, 3, 4, 5, 11, 16, 22 and 26 appeared. A per-image count of EID 5 events showed only PowerShell and CMD before P4, and `python.exe` was added by P4. |

Notes:
- The EID 11 events for `C:\Lab\staging` and `C:\Lab\manifests` are for the **directories** being created.
  The profile excludes paths that begin with `C:\Lab\manifests\`, so the manifest JSON file inside that
  folder is not expected in the log, and whether it appeared was not examined.
- Both ends of the W1 connection are on the laptop, so the `Initiated=false` event does not show which
  address is local for a connection that really arrives from another host (open question O1).

Not verified: **reboot persistence** (that the Sysmon service and this profile come back after a restart),
**cross-host inbound direction** (O1), and a **freshly started browser** (N1). The lab VM profile has not
been loaded at all.

## 4. Lab VM: lab profile

On `windows-vm-01` only (see `docs/08-LAB-SETUP.md` §3):
```powershell
New-Item -ItemType Directory -Force C:\ProgramData\nexus | Out-Null
Copy-Item <path to repo>\lab\sysmon\nexus-sysmon.xml C:\ProgramData\nexus\
.\Sysmon64.exe -accepteula -i C:\ProgramData\nexus\nexus-sysmon.xml
Add-MpPreference -ExclusionPath C:\Lab                   # lab VM only; never on the laptop
Add-Content C:\Windows\System32\drivers\etc\hosts "192.168.20.1 nexus-server"
w32tm /config /manualpeerlist:192.168.20.1 /syncfromflags:manual /update ; w32tm /resync
```
Verify with the same `Get-WinEvent` commands, then run the lab checks in `docs/08-LAB-SETUP.md` §5:
EID 3 with `Initiated`, 5-tuple and `ProcessGuid`; EID 11 for `C:\Lab\staging\*`; EID 26 for a deleted lab file;
**no** EID 3 to 192.168.20.1 while the agent is posting; no EID 22 for `nexus-server`; no EID 11 for
`C:\Lab\manifests\*`. Then snapshot the VM.

## 5. What the adapter reads (EID to HostEvent)

All fields are `<Data Name="...">` elements of `EventData`. Parse by name, never by position, and treat
every field except `ProcessGuid`, `UtcTime` and `Image` as optional. Ignore `RuleName`.

| EID | Maps to | Fields |
|---|---|---|
| 1 | `process_start` | `ProcessGuid` to `process_instance_id`; `ParentProcessGuid` to the parent; `ProcessId`, `ParentProcessId`; `Image` to `binary`; `CommandLine`; `User`; `Hashes` (parse the `SHA256=` entry by key); `UtcTime` |
| 3 | `network_connect` | `Protocol` (upper-case), `SourceIp/SourcePort/DestinationIp/DestinationPort`, `Initiated` (true = outbound, false = inbound). The process start time is **not** in EID 3: take it from the graph node created by EID 1 |
| 5 | `process_exit` | `ProcessGuid`, `UtcTime` |
| 11 | `file_access`, operation `create` | `TargetFilename` to `file.path`. Sysmon cannot tell create from overwrite; use `create` |
| 22 | `dns_query` | `QueryName` to `dns.query`; `QueryResults` (extract IPs) |
| 26 | `file_access`, operation `delete` | `TargetFilename`; `Hashes` and `IsExecutable` optional |
| 23 | same as 26 (**not enabled** by either profile) | tolerate it if present; `Archived` is optional and ignored |

`UtcTime` format is expected to be `yyyy-MM-dd HH:mm:ss.fff`; convert to ISO with `Z`.

Rules the adapter must follow with these profiles (no contract change is needed for any of them):
1. **Unknown EIDs are ignored** (debug log only).
2. **A process seen first in EID 3, 11, 22 or 26** (its EID 1 was filtered out, normal on the laptop) gets a
   placeholder node: `binary` from `Image`, `attributes.identity_resolution = "placeholder"`, parent unknown.
   The resulting incident carries the existing gaps `PARENT_NOT_OBSERVED` / `IDENTITY_INFERRED` and confidence
   at most `medium`. Do not drop the event and do not invent a parent.
3. **EID 5 for a ProcessGuid that is not in the graph is ignored** silently.
4. Never fail on an extra field or a missing optional field; Sysmon versions add fields.
5. `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS` is still attached to every Windows incident that has file evidence.

### 5.1 Open questions, settled by the first real samples
| # | Question | How to settle it |
|---|---|---|
| O1 | For `Initiated=false`, which of Source/Destination is the local machine? The adapter and `docs/02-CORRELATION.md` §direction must not assume. | P4: look at the python receiver's EID 3 |
| O2 | Is `ParentCommandLine` accepted by 4.91 and present in EID 1? | Pre-install check 3, then P4 |
| O3 | What `Image` does EID 22 report for `Resolve-DnsName` (powershell.exe or the DNS client service)? | P3 |
| O4 | Is a refused or failed TCP connection logged as EID 3? | Run W1 with the receiver stopped |
| O5 | Does EID 22 show up for names answered from the hosts file (`nexus-server`)? | Lab profile check in §4 |
| O6 | Exact `UtcTime` and `Hashes` formats | Any EID 1 sample |

## 6. Consuming the channel from Python (push subscription)
Unverified sketch; confirm against pywin32 on the laptop. The callback runs on a pywin32 thread, so it only
renders and queues; parsing happens in the adapter's generator.
```python
import queue
import win32evtlog  # pywin32

q: "queue.Queue[str]" = queue.Queue()

def cb(action, ctx, event):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        ctx.put(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
    return 0

sub = win32evtlog.EvtSubscribe(
    "Microsoft-Windows-Sysmon/Operational", win32evtlog.EvtSubscribeToFutureEvents,
    None, cb, q, None, None)
```
Run the agent in an elevated PowerShell for the MVP; a service wrapper (NSSM) is a stretch. Offline testing:
`main.py --replay-xml DIR` reads XML files exported as in `SAMPLE-COLLECTION.md`.

## 7. Known limitations (write these in the report)
- Sysmon does not log file reads; the `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS` gap stays.
- Sysmon has no dropped-event counter; event loss under load cannot be measured from Sysmon itself.
- The dev profile cannot show what normal activity looks like; false-positive numbers come only from the
  lab VM with `lab/scenarios/noise.ps1`.
- Samples committed to the public repository must follow `SAMPLE-COLLECTION.md`.
