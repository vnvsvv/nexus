# Sysmon on the Windows endpoint

1. Download Sysmon from Microsoft Sysinternals (`https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`).
2. Admin PowerShell: `.\Sysmon64.exe -accepteula -i C:\Lab\nexus-sysmon.xml`
3. Verify: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List`
4. Lab VM only: Defender exclusion for `C:\Lab` (`Add-MpPreference -ExclusionPath C:\Lab`) so the harmless scenario scripts are not quarantined. Do **not** do this on your personal laptop.
5. Time sync to the gateway: `w32tm /config /manualpeerlist:192.168.20.1 /syncfromflags:manual /update ; w32tm /resync`

Fields the adapter maps (EID → HostEvent):
- 1 ProcessCreate: `ProcessGuid`→`process_instance_id`, `ParentProcessGuid`→parent, `ProcessId`, `ParentProcessId`, `Image`→`binary`, `CommandLine`, `User`, `Hashes` (parse `SHA256=`), `UtcTime` (format `yyyy-MM-dd HH:mm:ss.fff`, convert to ISO `Z`).
- 3 NetworkConnect: `Protocol` (tcp/udp → upper), `SourceIp/SourcePort/DestinationIp/DestinationPort`, `Initiated` (true→outbound, false→inbound). The **process start time is not in EID 3**; take it from the graph node created by EID 1.
- 5 ProcessTerminate: `ProcessGuid`, `UtcTime`.
- 11 FileCreate: `TargetFilename`→`file.path`, operation `create`. (Sysmon cannot distinguish create from overwrite; use `create`.)
- 22 DnsQuery: `QueryName`→`dns.query`, `QueryResults` parse IPs.
- 23 FileDelete: `TargetFilename`, operation `delete`.

Known limitation to record as a gap on every Windows incident that involves file access: `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS`.

Consuming the channel from Python (push subscription, no polling):
```python
import win32evtlog  # pywin32
def cb(action, ctx, event):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
        ctx.put(xml)
sub = win32evtlog.EvtSubscribe("Microsoft-Windows-Sysmon/Operational", win32evtlog.EvtSubscribeToFutureEvents,
                               None, cb, queue, None, None)
```
Run the agent in an elevated PowerShell for the MVP; wrap as a service with NSSM only as a stretch.
