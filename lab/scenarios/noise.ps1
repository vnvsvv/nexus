<#
.SYNOPSIS
  Benign noise generator for false-positive measurement on Windows. Expected NEXUS outcome: zero incidents.

.DESCRIPTION
  Runs harmless everyday-looking activity every MinDelay..MaxDelay seconds for -Minutes minutes:
  directory listings, text search, child processes (cmd, python, curl.exe), small file copies and
  deletes inside -WorkDir, HTTP GETs to the other VM's web server, and an occasional DNS lookup of
  a reserved test name. Every incident NEXUS raises between start_utc and end_utc of the manifest
  is a false positive (use: nexus-eval noise --window START END).

  It deliberately does NOT: use -ExecutionPolicy Bypass, -enc or -EncodedCommand, write under
  C:\Lab\staging or C:\Lab\bin, or contact many ports (NX-WIN-001, -002 and -003 stay quiet).
  Compatible with Windows PowerShell 5.1. Runs unelevated.

.EXAMPLE
  # Lab VM (Sysmon lab profile): 60 minutes against the Linux VM's web server
  powershell -NoProfile -ExecutionPolicy RemoteSigned -File C:\Lab\scenarios\noise.ps1 -Minutes 60
  # (if the file came from a download or zip: Unblock-File C:\Lab\scenarios\noise.ps1 first)

.EXAMPLE
  # Dev laptop (Sysmon dev profile): short run against your own LAN IP, with `python -m http.server 8080` running
  powershell -NoProfile -ExecutionPolicy RemoteSigned -File C:\Lab\scenarios\noise.ps1 -Minutes 2 -Target 192.168.1.23 -Port 8080 -EndpointId dev-laptop
#>
param(
    [int]$Minutes = 30,
    [string]$Target = $(if ($env:NEXUS_TARGET) { $env:NEXUS_TARGET } else { "192.168.10.10" }),
    [int]$Port = $(if ($env:NEXUS_PORT) { [int]$env:NEXUS_PORT } else { 8080 }),
    [string]$WorkDir = "C:\Lab\noise",
    [string]$EndpointId = "windows-vm-01",
    [int]$MinDelay = 2,
    [int]$MaxDelay = 10
)

$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path $WorkDir, "C:\Lab\manifests" | Out-Null
$now = { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
$startUtc = & $now
$end = (Get-Date).AddMinutes($Minutes)
$url = "http://${Target}:${Port}/"
$python = Get-Command python -ErrorAction SilentlyContinue
$counts = [ordered]@{ iterations = 0; cmd = 0; python = 0; curl = 0; file_copy = 0; file_delete = 0; dns = 0; http_ok = 0; http_fail = 0 }

Write-Host "noise: $Minutes min, target $url, workdir $WorkDir (Ctrl+C stops early; the manifest is still written)"
try {
    while ((Get-Date) -lt $end) {
        $counts.iterations++
        # 1. in-process work: no Sysmon event of its own
        Get-ChildItem "C:\Windows\System32\drivers\etc" | Out-Null
        Select-String -Path "C:\Windows\System32\drivers\etc\hosts" -Pattern "nexus" | Out-Null

        # 2. a child process, like a user running a command
        & cmd.exe /c "dir $WorkDir >NUL" | Out-Null
        $counts.cmd++

        # 3. small file copy and delete inside the work dir
        $f = Join-Path $WorkDir ("noise-" + (Get-Random -Maximum 100000) + ".txt")
        Copy-Item "C:\Windows\System32\drivers\etc\hosts" $f
        $counts.file_copy++
        Remove-Item $f -Force
        $counts.file_delete++

        # 4. python one-liner when python is installed
        if ($python) {
            & python -c "import json; print(json.dumps({'ok': 1}))" | Out-Null
            $counts.python++
        }

        # 5. HTTP GET to the other VM's web server (curl.exe ships with Windows 10 and 11)
        & curl.exe -s -m 3 -o NUL $url
        $counts.curl++
        if ($LASTEXITCODE -eq 0) { $counts.http_ok++ } else { $counts.http_fail++ }

        # 6. an occasional lookup of a reserved test name (Sysmon EID 22 on the lab profile)
        if ((Get-Random -Maximum 5) -eq 0) {
            Resolve-DnsName "noise.nexus.test" -ErrorAction SilentlyContinue | Out-Null
            $counts.dns++
        }

        Start-Sleep -Seconds (Get-Random -Minimum $MinDelay -Maximum ($MaxDelay + 1))
    }
}
finally {
    $manifest = [ordered]@{
        scenario        = "NOISE"
        endpoint_id     = $EndpointId
        start_utc       = $startUtc
        end_utc         = (& $now)
        root_pid        = $PID
        root_binary     = (Get-Process -Id $PID).Path
        expected_incidents = 0
        target          = $url
        work_dir        = $WorkDir
        counts          = $counts
    }
    $path = "C:\Lab\manifests\NOISE-" + ($startUtc -replace ":", "") + ".json"
    # UTF-8 without BOM so Python's json module reads it directly
    [System.IO.File]::WriteAllText($path, ($manifest | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding $false))
    Write-Host "manifest: $path"
}
