# Demonstration scenarios (all harmless, all inside the isolated lab)

Every scenario script writes a **ground-truth manifest** (`/lab/manifests/<scenario>-<timestamp>.json` or `C:\Lab\manifests\...`) containing: scenario id, start/end time, the PIDs and binaries it spawned (in order), the files it touched, and the connections it made (5-tuples as seen by the OS). The evaluation harness compares NEXUS incidents against these manifests.

| ID | Endpoint | Story | Expected rule | Expected network side | Response |
|---|---|---|---|---|---|
| L1 | Linux | `python3` → `bash` → `cat /lab/protected/confidential.txt` → `curl` POST to Windows VM `:8443` (a Python `http.server` with a tiny upload handler) | NX-LIN-001 | matched connection; flow likely **benign** by ML — shown anyway | manual terminate (denied: curl not allowlisted) — demonstrates the gate |
| L2 | Linux | `/lab/bin/beacon-sim` (a 20-line Python script copied there, compiled with `pyinstaller` or run as script) connects to Windows VM `:9000` every 5 s | NX-LIN-003 | matched; ML verdict whatever it is | **automatic terminate** (allowlisted path; dry_run=false on the lab VM) |
| L3 | Linux | one process connects to 30 sequential ports on the Windows VM (a Python loop; no third-party tools) | NX-LIN-002 | 30 matched gateway connections; several flows may be flagged suspicious → standalone alerts linked to the incident | none |
| W1 | Windows | `cmd` → `powershell -ExecutionPolicy Bypass -File w1_stage.ps1` → writes `C:\Lab\staging\report.zip` → `Invoke-WebRequest` to Linux VM `:8080` | NX-WIN-001 | matched; gap `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS` shown | manual terminate (denied) |
| W2 | Windows | `C:\Lab\bin\eicar.com` is **created** (Sysmon 11) and a copy of `C:\Lab\bin\lab-test.exe` (a renamed harmless console app) is executed | NX-WIN-002 (+ NX-ANY-001 on the EICAR hash if executed via a wrapper) | none required | **automatic terminate** |
| N1 | Network-only | Windows VM opens many connections to the Linux VM's closed ports from a script that NEXUS rules do not cover (temporarily disable NX-WIN-003) | none | ML standalone network alerts — proves the network path works without the host | manual gateway block of the source, then unblock |

Run order for the final demo: L1 (story), W1 (cross-OS parity + gaps), L2 (automatic response), N1 (network-only + gateway block), L3 (threshold rule + many matches). Keep W2 as backup.

Benign noise generator (`noise.sh` / `noise.ps1`): loops of `ls`/`dir`, `grep`/`Select-String`, file copies and deletes in a work folder (`noise.ps1`: `C:\Lab\noise`, or `-WorkDir $env:TEMP\nexus-noise` for extra lab realism), HTTP GETs to the other VM's web server, an occasional DNS lookup of `noise.nexus.test`, every 2–10 s, for the duration of an evaluation run. Expected: zero incidents.

`noise.ps1` (Windows PowerShell 5.1, unelevated, **not yet run on a real Windows machine**) writes `C:\Lab\manifests\NOISE-<start>.json` with `start_utc`, `end_utc`, `expected_incidents: 0` and counters, so `nexus-eval noise --window START END` can use it. It avoids `-ExecutionPolicy Bypass`, `-enc`, `C:\Lab\staging`, `C:\Lab\bin` and many-port connections so NX-WIN-001/002/003 stay quiet. Run: `Unblock-File C:\Lab\scenarios\noise.ps1; powershell -NoProfile -ExecutionPolicy RemoteSigned -File C:\Lab\scenarios\noise.ps1 -Minutes 60`. `noise.sh` still lacks the window manifest; Omar adds it in the same format.

## W1 on the laptop (dev Sysmon profile)
Only for adapter development; evaluation numbers still come from the lab VM. After the verification matrix in `lab/sysmon/README.md` has passed:
1. Copy `w1_stage.ps1` to `C:\Lab\scenarios\` and put any harmless file in `C:\Lab\protected\`.
2. Start a receiver whose command line mentions the lab folder (so the dev profile logs it): `python -m http.server 8080 --bind <your LAN IP> --directory C:\Lab\receiver`. If Windows Firewall asks, prefer Cancel; allow only for the Private profile and only temporarily if the connection fails.
3. `$env:NEXUS_TARGET = '<your LAN IP>'` then `cmd /c powershell -ExecutionPolicy Bypass -File C:\Lab\scenarios\w1_stage.ps1`.

Use your LAN IP, not `127.0.0.1`: the dev profile excludes loopback and NX-WIN-001 ignores `127.0.0.0/8`. Use a port other than 80 or 443. Expect a medium-confidence incident with a `PARENT_NOT_OBSERVED` gap, because the parent of `cmd` (your terminal) was never logged by EID 1 and is a placeholder. The python receiver is a separate process and not part of the W1 incident.
