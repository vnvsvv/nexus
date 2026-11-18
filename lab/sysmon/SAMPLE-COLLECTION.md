# Collecting and committing Sysmon XML samples (public repository)

The repository is **public**. Anything committed is public permanently, including in git history and in
forks. A raw Sysmon event contains more than a user name: computer name, user name and SID, full paths
(which may include a OneDrive folder or a university name), command lines, LAN and public IP addresses,
host names, process GUIDs derived from the machine, hashes and exact timestamps.

This replaces the earlier instruction "save real ones from your laptop, redact nothing sensitive beyond
the username". That instruction was wrong for a public repository.

## Rules
1. **Prefer the lab VM.** `windows-vm-01` is a clean disposable machine; samples committed to the repo
   should come from it. Laptop captures are for local development and stay in the private folder (rule 3)
   unless there is a specific reason to commit one.
2. **Capture scripted activity only**, with the matching profile installed: W1, the probes in
   `README.md` §3.1, or `noise.ps1` for a short run. Never capture while doing anything else on the machine.
3. **Raw exports live outside the repository** and outside any synced folder (not OneDrive, not Dropbox),
   for example `C:\dev-private\nexus-samples-raw\`. `*.evtx` files must never exist inside the repo folder;
   `.gitignore` and `tools/check_samples.py` both enforce this.
4. **Scrub, then check, then read, then review.** All four, every time.
5. Commit only through a pull request that a teammate has looked at, and stage by path
   (`git add endpoint-windows/tests/samples/`), never `git add .` or `git add -A`.

## Step 1: export only the scenario window
Take `start_utc` and `end_utc` from the scenario manifest in `C:\Lab\manifests\`, widen by a few seconds, and
export just that window:
```powershell
$start = [DateTimeOffset]::Parse('2026-11-20T10:00:00Z').LocalDateTime
$end   = [DateTimeOffset]::Parse('2026-11-20T10:01:00Z').LocalDateTime
$out   = 'C:\dev-private\nexus-samples-raw'
New-Item -ItemType Directory -Force $out | Out-Null
$i = 0
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start; EndTime=$end } |
  Sort-Object TimeCreated | ForEach-Object {
    $i++
    $_.ToXml() | Set-Content -Encoding UTF8 -Path (Join-Path $out ('raw-{0:000}-eid{1}.xml' -f $i, $_.Id))
  }
```
Keep one event per file. Keep only EID 1, 3, 5, 11, 22, 26 (delete the others); never export the whole log.

## Step 2: scrub
```powershell
python tools\scrub_samples.py C:\dev-private\nexus-samples-raw endpoint-windows\tests\samples `
  --computer <your computer name> --user <your Windows user name> `
  --map <your LAN IP>=192.168.20.10 --map "<your OneDrive folder name>=Documents"
```
(Use `--computer-as windows-vm-01 --user-as labuser` for lab-VM captures.) The scrubber replaces the computer
name, user name, every real SID, and consistently maps `ProcessGuid`, `ParentProcessGuid` and `LogonGuid` to
`{5eed0000-0000-0000-0000-0000000000NN}` so parent/child links survive, and renames files to
`eid<N>-<index>.xml`. It is a helper, not a guarantee.

## Step 3: automated check (fails closed)
Create a private deny-list **outside the repo**: one string per line, containing exactly the things that
must never appear: your real user name, computer name, e-mail address, university or OneDrive folder name,
home-network SSID or IP. Then:
```powershell
python tools\check_samples.py --deny-file C:\dev-private\deny.txt
```
CI runs the same script without the deny-list, so the allowlist rules are enforced for everyone:

| Allowed | Everything else is an error |
|---|---|
| Computer `dev-laptop` or `windows-vm-01`; user `dev-laptop\dev`, `windows-vm-01\labuser`, `NT AUTHORITY\...` | any real name |
| SIDs `S-1-5-18` and `S-1-5-21-1000-1000-1000-1001` | any other SID |
| GUID fields of the form `{5eed0000-0000-0000-0000-xxxxxxxxxxxx}` | real GUIDs (the public Sysmon provider GUID is the one exception) |
| IPv4 in `127.0.0.0/8`, `192.168.10.0/24`, `192.168.20.0/24` | any other address, any non-loopback IPv6 |
| `C:\Users\dev\`, `Public`, `labuser`, `Default`, `Administrator` | any other profile path; any `OneDrive` path |
| Command lines that mention `C:\Lab\`, contain `NEXUS_TEST`, or are a bare system `.exe` | anything else (it may hold tokens or personal data) |
| DNS names under `.nexus.test`, `nexus-server`, lab host names | any other name |
| Files ending `.xml`, `.json`, `.md` | `.evtx`, `.csv`, screenshots, archives |

## Step 4: read every file
Open each scrubbed file and look at these fields by eye: `CommandLine`, `ParentCommandLine`,
`CurrentDirectory`, `Image`, `TargetFilename`, `QueryName`, `QueryResults`, `User`, `Hashes`. The checker
catches patterns, not meaning: a command line that mentions `C:\Lab\` can still carry a password on the
same line. Look at the timestamps too; they show when you work. If the dates matter to you, shift them
(consistently) before committing; the tests use relative timing.

## Step 5: expected-output files
For each XML sample, the adapter test has an expected `HostEvent` JSON next to it
(`eid1-001.expected.json`). Generate it from the scrubbed XML, never from the raw one, and run
`python tools\check_samples.py` again, because the JSON is checked by the same rules.

## If something private is committed
Deleting the file in a new commit does not remove it from history. Tell the team immediately. Because this
repository is new, the cleanest fix is to rewrite history before anyone builds on it (`git filter-repo`), or
delete and recreate the repository; also treat anything secret in it (tokens, passwords) as compromised and
rotate it. GitHub may keep cached views of pull-request commits until support purges them.
