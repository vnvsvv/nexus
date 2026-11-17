# NEXUS — Endpoint Detection, Threat Intelligence, and Semi-Automated Response

## 1. Endpoint detection

### 1.1 Philosophy
Rules exist to **trigger reconstruction**, not to be a complete detection catalogue. Six to ten well-tested rules that fire on the scripted scenarios and stay silent on benign noise beat sixty untested ones. Every rule carries the ATT&CK technique IDs it justifies; the incident builder never adds techniques on its own.

### 1.2 Sources
- **Custom NEXUS rules** (in `contracts/rules/*.yaml`) written for the lab scenarios.
- **Hand-ported** rules from SigmaHQ and Elastic detection-rules (cite the original rule ID in `references`). Only the logic is ported; the Sigma format is not executed. Candidates: "Shell spawned by scripting interpreter", "PowerShell with encoded command / execution policy bypass", "Suspicious outbound from script host", "Many distinct destination ports from one process" (scan behavior), "Executable written to user-writable path then executed".

### 1.3 Starter rule set (v1)

| ID | Kind | OS | Trigger | Techniques | Response |
|---|---|---|---|---|---|
| NX-LIN-001 | sequence | linux | interpreter → shell descendant → read under `/lab/protected/` → outbound connect | T1059.004, T1005, T1041 | none (manual) |
| NX-LIN-002 | threshold | linux | one process opens ≥ 15 distinct dst ports on one host within 10 s | T1046 | none |
| NX-LIN-003 | sequence | linux | binary under `/lab/bin/` executed → outbound connect to non-gateway IP | T1204, T1071 | `terminate_process` (allowlisted) |
| NX-WIN-001 | sequence | windows | cmd/explorer → powershell with `-enc`/`-ExecutionPolicy Bypass` → file created under `C:\Lab\staging\` → outbound connect | T1059.001, T1074.001, T1105 | none (manual) |
| NX-WIN-002 | single | windows | process with image under `C:\Lab\bin\` starts | T1204.002 | `terminate_process` (allowlisted) |
| NX-WIN-003 | threshold | windows | one process ≥ 15 distinct dst ports within 10 s | T1046 | none |
| NX-ANY-001 | single | both | process start whose SHA-256 is in the local TI hash table (agent-local copy of the feed) | T1204 | none |

All rule IDs are also the `rule_ids` referenced by the fixtures and the evaluation manifests.

### 1.4 Telemetry coverage matrix (write this into the report)

| Event | Linux (Tetragon) | Windows (Sysmon) |
|---|---|---|
| process start/exit | base exec/exit events, `exec_id` | EID 1 / 5, `ProcessGuid` |
| file read | `security_file_permission` kprobe (MAY_READ) on watched prefixes | **not available** → gap recorded; stretch: SACL + Security 4663 |
| file create/write/delete | same kprobe (MAY_WRITE) / stretch: `security_path_unlink` | EID 11 (create), 23/26 (delete) |
| TCP connect (outbound) | `tcp_connect` kprobe with `sock` arg (5-tuple) | EID 3 `Initiated=true` |
| TCP accept (inbound) | stretch: `inet_csk_accept` kretprobe | EID 3 `Initiated=false` |
| UDP | stretch | EID 3 (udp) |
| DNS query | not in v1 | EID 22 |
| binary hash | computed by agent | EID 1 `Hashes=SHA256` |

## 2. Threat intelligence

### 2.1 Role
Enrichment, not detection: TI adds tags and context to evidence already in an incident. One exception, by design: `NX-ANY-001` uses an agent-local hash list so a *known* bad file can trigger an incident even without behavior — this demonstrates TI feeding detection.

### 2.2 Sources (free, lab-friendly)
| Source | Indicator | How used |
|---|---|---|
| abuse.ch MalwareBazaar (full SHA-256 export) | file hash | loaded into `ti_indicators`; exported daily to endpoints as a compact hash list (`/api/v1/ti/hashes`) |
| abuse.ch Feodo Tracker | IP | `ti_indicators` |
| abuse.ch URLhaus | URL/domain | `ti_indicators` (matched against EID 22 DNS queries) |
| VirusTotal API v3 (`GET /files/{sha256}`) | file hash | on-demand, persistent cache, token bucket 4 req/min, daily cap 500; never called for hashes already cached |
| Lab indicator file (`lab/ti/lab-indicators.csv`) | IP:port, hash | clearly tagged `lab-test`; exists so enrichment is visible in an isolated network |

### 2.3 Flow
Incident upsert → `ti_service` extracts indicators (process `sha256`, `dst_ip`, DNS `query`) → local table lookup (ms) → VT lookup for *new* hashes only (async) → `incident.enrichment[]` entries `{indicator_type, value, source, verdict, tags, fetched_utc}` → SSE `incident.updated`. The demo uses the EICAR test file (`C:\Lab\bin\eicar.com`, `/lab/bin/eicar.com`) which every vendor flags and which is harmless.

## 3. Semi-automated response

### 3.1 Decision model
| Trigger | Decided by | Executed by | Conditions |
|---|---|---|---|
| Rule with `response.action: terminate_process` | endpoint agent, locally, immediately | endpoint `ResponseExecutor` | target binary matches agent allowlist; PID not protected; `agent.dry_run=false`; rule severity ≥ high |
| Analyst clicks "Terminate" on the dashboard | human | endpoint (via command queue) | confirm dialog; allowlist still enforced on the endpoint; audited |
| Analyst clicks "Block connection/destination" | human | gateway `response_controller` → nftables set `nexus_block` (timeout 10 min default) | confirm dialog; never automatic in v1 |
| Unblock / re-enable | human | gateway | audited |

### 3.2 Safety gate (identical on both OSes, in `nexus_endpoint_core.response`)
```python
def allowed(target: ProcessNode, cfg) -> tuple[bool, str]:
    if target.pid in cfg.protected_pids or target.pid <= 4: return False, "protected pid"
    if target.binary.lower() in cfg.protected_binaries: return False, "protected binary"   # agent, init, explorer, svchost, sshd...
    if not any(fnmatch(target.binary, p) for p in cfg.allowlist): return False, "not allowlisted"
    if target.end_time_utc is not None: return False, "already exited"
    return True, "ok"
```
Default config ships with `dry_run: true`. Dry-run produces a `ResponseResult(status="dry_run")` so the whole path is testable without killing anything.

### 3.3 Audit
Every action, automatic or manual, produces a `ResponseResult` with `command_id`, `executed_utc`, `status ∈ {executed, dry_run, denied, failed}`, `detail` (reason, pid, binary, exit status). Results are posted to the server and shown in the incident's response history and in the global Response page. Nothing executes arbitrary commands: the command schema is a closed enum of actions with typed parameters.

### 3.4 Not in v1
File quarantine, host isolation, automatic gateway blocking from ML or TI, Tetragon enforcement (stretch), user-session actions.
