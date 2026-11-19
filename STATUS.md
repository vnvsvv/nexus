# STATUS (edit every Friday; one line per deliverable: ✅ done · 🟡 in progress · 🔴 blocked + blocker)

## Anas — contracts / endpoint-core / endpoint-windows
- 🟡 contracts frozen (I0)
- ✅ Sysmon dev profile `VALIDATED 2026-11-18` on the Windows 11 laptop (Sysmon 15.22; matrix P1–P4, N2–N5, H passed). Open: N1 browser check only partial, reboot persistence untested, cross-host `Initiated=false` direction (O1) unverified; see `lab/sysmon/README.md` §3.3
- 🟡 Sysmon lab-VM profile `nexus-sysmon.xml` still `UNVALIDATED`: load it on `windows-vm-01` and run the lab checks in `docs/08-LAB-SETUP.md` §5, then replace `UNVALIDATED` with `VALIDATED YYYY-MM-DD` in its header
- 🟡 `lab/scenarios/noise.ps1` written, **not yet run on Windows**
## Omar — endpoint-linux / lab / eval harness
- 🟡 lab VMs
- 🟡 WP1 adapter verified with exec, exit, file permission and IPv4 loopback captures. Sanitized replays are in `endpoint-linux/tests/data/`. Routed TCP and live reader recovery remain unverified.
## Rakan — server
- 🟡 gateway bootstrap
## Bashar — ml / dashboard
- 🟡 dataset study
## Requests to other members
- (name) → (name): ...
