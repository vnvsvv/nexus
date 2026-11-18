# NEXUS — Lab Setup (VirtualBox)

## 1. VMs

| VM | OS | vCPU | RAM | Disk | NICs |
|---|---|---|---|---|---|
| `nexus-gw` | Ubuntu Server 24.04 LTS | 2 | 3 GB | 25 GB | NIC1 NAT (`ens-ext`), NIC2 Internal `nexus-lin` (`ens-lin`), NIC3 Internal `nexus-win` (`ens-win`), NIC4 Host-only (`ens-mgmt`) |
| `linux-vm-01` | Ubuntu Desktop or Server 24.04 | 2 | 2 GB | 20 GB | NIC1 Internal `nexus-lin` |
| `windows-vm-01` | Windows 11 Enterprise Evaluation (90 days) | 2 | 4 GB | 50 GB | NIC1 Internal `nexus-win` |

Total ≈ 9 GB RAM → fits a 16 GB host. Enable nested paging/VT-x in BIOS. After Week 1, `File → Export Appliance` each VM to OVA and copy to the second lab laptop.

Scripted creation (optional, run on the host):
```bash
VBoxManage modifyvm nexus-gw --nic1 nat --nic2 intnet --intnet2 nexus-lin --nic3 intnet --intnet3 nexus-win --nic4 hostonly --hostonlyadapter4 vboxnet0
VBoxManage modifyvm linux-vm-01 --nic1 intnet --intnet1 nexus-lin
VBoxManage modifyvm windows-vm-01 --nic1 intnet --intnet1 nexus-win
```
Host-only network `vboxnet0` = 192.168.56.0/24 (VirtualBox default).

## 2. Addressing

| Host | Interface | Address | Gateway | DNS |
|---|---|---|---|---|
| nexus-gw | ens-lin | 192.168.10.1/24 | — | — |
| nexus-gw | ens-win | 192.168.20.1/24 | — | — |
| nexus-gw | ens-mgmt | 192.168.56.10/24 | — | — |
| nexus-gw | ens-ext | DHCP (NAT) | VirtualBox NAT | upstream |
| linux-vm-01 | ens | 192.168.10.10/24 | 192.168.10.1 | 192.168.10.1 |
| windows-vm-01 | Ethernet | 192.168.20.10/24 | 192.168.20.1 | 192.168.20.1 |

`/etc/hosts` and `C:\Windows\System32\drivers\etc\hosts`: `nexus-server` → the gateway address on that host's subnet.

Interface naming on the gateway: either accept the predictable names (`enp0s3`, `enp0s8`, `enp0s9`, `enp0s10`) and pass them to `gateway-setup.sh` via `IF_EXT=enp0s3 IF_LIN=enp0s8 IF_WIN=enp0s9 IF_MGMT=enp0s10`, or create `/etc/systemd/network/10-*.link` files to rename by MAC. The docs use the logical names.

## 3. Steps (Day 1–3)
1. Install the gateway OS; attach the 4 NICs; run `lab/gateway/gateway-setup.sh` as root with the `IF_*` variables.
2. Install `linux-vm-01`; set the static IP (netplan); `sudo apt install chrony curl python3-pip`; point chrony at 192.168.10.1 (`server 192.168.10.1 iburst` in `/etc/chrony/sources.d/nexus.sources`); create `/lab/{protected,staging,bin,scenarios,manifests}`; `echo "TOP SECRET LAB DATA" | sudo tee /lab/protected/confidential.txt`; install Tetragon per `lab/tetragon-policies/README.md`.
3. Install `windows-vm-01` from the evaluation ISO; static IP; `w32tm` to 192.168.20.1; create `C:\Lab\{protected,staging,bin,scenarios,manifests}`; Sysmon **lab profile** per `lab/sysmon/README.md` §4 (never the dev profile here, never the lab profile on a laptop); Defender exclusion for `C:\Lab` on this VM only; `python` (from python.org) for the `http.server` receiver.
4. Verify routing: from Linux `curl -m 3 http://192.168.20.10:8443/` with `python -m http.server 8443` running on Windows (Windows Firewall: allow inbound 8443/8080 for the lab profile). On the gateway: `conntrack -E -e NEW -o timestamp` shows the connection; `nft list set inet nexus nexus_block_dst` exists.
5. Verify time: `chronyc tracking` on Linux (offset < 10 ms); `w32tm /query /status` on Windows.
6. Snapshot all three VMs: `lab-base`.

## 4. Week-1 timing experiment (sets `MATCH_TOLERANCE_SECONDS`)
On the gateway, record `conntrack -E -e NEW -o timestamp` to a file. On the Linux VM, run `lab/scenarios/l3_many_ports.py` (30 connections) and note Tetragon `tcp_connect` timestamps for the same tuples. Compute `Δ = gateway − host` per tuple. Set `T = max(2.0, 3 × max|Δ|)` in `server/.env`. Expected |Δ| is milliseconds; if it is seconds, time sync is broken — fix before continuing.

## 5. Verified (fill in during Week 1)
| Check | Result | Date | By |
|---|---|---|---|
| Tetragon `tcp_connect` sport non-zero | | | |
| Tetragon file reads/writes under `/lab/protected` visible | | | |
| `exec_id` consistent exec vs kprobe (issue #4349) | | | |
| Sysmon EID 3 includes `Initiated`, 5-tuple, ProcessGuid | | | |
| Sysmon EID 11 for `C:\Lab\staging\*` | | | |
| Sysmon EID 26 for a deleted `C:\Lab\` file; EID 23 absent | | | |
| No Sysmon EID 3 to 192.168.20.1 while the agent posts; no EID 22 for `nexus-server`; no EID 11 for `C:\Lab\manifests\*` | | | |
| Sysmon EID 3 with `Initiated=false`: which address is local (open question O1) | Not determinable on the dev laptop (both ends were the same host); needs a cross-host run on the lab VMs | | |
| Dev Sysmon config loaded by a real Sysmon; header says `VALIDATED YYYY-MM-DD` | Loaded; matrix passed with limits (N1 partial, no reboot test): `lab/sysmon/README.md` §3.3 | 2026-11-18 | Anas |
| Lab Sysmon config (`nexus-sysmon.xml`) loaded on `windows-vm-01`; `UNVALIDATED` replaced by `VALIDATED YYYY-MM-DD` | | | |
| conntrack NEW within 50 ms of host connect | | | |
| NFStream flow emitted ≤ 20 s after connection end (idle 15) | | | |
| `nf-lite-1` direction convention confirmed | | | |
| `T` measured | | | |
