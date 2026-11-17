# Tetragon on the Linux endpoint

Install (Ubuntu 24.04, kernel ≥ 5.15 with BTF — check `ls /sys/kernel/btf/vmlinux`):

```bash
# Option A (recommended for a VM): systemd install from the release tarball
TV=$(curl -s https://api.github.com/repos/cilium/tetragon/releases/latest | jq -r .tag_name)
curl -L https://github.com/cilium/tetragon/releases/download/${TV}/tetragon-${TV#v}-amd64.tar.gz | tar xz
cd tetragon-*-amd64 && sudo ./install.sh          # installs /usr/local/bin/tetragon + tetra, systemd unit
sudo mkdir -p /etc/tetragon/tetragon.tp.d
sudo cp /opt/nexus/repo/lab/tetragon-policies/*.yaml /etc/tetragon/tetragon.tp.d/
# JSON export to a file the adapter tails (also available over gRPC on unix socket):
sudo mkdir -p /var/log/tetragon
echo 'export-filename: /var/log/tetragon/tetragon.log' | sudo tee -a /etc/tetragon/tetragon.conf.d/export-filename
sudo systemctl restart tetragon
sudo tetra getevents -o compact        # sanity: run `curl http://192.168.20.10:8443` and see "connect" lines
```

Expectations to verify in Week 1 (write the results into `docs/08-LAB-SETUP.md` §Verified):
1. `process_exec` events carry `process.exec_id`, `process.parent_exec_id`, `process.start_time`, `process.binary`, `process.arguments`.
2. `process_kprobe` events for `tcp_connect` carry the socket arg with `saddr/daddr/sport/dport/protocol`. Check whether `sport` is non-zero at `tcp_connect` time on your kernel; if it is zero, switch the hook to `tcp_finish_connect` or read sport from `/proc/<pid>/net/tcp` in the adapter.
3. `process_kprobe` events for `security_file_permission` carry the path; confirm that reads via `cat` appear and that writes via `>` appear.
4. Compare `exec_id` in `process_exec` and in `process_kprobe` for the same PID (upstream issue #4349) — keep the pid+start_time fallback regardless.
5. Measure event rate at idle and under the benign noise generator; it should stay below a few hundred events/minute with these policies.
