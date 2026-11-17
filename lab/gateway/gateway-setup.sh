#!/usr/bin/env bash
# NEXUS gateway VM bootstrap (Ubuntu 24.04). Run once as root after the VM has its 4 NICs.
# Interfaces are renamed by lab/gateway/10-nexus-ifnames.link-style udev rules or set here by MAC; adjust the names below.
set -euo pipefail

IF_LIN=${IF_LIN:-ens-lin}    # internal net nexus-lin  192.168.10.1/24
IF_WIN=${IF_WIN:-ens-win}    # internal net nexus-win  192.168.20.1/24
IF_EXT=${IF_EXT:-ens-ext}    # NAT adapter (internet)
IF_MGMT=${IF_MGMT:-ens-mgmt} # host-only 192.168.56.10/24

apt-get update
apt-get install -y conntrack nftables chrony dnsmasq postgresql-16 python3.12-venv python3-pip libpcap0.8 git jq

# ---- addressing (netplan) ----
cat >/etc/netplan/60-nexus.yaml <<EOF
network:
  version: 2
  ethernets:
    ${IF_LIN}:  { addresses: [192.168.10.1/24] }
    ${IF_WIN}:  { addresses: [192.168.20.1/24] }
    ${IF_MGMT}: { addresses: [192.168.56.10/24] }
    ${IF_EXT}:  { dhcp4: true }
EOF
netplan apply

# ---- routing ----
cat >/etc/sysctl.d/90-nexus.conf <<EOF
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_timestamp = 1
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
EOF
sysctl --system

# ---- nftables: forward only between the two internal nets and to the internet; NAT only on ext ----
cat >/etc/nftables.conf <<EOF
flush ruleset
table inet nexus {
  set nexus_block_dst { type ipv4_addr . inet_proto . inet_service; flags timeout; }
  set nexus_block_src { type ipv4_addr; flags timeout; }
  chain input   { type filter hook input priority 0; policy accept; }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ip saddr @nexus_block_src drop
    ip daddr . ip protocol . th dport @nexus_block_dst drop
    iifname "${IF_LIN}" oifname "${IF_WIN}" accept
    iifname "${IF_WIN}" oifname "${IF_LIN}" accept
    iifname { "${IF_LIN}", "${IF_WIN}" } oifname "${IF_EXT}" accept
  }
  chain postrouting { type nat hook postrouting priority 100; oifname "${IF_EXT}" masquerade; }
}
EOF
systemctl enable --now nftables
nft -f /etc/nftables.conf

# ---- time: gateway is the lab NTP server ----
cat >>/etc/chrony/chrony.conf <<EOF
allow 192.168.10.0/24
allow 192.168.20.0/24
local stratum 8
EOF
systemctl restart chrony

# ---- DNS for the lab (forwarder; can be disabled for fully isolated runs) ----
cat >/etc/dnsmasq.d/nexus.conf <<EOF
interface=${IF_LIN}
interface=${IF_WIN}
bind-interfaces
address=/nexus-server/192.168.10.1
EOF
systemctl restart dnsmasq

# ---- PostgreSQL ----
sudo -u postgres psql -c "CREATE USER nexus WITH PASSWORD 'nexus';" || true
sudo -u postgres psql -c "CREATE DATABASE nexus OWNER nexus;" || true

# ---- NEXUS server venv ----
mkdir -p /opt/nexus && python3 -m venv /opt/nexus/venv
/opt/nexus/venv/bin/pip install -U pip wheel
echo "Gateway base ready. Install server/ with: /opt/nexus/venv/bin/pip install -e /opt/nexus/repo/server"
echo "Verify: sysctl net.ipv4.ip_forward ; nft list ruleset ; conntrack -E -e NEW -o timestamp (then ping across subnets)"
