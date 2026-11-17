# Flow Feature Contract `nf-lite-1` (frozen)

One ordered vector, 24 features, produced identically by:
- `nexus_ml.features.from_dataset_row(row: dict) -> list[float]` (training; UQ NetFlow v2 CSV columns), and
- `nexus_ml.features.from_nflow(flow: nfstream.NFlow) -> list[float]` (live; gateway `flow_service`).

Both must reproduce `contracts/fixtures/flow_feature_fixture.json` exactly (`tools/validate_fixtures.py` checks it when `nexus_ml` is importable). The server refuses a model bundle whose `features.json` order or `feature_version` differs.

NFStreamer settings on the gateway: `statistical_analysis=True`, `splt_analysis=0`, `n_dissections=20`, `idle_timeout=15`, `active_timeout=60`, `accounting_mode=1` (IP size), plus the `PacketSizeBins` NFPlugin (below).

## Direction convention
Dataset `IN_*` / `DURATION_IN` / `CLIENT_TCP_FLAGS` = **client→server** = NFStream `src2dst_*`. Dataset `OUT_*` = server→client = `dst2src_*`. **[verify W1]**: inspect 20 rows of NF-UNSW-NB15-v2 with `L4_DST_PORT` 80/443 — `IN_BYTES` should be the smaller (request) side for typical HTTP flows. If reversed, swap in `features.py` only.

## Feature table

| # | Feature (vector name) | Dataset column (UQ NetFlow v2) | Live formula (NFStream `NFlow`) |
|---|---|---|---|
| 1 | `protocol` | `PROTOCOL` | `flow.protocol` |
| 2 | `l4_dst_port` | `L4_DST_PORT` | `flow.dst_port` |
| 3 | `in_bytes` | `IN_BYTES` | `flow.src2dst_bytes` |
| 4 | `out_bytes` | `OUT_BYTES` | `flow.dst2src_bytes` |
| 5 | `in_pkts` | `IN_PKTS` | `flow.src2dst_packets` |
| 6 | `out_pkts` | `OUT_PKTS` | `flow.dst2src_packets` |
| 7 | `flow_duration_ms` | `FLOW_DURATION_MILLISECONDS` | `flow.bidirectional_duration_ms` |
| 8 | `duration_in_ms` | `DURATION_IN` | `flow.src2dst_duration_ms` |
| 9 | `duration_out_ms` | `DURATION_OUT` | `flow.dst2src_duration_ms` |
| 10 | `tcp_flags` | `TCP_FLAGS` | `flags_mask(bidirectional_*_packets)` |
| 11 | `client_tcp_flags` | `CLIENT_TCP_FLAGS` | `flags_mask(src2dst_*_packets)` |
| 12 | `server_tcp_flags` | `SERVER_TCP_FLAGS` | `flags_mask(dst2src_*_packets)` |
| 13 | `longest_flow_pkt` | `LONGEST_FLOW_PKT` | `flow.bidirectional_max_ps` |
| 14 | `shortest_flow_pkt` | `SHORTEST_FLOW_PKT` | `flow.bidirectional_min_ps` |
| 15 | `mean_pkt_size` | `(IN_BYTES+OUT_BYTES)/(IN_PKTS+OUT_PKTS)` | `flow.bidirectional_mean_ps` |
| 16 | `src_to_dst_second_bytes` | `SRC_TO_DST_SECOND_BYTES` | `in_bytes / max(duration_in_ms,1)*1000` |
| 17 | `dst_to_src_second_bytes` | `DST_TO_SRC_SECOND_BYTES` | `out_bytes / max(duration_out_ms,1)*1000` |
| 18 | `src_to_dst_avg_throughput` | `SRC_TO_DST_AVG_THROUGHPUT` | `in_bytes*8 / max(flow_duration_ms,1)*1000` |
| 19 | `dst_to_src_avg_throughput` | `DST_TO_SRC_AVG_THROUGHPUT` | `out_bytes*8 / max(flow_duration_ms,1)*1000` |
| 20 | `num_pkts_up_to_128_bytes` | `NUM_PKTS_UP_TO_128_BYTES` | plugin bin `(0,128]` |
| 21 | `num_pkts_128_to_256_bytes` | `NUM_PKTS_128_TO_256_BYTES` | plugin bin `(128,256]` |
| 22 | `num_pkts_256_to_512_bytes` | `NUM_PKTS_256_TO_512_BYTES` | plugin bin `(256,512]` |
| 23 | `num_pkts_512_to_1024_bytes` | `NUM_PKTS_512_TO_1024_BYTES` | plugin bin `(512,1024]` |
| 24 | `num_pkts_1024_to_1514_bytes` | `NUM_PKTS_1024_TO_1514_BYTES` | plugin bin `(1024,1514]` |

**Important caveat on 16–19:** the dataset's rate columns are computed by nProbe and may use a different duration denominator (e.g., whole-flow seconds, or 0 when duration is 0). Bashar must check the empirical relation on 1,000 dataset rows (`IN_BYTES / FLOW_DURATION_MILLISECONDS*1000` vs `SRC_TO_DST_SECOND_BYTES`) and, if the dataset's definition cannot be reproduced, **recompute** those four columns from the base columns using the live formula *before* training so both sides use the same definition. Record the decision in `ml/reports/feature-parity.md`. **[verify W1]**

`flags_mask`: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32, ECE=64, CWR=128; a bit is set if the corresponding NFStream `*_<flag>_packets` counter > 0. This matches the dataset's "cumulative of all TCP flags" semantics (presence, not counts). **[verify W1]**: confirm on a few dataset rows that `TCP_FLAGS` values are ≤ 255 and consistent with `CLIENT|SERVER`.

## Plugin

```python
from nfstream import NFPlugin

class PacketSizeBins(NFPlugin):
    """Counts packets per IP-size bin to reproduce NUM_PKTS_* dataset columns."""
    BINS = [(0,128,"b128"),(128,256,"b256"),(256,512,"b512"),(512,1024,"b1024"),(1024,1514,"b1514")]
    def on_init(self, packet, flow):
        for _,_,n in self.BINS: setattr(flow.udps, n, 0)
        self.on_update(packet, flow)
    def on_update(self, packet, flow):
        s = packet.ip_size
        for lo,hi,n in self.BINS:
            if lo < s <= hi:
                setattr(flow.udps, n, getattr(flow.udps, n)+1); break
```

## Excluded from v1 and why
`L4_SRC_PORT` (ephemeral noise), `L7_PROTO` (nDPI numeric IDs differ by nDPI version; `application_name` stored for display only), TTL/TCP-window/retransmission/ICMP/DNS/FTP columns (not produced by NFStream without deep work). `l4_dst_port` is kept but is a known shortcut feature; the ablation in `03-ML-IDS.md` §6 quantifies its effect.

## Scope exclusions at inference
Flows where `dst_ip` is a gateway address and `dst_port ∈ {8443, 123, 53}` or `src_ip` is a gateway address are tagged `scope: gateway-internal` and not scored.
