# NEXUS Rule Format v1

YAML, one rule per file, in `contracts/rules/`. Loaded by `nexus_endpoint_core.rules`. Validated on load; a rule that fails validation is rejected and logged, not silently ignored.

## Top level

```yaml
id: NX-LIN-001                 # unique; prefix NX-LIN / NX-WIN / NX-ANY
version: "1.0"
title: Interpreter spawns shell, reads protected file, connects out
kind: sequence                 # single | sequence | threshold
os: [linux]                    # linux, windows, or both
severity: high                 # low | medium | high | critical
technique_ids: [T1059.004, T1005, T1041]
references:                    # optional; cite ported Sigma/Elastic rules
  - "sigma: proc_creation_lnx_susp_shell_from_script_interpreter (ported logic)"
window_seconds: 60             # all bound events must fall within this span
ordered: true                  # sequence only: steps must occur in listed order
context:
  max_ancestors: 3             # how far above the earliest matched process the root may be
  max_descendant_depth: 3
  incident_window_seconds: 120 # how long the incident stays open for new evidence
steps: [...]                   # sequence/single
threshold: {...}               # threshold only
response:                      # optional
  action: terminate_process    # closed set: terminate_process
  target_step: shell           # which bound step's process is the target
```

## Steps (sequence; `single` has exactly one step)

```yaml
steps:
  - step: interp
    event_type: process_start
    where:
      binary: { endswith_any: ["/python3", "/python3.12", "/perl", "/node"] }
  - step: shell
    event_type: process_start
    where:
      binary: { endswith_any: ["/bash", "/sh", "/dash", "/zsh"] }
    lineage: { relation: descendant_of, of: interp, max_depth: 2 }
  - step: read
    event_type: file_access
    where:
      file.operation: { equals: read }
      file.path: { prefix_any: ["/lab/protected/"] }
    lineage: { relation: descendant_of, of: shell, max_depth: 2, include_self: true }
  - step: net
    event_type: network_connect
    where:
      network.direction: { equals: outbound }
      network.dst_ip: { not_in_cidr: ["127.0.0.0/8", "::1/128"] }
    lineage: { relation: descendant_of, of: shell, max_depth: 2, include_self: true }
```

`lineage.relation` ∈ `same` (same process as step `of`), `child_of`, `descendant_of` (with `max_depth`, `include_self`). Lineage is evaluated on the endpoint process graph using `process_instance_id` and `PARENT_OF` edges; placeholder nodes count, but a path through a placeholder lowers incident `confidence` to `medium` and records `IDENTITY_INFERRED`.

## Predicates (closed set)

| Operator | Applies to | Semantics |
|---|---|---|
| `equals` | any scalar | exact match (strings case-insensitive on Windows, case-sensitive on Linux) |
| `in` | scalar | value in list |
| `prefix_any` | string | starts with any (path normalization: backslash→slash on Windows, lowercase on Windows) |
| `endswith_any` | string | ends with any |
| `contains_any` | string | substring match |
| `regex` | string | Python `re.search`, compiled once |
| `in_cidr` / `not_in_cidr` | IP string | `ipaddress` membership |
| `gte` / `lte` | number | numeric compare |

Field paths: `binary`, `command_line`, `user`, `sha256`, `file.path`, `file.operation`, `network.protocol`, `network.src_port`, `network.dst_ip`, `network.dst_port`, `network.direction`, `dns.query`, `attributes.<key>`.

## Threshold rules

```yaml
kind: threshold
threshold:
  event_type: network_connect
  where: { network.direction: { equals: outbound } }
  scope: process            # process | lineage(max_depth)
  distinct_field: network.dst_port
  group_by: network.dst_ip  # optional; count distinct per group
  min_distinct: 15
  window_seconds: 10
```
Fires once per `(rule, process)` per `incident_window_seconds`; all contributing events become `matched` evidence.

## Response block

Only `terminate_process` exists in v1. The endpoint policy gate (allowlist, protected PIDs/binaries, dry-run) is always applied; a rule cannot bypass it. The rule only *requests*.

## Testing a rule

Every rule file must have a sibling fixture `contracts/fixtures/rules/<rule_id>.events.jsonl` and `.expect.json` (expected: fires yes/no, bound step→event ids). `python tools/validate_fixtures.py` runs them through `nexus_endpoint_core` when it is installed, and only schema-validates when it is not.
