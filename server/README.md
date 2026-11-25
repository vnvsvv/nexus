# server/ — NEXUS gateway server (owner: Rakan)

Spec: `prompts/RAKAN-gateway-server.md`, `docs/02-CORRELATION.md` §5–6, `contracts/openapi.yaml`.

This is the skeleton only. Every module states its job and its roadmap step; none is implemented yet.

## Layout

| File | Job | Process | Roadmap |
|---|---|---|---|
| `config.py` | env vars + JSON-lines logging | all | R2 |
| `db.py` | 11 tables (SQLAlchemy Core), indexes, `create_all` | all | R2 |
| `manage.py` | `init-db`, `gen-token` | admin CLI | R2, R3 |
| `api.py` | FastAPI for `openapi.yaml`, auth, SSE, incident view | `nexus-api` | R3 |
| `gen_cert.sh` | self-signed TLS cert into `lab/pki/` | admin CLI | R3 |
| `registry.py` | conntrack parser + `conntrack -E` loop | `nexus-registry` | R4 |
| `correlator.py` | `correlate()`, pending retry, `pin()` | `nexus-correlator` | R5 (Gate G1) |
| `flows.py` | NFStream, ML, flow linking, network alerts | `nexus-flows` | R6 |
| `ti.py` | TI feeds, `enrich()`, VirusTotal cache | `nexus-ti` | R7 |
| `response.py` | gateway command worker, `nft` argv builder | `nexus-response` | R8 |
| `systemd/` | one unit per process (6) | | R9 |
| `tests/` | one test file per module | | each step |

## Processes

Six small processes, one per component in `docs/01-ARCHITECTURE.md` §2.5 (AGENTS.md: "one process per service"). They share one PostgreSQL database and nothing else: no broker, no shared memory.

| Process | Wakes on | Linux privileges |
|---|---|---|
| `nexus-api` | HTTP requests | none |
| `nexus-registry` | conntrack events | `CAP_NET_ADMIN` |
| `nexus-flows` | captured packets | `CAP_NET_RAW`, `CAP_NET_ADMIN` |
| `nexus-correlator` | NOTIFY (incident stored, connection inserted) + 60 s timer | none |
| `nexus-ti` | NOTIFY (incident stored) + feed refresh timer | none (outbound internet only) |
| `nexus-response` | NOTIFY (command queued) + short poll | `CAP_NET_ADMIN` only |

Rules that keep this simple and recoverable:
1. **PostgreSQL is the queue.** Work is found by querying tables (`pending` correlations, unenriched incidents, `queued` gateway commands). `LISTEN/NOTIFY` only wakes a worker early; a lost notification is caught by the next sweep.
2. **Every worker sweeps on start-up**, so a crash or restart of any process loses no work. systemd restarts a failed process (`Restart=on-failure`).
3. **Writes are idempotent**, so re-running an item after a crash cannot duplicate results.
4. **One bad item never stops a loop**: it is logged and left for the next sweep.
5. **Least privilege:** the network-facing API has no capabilities. Only `nexus-response` can change nftables, and it re-validates every command, defaults to `dry_run=true`, and runs `nft` with fixed argument lists, never a shell string. Endpoint commands are never executed on the gateway; agents poll them.

## Run
TODO (R3+).

## Test with fixtures
TODO (R2): `pytest -q server/tests` with `NEXUS_TEST_DB_URL` pointing at a dedicated test database.

## Run against mock server
TODO (R3+).

## Run in the lab
TODO (R9).
