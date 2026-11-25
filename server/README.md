# server/ — NEXUS gateway server (owner: Rakan)

Spec: `prompts/RAKAN-gateway-server.md`, `docs/02-CORRELATION.md` §5–6, `contracts/openapi.yaml`.

This is the skeleton only. Every module states its job and its roadmap step; none is implemented yet.

## Layout

| File | Job | Roadmap |
|---|---|---|
| `config.py` | env vars + JSON-lines logging | R2 |
| `db.py` | 11 tables (SQLAlchemy Core), indexes, `create_all` | R2 |
| `manage.py` | `init-db`, `gen-token` | R2, R3 |
| `api.py` | FastAPI for `openapi.yaml`, auth, SSE, incident view | R3 |
| `gen_cert.sh` | self-signed TLS cert into `lab/pki/` | R3 |
| `registry.py` | conntrack parser + `conntrack -E` loop | R4 |
| `correlator.py` | `correlate()`, pending retry, `pin()` | R5 (Gate G1) |
| `flows.py` | NFStream, ML, flow linking, network alerts | R6 |
| `ti.py` | TI feeds, `enrich()`, VirusTotal cache | R7 |
| `response.py` | command queue, `nft` argv builder | R8 |
| `systemd/` | 3 units: api, registry, flows | R9 |
| `tests/` | one test file per module | each step |

## Processes

Three processes share one PostgreSQL database:
- `nexus-api`: the API, plus the correlator, TI and response as asyncio tasks in the same process.
- `nexus-registry`: conntrack reader (needs network admin rights).
- `nexus-flows`: NFStream capture (needs raw capture rights).

The spec names five services. Correlator, TI and response run inside the API process to keep the first version simple; they can be split out later without changing their code.

## Run
TODO (R3+).

## Test with fixtures
TODO (R2): `pytest -q server/tests` with `NEXUS_TEST_DB_URL` pointing at a dedicated test database.

## Run against mock server
TODO (R3+).

## Run in the lab
TODO (R9).
