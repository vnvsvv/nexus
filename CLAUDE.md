# AGENTS.md — rules for every AI coding agent working in this repository

You are implementing one component of NEXUS, a four-person cybersecurity graduation project with a six-week deadline. Read, in this order, before writing code:
1. `docs/01-ARCHITECTURE.md` (what the system is and which component you own)
2. `contracts/README.md` and the schemas/fixtures it points to
3. `docs/02-CORRELATION.md` if you touch endpoint-core or server/correlator; `contracts/flow-features.md` if you touch ml or server/flow_service
4. Your prompt in `prompts/`

## Non-negotiable rules
- **Contracts are imported, not re-typed.** Use `nexus_contracts` models and `contracts/schemas/*.json`. Never define a parallel dataclass/TypedDict/TS interface for a contract object. If a field is missing, stop and write a note `CONTRACT-CHANGE-REQUEST.md` in your package describing the field and why; do not add it locally.
- **Fixtures are acceptance tests.** Your package must have tests that load `contracts/fixtures/*` and prove your side of the interface. `python tools/validate_fixtures.py` must pass.
- **Simplest working implementation.** No plugins frameworks, no abstract base classes for one implementation, no message brokers, no ORMs beyond what the prompt names. Mark optional ideas `TODO(stretch)` and move on.
- **Safety.** Response code must go through `nexus_endpoint_core.response.allowed()` (or the gateway equivalent). Default `dry_run=true`. Never execute shell strings from network input. Never kill PID ≤ 4, the agent itself, or anything outside the allowlist.
- **Honesty in data.** Set `basis: inferred` and add `gaps[]` whenever something is not directly observed. Never invent a parent, a match, or a technique.
- **Timestamps** UTC ISO-8601 with milliseconds and `Z`. **Serialize with `exclude_none=True`.**
- **Python**: 3.11+, type hints, `ruff`/`black` defaults, `pydantic` v2, `logging` (JSON lines), configuration via environment variables documented in `.env.example`, `pytest`. One process per service; no threads for logic (asyncio or a simple loop), threads only for blocking I/O readers.
- **TypeScript** (dashboard): strict mode, types generated from `contracts/openapi.yaml` via `openapi-typescript`; no `any`.
- **Tests before features**: each PR adds or updates tests; CI runs `tools/validate_fixtures.py` and `pytest`.
- **Document as you go**: each package `README.md` has "run", "test with fixtures", "run against mock server", "run in the lab".
- **Do not touch other packages.** If you need something from another package, write it as a request in `STATUS.md` under your name.
- **Commit small, describe precisely.** Conventional commit style: `feat(endpoint-linux): tcp_connect normalization`, `fix(server): pending retry on registry insert`.
- Versions pinned in `requirements.txt` / `package.json`.

## Useful commands
```bash
pip install -e .                               # nexus_contracts
python tools/validate_fixtures.py              # contract gate
python tools/mock_server.py --port 8000        # API mock with fixture data; token "devtoken"
python tools/generate_fixtures.py              # only when contracts change (keeper: Anas)
```
