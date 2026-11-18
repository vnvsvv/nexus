# NEXUS — Team Responsibilities, Repository, and Integration Strategy

## 1. Ownership (revised)

| Member | Owns | Also owns | Does NOT own |
|---|---|---|---|
| **Anas** | `endpoint-windows/` (Sysmon adapter, Windows response adapter) | `contracts/` (keeper), `endpoint-core/` (shared OS-agnostic library) | server, dashboard, ML |
| **Omar** | `endpoint-linux/` (Tetragon deploy + policies, Linux adapter, Linux response) | `lab/` (VM lab, OVAs, scenario scripts, ground-truth manifests), endpoint replay/evaluation harness, benign noise generator | server, ML |
| **Rakan** | `server/` (gateway networking, connection_registry, flow_service, correlator, api_service, PostgreSQL, ti_service, response_controller) | gateway configuration, server-side evaluation (matching metrics, latency), VirusTotal/abuse.ch integration | ML model, dashboard code |
| **Bashar** | `ml/` (datasets, `nf-lite-1` features, training, model bundle, `FlowClassifier`, ML evaluation) | `dashboard/` (React UI) | server internals |

Why this is balanced: each member has one component with a hard external interface (sensor, gateway, model, UI) and one supporting responsibility that makes the integration work (contracts, lab, correlation, dashboard). Nobody waits on anybody for the first two weeks.

## 2. Dependency map and how each one is cut

| Dependency | Cut by |
|---|---|
| Linux/Windows adapters → `nexus_endpoint_core` | Adapters write `HostEvent` JSONL and POST hand-built incidents to the **mock server** until the core ships (Day 10). The core is developed against `contracts/fixtures/*.jsonl`, so it does not need the adapters either. |
| Agents → server API | `tools/mock_server.py` implements the agent-facing API with validation from Day 1. |
| Dashboard → server | Mock server serves fixture incidents; TS types from `openapi.yaml`. |
| Server flow_service → ML model | `nexus_ml` ships a `DummyClassifier` (always benign, `model_version: ids-dummy-000`) on Day 3; the real bundle replaces it in Week 3 without code changes. |
| ML trainer → live features | The fixture `flow_feature_fixture.json` pins the contract; Bashar never needs the gateway to train. |
| Correlator → endpoints | Rakan tests correlation by POSTing fixture incidents and injecting synthetic conntrack lines. |
| Everything → lab | Only integration days (Week 2 Fri, Week 4, Week 6) need the full lab. |

## 3. Repository layout (monorepo, GitHub, `main` protected)

```
nexus/
  AGENTS.md  CLAUDE.md            # conventions for AI coding agents (same content)
  README.md
  pyproject.toml                  # installs nexus_contracts
  contracts/                      # schemas, openapi, rules, fixtures  (Anas keeper)
  nexus_contracts/                # pydantic models + loader
  tools/                          # mock_server.py, validate_fixtures.py, generate_fixtures.py
  docs/                           # this package
  lab/                            # gateway/, tetragon-policies/, sysmon/, scenarios/, ti/
  endpoint-core/                  # nexus_endpoint_core (Anas)
  endpoint-linux/                 # linux adapter + response (Omar)
  endpoint-windows/               # windows adapter + response (Anas)
  server/                         # Rakan
  ml/                             # nexus_ml (Bashar)
  dashboard/                      # React app (Bashar)
  prompts/                        # the four AI coding prompts
  .github/workflows/ci.yml        # validate fixtures + unit tests per package
```

Rules:
- Branch per task: `anas/win-adapter-eid3`, `rakan/conntrack-registry`, … Squash-merge via PR; one approving review from another member (reviews are 10 minutes, not audits — check the contract boundary, not style).
- `contracts/` changes require Anas's review and a passing `tools/validate_fixtures.py`.
- CI (GitHub Actions, free): `pip install -e . && python tools/validate_fixtures.py`, then `pytest` in each package that has tests. Dashboard: `npm run typecheck && npm run build`.
- No binary artifacts in git except model bundles via Git LFS (or GitHub Releases).
- Each package has its own `README.md` with: how to run, how to test with fixtures, how to run against the mock server.

## 4. Working with AI coding agents without divergence

1. **Every agent session starts with the same files:** `AGENTS.md`, `docs/01-ARCHITECTURE.md`, `contracts/README.md`, the member's prompt in `prompts/`, and the fixtures. The prompts say so explicitly.
2. **Contracts are imported, never re-typed.** If an agent proposes a new field, the answer is "open a contracts PR", not "add it locally".
3. **Fixtures are the acceptance tests.** An adapter is done when it turns real sensor output into events that validate and, for the scripted scenario, match the expected process chain. The core is done when the rule fixtures pass. The server is done when the fixture incident correlates to an injected conntrack record. The dashboard is done when it renders `server_incident_view_linux_l1.json` fully.
4. **Python conventions:** 3.11+, `ruff` + `black` defaults, type hints, `pydantic` models from `nexus_contracts`, structured logging (`logging` with JSON formatter), config via environment variables with a documented `.env.example`, no global state outside the app object, `pytest` with fixtures from `contracts/fixtures`.
5. **Nothing speculative.** Agents are told to prefer the simplest working implementation and to mark `TODO(stretch)` instead of building optional features.
6. **Daily 15-minute sync** (voice or chat): what merged, what is blocked, any contract question. Contract questions are answered the same day.

## 5. Development environments

| Member | Dev machine | Needs lab? |
|---|---|---|
| Anas (8 GB, Windows) | Sysmon **dev profile** (`nexus-sysmon-dev.xml`, `C:\Lab\` only) on his laptop; Python 3.11; mock server locally. Endpoint-core is pure Python. | Integration days only |
| Omar (16 GB, RTX) | VirtualBox lab host #1 (gateway + Linux + Windows VMs). Develops the Linux adapter inside the Linux VM (or on a bare-metal Ubuntu if dual-booted). | Daily |
| Rakan (16 GB) | VirtualBox lab host #2 (same OVAs). Develops the server inside the gateway VM. | Daily |
| Bashar (6 GB) | Colab/Kaggle for training; Node 20 + Vite for the dashboard; mock server locally. | Integration days only |

## 6. Integration ladder (each rung is a checklist item in the plan)

1. **I0 (Day 2):** contracts frozen; `validate_fixtures.py` green; mock server up; everybody has run it.
2. **I1 (Day 5):** lab VMs routed; `conntrack -E` shows a cross-subnet `curl`; chrony synced; Tetragon and Sysmon emit the five event types.
3. **I2 (Day 10, Gate G1):** Linux adapter → real `HostEvent`s → hand-built or core-built incident → real server → correlator `matched` for scenario L1's connection. *This is the go/no-go.*
4. **I3 (Day 15):** Windows path reaches `matched` the same way; dashboard shows live incidents from the real server.
5. **I4 (Day 20, Gate G2):** L1, W1 end-to-end with rules, ML verdicts (real model), TI enrichment, dry-run response; evaluation harness produces its first report.
6. **I5 (Day 25):** L2 automatic response (real), N1 network-only alert + manual gateway block, L3 threshold; metrics collected.
7. **I6 (Day 30):** Code freeze; only bug fixes; rehearsals.

## 7. Communication of state
A single `STATUS.md` at repo root, edited by each member on Fridays: one line per deliverable with ✅/🟡/🔴 and the blocking item. The project lead (Anas) decides fallback activation (see `06-SIX-WEEK-PLAN.md` §4) based on it.
