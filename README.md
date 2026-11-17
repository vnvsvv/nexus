# NEXUS — evidence-backed endpoint + network attack reconstruction (graduation project)

Linux (eBPF/Tetragon) and Windows (Sysmon/ETW) endpoints reconstruct suspicious activity locally and send *incidents with evidence*. A Linux gateway between two isolated subnets records every connection it routes, scores flows with a team-trained ML classifier, deterministically matches incident connections to gateway records (including normal ones), enriches with threat intelligence, and shows one evidence-graded story with limited, audited response.

## Start here
| Read | Why |
|---|---|
| `docs/00-ASSESSMENT.md` | What was wrong with the previous plan and what changed |
| `docs/01-ARCHITECTURE.md` | The frozen architecture, components, lab, must-have vs stretch |
| `docs/02-CORRELATION.md` | Process graph, rule engine, incident builder, central matching algorithm |
| `docs/03-ML-IDS.md` | Dataset, feature contract, training, live inference, evaluation |
| `docs/04-DETECTION-TI-RESPONSE.md` | Rules, telemetry coverage, TI sources, response safety |
| `docs/05-TEAM-AND-INTEGRATION.md` | Ownership, repo layout, dependency cuts, integration ladder |
| `docs/06-SIX-WEEK-PLAN.md` | Week-by-week plan, gates, fallbacks |
| `docs/07-DEMO-AND-EVALUATION.md` | Demo script and measurable evaluation |
| `docs/08-LAB-SETUP.md` | VMs, addressing, Week-1 verification table |
| `contracts/` | Schemas, API, rules, feature contract, fixtures — the shared truth |
| `prompts/` | One ready-to-paste coding prompt per member |
| `AGENTS.md` / `CLAUDE.md` | Rules for AI coding agents |

## Quick start (every member, Day 1)
```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e . && pip install fastapi uvicorn httpx pytest
python tools/validate_fixtures.py                 # must print "all fixtures valid"
python tools/mock_server.py --port 8000           # API mock seeded with the L1 fixture; token devtoken
pytest tests/
```

## Package layout
```
contracts/  nexus_contracts/  tools/  docs/  lab/  prompts/  tests/
endpoint-core/  endpoint-linux/  endpoint-windows/  server/  ml/  dashboard/   <- created by the owners in Week 1
```

## Team
Anas — Windows endpoint, shared endpoint core, contracts keeper · Omar — Linux endpoint, lab, evaluation harness · Rakan — gateway server (registry, flows, correlator, API, TI, response) · Bashar — ML IDS and dashboard.
