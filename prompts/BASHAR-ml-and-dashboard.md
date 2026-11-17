# Coding prompt — Bashar: `ml/` (package `nexus_ml`) and `dashboard/`

Paste this whole file as the first message to your coding agent, with the repository open at its root. Training runs on Google Colab/Kaggle; the package and the dashboard are developed locally.

---

You are the implementing engineer for the NEXUS machine-learning network IDS (`ml/`) and the analyst dashboard (`dashboard/`). Read `AGENTS.md`, `docs/01-ARCHITECTURE.md` (§2.6–2.7), `docs/03-ML-IDS.md`, `contracts/flow-features.md`, `contracts/README.md`, `contracts/openapi.yaml`, `contracts/schemas/server_incident_view.schema.json`, `docs/07-DEMO-AND-EVALUATION.md`, and every file in `contracts/fixtures/` (especially `flow_feature_fixture.json` and `server_incident_view_linux_l1.json`). Work in this order.

## Part A — `ml/` (package `nexus_ml`, Python 3.11; deps: `numpy`, `pandas`, `scikit-learn`, `xgboost` (optional), `joblib`, `nexus_contracts`; `nfstream` only as an optional import for the live path)

1. `features.py` — the single implementation of `nf-lite-1`:
   - `FEATURE_ORDER = NfLite1.ORDER` (import from `nexus_contracts`; never retype).
   - `from_dataset_row(row: dict) -> list[float]` mapping UQ NetFlow v2 columns per the table in `contracts/flow-features.md` (mean_pkt_size derived; rate columns per the caveat — implement the live formula and expose `recompute_rates=True` default).
   - `from_nflow_fields(fields: dict) -> list[float]` from a dict of NFStream `NFlow` attributes (+ `udps` bins), and `from_nflow(flow) -> list[float]` that builds that dict from a live `NFlow` (`getattr` for the listed fields; `flow.udps.b128`…).
   - `flags_mask(...)` per the contract.
   - Test: both paths reproduce `contracts/fixtures/flow_feature_fixture.json["expected_vector"]` exactly; `python tools/validate_fixtures.py` must print "feature parity fixture OK".
2. `classifier.py` — `FlowClassifier.load(bundle_dir)` (reads `features.json`, verifies order and `feature_version == "nf-lite-1"`, loads `model.joblib`, reads `threshold`/`model_version` from `metadata.json`), `predict(features: dict | NfLite1) -> MLPrediction`; `DummyClassifier` with `model_version="ids-dummy-000"`, always benign, score 0.0, threshold 0.5. No I/O in `predict`; < 1 ms.
3. `data.py` — chunked CSV loader for the UQ datasets keeping only needed columns; `prepare(df)` cleaning as in `03-ML-IDS.md` §4; stratified split with fixed seed; writes Parquet caches.
4. `train.py` — CLI: `python -m nexus_ml.train --dataset NF-UNSW-NB15-v2.csv --out models/ids-rf-001 --model rf|xgb --target-fpr 0.01`. Trains, selects the threshold on validation at the target FPR, evaluates on test, writes the bundle (`model.joblib`, `features.json`, `metadata.json` with dataset name/rows/split/metrics/threshold/feature importances/training time/sklearn version, `CHANGELOG.md`) and `reports/<model_version>.md` (+ `.json`). Must run on Colab from the repo (`!pip install -e .` then the CLI).
5. `evaluate_lab.py` — CLI that takes pcaps (`nfstream` on the pcap with the same streamer settings as the gateway), scores every flow, and reports alerts/hour, per-pcap flagged fraction, and the feature-parity comparison for flows that also exist in a server export (`03-ML-IDS.md` §6). Ablation flag `--drop l4_dst_port`.
6. `README.md`: Colab recipe, dataset citation text, bundle layout, how the server consumes the bundle.

Deliverables: `DummyClassifier` by Day 3; `ids-rf-001` bundle + report by Day 8; `ids-rf-002`/XGBoost comparison by Day 12; lab evaluation report by Day 18; model card by Day 23.

## Part B — `dashboard/` (React 18 + Vite + TypeScript strict; `@xyflow/react` (React Flow), Tailwind, `openapi-typescript` for types, `eventsource` for SSE)

Data source: `tools/mock_server.py` on `http://127.0.0.1:8000/api/v1` with token `devtoken` (`VITE_API_BASE`, `VITE_API_TOKEN`), later the real server. All types are generated from `contracts/openapi.yaml` (`npm run gen:types`); never hand-write contract types.

Pages:
1. **Incidents** (`/`): live list (SSE `incident.created/updated` → refetch), columns: time, endpoint/OS, severity, confidence, title, techniques, correlation summary chips (`matched/ambiguous/pending/unmatched`, `ml_suspicious`), local response status. Filters by status/endpoint/severity.
2. **Incident detail** (`/incidents/:id`):
   - **Graph** (React Flow): nodes = `process_nodes` (root highlighted; placeholder nodes dashed), file nodes, net nodes, and gateway-connection nodes from `server.network_evidence`; edges from `relationships` plus one `NETWORK_FLOW` edge per `matched` correlation (from the host connection node to the gateway record). Edge style by `basis`: `observed` solid, `inferred` dashed with the `note` in a tooltip. ML verdict badge on the gateway node (`benign`/`suspicious` + score, model version). Legend always visible: "solid = observed, dashed = inferred".
   - **Timeline**: `evidence[]` sorted by `timestamp_utc`, role tag (`matched` bold), one line per event with type-specific summary.
   - **Connections panel**: each `connections[i]` with its correlation state, score, gateway record (times, counters), flows (features collapsed, ML verdict), candidates list for `ambiguous` with a "Pin" button (`POST .../pin` with a note), pending/unmatched explanations.
   - **TI panel**: `server.enrichment[]` grouped by indicator with verdict colour; `lab-test` clearly labelled.
   - **Gaps panel**: `gaps[]` with codes explained in plain words.
   - **Response panel**: buttons "Terminate process" (per process node; disabled for placeholders), "Block destination", "Block source", "Unblock"; each opens a confirm dialog that shows the exact `ResponseCommand` JSON that will be sent and whether `dry_run` is on; history from `server.response_history`.
   - **ATT&CK strip**: `technique_ids` with names from `contracts/attack-mapping.yaml` (bundle it at build time).
   - **Raw JSON** tab: the full `ServerIncidentView`.
3. **Network alerts** (`/network`): standalone `network_alerts` with flow summary and link to incident when linked; "Block source" action.
4. **Endpoints** (`/endpoints`): heartbeat table (last seen, clock offset, sensor status, events/min, dry-run flag, agent version).
5. **Responses** (`/responses`): global history.
6. **Overview** header: model version, counts from `/stats`, server time.

Quality bar: renders `server_incident_view_linux_l1.json` completely with no console errors; `npm run typecheck`, `npm run build` clean; empty/error/loading states; keyboard-accessible dialogs; a `walkthrough` query flag (`?walkthrough=1`) that highlights the graph → correlation → ML → TI → response order for the demo.

Deliverables: scaffold + incident list/detail with fixtures by Day 5; graph/timeline/connections by Day 10; TI/gaps/network/endpoints/responses by Day 15; polish and walkthrough by Day 20; screenshots for the report by Day 25.

Constraints: no backend code in the dashboard; no state libraries beyond React Query (or plain fetch + hooks); no component library that hides Tailwind; no LLM features.
