# NEXUS — ML Network IDS: feasibility, dataset, features, training, live inference

## 1. Feasibility verdict

| Step | Difficulty | Verdict |
|---|---|---|
| Train a binary flow classifier on a public dataset | Easy | ~1 week including cleaning. |
| Reproduce the dataset's features on live traffic | **Hard — the main risk** | Solved by freezing one feature subset (`nf-lite-1`) that both the trainer and the gateway implement from the same spec and the same fixture. |
| Make the model useful on lab traffic | Uncertain | Expect degradation versus the dataset split; measure it and report it. |
| Inference inside the gateway flow pipeline | Easy | RandomForest predicts in microseconds on CPU. |
| Use ML to drive automatic blocking | Not advisable | Out of scope. ML is an annotation and a standalone alert source only. |

What ML contributes to NEXUS: an independent network-side evidence source, standalone network alerts when no host incident exists, and a *measured* generalization study — which is more defensible academically than a near-perfect test-split score.

## 2. Dataset decision

**Primary:** University of Queensland NetFlow v2 family (Sarhan, Layeghy, Portmann et al.): 43 NetFlow/nProbe-style features with nDPI, identical schema across NF-UNSW-NB15-v2, NF-ToN-IoT-v2, NF-BoT-IoT-v2, NF-CSE-CIC-IDS2018-v2 and the merged NF-UQ-NIDS-v2. Download page: `https://staff.itee.uq.edu.au/marius/NIDS_datasets/`. Cite the two papers (BDTA 2020; Mobile Networks and Applications 2021).

Why this family: NetFlow-style counters can be reproduced from NFStream fields; CICFlowMeter's handcrafted CIC-IDS2017/2018 CSV features cannot be reproduced live without running CICFlowMeter itself, which is not an option. The newer v3 family (53 features) is not used in v1 — more features means a larger live-parity surface for no demo benefit.

Order of work:
1. `NF-UNSW-NB15-v2` (~2.4 M rows, ~96 % benign) — baseline; fits Colab RAM.
2. Stratified sample (≤ 3 M rows) of `NF-CSE-CIC-IDS2018-v2` for brute-force/DoS/bot families.
3. Optional: stratified sample (≤ 5 M rows) of `NF-UQ-NIDS-v2`. Never load the full file on a laptop.

Lab traffic (benign baseline and the scripted scenarios from `07-DEMO-AND-EVALUATION.md`) is used for **evaluation**, and optionally as a small augmentation set with a held-out portion. Keep that experiment separate and clearly labelled; do not train and test on the same lab capture.

## 3. Feature contract `nf-lite-1` (frozen; full text in `contracts/flow-features.md`)

Principles: only features that NFStream can produce from packet headers in a bidirectional flow, with one explicit formula each; dataset column ↔ NFStream field mapping written down; identical ordered vector on both sides; a shared fixture (`contracts/fixtures/flow_feature_fixture.json`) that both `nexus_ml.features.from_dataset_row()` and `nexus_ml.features.from_nflow()` must reproduce: exactly for the feature names, their order and the integer features, and within the float tolerance defined in `contracts/flow-features.md` ("Fixture comparison") for the computed float features.

Direction convention: dataset `IN_*` = client→server = NFStream `src2dst_*`; `OUT_*` = server→client = `dst2src_*`. **[verify W1 against the dataset paper and a few rows; if reversed, flip the mapping in one place — `features.py` — not in the trainer.]**

Excluded on purpose in v1: TTL, TCP window, retransmission counters, ICMP/DNS/FTP fields, L7_PROTO (nDPI numeric IDs are version-dependent; `application_name` is stored for display only), source port (ephemeral noise).

## 4. Training (`ml/train.py`, run on Colab/Kaggle)

1. Load CSV in chunks; keep `nf-lite-1` columns + `Label` (+ `Attack` for analysis only).
2. Clean: drop NaN/inf, clip rates at the 99.99th percentile, cast ints.
3. Split: stratified 70/15/15 (train/val/test), `random_state=42`. Report class balance.
4. Models: `RandomForestClassifier(n_estimators=200, max_depth=None, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1)` as the baseline; `XGBClassifier` as the candidate. Keep whichever has the better validation precision at the chosen recall.
5. Threshold: choose the score threshold on **validation** that yields FPR ≤ 1 % on benign; store it in `metadata.json`. `ml_score` is the raw tree-vote fraction, not a calibrated probability — the dashboard must say "score", not "probability".
6. Report: precision/recall/F1/ROC-AUC/PR-AUC on test; confusion matrix; per-attack-family recall; feature importances; training time. Save as `reports/model-<version>.md` + JSON.
7. Export bundle: `models/<model_version>/{model.joblib, features.json, metadata.json, CHANGELOG.md}`. `features.json` = ordered feature names + `feature_version: "nf-lite-1"`. The server refuses to load a bundle whose `feature_version` differs from its own.

## 5. Live inference (`nexus_ml.FlowClassifier`, called by `server/flow_service`)

```python
clf = FlowClassifier.load("/opt/nexus/models/ids-rf-001")
pred = clf.predict(features_dict)   # -> MLPrediction(label="benign"|"suspicious", score=0.07, model_version, feature_version, threshold)
```
Rules: pure CPU, no I/O at predict time, < 1 ms per flow, raises on missing/extra feature keys. Flows terminating at the gateway itself (ports 8443/123/53 to gateway IPs) are tagged `scope: "gateway-internal"` and not scored.

## 6. Evaluation that counts (owned by Bashar, data provided by Omar/Rakan)

| Measurement | How |
|---|---|
| Dataset test-split metrics | Standard; reported but not the headline. |
| **Benign lab baseline** | ≥ 1 h of ordinary lab activity (updates, browsing the internal web service, file copies) → alerts per hour at the chosen threshold. This is the number judges will ask about. |
| **Scripted scenario recall** | Each demo scenario's flows: fraction labelled suspicious; which families generalize, which do not. |
| Feature-parity test | Fixture parity test in CI (the comparison in `contracts/flow-features.md`); plus a 50-flow comparison between NFStream-on-pcap and the live path on the gateway. |
| Latency | Flow expiry → prediction available; connection start → prediction available (dominated by the 15 s idle timeout; state it). |
| Ablation (optional) | Drop `l4_dst_port`; report the change. Port is a known shortcut feature. |

## 7. Hardware plan
Bashar's laptop (6 GB) is for code and dashboard work; all training happens on Google Colab or Kaggle (free tier is sufficient for RF on ≤ 5 M rows). Model bundles are < 200 MB; commit via Git LFS or attach to a GitHub release. Inference runs on the gateway VM (3 GB RAM) without issue.

## 8. What to say in the report
"A team-trained binary flow classifier, trained on a public NetFlow-feature dataset with a feature subset chosen for live reproducibility, evaluated on both the dataset split and on independent lab traffic. The classifier annotates gateway flows and raises standalone network alerts; it never drives automatic blocking."
