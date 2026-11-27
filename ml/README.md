# NEXUS ML

Install from the repository root in a Python 3.11+ virtual environment.

```sh
python -m pip install -e ".[tools]" -e ./ml
```

## Run

Use `from_dataset_row(row)` for UQ NetFlow v2 data and `from_nflow(flow)`
for an NFStream flow with the packet-size plugin described in the shared
[feature contract](../contracts/flow-features.md). Both use the documented rate
formulas. Set `recompute_rates=False` on the dataset converter only to inspect
the original dataset rates.

## Test with fixtures

```sh
python -m pytest -q ml
python tools/validate_fixtures.py
```

The exact shared validator currently reports a difference for
`src_to_dst_second_bytes`. The documented arithmetic gives
`867.816091954023` and the fixture stores `867.8160919540229`. The package tests
require exact equality between the two recomputed paths and allow a tight
tolerance only for this one fixture comparison. The shared validator and
fixture retain their existing comparison behavior pending a team decision.

## Run against the mock server

The converters run locally with the fixture. They do not depend on the mock API.

## Run in the lab

Use the gateway's NFStream fields and packet-size counters. Dataset direction,
nProbe rate semantics, and parity on live gateway exports still need empirical
verification before training or integration.
