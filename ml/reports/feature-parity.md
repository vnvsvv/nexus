# Week 1 flow feature parity

The NF-UNSW-NB15-v2 CSV used for this check has SHA-1 dde9a9e38009ec60121cbb4fd884bf2c7cf5c0b0, verified against the UQ archive manifest. It contains 2,390,275 labeled flows. The checks below used rows in file order.

## Rate comparison

Each of the first 1,000 rows produced 24 finite features. For each of the four published rate columns, zero of the 1,000 values matched its recomputed value with relative and absolute tolerance 1e-12. Only 55 rows had positive whole-flow duration. Using that duration for the source byte rate yielded zero matches among those 55 rows. This sample establishes a difference but does not identify the publisher's formula.

Use the existing default recompute_rates=True for training. It derives directional byte rates from directional durations and throughput from whole-flow duration, with a 1 ms denominator floor, as specified in the shared feature contract.

## Direction and flags

Among the first 20 TCP flows to destination port 80 or 443, 11 had fewer IN_BYTES than OUT_BYTES and nine had more. Payload sizes alone cannot identify the initiator. Keep the documented IN to src2dst mapping. Rakan can verify direction on a gateway capture with a known initiator.

Across the first 1,000 rows, all three TCP flag masks were in the range 0 to 255, and the overall mask equaled the bitwise OR of the directional masks in every row.

## Fixture and live integration

The dataset and simulated NFStream paths produce identical vectors on the shared fixture. The computed source byte rate is 867.816091954023 and the fixture expects 867.8160919540229. The shared validator uses exact equality. Anas owns the comparison policy. Actual NFStream packet bins and direction still require a gateway comparison.

Dataset reference: Sarhan, Layeghy and Portmann, Towards a Standard Feature Set for Network Intrusion Detection System Datasets. https://doi.org/10.1007/s11036-021-01843-0
