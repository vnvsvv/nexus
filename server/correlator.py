"""Incident connection <-> gateway connection matching (process: nexus-correlator).

Roadmap: R5 (Gate G1). correlate() exactly as docs/02-CORRELATION.md sections 5.2-5.3:
score >= 1.5, states matched / ambiguous / pending / unmatched, pin() for analysts
(basis: inferred).

Worker loop (plain asyncio loop, no thread pool):
- Wakes on NOTIFY from nexus-api (incident stored) and nexus-registry (connection
  inserted), and on a 60 s timer (the section 5.3 "once a minute" retry).
- Work list comes from PostgreSQL, not memory: incident connections of the current
  incident_version with no correlation row, plus rows in state pending.
- On start-up it runs the same sweep, so nothing is lost if any process crashed.
- Writes are idempotent (one row per endpoint/incident/version/connection), so a
  retry after a crash cannot duplicate results. One failing item is logged and left
  for the next sweep; it does not stop the loop.
Needs no Linux capabilities.
Not implemented yet.
"""
