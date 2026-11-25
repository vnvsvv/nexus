"""Incident connection <-> gateway connection matching.

Roadmap: R5 (Gate G1). correlate() exactly as docs/02-CORRELATION.md sections 5.2-5.3:
score >= 1.5, states matched / ambiguous / pending / unmatched, pending retry on
registry inserts and once a minute, pin() for analysts (basis: inferred).
Not implemented yet.
"""
