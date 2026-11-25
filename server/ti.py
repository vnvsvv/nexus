"""Threat intelligence feeds and incident enrichment (process: nexus-ti).

Roadmap: R7. MalwareBazaar, Feodo, URLhaus and lab/ti/lab-indicators.csv into
ti_indicators; enrich(incident); optional VirusTotal lookups with persistent cache,
4 requests/min and 500/day.

Worker loop:
- Wakes on NOTIFY from nexus-api (incident stored); refreshes feeds on a timer.
- Work list comes from PostgreSQL: incidents whose current version has not been
  enriched yet. Start-up runs the same sweep. VirusTotal results are cached in
  ti_lookups, so a restart never repeats a paid lookup.
- Runs apart from the API so large feed downloads and slow external calls cannot
  stall the API on the 3 GB gateway VM.
Needs no Linux capabilities; only outbound internet through the NAT interface.
Not implemented yet.
"""
