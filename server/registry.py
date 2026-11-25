"""Gateway connection registry.

Roadmap: R4. Parses `conntrack -E -e NEW,DESTROY -o timestamp,extended`
(reference: lab/gateway/conntrack-parse-example.py) and writes gateway_connections.
Runs as its own process (nexus-registry.service). Supports --conntrack-file for tests.
Not implemented yet.
"""
