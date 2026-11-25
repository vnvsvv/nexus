"""FastAPI app implementing contracts/openapi.yaml (process: nexus-api).

Roadmap: R3. Bearer auth, request validation (JSON schema + nexus_contracts models),
incident upsert, heartbeat, command polling, ServerIncidentView assembly, SSE /stream.

Boundaries (see server/README.md, "Processes"):
- Runs with NO Linux capabilities. It never calls nft, conntrack or packet capture.
- Writes rows and sends a NOTIFY in the same transaction; the correlator, TI and
  response workers do the work. A lost NOTIFY is harmless: every worker also sweeps.
- Response requests: validates and authorizes them, stores them in response_commands,
  and returns. It never executes a gateway command itself.
Not implemented yet.
"""
