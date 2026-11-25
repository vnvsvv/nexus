"""FastAPI app implementing contracts/openapi.yaml.

Roadmap: R3. Bearer auth, request validation (JSON schema + nexus_contracts models),
incident upsert, heartbeat, command polling, ServerIncidentView assembly, SSE /stream.
Also starts the correlator, TI and response tasks inside the same process.
Not implemented yet.
"""
