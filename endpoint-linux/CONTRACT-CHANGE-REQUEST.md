# Clarification for incomplete TCP observations

**Owners:** Anas (shared contracts and endpoint core), with Rakan (gateway
correlation).

`HostEvent.network.src_port` and `Incident.connections[].src_port` require an
integer and have no documented unknown value. The gateway compares source
ports in its deterministic five-tuple match. Three genuine IPv4 loopback
samples contained assigned source ports. They do not establish that future
observations will always carry a complete tuple.

WP1-A emits complete tuples. Missing or invalid source ports remain raw
diagnostics and are excluded from normalized events and incident connections.

If a future Tetragon observation lacks a source port, should it stay as
raw evidence until the tuple is complete? If it must enter the shared
pipeline, what contract representation and evidence gap should it use, and
how should the correlator exclude it from exact matching? A schema change is
only needed if we agree to represent incomplete tuples in the shared objects.
