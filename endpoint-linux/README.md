# NEXUS Linux endpoint

The Tetragon JSONL adapter uses shared `nexus_contracts` models and checks
the serialized event against the canonical JSON Schema before yielding it.

## Run

From the repository root, create a Python 3.11+ environment and install the
shared contracts and test dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[tools]"
```

Run a finite replay from the repository root.

```bash
PYTHONPATH=endpoint-linux python - <<'PY'
from tetragon_adapter import TetragonAdapter

adapter = TetragonAdapter(
    "endpoint-linux/tests/data/sanitized_tetragon_v1_8_0_tcp_connect_loopback.jsonl",
    follow=False,
)
for event in adapter.events():
    print(event.model_dump_json(by_alias=True, exclude_none=True))
PY
```

For a continuous reader, instantiate `TetragonAdapter()` and consume its
`events()` iterator. It starts with the current export at
`/var/log/tetragon/tetragon.log` and waits for additions. Use a single consumer
per adapter and close the iterator to release its file descriptor. Each
`raw_ref` carries the export path, device, inode, generation and byte offset.
On rename rotation, the adapter opens the replacement while the old file is
still open, then drains the old file through its final observed EOF. Writes
to the old inode after that final read can still be missed. Copytruncate can
overwrite unread bytes, and a rewrite with identical head and tail checks
can escape detection. Multiple rotations between polls can skip an
intermediate file. The reader follows the current path and does not scan
archives.

### Restart replay

A restart reads the current export from byte zero and generates fresh event
IDs. A stable ID would need to distinguish individual raw records as well as
multiple events from one record, such as a combined read/write check. A raw
content hash can merge identical observations, and `raw_ref` includes file
coordinates and a generation counter that starts over on restart. A durable
checkpoint would need a way to validate the file and offset after rotation
and advance only after the consumer has durably accepted the events.

## Test with fixtures

```bash
python tools/validate_fixtures.py
PYTHONPATH=endpoint-linux python -m pytest tests/ endpoint-linux/tests/
```

The capture notes describe the sanitized TCP, lifecycle, and file permission
samples and the independent observations used to check them. Synthetic tests
cover recovery and identity edge cases. [Capture notes](tests/data/README.md)

## Run against mock server

The adapter yields local HostEvents. The mock accepts incidents, so a mock
submission requires the later incident path. WP1-A exercises the HostEvent
interface via the fixture tests.

## Run in the lab

Use an account that can read Tetragon's file export. Enable the repository TCP
and file permission policies, then point the reader at the current log.
The sanitized VM captures cover four process starts and exits, three file
permission checks, and three IPv4 loopback TCP events. The original TCP
observations agreed with independent curl and server measurements. Routed
Linux-to-Windows and IPv6 traffic, fallback identity with genuine sensor
data, and live log rotation remain unverified.
[Tetragon policies](../lab/tetragon-policies/README.md)

The adapter preserves observed native exec IDs. PID/start-time fallback
requires one live cached candidate within 10 ms and compatible observed
identity fields. If fallback is unsafe, a usable raw ID is retained as
`identity_resolution=unknown`. A probe without a usable association stays
a diagnostic. An observed exit closes the execution even if its start has
yet to arrive. A late start for a retained closed execution stays a raw
diagnostic so it cannot reopen the process. PID history and exit tombstones
are bounded in memory. After eviction, starts that predate or coincide with
the newest evicted exit timestamp stay diagnostic. This can also suppress
unrelated delayed starts. Exits without a valid timestamp can only be
tracked while their identity remains cached.

File events describe permission checks with an explicit integer return
code of zero. Missing, malformed, and nonzero results stay raw diagnostics.
A combined read/write mask yields two events sharing a raw reference.
An unsupported mask also produces a diagnostic.

Successful binary hashes carry `hash_basis=path_at_collection`. The digest
describes bytes at the observed path when the adapter collects them. The
cache uses file metadata, and hashing skips unreadable, nonregular, changing,
or oversized files. The live capture included a nonzero exit code and a
signal. The sensor omitted the status on successful exits, so those events
carry no exit code.

Incomplete TCP tuples produce a structured warning with the raw reference and
the original UTF-8 JSONL in `raw_jsonl`. These warnings can contain process
arguments and other private telemetry. Keep them in a restricted sink if they
need to survive Tetragon log rotation. The adapter emits network events only
for complete observed tuples. Source-port recovery via `/proc` is outstanding.
Socket cookies can repeat across distinct records.
