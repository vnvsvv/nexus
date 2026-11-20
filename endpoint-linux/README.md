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

Follow the live Tetragon export from the repository root.

```bash
capture_dir=$(mktemp -d)
python endpoint-linux/main.py --jsonl-out "$capture_dir/events.jsonl"
```

Use `--tetragon-log PATH` and `--endpoint-id ID` to override
`NEXUS_TETRAGON_LOG` and `NEXUS_ENDPOINT_ID`. The runner starts at byte zero
and follows the log until interrupted. Add `--replay` to stop at EOF.
The output file must be new. The runner creates it with mode `0600` and
omits command lines by default. Diagnostics log reasons without raw event
data in either mode. Keep all JSONL and original sensor logs outside the
repository. [Environment example](.env.example)

Use the sanitized TCP sample for a finite schema smoke test.

```bash
capture_dir=$(mktemp -d)
python endpoint-linux/main.py --replay \
  --tetragon-log endpoint-linux/tests/data/sanitized_tetragon_v1_8_0_tcp_connect_loopback.jsonl \
  --jsonl-out "$capture_dir/events.jsonl"
```

For trusted local capture or replay, add `--include-command-line`. The file
retains the adapter's command lines, which can contain credentials and other
private arguments. Keep it in a directory restricted to your account. The
default export still contains telemetry such as process IDs, file paths, and
network addresses. Share it only with authorized recipients. The Python
iterator always yields the original HostEvents with their available command
lines.

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
PYTHONPATH=.:endpoint-linux python -m pytest tests/ endpoint-linux/tests/
```

The capture notes describe the sanitized TCP, lifecycle, and file permission
samples and the independent observations used to check them. Synthetic tests
cover recovery and identity edge cases. [Capture notes](tests/data/README.md)

## Run against mock server

The regression suite submits a labeled test incident to the repository's
mock API and checks bearer authentication, schema acceptance, duplicate
acknowledgment, and its `pending` correlation state. The mock exercises
the submission contract. Actual matching requires the real gateway.

To check API acceptance with a genuine L1 capture inside the isolated lab,
start the mock bound to loopback. In the sender's shell, enter the mock token
`devtoken` at the hidden prompt and point the sender at the mock.

```bash
python -m uvicorn tools.mock_server:app --host 127.0.0.1 --port 8000
```

```bash
export NEXUS_SERVER_URL=http://127.0.0.1:8000/api/v1
read -rs -p 'Mock bearer token: ' NEXUS_TOKEN
export NEXUS_TOKEN
python endpoint-linux/tools/post_manual_incident.py \
  --events "$capture_dir/events.jsonl" --manifest "$l1_manifest"
unset NEXUS_TOKEN
```

## Run in the lab

Use an account that can read Tetragon's file export. Enable the repository TCP
and file permission policies, then point the reader at the current log.
The sanitized VM captures cover four process starts and exits, three file
permission checks, and three IPv4 loopback TCP events. The original TCP
observations agreed with independent curl and server measurements. Routed
Linux-to-Windows and IPv6 traffic, fallback identity with genuine sensor
data, and live log rotation remain unverified.
[Tetragon policies](../lab/tetragon-policies/README.md)

### Gate G1

1. Start the standalone capture on the Linux VM. On the approved isolated lab
   network, run L1 from a second terminal with the same `NEXUS_ENDPOINT_ID`.
   Keep the private manifest path printed by the scenario.
   [L1 setup](../lab/scenarios/README.md#l1-on-the-isolated-lab)
2. Stop the capture after the run. Set `l1_manifest` to the manifest from that
   run. Build and validate the incident locally before submitting.

   ```bash
   python endpoint-linux/tools/post_manual_incident.py --validate-only \
     --events "$capture_dir/events.jsonl" --manifest "$l1_manifest"
   ```

3. For the real gateway, set `NEXUS_SERVER_URL` to its HTTPS API base and
   `NEXUS_CA_FILE` if the lab CA is outside the system trust store. Read the
   endpoint bearer token into `NEXUS_TOKEN` with a hidden prompt and run the
   sender without `--validate-only`. The sender removes command lines from
   process nodes and embedded HostEvents in the API payload, including when
   the local capture contains them. The in-memory incident retains those
   fields for local use. Terminal output contains only acknowledgment or
   error metadata. Reusing the same capture and network event preserves
   the incident ID for a manual retry.
4. Check the real gateway's incident view for the L1 connection in state
   `matched` with score at least `1.5`. Compare the Tetragon tuple with the
   manifest's curl tuple when available and with the gateway's conntrack
   record.

The fallback binds a single run using the manifest's process IDs, time window
and canary path. It derives edges and the connection from Tetragon HostEvents.
If Tetragon omits the source port, the manifest alone cannot supply it. A
missing parent link, an incomplete network event, or ambiguous evidence
prevents submission. PID/start-time probe associations are marked inferred
with an evidence gap. The fallback leaves endpoint response inactive.

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
