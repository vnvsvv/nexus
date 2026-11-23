# Tetragon replay fixtures

The `sanitized_` fixtures derive from genuine Tetragon v1.8.0 JSON exports.
The fixtures use an example hostname, regenerated base64 execution IDs, and
substitute PIDs, UIDs, paths, arguments, ports, and socket cookies. Times are
rebased while preserving event order and relative intervals. Repeated process
and parent references use the same replacement IDs throughout each capture.
The lifecycle expectation file uses the same substitutions. Keep original
exports and observation files private.

## IPv4 loopback TCP

`sanitized_tetragon_v1_8_0_tcp_connect_loopback.jsonl` contains three
`tcp_connect` records from the monitor-only policy. Each original IPv4
request returned HTTP 200, and curl and the HTTP server independently agreed
on each source port. In the fixture, the client and server use `127.0.0.1`.
The destination port is `18080`, and the substituted source ports are
`50001`, `50002`, and `50003` in capture order.
Two records share a socket cookie, and each has its own raw record.

## Process lifecycle and file permissions

`sanitized_tetragon_v1_8_0_lifecycle_file.jsonl` contains 11 records.
The companion `sanitized_tetragon_v1_8_0_lifecycle_file.expected.json`
preserves the independent subprocess observations with substituted
arguments, PIDs, and time bounds.

| Case | Independent result | Tetragon evidence |
| --- | --- | --- |
| `cat` | Read the test file and exited successfully | Exec, two read permission checks with mask `4` and return `0`, exit without `status` |
| `tee` | Wrote the test file and exited successfully | Exec, one write permission check with mask `2` and return `0`, exit without `status` |
| `python3` | Exit code 17 | Exec and exit with `status: 17` |
| `python3` | Terminated by SIGTERM | Exec and exit with `signal: "SIGTERM"` |

The read and write checks came from the monitor-only `nexus-file-access` policy.
The two read checks are distinct records that truncate to the same
millisecond. The adapter uses the envelope timestamp, which differs slightly
from the nested exit timestamp. Successful exits with omitted status have an
unset exit code in the normalized event.

## Synthetic input

`synthetic_lifecycle_and_file.jsonl` is a hand-written fixture for process
exec, file permission checks, and exit parsing.
