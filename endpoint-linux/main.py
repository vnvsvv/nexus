"""Export Tetragon telemetry as standalone NEXUS HostEvent JSONL."""

from __future__ import annotations

import argparse
import json
import logging
import os
from contextlib import closing
from pathlib import Path

from tetragon_adapter import TetragonAdapter

LOG = logging.getLogger(__name__)


class PrivateDiagnostics(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        diagnostic = json.loads(record.getMessage())
        record.msg = json.dumps({"sensor": "tetragon", "reason": diagnostic["reason"]})
        record.args = ()
        return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tetragon-log",
        type=Path,
        default=os.getenv("NEXUS_TETRAGON_LOG", "/var/log/tetragon/tetragon.log"),
        help="Tetragon's JSONL export (default: %(default)s)",
    )
    parser.add_argument(
        "--endpoint-id",
        default=os.getenv("NEXUS_ENDPOINT_ID", "linux-vm-01"),
        help="endpoint slug (default: %(default)s)",
    )
    parser.add_argument(
        "--jsonl-out",
        required=True,
        type=Path,
        help="new private HostEvent JSONL file (command lines omitted by default)",
    )
    parser.add_argument(
        "--replay", action="store_true", help="stop at EOF instead of following the log"
    )
    parser.add_argument(
        "--include-command-line",
        action="store_true",
        help="retain potentially sensitive command lines for trusted local replay",
    )
    args = parser.parse_args(argv)

    if not args.tetragon_log.is_file() or not os.access(args.tetragon_log, os.R_OK):
        LOG.error('{"error":"tetragon_export_unreadable"}')
        return 1
    adapter_log = logging.getLogger(TetragonAdapter.__module__)
    private_diagnostics = PrivateDiagnostics()
    adapter_log.addFilter(private_diagnostics)
    excluded_fields = None if args.include_command_line else {"command_line"}
    count = 0
    try:
        adapter = TetragonAdapter(
            args.tetragon_log, endpoint_id=args.endpoint_id, follow=not args.replay
        )
        fd = os.open(args.jsonl_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with (
            os.fdopen(fd, "w", encoding="utf-8", buffering=1) as output,
            closing(adapter.events()) as events,
        ):
            for event in events:
                output.write(
                    event.model_dump_json(
                        by_alias=True, exclude_none=True, exclude=excluded_fields
                    )
                    + "\n"
                )
                count += 1
    except KeyboardInterrupt:
        LOG.info(json.dumps({"status": "interrupted", "events_written": count}))
        return 130
    except ValueError:
        LOG.error('{"error":"invalid_endpoint_id"}')
        return 1
    except FileExistsError:
        LOG.error('{"error":"output_already_exists"}')
        return 1
    except OSError as exc:
        LOG.error(json.dumps({"error": "capture_io_failed", "errno": exc.errno}))
        return 1
    finally:
        adapter_log.removeFilter(private_diagnostics)
    LOG.info(json.dumps({"status": "complete", "events_written": count}))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    raise SystemExit(main())
