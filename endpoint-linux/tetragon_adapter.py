"""Read Tetragon's JSON export and emit canonical NEXUS host events."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import pwd
import re
import signal
import stat
import time
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from io import FileIO
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from pydantic_core import PydanticSerializationError

from nexus_contracts import (
    ExitInfo,
    FileInfo,
    HostEvent,
    NetworkInfo,
    new_event_id,
    validate_against_schema,
)
from nexus_contracts.models import EventType

_LOG = logging.getLogger(__name__)
_CHUNK_SIZE = 64 * 1024
_HASH_LIMIT = 64 * 1024 * 1024
_IDENTITY_TOLERANCE_NS = 10_000_000
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# datetime.fromisoformat() can normalize malformed offset minutes.
_TIMESTAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


@dataclass(frozen=True, slots=True)
class _ObservedIdentity:
    binary: str
    parent_id: str | None
    ppid: int | None
    auid: int | None
    node_name: str | None

    def conflicts_with(self, other: _ObservedIdentity) -> bool:
        return self.binary != other.binary or any(
            left is not None and right is not None and left != right
            for left, right in (
                (self.parent_id, other.parent_id),
                (self.ppid, other.ppid),
                (self.auid, other.auid),
                (self.node_name, other.node_name),
            )
        )


@dataclass(slots=True)
class _Execution:
    exec_id: str
    start_ns: int | None
    seen_ns: int
    identity: _ObservedIdentity | None
    active: bool = True


class _Rejected(ValueError):
    """A sensor event cannot be represented without losing evidence."""


def _report(reason: str, raw_ref: str, **fields: object) -> None:
    _LOG.warning(
        json.dumps(
            {"sensor": "tetragon", "reason": reason, "raw_ref": raw_ref, **fields}
        )
    )


def _obj(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _native_id(value: object) -> str | None:
    if (
        isinstance(value, str)
        and value.isascii()
        and value.isprintable()
        and " " not in value
    ):
        return value
    return None


def _integer(value: object) -> int | None:
    return value if type(value) is int else None


def _timestamp(value: object) -> tuple[str, int]:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise _Rejected("invalid_timestamp")
    seconds, fraction, offset = match.groups()
    try:
        whole = datetime.fromisoformat(seconds + offset.replace("Z", "+00:00"))
        whole = whole.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise _Rejected("invalid_timestamp") from exc
    elapsed = whole - _EPOCH
    nanos = int((fraction or "").ljust(9, "0"))
    utc = whole.replace(microsecond=nanos // 1000).isoformat(timespec="milliseconds")
    return (
        utc.replace("+00:00", "Z"),
        (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + nanos,
    )


def _argument(body: dict[str, Any], name: str) -> Any:
    args = body.get("args")
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, dict) and name in arg:
                return arg[name]
    return None


def _network(body: dict[str, Any]) -> NetworkInfo:
    sock = _obj(_argument(body, "sock_arg"))
    sport = _integer(sock.get("sport"))
    if sport is None or not 1 <= sport <= 65535:
        raise _Rejected("invalid_source_port")
    dport = _integer(sock.get("dport"))
    if dport is None or not 1 <= dport <= 65535:
        raise _Rejected("invalid_destination_port")
    if sock.get("protocol") != "IPPROTO_TCP":
        raise _Rejected("invalid_tcp_protocol")
    src = sock.get("saddr")
    dst = sock.get("daddr")
    if not isinstance(src, str) or not isinstance(dst, str):
        raise _Rejected("invalid_tcp_addresses")
    try:
        src_address = ipaddress.ip_address(src)
        dst_address = ipaddress.ip_address(dst)
    except ValueError as exc:
        raise _Rejected("invalid_tcp_addresses") from exc
    if (
        src_address.version != dst_address.version
        or src_address.is_unspecified
        or dst_address.is_unspecified
        or "%" in src
        or "%" in dst
    ):
        raise _Rejected("invalid_tcp_addresses")
    return NetworkInfo(
        protocol="TCP",
        src_ip=src,
        src_port=sport,
        dst_ip=dst,
        dst_port=dport,
        direction="outbound",
    )


def _file_access(
    body: dict[str, Any], attributes: dict[str, Any]
) -> Iterator[FileInfo]:
    # The return-enabled policy must explicitly report an integer zero.
    if "return" not in body:
        raise _Rejected("file_permission_result_missing")
    returned = body["return"]
    if not isinstance(returned, dict):
        raise _Rejected("file_permission_result_invalid")
    if "int_arg" not in returned:
        raise _Rejected("file_permission_result_missing")
    result = _integer(returned["int_arg"])
    if result is None:
        raise _Rejected("file_permission_result_invalid")
    if result != 0:
        raise _Rejected("file_permission_check_failed")
    path = _text(_obj(_argument(body, "file_arg")).get("path"))
    if path is None or not path.startswith("/") or "\0" in path:
        raise _Rejected("invalid_file_path")
    mask = _integer(_argument(body, "int_arg"))
    if mask not in (2, 4, 6):
        raise _Rejected("unsupported_file_permission_mask")
    attributes["permission_mask"] = mask
    attributes["permission_check"] = "allowed"
    if mask & 4:
        yield FileInfo(path=path, operation="read")
    if mask & 2:
        yield FileInfo(path=path, operation="write")


def _exit_info(body: dict[str, Any], attributes: dict[str, Any]) -> ExitInfo | None:
    # The exporter uses status and a signal name. A zero status can be omitted.
    exit_code = _integer(body.get("status"))
    raw_signal = _text(body.get("signal"))
    signum = None
    if raw_signal is not None:
        member = signal.Signals.__members__.get(raw_signal)
        if member is None:
            attributes["unmapped_signal"] = raw_signal
        else:
            signum = int(member)
    if exit_code is None and signum is None:
        return None
    return ExitInfo(exit_code=exit_code, signal=signum)


class TetragonAdapter:
    """Follow the export in order, beginning with the existing log contents."""

    def __init__(
        self,
        log_path: str | Path = "/var/log/tetragon/tetragon.log",
        endpoint_id: str = "linux-vm-01",
        *,
        follow: bool = True,
        poll_interval: float = 0.25,
        max_line_bytes: int = 1024 * 1024,
        identity_cache_size: int = 50_000,
        hash_cache_size: int = 4096,
    ) -> None:
        if not re.fullmatch(r"[a-z0-9-]+", endpoint_id):
            raise ValueError("invalid endpoint_id")
        if (
            min(max_line_bytes, identity_cache_size, hash_cache_size) < 1
            or poll_interval <= 0
        ):
            raise ValueError("cache, line and polling limits must be positive")
        self.log_path = Path(log_path).absolute()
        self.endpoint_id = endpoint_id
        self.follow = follow
        self.poll_interval = poll_interval
        self.max_line_bytes = max_line_bytes
        self.identity_cache_size = identity_cache_size
        self.hash_cache_size = hash_cache_size
        self._identities: OrderedDict[int, list[_Execution]] = OrderedDict()
        self._exits: OrderedDict[tuple[int, str], int | None] = OrderedDict()
        self._evicted_exit_ns: int | None = None
        self._hashes: OrderedDict[tuple[str, int, int, int, int, int], str] = (
            OrderedDict()
        )

    def events(self) -> Iterator[HostEvent]:
        """Yield events in export order. Close the iterator to release its file."""
        self._identities.clear()
        self._exits.clear()
        self._evicted_exit_ns = None
        for raw_ref, raw in self._raw_lines():
            try:
                line = raw.decode("utf-8")
                record = json.loads(line)
            except (UnicodeError, ValueError, RecursionError):
                _report("invalid_json", raw_ref)
                continue
            if not isinstance(record, dict):
                _report("invalid_json_record", raw_ref)
                continue
            try:
                yield from self._normalize(record, raw_ref, line)
            except _Rejected as exc:
                _report(str(exc), raw_ref)
            except (ValidationError, PydanticSerializationError, UnicodeError):
                _report("host_event_model_invalid", raw_ref)

    def _raw_lines(self) -> Iterator[tuple[str, bytes]]:
        """Open the successor, then drain the replaced inode before switching.

        Writers that append to the old inode after the final drain can still
        lose lines. Copytruncate can also overwrite unseen bytes or leave
        both byte checks unchanged. Archived logs are outside this reader.
        """
        successor: FileIO | None = None
        try:
            generation = 0
            last_error: int | None = None
            while True:
                try:
                    if successor is None:
                        log = self._open_export()
                    else:
                        log, successor = successor, None
                except OSError as exc:
                    if not self.follow:
                        raise
                    if exc.errno != last_error:
                        _report("log_open_failed", str(self.log_path), errno=exc.errno)
                        last_error = exc.errno
                    time.sleep(self.poll_interval)
                    continue
                with log:
                    fd = log.fileno()
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("Tetragon export must be a regular file")
                    last_error = None
                    file_id = (info.st_dev, info.st_ino)
                    pending = bytearray()
                    skipping = False
                    offset = start = 0
                    head = tail = b""
                    while True:
                        prefix = (
                            f"{self.log_path}:{file_id[0]}:{file_id[1]}:{generation}"
                        )
                        # A copytruncate writer can grow the file past the previous
                        # offset between reads. Compare bytes at both ends.
                        try:
                            if head and (
                                os.pread(fd, len(head), 0) != head
                                or os.pread(fd, len(tail), offset - len(tail)) != tail
                            ):
                                if pending:
                                    _report("incomplete_line", f"{prefix}:{start}")
                                log.seek(0)
                                generation += 1
                                pending.clear()
                                skipping = False
                                offset = start = 0
                                head = tail = b""
                                continue
                            chunk = log.read(_CHUNK_SIZE)
                        except OSError as exc:
                            if not self.follow:
                                raise
                            _report(
                                "log_read_failed", f"{prefix}:{offset}", errno=exc.errno
                            )
                            time.sleep(self.poll_interval)
                            continue

                        if not chunk:
                            if not self.follow:
                                if pending:
                                    _report("incomplete_line", f"{prefix}:{start}")
                                return
                            if successor is not None:
                                if pending:
                                    _report("incomplete_line", f"{prefix}:{start}")
                                generation += 1
                                break
                            try:
                                current = self.log_path.stat()
                            except FileNotFoundError:
                                # The writer may be between rename and recreation.
                                current = None
                            except OSError as exc:
                                _report(
                                    "log_stat_failed",
                                    str(self.log_path),
                                    errno=exc.errno,
                                )
                                current = None
                            if current and (current.st_dev, current.st_ino) != file_id:
                                try:
                                    successor = self._open_export()
                                    opened = os.fstat(successor.fileno())
                                except OSError as exc:
                                    if successor is not None:
                                        successor.close()
                                        successor = None
                                    if exc.errno != last_error:
                                        _report(
                                            "log_open_failed",
                                            str(self.log_path),
                                            errno=exc.errno,
                                        )
                                        last_error = exc.errno
                                else:
                                    if (opened.st_dev, opened.st_ino) != file_id:
                                        # Drain after opening the replacement, while
                                        # the old inode is still readable.
                                        continue
                                    successor.close()
                                    successor = None
                            time.sleep(self.poll_interval)
                            continue

                        if not head:
                            head = chunk[:64]
                        tail = (tail + chunk)[-64:]
                        pos = 0
                        while pos < len(chunk):
                            newline = chunk.find(b"\n", pos)
                            end = newline + 1 if newline >= 0 else len(chunk)
                            if not skipping:
                                if len(pending) + end - pos > self.max_line_bytes:
                                    _report("line_too_large", f"{prefix}:{start}")
                                    pending.clear()
                                    skipping = True
                                else:
                                    pending.extend(chunk[pos:end])
                            if newline >= 0:
                                if not skipping and pending.strip():
                                    yield f"{prefix}:{start}", bytes(pending)
                                pending.clear()
                                skipping = False
                                start = offset + end
                            pos = end
                        offset += len(chunk)
        finally:
            if successor is not None:
                successor.close()

    def _open_export(self) -> FileIO:
        return FileIO(os.open(self.log_path, os.O_RDONLY | os.O_NONBLOCK), "rb")

    def _normalize(
        self, record: dict[str, Any], raw_ref: str, raw_jsonl: str
    ) -> Iterator[HostEvent]:
        event_type: EventType
        if "process_exec" in record:
            event_type, kind = "process_start", "process_exec"
        elif "process_exit" in record:
            event_type, kind = "process_exit", "process_exit"
        elif "process_kprobe" in record:
            kind = "process_kprobe"
            function = _obj(record[kind]).get("function_name")
            if function == "tcp_connect":
                event_type = "network_connect"
            elif function == "security_file_permission":
                event_type = "file_access"
            else:
                return
        else:
            return
        body = _obj(record[kind])
        attributes: dict[str, Any] = {
            "sensor": "tetragon",
            "sensor_event_id": (
                body.get("function_name") if kind == "process_kprobe" else kind
            ),
            "raw_ref": raw_ref,
        }
        network = None
        files: list[FileInfo | None] = [None]
        try:
            if event_type == "network_connect":
                network = _network(body)
            elif event_type == "file_access":
                files = list(_file_access(body, attributes))
        except _Rejected as exc:
            _report(str(exc), raw_ref, raw_jsonl=raw_jsonl)
            return

        proc = _obj(body.get("process"))
        pid = _integer(proc.get("pid"))
        if pid is None or pid < 0:
            raise _Rejected("missing_process_pid")
        exec_id = _native_id(proc.get("exec_id"))
        event_ns = start_ns = None
        try:
            timestamp, event_ns = _timestamp(
                record.get("time")
                or (body.get("time") if event_type == "process_exit" else None)
            )
            start_time, start_ns = (
                _timestamp(proc["start_time"])
                if proc.get("start_time") is not None
                else (None, None)
            )
        finally:
            if event_type == "process_exit" and exec_id is not None:
                self._remember_exit(pid, exec_id, start_ns, event_ns)
        if event_type == "process_start" and exec_id is not None:
            if (pid, exec_id) in self._exits or any(
                row.exec_id == exec_id and not row.active
                for row in self._identities.get(pid, ())
            ):
                _report("process_start_after_exit", raw_ref, raw_jsonl=raw_jsonl)
                return
            if self._evicted_exit_ns is not None and (
                event_ns <= self._evicted_exit_ns
                or (start_ns is not None and start_ns <= self._evicted_exit_ns)
            ):
                # We can no longer tell a delayed start from a closed execution.
                _report(
                    "process_start_before_retained_exits", raw_ref, raw_jsonl=raw_jsonl
                )
                return
        binary = _text(proc.get("binary"))
        if binary is None or "\0" in binary:
            raise _Rejected("missing_or_invalid_process_binary")
        parent = _obj(body.get("parent"))
        parent_id = _native_id(proc.get("parent_exec_id"))
        parent_object_id = _native_id(parent.get("exec_id"))
        ppid = _integer(parent.get("pid"))
        if ppid is not None and ppid < 0:
            ppid = None
        flags = set((_text(proc.get("flags")) or "").split())
        parent_conflict = (
            parent_id is not None
            and parent_object_id is not None
            and parent_id != parent_object_id
        )
        if "taskWalk" in flags:
            parent_id = ppid = None
            attributes["parent_unresolved"] = "sensor_task_walk"
        elif parent_conflict:
            parent_id = ppid = None
            attributes["parent_unresolved"] = "conflicting_sensor_parent"
        else:
            parent_id = parent_id or parent_object_id
        auid = _integer(proc.get("auid"))
        # An audit UID can be unset even for a valid process observation.
        if auid is not None and not 0 <= auid < 0xFFFFFFFF:
            auid = None
        identity = (
            None
            if parent_conflict or "taskWalk" in flags or binary == "<unknown>"
            else _ObservedIdentity(
                binary, parent_id, ppid, auid, _text(record.get("node_name"))
            )
        )
        resolution = "native"
        if kind == "process_kprobe":
            exec_id, resolution = self._probe_identity(
                pid, exec_id, start_ns, event_ns, identity
            )
            if exec_id is None:
                _report("missing_process_identity", raw_ref, raw_jsonl=raw_jsonl)
                return
        if exec_id is None:
            raise _Rejected("missing_process_identity")
        # A procFS snapshot identifies an existing process without observing its start.
        if event_type == "process_start" and "procFS" in flags:
            resolution = "placeholder"
            attributes["placeholder"] = True
        attributes["identity_resolution"] = resolution

        uid = _integer(proc.get("uid"))
        user = None
        if uid is not None and uid >= 0:
            attributes["uid"] = uid
            try:
                user = pwd.getpwuid(uid).pw_name
            except (KeyError, OverflowError, OSError):
                pass

        command_line = None
        sha256 = None
        exit_info = None
        if event_type == "process_start":
            arguments = _text(proc.get("arguments"))
            command_line = f"{binary} {arguments}" if arguments else binary
            sha256, skipped = self._binary_hash(binary)
            if skipped:
                attributes["hash_skipped"] = skipped
            if sha256:
                # This identifies the file at collection time. A replay may
                # find different bytes at the same path than the process ran.
                attributes["hash_basis"] = "path_at_collection"
        elif event_type == "process_exit":
            exit_info = _exit_info(body, attributes)

        for file_info in files:
            event = HostEvent(
                event_id=new_event_id(self.endpoint_id),
                endpoint_id=self.endpoint_id,
                os="linux",
                timestamp_utc=timestamp,
                event_type=event_type,
                process_instance_id=f"{self.endpoint_id}:{exec_id}",
                parent_process_instance_id=(
                    f"{self.endpoint_id}:{parent_id}" if parent_id else None
                ),
                pid=pid,
                ppid=ppid,
                binary=binary,
                command_line=command_line,
                user=user,
                sha256=sha256,
                process_start_time_utc=start_time,
                file=file_info,
                network=network,
                exit=exit_info,
                attributes=attributes,
            )
            payload = event.model_dump(mode="json", by_alias=True, exclude_none=True)
            if validate_against_schema("host_event", payload) != []:
                raise _Rejected("host_event_schema_invalid")
            if event_type == "process_start":
                self._remember_execution(
                    pid, _Execution(exec_id, start_ns, event_ns, identity)
                )
            yield event

    def _probe_identity(
        self,
        pid: int,
        exec_id: str | None,
        start_ns: int | None,
        event_ns: int,
        identity: _ObservedIdentity | None,
    ) -> tuple[str | None, str]:
        if exec_id is not None and (pid, exec_id) in self._exits:
            return exec_id, "native"
        history = self._identities.get(pid)
        if history:
            self._identities.move_to_end(pid)
            if any(row.exec_id == exec_id for row in history):
                return exec_id, "native"
            if start_ns is not None:
                candidates = [
                    row
                    for row in history
                    if row.start_ns is not None
                    and abs(row.start_ns - start_ns) <= _IDENTITY_TOLERANCE_NS
                ]
                latest = history[0]
                if (
                    candidates == [latest]
                    and latest.active
                    and latest.start_ns is not None
                    and latest.start_ns <= event_ns
                    and start_ns <= event_ns
                    and identity is not None
                    and latest.identity is not None
                    and not identity.conflicts_with(latest.identity)
                ):
                    return latest.exec_id, "pid_start_time"
        return exec_id, "unknown"

    def _remember_execution(self, pid: int, execution: _Execution) -> None:
        history = self._identities.setdefault(pid, [])
        self._identities.move_to_end(pid)
        if all(row.exec_id != execution.exec_id for row in history):
            history.append(execution)
            history.sort(
                key=lambda row: (
                    row.start_ns if row.start_ns is not None else row.seen_ns,
                    not row.active,
                ),
                reverse=True,
            )
            del history[2:]
        if len(self._identities) > self.identity_cache_size:
            self._identities.popitem(last=False)

    def _remember_exit(
        self, pid: int, exec_id: str, start_ns: int | None, event_ns: int | None
    ) -> None:
        # Keep exits even when their exec has not arrived.
        key = (pid, exec_id)
        previous = self._exits.get(key)
        if previous is not None and (event_ns is None or previous > event_ns):
            event_ns = previous
        self._exits[key] = event_ns
        self._exits.move_to_end(key)
        if len(self._exits) > self.identity_cache_size:
            _, evicted_ns = self._exits.popitem(last=False)
            if evicted_ns is not None and (
                self._evicted_exit_ns is None or evicted_ns > self._evicted_exit_ns
            ):
                self._evicted_exit_ns = evicted_ns
        for row in self._identities.get(pid, ()):
            if row.exec_id == exec_id:
                row.active = False
                return
        if event_ns is not None:
            # An exit can be the first observation of a different execution
            # on this PID. An unknown start time cannot prove it was older.
            self._remember_execution(
                pid, _Execution(exec_id, start_ns, event_ns, None, active=False)
            )

    def _binary_hash(self, path: str) -> tuple[str | None, str | None]:
        if not os.path.isabs(path) or "\0" in path:
            return None, "unreadable"
        try:
            named = os.stat(path)
            if not stat.S_ISREG(named.st_mode):
                return None, "not_regular"
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    return None, "not_regular"
                if before.st_size > _HASH_LIMIT:
                    return None, "too_large"
                key = (
                    path,
                    before.st_mtime_ns,
                    before.st_size,
                    before.st_dev,
                    before.st_ino,
                    before.st_ctime_ns,
                )
                if key in self._hashes:
                    self._hashes.move_to_end(key)
                    return self._hashes[key], None
                digest = hashlib.sha256()
                remaining = _HASH_LIMIT + 1
                while remaining:
                    piece = os.read(fd, min(remaining, _CHUNK_SIZE))
                    if not piece:
                        break
                    digest.update(piece)
                    remaining -= len(piece)
                if not remaining:
                    return None, "too_large"
                after = os.fstat(fd)
                if (after.st_mtime_ns, after.st_size, after.st_ctime_ns) != (
                    before.st_mtime_ns,
                    before.st_size,
                    before.st_ctime_ns,
                ):
                    return None, "changed_during_read"
                value = digest.hexdigest()
            finally:
                os.close(fd)
        except OSError:
            return None, "unreadable"
        self._hashes[key] = value
        if len(self._hashes) > self.hash_cache_size:
            self._hashes.popitem(last=False)
        return value, None
