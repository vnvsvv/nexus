"""Predicate evaluation (task A3a): does one HostEvent satisfy the ``where`` of a loaded rule step?

Pure functions over the immutable A2 ``Predicate`` models and ``nexus_contracts.HostEvent``. No state, no
clock, no graph, no I/O and no mutation of the event.

Public API
    ``get_field(event, path)``                      value of a rule field path, or None when absent
    ``evaluate_predicate(pred, event, regex_backend=None)``   one predicate -> bool
    ``evaluate_where(preds, event, regex_backend=None)``      all predicates must hold (AND) -> bool
    ``has_regex(preds)``                            True if any predicate needs a regex backend
    ``RegexBackend`` (Protocol), ``RegexTimeout``, ``MAX_REGEX_INPUT_CHARS``

Semantics (contracts/rules/RULE-FORMAT.md)
    * A missing, optional or unusable value never matches, for every operator, including ``not_in_cidr``.
      The placeholder binary ``"<unknown>"`` counts as missing: nothing was observed.
    * Comparisons are typed: ``True`` is not ``1``, ``"80"`` is not ``80``, a bool matches only a bool. Numbers
      compare across int and float.
    * Windows events (``event.os == "windows"``): string comparisons (``equals``, ``in``, ``prefix_any``,
      ``endswith_any``, ``contains_any``) are case-insensitive and treat ``\\`` as ``/`` on both sides.
      Linux events compare exactly. ``regex`` is never normalized: it sees the raw text, as written.
    * ``network.dst_ip`` is compared as an address, not as text, by ``equals``, ``in``, ``in_cidr`` and
      ``not_in_cidr``: equivalent IPv6 spellings are equal, and an IPv4-mapped IPv6 address IS the IPv4 address
      in all four operators, whether the mapped form appears in the event, in an ``equals``/``in`` operand or in a
      CIDR (``::ffff:10.0.0.0/104`` is ``10.0.0.0/8``). Networks wider than the mapped range (``::/0``) do not
      contain IPv4 addresses. An unparsable address never matches. The text operators (``prefix_any``...) still
      see the text as emitted.
    * ``attributes.<key>`` values keep whatever type the sensor gave; only a scalar of the same type can match.
    * An empty predicate sequence is vacuously true (a threshold rule may have no ``where``).

Security
    * ``regex`` fails closed. Python's ``re`` backtracks and has no timeout, so this module never calls a
      compiled pattern (``Predicate.compiled`` is not touched). Without a ``RegexBackend`` a regex predicate is
      False. Callers that want to know in advance use ``has_regex`` (the engine disables such rules visibly).
      With a backend, the *pattern text* and the raw event text go to ``backend.search``; text longer than
      ``MAX_REGEX_INPUT_CHARS`` is never sent (False, not truncated, so semantics cannot change silently); a
      ``RegexTimeout`` is False; any other backend exception propagates (a defect must not be hidden).
    * Caches only hold values that come from rules or short address strings (at most 64 characters); event text
      such as command lines is never cached, so an attacker cannot grow memory through event content.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Any, Final, Protocol, Sequence

from nexus_contracts import HostEvent

from .graph import UNKNOWN_BINARY
from .rules import Predicate

MAX_REGEX_INPUT_CHARS: Final = 4096
_MAX_IP_TEXT: Final = 64
_IP_FIELDS: Final = frozenset({"network.dst_ip"})          # fields compared as addresses (kept in sync by a test)
_WINDOWS: Final = "windows"


class RegexTimeout(Exception):
    """Raised by a ``RegexBackend`` when one match exceeded its time budget; the predicate is then False."""


class RegexBackend(Protocol):
    """A safe regular-expression engine. Not provided yet: without one, regex predicates fail closed."""

    def search(self, pattern: str, text: str) -> bool:
        """True if ``pattern`` is found in ``text``. Must bound its own running time (raise ``RegexTimeout``)."""
        ...


# ---------------------------------------------------------------------------------------------- field access
def get_field(event: HostEvent, path: str) -> Any:
    """Value of a rule field path on ``event``, or None when the event does not carry it (or the path is unknown)."""
    if path.startswith("attributes."):
        return event.attributes.get(path[len("attributes."):])
    if path == "binary":
        return None if event.binary == UNKNOWN_BINARY else event.binary
    if path in ("command_line", "user", "sha256"):
        return getattr(event, path)
    head, _, tail = path.partition(".")
    if head == "file" and event.file is not None and tail in ("path", "operation"):
        return getattr(event.file, tail)
    if head == "network" and event.network is not None and tail in (
            "protocol", "src_port", "dst_ip", "dst_port", "direction"):
        return getattr(event.network, tail)
    if head == "dns" and event.dns is not None and tail == "query":
        return event.dns.query
    return None


# ---------------------------------------------------------------------------------------------- helpers
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _fold(text: str) -> str:
    """Windows comparison key: case-insensitive, ``\\`` equals ``/``. NOT cached: ``text`` may be event content."""
    return text.replace("\\", "/").casefold()


@lru_cache(maxsize=2048)
def _fold_operand(text: str) -> str:
    """Same key for a rule operand (a small, rule-controlled set, so caching it is safe)."""
    return _fold(text)


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Canonical address for ``text`` or None. The length check sits outside the cache so a long string from an
    event is rejected without ever becoming a cache key."""
    return None if len(text) > _MAX_IP_TEXT else _parse_ip(text)


@lru_cache(maxsize=4096)
def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.scope_id:
            return ipaddress.IPv6Address(int(address))
    return address


_MAPPED_RANGE: Final = ipaddress.ip_network("::ffff:0:0/96")


@lru_cache(maxsize=512)
def _parse_networks(operand: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(text, strict=True) for text in operand)


@lru_cache(maxsize=512)
def _canonical_networks(networks: tuple) -> tuple:
    """Rewrite a network written in IPv4-mapped IPv6 form (``::ffff:10.0.0.0/104``) as the IPv4 network it is
    (``10.0.0.0/8``), so it agrees with addresses, which ``_ip`` canonicalizes the same way. A network that is
    wider than the mapped range (``::/0``) or unrelated to it is left alone: IPv6 networks do not contain IPv4
    addresses, exactly as an IPv4 network does not contain a native IPv6 address."""
    out = []
    for network in networks:
        if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96 and network.subnet_of(_MAPPED_RANGE):
            network = ipaddress.IPv4Network((network.network_address.ipv4_mapped, network.prefixlen - 96))
        out.append(network)
    return tuple(out)


def _networks(pred: Predicate) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """The CIDR networks A2 compiled, or (for a hand-built predicate) parsed from the operand, in canonical form."""
    raw = pred.compiled if isinstance(pred.compiled, tuple) else _parse_networks(tuple(pred.operand))
    return _canonical_networks(raw)


def _equal(field: str, value: Any, operand: Any, windows: bool) -> bool:
    if field in _IP_FIELDS:
        if not isinstance(value, str) or not isinstance(operand, str):
            return False
        left, right = _ip(value), _ip(operand)
        return left is not None and left == right
    if isinstance(value, bool) or isinstance(operand, bool):
        return isinstance(value, bool) and isinstance(operand, bool) and value == operand
    if isinstance(operand, str):
        if not isinstance(value, str):
            return False
        return _fold(value) == _fold_operand(operand) if windows else value == operand
    if _is_number(operand):
        return _is_number(value) and value == operand
    return False


def _regex(pred: Predicate, value: Any, backend: RegexBackend | None) -> bool:
    if backend is None or not isinstance(value, str) or not isinstance(pred.operand, str):
        return False                                   # fail closed; ``Predicate.compiled`` is deliberately never used
    if len(value) > MAX_REGEX_INPUT_CHARS:
        return False
    try:
        return bool(backend.search(pred.operand, value))
    except RegexTimeout:
        return False


# ---------------------------------------------------------------------------------------------- evaluation
def _apply(pred: Predicate, value: Any, windows: bool, backend: RegexBackend | None) -> bool:
    if value is None:
        return False
    op = pred.op
    if op == "equals":
        return _equal(pred.field, value, pred.operand, windows)
    if op == "in":
        return any(_equal(pred.field, value, item, windows) for item in pred.operand)
    if op in ("prefix_any", "endswith_any", "contains_any"):
        if not isinstance(value, str):
            return False
        text = _fold(value) if windows else value
        operands = (_fold_operand(item) for item in pred.operand) if windows else pred.operand
        if op == "prefix_any":
            return any(text.startswith(item) for item in operands)
        if op == "endswith_any":
            return any(text.endswith(item) for item in operands)
        return any(item in text for item in operands)
    if op in ("gte", "lte"):
        if not _is_number(value) or not _is_number(pred.operand):
            return False
        return value >= pred.operand if op == "gte" else value <= pred.operand
    if op in ("in_cidr", "not_in_cidr"):
        address = _ip(value) if isinstance(value, str) else None
        if address is None:
            return False                               # even not_in_cidr: an unusable address proves nothing
        inside = any(address in network for network in _networks(pred))
        return inside if op == "in_cidr" else not inside
    if op == "regex":
        return _regex(pred, value, backend)
    return False                                       # an operator this module does not know fails closed


def evaluate_predicate(pred: Predicate, event: HostEvent, *, regex_backend: RegexBackend | None = None) -> bool:
    """True if ``event`` satisfies this one predicate."""
    return _apply(pred, get_field(event, pred.field), event.os == _WINDOWS, regex_backend)


def evaluate_where(preds: Sequence[Predicate], event: HostEvent, *, regex_backend: RegexBackend | None = None) -> bool:
    """True if ``event`` satisfies every predicate (several operators on one field are ANDed). Empty means True."""
    windows = event.os == _WINDOWS
    values: dict[str, Any] = {}
    for pred in preds:
        if pred.field not in values:
            values[pred.field] = get_field(event, pred.field)
        if not _apply(pred, values[pred.field], windows, regex_backend):
            return False
    return True


def has_regex(preds: Sequence[Predicate]) -> bool:
    """True if any predicate is a regex, i.e. cannot be evaluated without a ``RegexBackend``."""
    return any(pred.op == "regex" for pred in preds)
