"""Predicate evaluation tests (task A3a). Pure functions: no graph, no engine, no rule matching."""
from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any

import pytest
from nexus_contracts import HostEvent
from nexus_endpoint_core import predicates as P_
from nexus_endpoint_core import rules as rules_module
from nexus_endpoint_core.predicates import (MAX_REGEX_INPUT_CHARS, RegexTimeout, evaluate_predicate, evaluate_where,
                                            get_field, has_regex)
from nexus_endpoint_core.rules import FIELD_PATHS, Predicate, load_rules

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "contracts" / "rules"
FIX = ROOT / "contracts" / "fixtures" / "rules"
_ids = iter(range(1, 10_000_000))


# ------------------------------------------------------------------ builders
def event(os_: str = "linux", event_type: str = "process_start", binary: str = "/usr/bin/python3",
          command_line: str | None = None, user: str | None = None, sha256: str | None = None,
          file: dict | None = None, network: dict | None = None, dns: dict | None = None,
          attributes: dict | None = None) -> HostEvent:
    body: dict[str, Any] = {
        "event_id": f"ep-01:evt-{next(_ids):012x}", "endpoint_id": "ep-01", "os": os_,
        "timestamp_utc": "2026-11-15T10:00:00.000Z", "event_type": event_type, "process_instance_id": "ep-01:p",
        "pid": 10, "binary": binary, "command_line": command_line, "user": user, "sha256": sha256,
        "file": file, "network": network, "dns": dns, "attributes": attributes or {},
    }
    return HostEvent.model_validate({k: v for k, v in body.items() if v is not None})


def net(dst_ip: str = "10.0.0.2", dst_port: int = 80, direction: str = "outbound", protocol: str = "TCP",
        src_port: int = 50000) -> dict:
    return {"protocol": protocol, "src_ip": "10.0.0.1", "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port,
            "direction": direction}


def pred(field: str, op: str, operand: Any, compile_cidr: bool = True) -> Predicate:
    """Hand-built predicate shaped like the ones the A2 loader produces."""
    compiled = None
    if op in ("in", "prefix_any", "endswith_any", "contains_any", "in_cidr", "not_in_cidr"):
        operand = tuple(operand)
    if op in ("in_cidr", "not_in_cidr") and compile_cidr:
        compiled = tuple(ipaddress.ip_network(text) for text in operand)
    return Predicate(field=field, op=op, operand=operand, compiled=compiled)


def check(p: Predicate, e: HostEvent, **kw) -> bool:
    return evaluate_predicate(p, e, **kw)


class Backend:
    """A fake RegexBackend that records what it was asked."""

    def __init__(self, result: bool = True, raises: BaseException | None = None) -> None:
        self.result, self.raises, self.calls = result, raises, []

    def search(self, pattern: str, text: str) -> bool:
        self.calls.append((pattern, text))
        if self.raises is not None:
            raise self.raises
        return self.result


class Tripwire:
    """Stands in for a compiled stdlib pattern: any use is a failure (the module must never run ``re`` on events)."""

    def __getattr__(self, name: str):
        raise AssertionError(f"compiled pattern was used: {name}")


# ------------------------------------------------------------------ field access
def test_every_rule_field_path_resolves_on_a_full_event():
    full = event(command_line="c", user="u", sha256="a" * 64, file={"path": "/f", "operation": "read"},
                 network=net(), dns={"query": "a.test"}, attributes={"k": 1})
    expected = {"binary": "/usr/bin/python3", "command_line": "c", "user": "u", "sha256": "a" * 64, "file.path": "/f",
                "file.operation": "read", "network.protocol": "TCP", "network.src_port": 50000,
                "network.dst_ip": "10.0.0.2", "network.dst_port": 80, "network.direction": "outbound",
                "dns.query": "a.test"}
    assert set(expected) == set(FIELD_PATHS)
    for path, value in expected.items():
        assert get_field(full, path) == value, path
    assert get_field(full, "attributes.k") == 1


def test_absent_values_are_none_not_errors():
    bare = event()
    for path in FIELD_PATHS - {"binary"}:
        assert get_field(bare, path) is None, path
    assert get_field(bare, "attributes.missing") is None
    assert get_field(bare, "nonsense.path") is None and get_field(bare, "file") is None and get_field(bare, "") is None
    assert get_field(bare, "file.new_path") is None and get_field(bare, "network.src_ip") is None   # not rule fields


def test_the_unknown_binary_placeholder_counts_as_missing():
    placeholder = event(binary="<unknown>")
    assert get_field(placeholder, "binary") is None
    for op, operand in (("equals", "<unknown>"), ("contains_any", ["unknown"]), ("endswith_any", [">"]),
                        ("prefix_any", ["<"])):
        assert not check(pred("binary", op, operand), placeholder)


def test_the_ip_field_set_matches_the_loader():
    assert P_._IP_FIELDS == {f for f in FIELD_PATHS if rules_module._FIELDS[f].kind == "ip"}


def test_evaluation_never_mutates_the_event():
    e = event(os_="windows", command_line="C:\\X", network=net(), attributes={"a": [1]})
    before = e.model_dump()
    for p in (pred("command_line", "contains_any", ["x"]), pred("network.dst_ip", "in_cidr", ["10.0.0.0/8"]),
              pred("attributes.a", "equals", 1)):
        check(p, e)
    evaluate_where((pred("binary", "prefix_any", ["/"]),), e)
    assert e.model_dump() == before


# ------------------------------------------------------------------ equals / in, typing
@pytest.mark.parametrize("value, operand, expected", [
    ("abc", "abc", True), ("abc", "ABC", False), ("abc", "ab", False), (1, 1, True), (1, 1.0, True), (1.5, 1.5, True),
    (1, "1", False), ("1", 1, False), (True, True, True), (False, False, True), (True, False, False),
    (True, 1, False), (1, True, False), (0, False, False), (False, 0, False), (None, "x", False),
    ([1], 1, False), ({"a": 1}, "a", False), ("true", True, False), (True, "true", False),
])
def test_equals_is_typed_on_attributes(value, operand, expected):
    e = event(attributes={"k": value} if value is not None else {})
    assert check(pred("attributes.k", "equals", operand), e) is expected


def test_equals_on_ports_is_numeric_only():
    e = event(network=net(dst_port=443))
    assert check(pred("network.dst_port", "equals", 443), e)
    assert not check(pred("network.dst_port", "equals", 80), e)
    assert not check(pred("network.dst_port", "equals", "443"), e)
    assert not check(pred("network.dst_port", "equals", True), e)


def test_in_matches_any_member_with_typed_comparison():
    e = event(file={"path": "/f", "operation": "create"})
    assert check(pred("file.operation", "in", ["create", "write"]), e)
    assert not check(pred("file.operation", "in", ["read", "delete"]), e)
    assert not check(pred("file.operation", "in", ["CREATE"]), e)                       # Linux is exact
    ports = event(network=net(dst_port=8080))
    assert check(pred("network.dst_port", "in", [80, 8080]), ports)
    assert not check(pred("network.dst_port", "in", ["8080", True]), ports)
    flag = event(attributes={"k": True})
    assert check(pred("attributes.k", "in", [1, True]), flag) and not check(pred("attributes.k", "in", [1, "True"]), flag)


# ------------------------------------------------------------------ text operators, Linux vs Windows
@pytest.mark.parametrize("op, operand, value, linux, windows", [
    ("equals", "C:\\Lab\\a.exe", "c:/lab/A.EXE", False, True),
    ("equals", "c:/lab/a.exe", "C:\\LAB\\A.exe", False, True),
    ("equals", "C:\\Lab\\a.exe", "C:\\Lab\\a.exe", True, True),
    ("equals", "C:\\Lab\\a.exe", "C:\\Lab\\b.exe", False, False),
    ("prefix_any", ["C:\\Lab\\staging\\"], "c:\\lab\\STAGING\\report.zip", False, True),
    ("prefix_any", ["C:\\Lab\\staging\\"], "C:\\Lab\\staging\\report.zip", True, True),
    ("prefix_any", ["C:\\Lab\\bin\\"], "C:\\Lab\\binary\\x.exe", False, False),
    ("endswith_any", ["\\powershell.exe"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE", False, True),
    ("endswith_any", ["/bash", "/sh"], "/usr/bin/bash", True, True),
    ("endswith_any", ["/bash"], "/usr/bin/BASH", False, True),
    ("contains_any", ["-executionpolicy bypass"], "powershell.exe -ExecutionPolicy Bypass -File x", False, True),
    ("contains_any", ["-enc", "-ep bypass"], "powershell -EP BYPASS", False, True),
    ("contains_any", ["whoami"], "cmd /c whoami", True, True),
    ("contains_any", ["whoami"], "cmd /c ls", False, False),
    ("prefix_any", ["/lab/bin/"], "/lab/bin/beacon-sim", True, True),
    ("prefix_any", ["/lab/bin/"], "/lab\\bin/beacon-sim", False, True),                  # a backslash is a slash only on Windows
])
def test_string_operators_follow_the_os_of_the_event(op, operand, value, linux, windows):
    for os_, expected in (("linux", linux), ("windows", windows)):
        e = event(os_=os_, binary=value)
        assert check(pred("binary", op, operand), e) is expected, (os_, op)


def test_windows_normalization_applies_to_every_string_field():
    e = event(os_="windows", user="LAB\\Student", command_line="CMD /C Dir C:\\Temp", sha256="ab" * 32,
              dns={"query": "Noise.Nexus.TEST"}, attributes={"s": "MiXeD"})
    assert check(pred("user", "equals", "lab\\student"), e)
    assert check(pred("command_line", "contains_any", ["c:/temp"]), e)
    assert check(pred("dns.query", "endswith_any", [".nexus.test"]), e)
    assert check(pred("attributes.s", "equals", "mixed"), e)
    assert check(pred("sha256", "equals", "AB" * 32), e)                                  # a hash compares case-insensitively on Windows
    linux = event(os_="linux", user="LAB\\Student", dns={"query": "Noise.Nexus.TEST"}, attributes={"s": "MiXeD"})
    assert not check(pred("user", "equals", "lab\\student"), linux)
    assert not check(pred("dns.query", "endswith_any", [".nexus.test"]), linux)
    assert not check(pred("attributes.s", "equals", "mixed"), linux)


def test_text_operators_need_a_string_value():
    e = event(attributes={"n": 5, "b": True, "l": ["a"]})
    for key in ("n", "b", "l"):
        for op in ("prefix_any", "endswith_any", "contains_any"):
            assert not check(pred(f"attributes.{key}", op, ["a", "5"]), e)


def test_text_operators_on_destination_ip_see_the_text_as_emitted():
    e = event(network=net(dst_ip="192.168.20.10"))
    assert check(pred("network.dst_ip", "prefix_any", ["192.168."]), e)
    assert check(pred("network.dst_ip", "endswith_any", [".10"]), e)
    assert not check(pred("network.dst_ip", "contains_any", ["10.0"]), e)


def test_huge_event_text_is_handled_without_caching_it():
    big = "A" * 1_000_000 + "needle"
    before = P_._fold_operand.cache_info().currsize
    t = time.perf_counter()
    assert check(pred("command_line", "contains_any", ["NEEDLE"]), event(os_="windows", command_line=big))
    assert not check(pred("command_line", "contains_any", ["needle"]), event(os_="linux", command_line=big.lower().upper()))
    assert time.perf_counter() - t < 5
    for i in range(3000):                                   # distinct event strings must not grow the operand cache
        check(pred("command_line", "contains_any", ["x"]), event(os_="windows", command_line=f"cmd {i}"))
    assert P_._fold_operand.cache_info().currsize <= before + 1


# ------------------------------------------------------------------ numbers
@pytest.mark.parametrize("value, op, operand, expected", [
    (10, "gte", 10, True), (9, "gte", 10, False), (10, "lte", 10, True), (11, "lte", 10, False),
    (10.5, "gte", 10, True), (10, "gte", 9.99, True), (0, "lte", 0, True), (-1, "gte", 0, False),
    ("10", "gte", 5, False), (True, "gte", 0, False), (True, "lte", 5, False), (None, "gte", 0, False),
    ([10], "gte", 5, False),
])
def test_numeric_operators(value, op, operand, expected):
    e = event(attributes={"n": value} if value is not None else {})
    assert check(pred("attributes.n", op, operand), e) is expected


def test_numeric_operators_on_ports_and_a_boolean_operand():
    e = event(network=net(dst_port=1024, src_port=0))
    assert check(pred("network.dst_port", "gte", 1024), e) and not check(pred("network.dst_port", "gte", 1025), e)
    assert check(pred("network.src_port", "lte", 0), e)                                  # zero is a value, not "missing"
    assert not check(pred("network.dst_port", "gte", True), e)


# ------------------------------------------------------------------ IP addresses and CIDR
@pytest.mark.parametrize("value, operand, expected", [
    ("::1", "0:0:0:0:0:0:0:1", True), ("0000:0000:0000:0000:0000:0000:0000:0001", "::1", True),
    ("2001:DB8::1", "2001:0db8:0:0:0:0:0:1", True), ("2001:db8::1", "2001:db8::2", False),
    ("::ffff:192.168.1.1", "192.168.1.1", True), ("192.168.1.1", "::ffff:c0a8:101", True),
    ("192.168.1.1", "192.168.1.1", True), ("192.168.1.1", "192.168.1.2", False), ("10.0.0.1", "::1", False),
    ("fe80::1%eth0", "fe80::1", True),
    ("not-an-ip", "not-an-ip", False), ("", "", False), ("999.1.1.1", "999.1.1.1", False),
    ("010.0.0.1", "10.0.0.1", False), (" 10.0.0.1", "10.0.0.1", False), ("10.0.0.1", "10.0.0.1/32", False),
])
def test_ip_equals_compares_addresses_not_text(value, operand, expected):
    e = event(network=net(dst_ip=value))
    assert check(pred("network.dst_ip", "equals", operand), e) is expected
    assert check(pred("network.dst_ip", "in", [operand]), e) is expected


@pytest.mark.parametrize("address, cidrs, inside", [
    ("10.0.0.0", ["10.0.0.0/8"], True), ("10.255.255.255", ["10.0.0.0/8"], True), ("11.0.0.0", ["10.0.0.0/8"], False),
    ("9.255.255.255", ["10.0.0.0/8"], False), ("192.168.20.1", ["192.168.20.1/32"], True),
    ("192.168.20.2", ["192.168.20.1/32"], False), ("127.0.0.1", ["127.0.0.0/8", "192.168.20.1/32"], True),
    ("192.168.20.1", ["127.0.0.0/8", "192.168.20.1/32"], True), ("8.8.8.8", ["127.0.0.0/8", "192.168.20.1/32"], False),
    ("::1", ["::1/128"], True), ("::2", ["::1/128"], False), ("::1", ["127.0.0.0/8"], False),
    ("127.0.0.1", ["::1/128"], False), ("2001:db8:ffff::1", ["2001:db8::/32"], True),
    ("2001:db9::1", ["2001:db8::/32"], False), ("::ffff:127.0.0.1", ["127.0.0.0/8"], True),
    ("fe80::1%eth0", ["fe80::/10"], True), ("0:0:0:0:0:0:0:1", ["::1/128"], True),
])
def test_cidr_operators_cover_v4_v6_and_mapped_addresses(address, cidrs, inside):
    e = event(network=net(dst_ip=address))
    for compile_cidr in (True, False):                                                # A2-compiled and hand-built predicates
        assert check(pred("network.dst_ip", "in_cidr", cidrs, compile_cidr), e) is inside
        assert check(pred("network.dst_ip", "not_in_cidr", cidrs, compile_cidr), e) is (not inside)


# One address, four spellings; one network, three spellings; all four operators must agree (A3a review decision 3).
V4_FORMS = ["10.1.2.3", "::ffff:10.1.2.3", "::ffff:a01:203", "0:0:0:0:0:ffff:10.1.2.3"]
OUTSIDE_FORMS = ["11.1.2.3", "::ffff:11.1.2.3", "::ffff:b01:203"]


@pytest.mark.parametrize("address", V4_FORMS)
@pytest.mark.parametrize("operand", ["10.1.2.3", "::ffff:10.1.2.3", "::ffff:a01:203"])
def test_mapped_and_plain_spellings_are_equal_in_equals_and_in(address, operand):
    e = event(network=net(dst_ip=address))
    assert check(pred("network.dst_ip", "equals", operand), e)
    assert check(pred("network.dst_ip", "in", ["192.0.2.1", operand]), e)
    other = event(network=net(dst_ip="10.1.2.4"))
    assert not check(pred("network.dst_ip", "equals", operand), other)
    assert not check(pred("network.dst_ip", "in", [operand]), other)


@pytest.mark.parametrize("compile_cidr", [True, False])
@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "::ffff:10.0.0.0/104", "::ffff:a00:0/104"])
def test_mapped_and_plain_spellings_agree_in_in_cidr_and_not_in_cidr(cidr, compile_cidr):
    for address in V4_FORMS:
        e = event(network=net(dst_ip=address))
        assert check(pred("network.dst_ip", "in_cidr", [cidr], compile_cidr), e), (cidr, address)
        assert not check(pred("network.dst_ip", "not_in_cidr", [cidr], compile_cidr), e), (cidr, address)
    for address in OUTSIDE_FORMS:
        e = event(network=net(dst_ip=address))
        assert not check(pred("network.dst_ip", "in_cidr", [cidr], compile_cidr), e), (cidr, address)
        assert check(pred("network.dst_ip", "not_in_cidr", [cidr], compile_cidr), e), (cidr, address)


def test_mapped_network_edges_and_family_separation():
    mapped_all = pred("network.dst_ip", "in_cidr", ["::ffff:0:0/96"])                    # every IPv4 address, in mapped form
    assert check(mapped_all, event(network=net(dst_ip="8.8.8.8"))) and check(mapped_all, event(network=net(dst_ip="::ffff:8.8.8.8")))
    assert not check(mapped_all, event(network=net(dst_ip="2001:db8::1")))
    host = pred("network.dst_ip", "in_cidr", ["::ffff:10.1.2.3/128"])                       # one mapped host is the IPv4 /32
    assert check(host, event(network=net(dst_ip="10.1.2.3"))) and not check(host, event(network=net(dst_ip="10.1.2.4")))
    wide = pred("network.dst_ip", "in_cidr", ["::/0"])                                      # wider than the mapped range: IPv6 only
    assert check(wide, event(network=net(dst_ip="2001:db8::1")))
    assert not check(wide, event(network=net(dst_ip="1.2.3.4"))) and not check(wide, event(network=net(dst_ip="::ffff:1.2.3.4")))
    assert not check(pred("network.dst_ip", "not_in_cidr", ["::/0"]), event(network=net(dst_ip="2001:db8::1")))
    assert check(pred("network.dst_ip", "not_in_cidr", ["::/0"]), event(network=net(dst_ip="1.2.3.4")))
    mixed = pred("network.dst_ip", "in_cidr", ["::ffff:10.0.0.0/104", "2001:db8::/32"])
    assert check(mixed, event(network=net(dst_ip="10.9.9.9"))) and check(mixed, event(network=net(dst_ip="2001:db8::5")))
    assert not check(mixed, event(network=net(dst_ip="2001:db9::5")))


def test_a_boolean_never_equals_a_number_in_any_operator():
    flag, zero = event(attributes={"k": True}), event(attributes={"k": 0})
    for operand in (1, 1.0, 0, 0.0):
        assert not check(pred("attributes.k", "equals", operand), flag)
        assert not check(pred("attributes.k", "in", [operand]), flag)
    for operand in (False, True):
        assert not check(pred("attributes.k", "equals", operand), zero)
        assert not check(pred("attributes.k", "in", [operand]), zero)
    assert not check(pred("attributes.k", "gte", 0), flag) and not check(pred("attributes.k", "lte", 5), flag)
    assert not check(pred("attributes.k", "gte", True), event(attributes={"k": 1}))
    assert check(pred("attributes.k", "equals", True), flag) and check(pred("attributes.k", "equals", 0.0), zero)


@pytest.mark.parametrize("address", ["not-an-ip", "", "999.1.1.1", "010.0.0.1", "10.0.0.1/8", "a" * 65, "1" * 100,
                                     "fe80::1%" + "x" * 80])
def test_an_unusable_address_matches_neither_cidr_operator(address):
    e = event(network=net(dst_ip=address)) if len(address) < 4000 else None
    assert not check(pred("network.dst_ip", "in_cidr", ["0.0.0.0/0", "::/0"]), e)
    assert not check(pred("network.dst_ip", "not_in_cidr", ["10.0.0.0/8"]), e)


def test_a_missing_address_or_a_non_string_value_matches_neither_cidr_operator():
    no_net = event()
    assert not check(pred("network.dst_ip", "in_cidr", ["0.0.0.0/0"]), no_net)
    assert not check(pred("network.dst_ip", "not_in_cidr", ["10.0.0.0/8"]), no_net)
    odd = event(attributes={"ip": 167772161})
    assert not check(pred("attributes.ip", "in_cidr", ["10.0.0.0/8"]), odd)
    assert not check(pred("attributes.ip", "not_in_cidr", ["10.0.0.0/8"]), odd)
    text = event(attributes={"ip": "10.0.0.1"})                                          # an attribute holding an address works
    assert check(pred("attributes.ip", "in_cidr", ["10.0.0.0/8"]), text)


def test_the_address_parse_cache_is_bounded_and_ignores_long_strings():
    for i in range(6000):
        check(pred("network.dst_ip", "in_cidr", ["10.0.0.0/8"]), event(network=net(dst_ip=f"10.{i // 256}.{i % 256}.1")))
    assert P_._parse_ip.cache_info().currsize <= 4096
    size = P_._parse_ip.cache_info().currsize
    for i in range(500):
        check(pred("network.dst_ip", "in_cidr", ["10.0.0.0/8"]), event(network=net(dst_ip=("1" * 80) + str(i))))
    assert P_._parse_ip.cache_info().currsize == size                                   # long strings never become keys


# ------------------------------------------------------------------ compound predicates
def test_where_is_a_conjunction_and_empty_is_true():
    e = event(os_="windows", binary="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              command_line="powershell.exe -ExecutionPolicy Bypass -File x.ps1")
    binary = pred("binary", "endswith_any", ["\\powershell.exe", "\\pwsh.exe"])
    cmd = pred("command_line", "contains_any", ["-enc", "-executionpolicy bypass"])
    assert evaluate_where((binary, cmd), e)
    assert evaluate_where((), e)
    assert not evaluate_where((binary, pred("command_line", "contains_any", ["-nop"])), e)
    assert not evaluate_where((pred("user", "equals", "x"), binary), e)                 # a missing field fails the conjunction


def test_several_operators_on_one_field_are_anded():
    e = event(network=net(dst_ip="10.1.2.3"))
    inside_not_blocked = (pred("network.dst_ip", "in_cidr", ["10.0.0.0/8"]), pred("network.dst_ip", "not_in_cidr", ["10.1.0.0/16"]))
    assert not evaluate_where(inside_not_blocked, e)
    assert evaluate_where(inside_not_blocked, event(network=net(dst_ip="10.2.0.1")))
    assert not evaluate_where(inside_not_blocked, event(network=net(dst_ip="11.0.0.1")))
    port = (pred("network.dst_port", "gte", 1024), pred("network.dst_port", "lte", 2000))
    assert evaluate_where(port, event(network=net(dst_port=1024))) and evaluate_where(port, event(network=net(dst_port=2000)))
    assert not evaluate_where(port, event(network=net(dst_port=1023))) and not evaluate_where(port, event(network=net(dst_port=2001)))


def test_where_stops_at_the_first_failure():
    class Boom(Backend):
        def search(self, pattern, text):
            raise AssertionError("evaluated after a failed predicate")
    e = event(command_line="abc")
    assert not evaluate_where((pred("user", "equals", "nobody"), pred("command_line", "regex", "a")), e, regex_backend=Boom())


# ------------------------------------------------------------------ regex fails closed
def test_regex_without_a_backend_is_false_even_when_it_would_match():
    e = event(command_line="powershell -enc AAAA")
    p = Predicate(field="command_line", op="regex", operand="-enc", compiled=Tripwire())
    assert check(p, e) is False and evaluate_where((p,), e) is False                    # the tripwire proves nothing touched it
    assert has_regex((p,)) and not has_regex((pred("binary", "equals", "x"),))
    assert has_regex((pred("binary", "equals", "x"), p)) and not has_regex(())


def test_regex_with_a_backend_uses_the_pattern_text_and_the_raw_event_text():
    backend = Backend(True)
    p = Predicate(field="command_line", op="regex", operand=r"-e(nc)?\s", compiled=Tripwire())
    windows = event(os_="windows", command_line="C:\\X -EnC y")
    assert check(p, windows, regex_backend=backend) is True
    assert backend.calls == [(r"-e(nc)?\s", "C:\\X -EnC y")]                            # not normalized, not the compiled object
    assert evaluate_where((p,), windows, regex_backend=Backend(False)) is False


def test_regex_input_cap_timeout_and_odd_values_all_fail_closed():
    p = Predicate(field="command_line", op="regex", operand="a", compiled=None)
    backend = Backend(True)
    assert check(p, event(command_line="a" * MAX_REGEX_INPUT_CHARS), regex_backend=backend) is True
    assert check(p, event(command_line="a" * (MAX_REGEX_INPUT_CHARS + 1)), regex_backend=backend) is False
    assert len(backend.calls) == 1                                                       # the long text was never sent
    assert check(p, event(command_line="a"), regex_backend=Backend(raises=RegexTimeout())) is False
    assert check(p, event(), regex_backend=backend) is False and len(backend.calls) == 1   # missing value: no call
    assert check(Predicate(field="attributes.n", op="regex", operand="1", compiled=None), event(attributes={"n": 1}),
                 regex_backend=backend) is False
    assert len(backend.calls) == 1


def test_a_backend_defect_is_not_hidden():
    p = Predicate(field="command_line", op="regex", operand="a", compiled=None)
    with pytest.raises(RuntimeError, match="backend bug"):
        check(p, event(command_line="a"), regex_backend=Backend(raises=RuntimeError("backend bug")))


def test_this_module_never_imports_or_runs_the_standard_regex_engine():
    source = Path(P_.__file__).read_text(encoding="utf-8")
    assert "import re" not in source and "re.search" not in source and "compiled.search" not in source
    assert "re" not in vars(P_) and not hasattr(P_, "_compile")


def test_an_unknown_operator_fails_closed():
    bogus = Predicate.model_construct(field="binary", op="startswith", operand=("/",), compiled=None)
    assert check(bogus, event()) is False


# ------------------------------------------------------------------ the seven shipped rules
@pytest.fixture(scope="module")
def shipped():
    return load_rules(RULES, strict=True)


def fixture_events(name: str) -> list[HostEvent]:
    return [HostEvent.model_validate(json.loads(line)) for line in (FIX / name).read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.parametrize("rule_id", ["NX-LIN-001", "NX-WIN-001"])
def test_each_fixture_step_is_satisfied_by_exactly_its_bound_event(shipped, rule_id):
    rule = shipped.get(rule_id)
    expect = json.loads((FIX / f"{rule_id}.expect.json").read_text(encoding="utf-8"))
    events = fixture_events(f"{rule_id}.events.jsonl")
    for step in rule.steps:
        satisfied = {e.event_id for e in events if e.event_type == step.event_type and evaluate_where(step.where, e)}
        assert satisfied == {expect["bindings"][step.name]}, step.name


def test_the_benign_fixture_satisfies_only_the_interpreter_step(shipped):
    rule = shipped.get("NX-LIN-001")
    events = fixture_events("NX-LIN-001.benign.events.jsonl")
    assert [s.name for s in rule.steps if any(e.event_type == s.event_type and evaluate_where(s.where, e) for e in events)] == ["interp"]


def where_of(shipped, rule_id: str, step: str) -> tuple[Predicate, ...]:
    return next(s.where for s in shipped.get(rule_id).steps if s.name == step)


def test_nx_lin_003_steps(shipped):
    start, connect = where_of(shipped, "NX-LIN-003", "bin"), where_of(shipped, "NX-LIN-003", "net")
    assert evaluate_where(start, event(binary="/lab/bin/beacon-sim"))
    for binary in ("/lab/binx/beacon-sim", "/usr/lab/bin/x", "/LAB/BIN/beacon-sim", "/tmp/lab/bin/"):
        assert not evaluate_where(start, event(binary=binary)), binary
    out = lambda ip, **kw: event(event_type="network_connect", network=net(dst_ip=ip, **kw))      # noqa: E731
    assert evaluate_where(connect, out("192.168.20.10"))
    for ip in ("192.168.10.1", "127.0.0.1", "127.255.255.254"):
        assert not evaluate_where(connect, out(ip)), ip
    assert not evaluate_where(connect, out("192.168.20.10", direction="inbound"))
    assert evaluate_where(connect, out("192.168.10.2"))                                              # only the gateway /32 is excluded


def test_nx_win_002_matches_the_lab_bin_prefix_case_insensitively(shipped):
    where = where_of(shipped, "NX-WIN-002", "bin")
    for binary in ("C:\\Lab\\bin\\lab-test.exe", "c:\\lab\\BIN\\x.exe", "C:/Lab/bin/y.exe", "C:\\LAB\\Bin\\sub\\z.exe"):
        assert evaluate_where(where, event(os_="windows", binary=binary)), binary
    for binary in ("C:\\Lab\\binary\\x.exe", "C:\\Lab\\scenarios\\bin\\x.exe", "D:\\Lab\\bin\\x.exe", "C:\\Windows\\cmd.exe"):
        assert not evaluate_where(where, event(os_="windows", binary=binary)), binary
    assert not evaluate_where(where, event(os_="linux", binary="c:\\lab\\bin\\x.exe"))               # Linux would be exact


def test_nx_win_001_powershell_steps_on_windows(shipped):
    ps = where_of(shipped, "NX-WIN-001", "ps")
    base = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    for cmd in ("powershell.exe -ExecutionPolicy Bypass -File x", "POWERSHELL -EP BYPASS", "powershell -EncodedCommand AAA",
                "powershell -enc AAA"):
        assert evaluate_where(ps, event(os_="windows", binary=base, command_line=cmd)), cmd
    assert evaluate_where(ps, event(os_="windows", binary="C:\\Program Files\\PowerShell\\7\\pwsh.exe", command_line="pwsh -enc x"))
    assert not evaluate_where(ps, event(os_="windows", binary=base, command_line="powershell -File x.ps1"))
    assert not evaluate_where(ps, event(os_="windows", binary="C:\\Windows\\System32\\cmd.exe", command_line="cmd /c -enc"))
    assert not evaluate_where(ps, event(os_="windows", binary=base))                                  # no command line observed
    stage = where_of(shipped, "NX-WIN-001", "stage")
    f = lambda path, op: event(os_="windows", event_type="file_access", file={"path": path, "operation": op})   # noqa: E731
    assert evaluate_where(stage, f("C:\\Lab\\staging\\report.zip", "create"))
    assert evaluate_where(stage, f("c:\\lab\\STAGING\\x", "write"))
    assert not evaluate_where(stage, f("C:\\Lab\\staging\\report.zip", "delete"))
    assert not evaluate_where(stage, f("C:\\Lab\\protected\\x", "create"))


def test_nx_any_001_flag_must_be_the_boolean_true(shipped):
    where = where_of(shipped, "NX-ANY-001", "bin")
    for os_ in ("linux", "windows"):
        assert evaluate_where(where, event(os_=os_, attributes={"ti_hash_hit": True}))
        for bad in (False, 1, "true", "True", None):
            attrs = {} if bad is None else {"ti_hash_hit": bad}
            assert not evaluate_where(where, event(os_=os_, attributes=attrs)), (os_, bad)


@pytest.mark.parametrize("rule_id, os_", [("NX-LIN-002", "linux"), ("NX-WIN-003", "windows")])
def test_threshold_where_selects_outbound_connections(shipped, rule_id, os_):
    where = shipped.get(rule_id).threshold.where
    assert evaluate_where(where, event(os_=os_, event_type="network_connect", network=net(direction="outbound")))
    assert not evaluate_where(where, event(os_=os_, event_type="network_connect", network=net(direction="inbound")))
    assert not evaluate_where(where, event(os_=os_))


def test_no_shipped_rule_needs_a_regex_backend(shipped):
    for rule in shipped:
        preds = [p for s in rule.steps for p in s.where] + (list(rule.threshold.where) if rule.threshold else [])
        assert not has_regex(preds), rule.id
