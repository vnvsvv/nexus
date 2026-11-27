"""The package-level API of ``nexus_endpoint_core``: what it exports, and that importing it has no side effects."""
from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path

import nexus_endpoint_core as package
import pytest

ROOT = Path(__file__).resolve().parents[2]

GRAPH_AND_RULES = {                                      # exported before the engine was: these must stay
    "graph": ("ProcessGraph", "ProcessNode", "format_utc", "parse_utc"),
    "rules": ("AttackMapping", "AttackMappingError", "Rule", "RuleError", "RuleLoadError", "RuleSet",
              "load_attack_mapping", "load_rule", "load_rules"),
}
RULE_ENGINE = {
    "engine": ("DEFAULT_ROOT_STOP_BINARIES", "DisabledRule", "EngineLimits", "EngineMatch", "EngineResult", "EngineStats",
               "RuleEngine", "RuleEngineError", "SuppressedMatch"),
    "predicates": ("RegexBackend", "RegexTimeout"),
}
PUBLIC = [(module, name) for group in (GRAPH_AND_RULES, RULE_ENGINE) for module, names in group.items() for name in names]
MODULE_LEVEL_ONLY = {                                    # reachable through their module, deliberately not re-exported
    "engine": ("Disposition", "IndexEntry"),
    "predicates": ("MAX_REGEX_INPUT_CHARS", "evaluate_predicate", "evaluate_where", "get_field", "has_regex"),
}


def run_isolated(code: str) -> None:
    """Run ``code`` in a fresh interpreter, so that nothing this test session imported can hide a problem."""
    done = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("module, name", PUBLIC, ids=[name for _, name in PUBLIC])
def test_every_public_name_is_the_original_object(module, name):
    namespace: dict = {}
    exec(f"from nexus_endpoint_core import {name}", namespace)
    assert namespace[name] is getattr(importlib.import_module(f"nexus_endpoint_core.{module}"), name)


def test_all_lists_exactly_the_public_names_once():
    assert len(package.__all__) == len(set(package.__all__))
    assert sorted(package.__all__) == sorted(name for _, name in PUBLIC)
    star: dict = {}
    exec("from nexus_endpoint_core import *", star)
    assert set(star) - {"__builtins__"} == set(package.__all__)


@pytest.mark.parametrize("module, names", MODULE_LEVEL_ONLY.items(), ids=MODULE_LEVEL_ONLY)
def test_internal_helpers_stay_at_module_level(module, names):
    source = importlib.import_module(f"nexus_endpoint_core.{module}")
    for name in names:
        assert hasattr(source, name), name
        assert not hasattr(package, name) and name not in package.__all__, name


@pytest.mark.parametrize("module", ["engine", "graph", "predicates", "rules"])
def test_each_module_can_be_the_first_import(module):
    """No import cycle: whichever module is asked for first, the package finishes loading with all its names."""
    run_isolated(f"import nexus_endpoint_core.{module}\n"
                 "import nexus_endpoint_core as p\n"
                 "assert all(hasattr(p, name) for name in p.__all__)")


def test_importing_the_package_needs_no_optional_package_and_starts_nothing():
    run_isolated("""
import logging, sys, threading

OPTIONAL = {"fastapi", "nexus_ml", "psutil", "pythoncom", "pywintypes", "re2", "uvicorn", "win32api", "win32con",
            "win32evtlog", "wmi"}

class Absent:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in OPTIONAL:
            raise ImportError("not installed on this host: " + name)

sys.meta_path.insert(0, Absent())
started = []
sys.addaudithook(lambda event, args: started.append(event) if event.startswith(
    ("socket.", "subprocess.", "os.system", "os.exec", "os.spawn", "os.posix_spawn")) else None)

import nexus_endpoint_core

assert not OPTIONAL & set(sys.modules)
assert started == [], started
assert threading.active_count() == 1
assert logging.getLogger().handlers == []
assert not [n for n, lg in logging.Logger.manager.loggerDict.items()
            if n.startswith("nexus") and getattr(lg, "handlers", [])]
""")


def test_the_package_sources_import_no_platform_specific_module():
    """It is OS-agnostic: only the standard library's portable part and the declared dependencies."""
    platform_only = {"fcntl", "grp", "msvcrt", "pwd", "resource", "syslog", "termios", "winreg", "winsound"}
    allowed = (set(sys.stdlib_module_names) - platform_only) | {"nexus_contracts", "pydantic", "yaml"}
    for path in sorted(Path(package.__file__).parent.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                found = [node.module]
            else:
                continue
            assert {name.split(".")[0] for name in found} <= allowed, f"{path.name}: {found}"


def test_every_name_the_linux_endpoint_imports_from_the_package_exists():
    """Read statically: the Linux endpoint itself only imports on Linux."""
    wanted = set()
    for path in sorted((ROOT / "endpoint-linux").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "nexus_endpoint_core":
                wanted |= {(node.module, alias.name) for alias in node.names}
    if not wanted:
        pytest.skip("endpoint-linux imports nothing from nexus_endpoint_core")
    for module, name in sorted(wanted):
        assert hasattr(importlib.import_module(module), name), f"{module}.{name}"
