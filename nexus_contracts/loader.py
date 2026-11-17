"""Load JSON Schemas from contracts/schemas with cross-file $ref resolution."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "contracts" / "schemas"


@lru_cache(maxsize=1)
def _registry() -> Registry:
    reg = Registry()
    for p in SCHEMA_DIR.glob("*.schema.json"):
        doc = json.loads(p.read_text(encoding="utf-8"))
        res = Resource.from_contents(doc)
        reg = reg.with_resource(doc["$id"], res).with_resource(p.name, res)
    return reg


def load_schema(name: str) -> dict:
    """name: e.g. 'incident' or 'incident.schema.json'"""
    if not name.endswith(".schema.json"):
        name = f"{name}.schema.json"
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate_against_schema(name: str, instance: dict) -> list[str]:
    schema = load_schema(name)
    v = Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker())
    return [f"{'/'.join(str(x) for x in e.absolute_path) or '<root>'}: {e.message}" for e in v.iter_errors(instance)]
