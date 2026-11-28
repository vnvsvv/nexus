"""Admin commands.

    python -m server.manage init-db
    python -m server.manage gen-token <endpoint_id> --os linux|windows

gen-token prints the new token once on stdout (put it in the agent's .env as NEXUS_TOKEN)
and stores only its sha256 in endpoints.token_hash. Running it again replaces the token.
"""

from __future__ import annotations

import argparse
import logging
import re
import secrets
import sys

from sqlalchemy.dialects.postgresql import insert as pg_insert

from server import db
from server.api import hash_token
from server.config import setup_logging

log = logging.getLogger("nexus.manage")
ENDPOINT_ID = re.compile(r"^[a-z0-9-]+$")


def init_db() -> None:
    db.create_all(db.get_engine())
    log.info("database schema created (idempotent)")


def gen_token(endpoint_id: str, os_name: str) -> str:
    if not ENDPOINT_ID.match(endpoint_id):
        raise SystemExit(f"endpoint_id must be a lowercase slug, got {endpoint_id!r}")
    token = secrets.token_urlsafe(32)
    stmt = pg_insert(db.endpoints).values(
        endpoint_id=endpoint_id, os=os_name, token_hash=hash_token(token)
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[db.endpoints.c.endpoint_id],
        set_={"token_hash": stmt.excluded.token_hash},
    )
    with db.get_engine().begin() as conn:
        conn.execute(stmt)
    log.info("endpoint token set", extra={"fields": {"endpoint_id": endpoint_id}})
    return token


def main(argv: list[str] | None = None) -> None:
    setup_logging()
    p = argparse.ArgumentParser(prog="python -m server.manage")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db", help="create tables and indexes")
    g = sub.add_parser("gen-token", help="create or replace an endpoint token")
    g.add_argument("endpoint_id")
    g.add_argument("--os", dest="os_name", choices=["linux", "windows"], required=True)
    args = p.parse_args(argv)
    if args.cmd == "init-db":
        init_db()
    else:
        sys.stdout.write(gen_token(args.endpoint_id, args.os_name) + "\n")


if __name__ == "__main__":
    main()
