"""Command-line interface.

    python -m casebook user add alice --role analyst          # prompts for a password
    python -m casebook verify-bundle case-1-bundle.zip         # check a bundle anyone sent you
    python -m casebook verify CASE_ID                          # re-hash evidence and the audit chain
    python -m casebook export CASE_ID -o case.zip
    python -m casebook serve [--secure-cookie]
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import bundle
from .db import DB, ROLES


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="casebook", description="OSINT Investigation Casebook")
    p.add_argument("--db")
    p.add_argument("--store")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("user")
    us = u.add_subparsers(dest="action", required=True)
    ua = us.add_parser("add")
    ua.add_argument("username")
    ua.add_argument("--role", choices=ROLES, default="analyst")
    us.add_parser("list")
    vb = sub.add_parser("verify-bundle")
    vb.add_argument("zip")
    v = sub.add_parser("verify")
    v.add_argument("case", type=int)
    e = sub.add_parser("export")
    e.add_argument("case", type=int)
    e.add_argument("-o", "--output", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    s.add_argument("--secure-cookie", action="store_true", help="set the Secure flag (use behind HTTPS)")
    a = p.parse_args(argv)

    if a.cmd == "serve":
        import uvicorn
        if a.secure_cookie:
            from .app import create_app
            uvicorn.run(create_app(a.db, a.store, secure_cookie=True), host=a.host, port=a.port)
        else:
            uvicorn.run("casebook.app:app", host=a.host, port=a.port, reload=a.reload)
        return 0
    if a.cmd == "verify-bundle":
        res = bundle.verify(Path(a.zip).read_bytes())
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    db = DB(a.db, a.store)
    if a.cmd == "user":
        if a.action == "add":
            pw = getpass.getpass("Password (min 10 chars): ")
            try:
                print(f"user {db.create_user(a.username, pw, a.role)} created")
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        else:
            for x in db.users():
                print(f"  {x['id']:>3} {x['username']:<20} {x['role']}")
    elif a.cmd == "verify":
        res = db.verify_case(a.case)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    elif a.cmd == "export":
        Path(a.output).write_bytes(bundle.export(db, a.case))
        print(f"wrote {a.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
