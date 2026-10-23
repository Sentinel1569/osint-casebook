"""Persistence: users, sessions, cases, evidence, findings and a hash-chained audit log.

Evidence bytes live in a content-addressed store (``<root>/ab/abcdef…``): the file
name *is* its SHA-256, so any tampering is detectable by re-hashing.

The audit log is append-only and hash-chained per case: each entry stores the
hash of the previous one, so editing or deleting a past entry breaks every
later hash. ``verify_case`` recomputes both.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .evidence import sha256_bytes, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst', created TEXT);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created TEXT, expires TEXT);
CREATE TABLE IF NOT EXISTS cases (id INTEGER PRIMARY KEY, title TEXT NOT NULL, summary TEXT DEFAULT '', status TEXT DEFAULT 'open',
    tlp TEXT DEFAULT 'TLP:AMBER', created_by TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, ref TEXT, kind TEXT,
    title TEXT, url TEXT DEFAULT '', final_url TEXT DEFAULT '', filename TEXT DEFAULT '', mime TEXT DEFAULT '', size INTEGER DEFAULT 0,
    sha256 TEXT DEFAULT '', captured_at TEXT, captured_by TEXT, http_status INTEGER, headers TEXT DEFAULT '{}', archive_url TEXT DEFAULT '',
    note TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE, title TEXT, body TEXT,
    confidence TEXT DEFAULT 'likely', status TEXT DEFAULT 'draft', created_by TEXT, created TEXT, updated TEXT, reviewed_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS finding_evidence (finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE, note TEXT DEFAULT '', PRIMARY KEY (finding_id, evidence_id));
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, case_id INTEGER, at TEXT, actor TEXT, action TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
"""
CONFIDENCE = ("almost certain", "very likely", "likely", "roughly even chance", "unlikely", "very unlikely")
ROLES = ("admin", "analyst", "reviewer", "viewer")


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class DB:
    def __init__(self, path: str | None = None, store_root: str | None = None):
        self.path = path or os.environ.get("CASEBOOK_DB", "casebook.db")
        self.root = Path(store_root or os.environ.get("CASEBOOK_STORE", "evidence_store"))
        self.con = sqlite3.connect(self.path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys = ON")
        self.con.executescript(SCHEMA)

    # ------------------------------------------------------------------ users
    @staticmethod
    def _hash_pw(password: str, salt: str) -> str:
        return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32).hex()

    def user_count(self) -> int:
        return self.con.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username: str, password: str, role: str = "analyst") -> int:
        username = username.strip().lower()
        if not username or len(password) < 10:
            raise ValueError("username required and password must be at least 10 characters")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        salt = secrets.token_hex(16)
        try:
            with self.con:
                return self.con.execute("INSERT INTO users (username, pw_hash, salt, role, created) VALUES (?,?,?,?,?)",
                                        (username, self._hash_pw(password, salt), salt, role, utcnow())).lastrowid
        except sqlite3.IntegrityError as exc:
            raise ValueError("username already exists") from exc

    def users(self) -> list[dict]:
        return [dict(r) for r in self.con.execute("SELECT id, username, role, created FROM users ORDER BY username")]

    def login(self, username: str, password: str, hours: int = 12) -> str | None:
        r = self.con.execute("SELECT * FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
        if not r or not hmac.compare_digest(r["pw_hash"], self._hash_pw(password, r["salt"])):
            return None
        token = secrets.token_urlsafe(32)
        exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
        with self.con:
            self.con.execute("INSERT INTO sessions VALUES (?,?,?,?)", (sha256_bytes(token), r["id"], utcnow(), exp))
        return token

    def session_user(self, token: str | None) -> dict | None:
        if not token:
            return None
        r = self.con.execute("SELECT u.id, u.username, u.role, s.expires FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash=?",
                             (sha256_bytes(token),)).fetchone()
        if not r or r["expires"] < datetime.now(timezone.utc).isoformat():
            return None
        return {"id": r["id"], "username": r["username"], "role": r["role"]}

    def logout(self, token: str) -> None:
        with self.con:
            self.con.execute("DELETE FROM sessions WHERE token_hash=?", (sha256_bytes(token),))

    # ------------------------------------------------------------------ audit chain
    def audit(self, case_id: int | None, actor: str, action: str, detail: dict) -> str:
        prev = self.con.execute("SELECT hash FROM audit WHERE case_id IS ? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
        prev_hash = prev["hash"] if prev else "0" * 64
        at = utcnow()
        entry = {"case_id": case_id, "at": at, "actor": actor, "action": action, "detail": detail, "prev_hash": prev_hash}
        h = sha256_bytes(_canon(entry))
        with self.con:
            self.con.execute("INSERT INTO audit (case_id, at, actor, action, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                             (case_id, at, actor, action, _canon(detail), prev_hash, h))
        return h

    def audit_log(self, case_id: int) -> list[dict]:
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in self.con.execute("SELECT * FROM audit WHERE case_id=? ORDER BY id", (case_id,))]

    # ------------------------------------------------------------------ cases
    def create_case(self, title: str, summary: str, tlp: str, actor: str) -> int:
        if not title.strip():
            raise ValueError("title is required")
        if tlp not in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"):
            raise ValueError("invalid TLP marking")
        with self.con:
            cid = self.con.execute("INSERT INTO cases (title, summary, tlp, created_by, created) VALUES (?,?,?,?,?)",
                                   (title.strip(), summary.strip(), tlp, actor, utcnow())).lastrowid
        self.audit(cid, actor, "case.create", {"title": title, "tlp": tlp})
        return cid

    def update_case(self, cid: int, actor: str, **f) -> None:
        f = {k: v for k, v in f.items() if k in ("title", "summary", "status", "tlp") and v is not None}
        if f:
            with self.con:
                self.con.execute(f"UPDATE cases SET {', '.join(f'{k}=?' for k in f)} WHERE id=?", (*f.values(), cid))
            self.audit(cid, actor, "case.update", f)

    def cases(self) -> list[dict]:
        return [dict(r) for r in self.con.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) evidence, (SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) findings "
            "FROM cases c ORDER BY c.id DESC")]

    def case(self, cid: int) -> dict | None:
        r = self.con.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
        return dict(r) if r else None

    # ------------------------------------------------------------------ evidence
    def _blob_path(self, digest: str) -> Path:
        return self.root / digest[:2] / digest

    def put_blob(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        p = self._blob_path(digest)
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(p)
        return digest

    def get_blob(self, digest: str) -> bytes | None:
        p = self._blob_path(digest)
        return p.read_bytes() if digest and p.exists() else None

    def add_evidence(self, case_id: int, actor: str, kind: str, title: str, data: bytes | None = None, **f) -> int:
        digest = self.put_blob(data) if data is not None else ""
        n = self.con.execute("SELECT COUNT(*) FROM evidence WHERE case_id=?", (case_id,)).fetchone()[0] + 1
        cols = {"case_id": case_id, "ref": f"E{n}", "kind": kind, "title": title, "sha256": digest, "size": len(data) if data is not None else 0,
                "captured_at": f.pop("captured_at", utcnow()), "captured_by": actor,
                **{k: (json.dumps(v) if k == "headers" else v) for k, v in f.items()}}
        with self.con:
            eid = self.con.execute(f"INSERT INTO evidence ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", tuple(cols.values())).lastrowid
        self.audit(case_id, actor, "evidence.add", {"ref": cols["ref"], "kind": kind, "title": title, "sha256": digest, "url": f.get("url", ""),
                                                    "size": cols["size"]})
        return eid

    def evidence(self, case_id: int) -> list[dict]:
        return [{**dict(r), "headers": json.loads(r["headers"] or "{}")} for r in self.con.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,))]

    def evidence_item(self, eid: int) -> dict | None:
        r = self.con.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
        return {**dict(r), "headers": json.loads(r["headers"] or "{}")} if r else None

    # ------------------------------------------------------------------ findings
    def save_finding(self, case_id: int, actor: str, title: str, body: str, confidence: str, evidence_ids: list[int], fid: int | None = None) -> int:
        if confidence not in CONFIDENCE:
            raise ValueError(f"confidence must be one of: {', '.join(CONFIDENCE)}")
        if not title.strip():
            raise ValueError("title is required")
        valid = {e["id"] for e in self.evidence(case_id)}
        if not set(evidence_ids) <= valid:
            raise ValueError("findings can only cite evidence from the same case")
        with self.con:
            if fid:
                self.con.execute("UPDATE findings SET title=?, body=?, confidence=?, updated=?, status='draft', reviewed_by='' WHERE id=? AND case_id=?",
                                 (title, body, confidence, utcnow(), fid, case_id))
                self.con.execute("DELETE FROM finding_evidence WHERE finding_id=?", (fid,))
            else:
                fid = self.con.execute("INSERT INTO findings (case_id, title, body, confidence, created_by, created, updated) VALUES (?,?,?,?,?,?,?)",
                                       (case_id, title, body, confidence, actor, utcnow(), utcnow())).lastrowid
            for e in evidence_ids:
                self.con.execute("INSERT INTO finding_evidence (finding_id, evidence_id) VALUES (?,?)", (fid, e))
        self.audit(case_id, actor, "finding.save", {"finding": fid, "title": title, "confidence": confidence, "evidence": sorted(evidence_ids)})
        return fid

    def review_finding(self, case_id: int, fid: int, actor: str, approve: bool) -> None:
        with self.con:
            self.con.execute("UPDATE findings SET status=?, reviewed_by=? WHERE id=? AND case_id=?",
                             ("reviewed" if approve else "draft", actor if approve else "", fid, case_id))
        self.audit(case_id, actor, "finding.review", {"finding": fid, "approved": approve})

    def findings(self, case_id: int) -> list[dict]:
        out = []
        for r in self.con.execute("SELECT * FROM findings WHERE case_id=? ORDER BY id", (case_id,)):
            d = dict(r)
            d["evidence_ids"] = [x[0] for x in self.con.execute("SELECT evidence_id FROM finding_evidence WHERE finding_id=? ORDER BY evidence_id", (d["id"],))]
            out.append(d)
        return out

    # ------------------------------------------------------------------ verification
    def verify_case(self, case_id: int) -> dict:
        problems, checked = [], 0
        for e in self.evidence(case_id):
            if not e["sha256"]:
                continue
            checked += 1
            data = self.get_blob(e["sha256"])
            if data is None:
                problems.append(f"{e['ref']}: stored file is missing")
            elif sha256_bytes(data) != e["sha256"]:
                problems.append(f"{e['ref']}: content no longer matches its recorded SHA-256")
        prev = "0" * 64
        log = self.audit_log(case_id)
        for a in log:
            entry = {"case_id": a["case_id"], "at": a["at"], "actor": a["actor"], "action": a["action"], "detail": a["detail"], "prev_hash": a["prev_hash"]}
            if a["prev_hash"] != prev:
                problems.append(f"audit #{a['id']}: chain broken (previous entry altered or removed)")
            if sha256_bytes(_canon(entry)) != a["hash"]:
                problems.append(f"audit #{a['id']}: entry content altered")
            prev = a["hash"]
        return {"ok": not problems, "evidence_checked": checked, "audit_entries": len(log), "head": prev, "problems": problems, "at": utcnow()}
