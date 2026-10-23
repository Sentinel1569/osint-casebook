import base64
import io
import sqlite3
import zipfile

import pytest
from fastapi.testclient import TestClient

from casebook import bundle, report
from casebook.app import create_app
from casebook.capture import CaptureError, capture
from casebook.db import DB
from casebook.demo import DemoCapturer, seed

PW = "correct-horse-battery"


@pytest.fixture
def db(tmp_path):
    return DB(str(tmp_path / "c.db"), str(tmp_path / "store"))


def test_users_and_sessions(db):
    db.create_user("Alice", PW, "analyst")
    with pytest.raises(ValueError):
        db.create_user("alice", PW)
    with pytest.raises(ValueError):
        db.create_user("bob", "short")
    assert db.login("alice", "wrong-password!") is None
    tok = db.login("ALICE", PW)
    assert db.session_user(tok)["username"] == "alice"
    db.logout(tok)
    assert db.session_user(tok) is None


def test_capture_preserves_bytes_and_hash(db):
    cid = db.create_case("t", "", "TLP:GREEN", "alice")
    eid = capture(db, cid, "alice", "https://secure-login-northwind.example/", DemoCapturer(), archive=True)
    e = db.evidence_item(eid)
    assert e["ref"] == "E1" and e["http_status"] == 200 and e["archive_url"].startswith("https://web.archive.org/")
    assert e["title"] == "Northwind Bank - Sign in" and "x-casebook-redirect-chain" in e["headers"]
    import hashlib
    assert hashlib.sha256(db.get_blob(e["sha256"])).hexdigest() == e["sha256"]
    with pytest.raises(CaptureError):
        capture(db, cid, "alice", "ftp://x", DemoCapturer())


def test_findings_only_cite_same_case(db):
    a = db.create_case("a", "", "TLP:GREEN", "u")
    b = db.create_case("b", "", "TLP:GREEN", "u")
    eb = db.add_evidence(b, "u", "note", "n", b"x")
    with pytest.raises(ValueError):
        db.save_finding(a, "u", "t", "", "likely", [eb])
    with pytest.raises(ValueError):
        db.save_finding(b, "u", "t", "", "pretty sure", [eb])


def test_tamper_detection(db, tmp_path):
    cid = seed(db, "alice")
    assert db.verify_case(cid)["ok"]
    e = db.evidence(cid)[0]
    path = tmp_path / "store" / e["sha256"][:2] / e["sha256"]
    path.write_bytes(path.read_bytes() + b"<!-- tampered -->")
    res = db.verify_case(cid)
    assert not res["ok"] and any("no longer matches" in p for p in res["problems"])
    path.write_bytes(path.read_bytes().replace(b"<!-- tampered -->", b""))
    assert db.verify_case(cid)["ok"]
    con = sqlite3.connect(db.path)
    con.execute("UPDATE audit SET detail = '{\"title\":\"edited\"}' WHERE id = (SELECT MIN(id) FROM audit WHERE case_id = ?)", (cid,))
    con.commit()
    assert any("altered" in p for p in db.verify_case(cid)["problems"])


def test_reports(db):
    cid = seed(db, "alice")
    r = report.build(db, cid)
    md, html = report.to_markdown(r), report.to_html(r)
    assert "## Evidence register" in md and "PASS" in md and "[E1]" in md
    assert "<html" in html and 'href=\'#E1\'' in html and "Integrity PASS" in html


def test_bundle_roundtrip_and_tamper(db):
    cid = seed(db, "alice")
    data = bundle.export(db, cid)
    ok = bundle.verify(data)
    assert ok["ok"] and ok["files"] >= 8
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for n in src.namelist():
            d = src.read(n)
            z.writestr(n, d + b"x" if n.startswith("evidence/E1_") else d)
    bad = bundle.verify(out.getvalue())
    assert not bad["ok"] and any("E1" in p for p in bad["problems"])


def _client(tmp_path):
    return TestClient(create_app(str(tmp_path / "a.db"), str(tmp_path / "s")))


def test_api_auth_roles_and_four_eyes(tmp_path):
    c = _client(tmp_path)
    assert c.get("/api/cases").status_code == 401
    assert c.get("/api/session").json()["needs_setup"]
    assert c.post("/api/setup", json={"username": "admin", "password": PW}).status_code == 200
    assert c.post("/api/setup", json={"username": "x", "password": PW}).status_code == 409
    cid = c.post("/api/demo").json()["id"]
    case = c.get(f"/api/cases/{cid}").json()
    assert len(case["evidence"]) == 6 and len(case["findings"]) == 3
    fid = case["findings"][0]["id"]
    assert c.post(f"/api/cases/{cid}/findings/{fid}/review", json={"approve": True}).status_code == 409  # own finding
    assert c.post("/api/users", json={"username": "rita", "password": PW, "role": "reviewer"}).status_code == 200
    assert c.post("/api/users", json={"username": "vic", "password": PW, "role": "viewer"}).status_code == 200
    r = _client(tmp_path)
    assert r.post("/api/login", json={"username": "rita", "password": PW}).status_code == 200
    assert r.post(f"/api/cases/{cid}/findings/{fid}/review", json={"approve": True}).status_code == 200
    assert r.post(f"/api/cases/{cid}/note", json={"title": "x", "text": "y"}).status_code == 403  # reviewers can't write
    v = _client(tmp_path)
    v.post("/api/login", json={"username": "vic", "password": PW})
    assert v.post(f"/api/cases/{cid}/findings/{fid}/review", json={"approve": True}).status_code == 403
    assert v.get(f"/api/cases/{cid}").status_code == 200
    assert c.get(f"/api/cases/{cid}").json()["findings"][0]["reviewed_by"] == "rita"
    assert c.post("/api/login", json={"username": "admin", "password": "nope-nope-nope"}).status_code == 401


def test_api_evidence_and_exports(tmp_path):
    c = _client(tmp_path)
    c.post("/api/setup", json={"username": "admin", "password": PW})
    cid = c.post("/api/cases", json={"title": "Case", "tlp": "TLP:RED"}).json()["id"]
    assert c.post("/api/cases", json={"title": "x", "tlp": "TLP:PINK"}).status_code == 422
    eid = c.post(f"/api/cases/{cid}/upload", json={"filename": "iocs.txt", "content_b64": base64.b64encode(b"1.2.3.4").decode(), "mime": "text/plain"}).json()["id"]
    assert c.get(f"/api/evidence/{eid}/preview").text == "1.2.3.4"
    dl = c.get(f"/api/evidence/{eid}/content")
    assert dl.headers["content-disposition"].startswith("attachment") and dl.content == b"1.2.3.4"
    assert c.post(f"/api/cases/{cid}/capture", json={"url": "https://paste-site.example/raw/k1t"}).status_code == 200
    assert c.post(f"/api/cases/{cid}/findings", json={"title": "F", "body": "see [E1]", "confidence": "likely", "evidence_ids": [eid]}).status_code == 200
    assert c.get(f"/api/cases/{cid}/verify").json()["ok"]
    z = c.get(f"/api/cases/{cid}/bundle.zip")
    assert z.status_code == 200
    assert c.post("/api/verify-bundle", json={"content_b64": base64.b64encode(z.content).decode()}).json()["ok"]
    assert c.post("/api/verify-bundle", json={"content_b64": base64.b64encode(b"nope").decode()}).status_code == 422
    assert "TLP:RED" in c.get(f"/api/cases/{cid}/report.html").text
    assert c.get("/").status_code == 200
