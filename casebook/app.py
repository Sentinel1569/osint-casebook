"""FastAPI application with accounts, roles and the casebook UI."""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, bundle, report
from .capture import CaptureError, capture
from .db import CONFIDENCE, DB, ROLES
from .demo import PAGES, DemoCapturer, seed

STATIC = Path(__file__).parent / "static"
COOKIE = "cb_session"
CAN_WRITE = {"admin", "analyst"}
CAN_REVIEW = {"admin", "reviewer"}


def create_app(db_path: str | None = None, store_root: str | None = None, secure_cookie: bool = False) -> FastAPI:
    app = FastAPI(title="OSINT Investigation Casebook", version=__version__)
    db = DB(db_path, store_root)

    def user(request: Request) -> dict:
        u = db.session_user(request.cookies.get(COOKIE))
        if not u:
            raise HTTPException(401, "sign in required")
        return u

    def writer(u: dict = Depends(user)) -> dict:
        if u["role"] not in CAN_WRITE:
            raise HTTPException(403, "your role cannot modify cases")
        return u

    def case_or_404(cid: int) -> dict:
        c = db.case(cid)
        if not c:
            raise HTTPException(404, "case not found")
        return c

    def _login(resp: Response, token: str):
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=secure_cookie, max_age=12 * 3600)

    # ---------------------------------------------------------------- auth
    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/api/session")
    def session(request: Request):
        return {"user": db.session_user(request.cookies.get(COOKIE)), "needs_setup": db.user_count() == 0, "confidence": CONFIDENCE, "roles": ROLES}

    @app.post("/api/setup")
    def setup(response: Response, username: str = Body(...), password: str = Body(...)):
        if db.user_count():
            raise HTTPException(409, "already set up")
        try:
            db.create_user(username, password, "admin")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        _login(response, db.login(username, password))
        db.audit(None, username.lower(), "user.setup", {"role": "admin"})
        return {"ok": True}

    @app.post("/api/login")
    def login(response: Response, username: str = Body(...), password: str = Body(...)):
        token = db.login(username, password)
        if not token:
            db.audit(None, username.lower()[:64], "user.login_failed", {})
            raise HTTPException(401, "wrong username or password")
        _login(response, token)
        return {"ok": True}

    @app.post("/api/logout")
    def logout(request: Request, response: Response):
        if request.cookies.get(COOKIE):
            db.logout(request.cookies[COOKIE])
        response.delete_cookie(COOKIE)
        return {"ok": True}

    @app.get("/api/users")
    def users(u: dict = Depends(user)):
        if u["role"] != "admin":
            raise HTTPException(403, "admins only")
        return db.users()

    @app.post("/api/users")
    def add_user(username: str = Body(...), password: str = Body(...), role: str = Body("analyst"), u: dict = Depends(user)):
        if u["role"] != "admin":
            raise HTTPException(403, "admins only")
        try:
            uid = db.create_user(username, password, role)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        db.audit(None, u["username"], "user.create", {"username": username, "role": role})
        return {"id": uid}

    # ---------------------------------------------------------------- cases
    @app.get("/api/cases")
    def cases(u: dict = Depends(user)):
        return db.cases()

    @app.post("/api/cases")
    def new_case(title: str = Body(...), summary: str = Body(""), tlp: str = Body("TLP:AMBER"), u: dict = Depends(writer)):
        try:
            return {"id": db.create_case(title, summary, tlp, u["username"])}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.patch("/api/cases/{cid}")
    def edit_case(cid: int, status: str | None = Body(None), summary: str | None = Body(None), tlp: str | None = Body(None), u: dict = Depends(writer)):
        case_or_404(cid)
        if status and status not in ("open", "closed"):
            raise HTTPException(422, "status must be open or closed")
        db.update_case(cid, u["username"], status=status, summary=summary, tlp=tlp)
        return {"ok": True}

    @app.get("/api/cases/{cid}")
    def get_case(cid: int, u: dict = Depends(user)):
        return {"case": case_or_404(cid), "evidence": db.evidence(cid), "findings": db.findings(cid), "audit": db.audit_log(cid)[-200:]}

    @app.post("/api/cases/{cid}/capture")
    def api_capture(cid: int, url: str = Body(...), archive: bool = Body(False), note: str = Body(""), u: dict = Depends(writer)):
        case_or_404(cid)
        capt = DemoCapturer() if url in PAGES else None
        try:
            return {"id": capture(db, cid, u["username"], url, capt, archive=archive, note=note)}
        except CaptureError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/api/cases/{cid}/upload")
    def upload(cid: int, filename: str = Body(...), content_b64: str = Body(...), mime: str = Body("application/octet-stream"), title: str = Body(""),
               note: str = Body(""), u: dict = Depends(writer)):
        case_or_404(cid)
        data = base64.b64decode(content_b64)
        if len(data) > 50 * 1024 * 1024:
            raise HTTPException(413, "file larger than 50 MB")
        return {"id": db.add_evidence(cid, u["username"], "file", title or filename, data, filename=filename, mime=mime, note=note)}

    @app.post("/api/cases/{cid}/note")
    def note(cid: int, title: str = Body(...), text: str = Body(...), u: dict = Depends(writer)):
        case_or_404(cid)
        return {"id": db.add_evidence(cid, u["username"], "note", title, text.encode(), mime="text/plain", note=text[:500])}

    @app.get("/api/evidence/{eid}/content")
    def content(eid: int, u: dict = Depends(user)):
        e = db.evidence_item(eid)
        if not e or not e["sha256"]:
            raise HTTPException(404, "no stored content")
        data = db.get_blob(e["sha256"]) or b""
        # served as an attachment and never rendered inline: captured pages may contain hostile markup
        name = f"{e['ref']}_{e['sha256'][:12]}.bin"
        return Response(data, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{name}"',
                                                                                "X-Content-Type-Options": "nosniff"})

    @app.get("/api/evidence/{eid}/preview", response_class=PlainTextResponse)
    def preview(eid: int, u: dict = Depends(user)):
        e = db.evidence_item(eid)
        if not e or not e["sha256"]:
            raise HTTPException(404, "no stored content")
        return (db.get_blob(e["sha256"]) or b"")[:20000].decode("utf-8", "replace")

    @app.post("/api/cases/{cid}/findings")
    def finding(cid: int, title: str = Body(...), body: str = Body(""), confidence: str = Body("likely"), evidence_ids: list[int] = Body([]),
                finding_id: int | None = Body(None), u: dict = Depends(writer)):
        case_or_404(cid)
        try:
            return {"id": db.save_finding(cid, u["username"], title, body, confidence, evidence_ids, finding_id)}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/cases/{cid}/findings/{fid}/review")
    def review(cid: int, fid: int, approve: bool = Body(True, embed=True), u: dict = Depends(user)):
        if u["role"] not in CAN_REVIEW:
            raise HTTPException(403, "only reviewers can approve findings")
        f = next((x for x in db.findings(cid) if x["id"] == fid), None)
        if not f:
            raise HTTPException(404, "finding not found")
        if f["created_by"] == u["username"] and approve:
            raise HTTPException(409, "four-eyes rule: you cannot review your own finding")
        db.review_finding(cid, fid, u["username"], approve)
        return {"ok": True}

    @app.get("/api/cases/{cid}/verify")
    def verify(cid: int, u: dict = Depends(user)):
        case_or_404(cid)
        res = db.verify_case(cid)
        db.audit(cid, u["username"], "case.verify", {"ok": res["ok"], "head": res["head"]})
        return res

    @app.get("/api/cases/{cid}/report.md", response_class=PlainTextResponse)
    def report_md(cid: int, u: dict = Depends(user)):
        case_or_404(cid)
        return report.to_markdown(report.build(db, cid))

    @app.get("/api/cases/{cid}/report.html", response_class=HTMLResponse)
    def report_html(cid: int, u: dict = Depends(user)):
        case_or_404(cid)
        return report.to_html(report.build(db, cid))

    @app.get("/api/cases/{cid}/bundle.zip")
    def export(cid: int, u: dict = Depends(user)):
        c = case_or_404(cid)
        data = bundle.export(db, cid)
        db.audit(cid, u["username"], "case.export", {"bytes": len(data)})
        return Response(data, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="case-{c["id"]}-bundle.zip"'})

    @app.post("/api/verify-bundle")
    def verify_bundle(content_b64: str = Body(..., embed=True), u: dict = Depends(user)):
        try:
            return bundle.verify(base64.b64decode(content_b64))
        except Exception as exc:  # noqa: BLE001 - any parsing failure means "not a valid bundle"
            raise HTTPException(422, f"not a readable bundle: {exc}") from exc

    @app.post("/api/demo")
    def demo(u: dict = Depends(writer)):
        return {"id": seed(db, u["username"])}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    return app


app = create_app()
