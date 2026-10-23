"""Capture web pages as evidence: exact bytes, response metadata, title, optional Wayback archiving."""

from __future__ import annotations

import re

import httpx

from .evidence import utcnow

UA = "Casebook/1.0 (+OSINT evidence capture)"
MAX_BYTES = 25 * 1024 * 1024
KEEP_HEADERS = ("content-type", "content-length", "last-modified", "etag", "server", "date", "location", "x-cache", "cf-ray")


class CaptureError(RuntimeError):
    pass


class LiveCapturer:
    def fetch(self, url: str) -> dict:
        try:
            with httpx.Client(follow_redirects=True, timeout=30, headers={"User-Agent": UA}) as c:
                r = c.get(url)
        except httpx.HTTPError as exc:
            raise CaptureError(f"{type(exc).__name__}: {exc}") from exc
        if len(r.content) > MAX_BYTES:
            raise CaptureError("response larger than 25 MB")
        return {"status": r.status_code, "final_url": str(r.url), "headers": {k: v for k, v in r.headers.items() if k.lower() in KEEP_HEADERS},
                "content": r.content, "mime": r.headers.get("content-type", "").split(";")[0], "redirects": [str(h.url) for h in r.history]}

    def archive(self, url: str) -> str:
        """Ask the Wayback Machine to save the page; returns the snapshot URL (best effort)."""
        try:
            r = httpx.get(f"https://web.archive.org/save/{url}", headers={"User-Agent": UA}, timeout=60, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise CaptureError(f"Wayback save failed: {exc}") from exc
        loc = r.headers.get("content-location") or r.headers.get("location") or ""
        return ("https://web.archive.org" + loc) if loc.startswith("/web/") else loc


def title_of(content: bytes, mime: str) -> str:
    if "html" not in mime:
        return ""
    m = re.search(rb"<title[^>]*>(.*?)</title>", content[:200_000], re.I | re.S)
    return " ".join(m.group(1).decode("utf-8", "replace").split())[:200] if m else ""


def capture(db, case_id: int, actor: str, url: str, capturer=None, *, archive: bool = False, note: str = "") -> int:
    if not url.startswith(("http://", "https://")):
        raise CaptureError("URL must start with http:// or https://")
    capturer = capturer or LiveCapturer()
    started = utcnow()
    r = capturer.fetch(url)
    archive_url = ""
    if archive:
        try:
            archive_url = capturer.archive(url)
        except CaptureError as exc:
            note = (note + f" [archive failed: {exc}]").strip()
    headers = {**r["headers"], "x-casebook-redirect-chain": " -> ".join(r.get("redirects", []) + [r["final_url"]])}
    return db.add_evidence(case_id, actor, "web", title_of(r["content"], r["mime"]) or url, r["content"], url=url, final_url=r["final_url"],
                           mime=r["mime"], http_status=r["status"], headers=headers, archive_url=archive_url, note=note, captured_at=started)
