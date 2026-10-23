"""Portable case bundles: a zip with manifest, evidence files, reports and SHA256SUMS that anyone can verify."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

from . import report


def export(db, case_id: int) -> bytes:
    r = report.build(db, case_id)
    buf = io.BytesIO()
    sums = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def put(name: str, data: bytes):
            z.writestr(name, data)
            sums.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
        for e in r["evidence"]:
            data = db.get_blob(e["sha256"]) if e["sha256"] else None
            if data is not None:
                ext = {"text/html": ".html", "application/json": ".json", "text/plain": ".txt", "image/png": ".png", "image/jpeg": ".jpg",
                       "application/pdf": ".pdf"}.get(e["mime"], "")
                put(f"evidence/{e['ref']}_{e['sha256'][:12]}{ext}", data)
        manifest = {"format": "casebook-bundle/1", "case": r["case"], "findings": r["findings"], "evidence": r["evidence"],
                    "audit": r["audit"], "verification": r["verification"], "generated_at": r["generated_at"]}
        put("manifest.json", json.dumps(manifest, indent=2, default=str).encode())
        put("report.md", report.to_markdown(r).encode())
        put("report.html", report.to_html(r).encode())
        z.writestr("SHA256SUMS", "\n".join(sums) + "\n")
    return buf.getvalue()


def verify(data: bytes) -> dict:
    """Check every file against SHA256SUMS and every evidence file against the manifest's recorded hash."""
    problems = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = set(z.namelist())
        if "SHA256SUMS" not in names or "manifest.json" not in names:
            return {"ok": False, "problems": ["not a casebook bundle (SHA256SUMS or manifest.json missing)"], "files": 0}
        lines = [x.split("  ", 1) for x in z.read("SHA256SUMS").decode().splitlines() if x.strip()]
        for digest, name in lines:
            if name not in names:
                problems.append(f"{name}: missing")
            elif hashlib.sha256(z.read(name)).hexdigest() != digest:
                problems.append(f"{name}: modified")
        listed = {n for _, n in lines}
        extra = names - listed - {"SHA256SUMS"}
        problems += [f"{n}: not listed in SHA256SUMS" for n in sorted(extra)]
        manifest = json.loads(z.read("manifest.json"))
        for e in manifest["evidence"]:
            if not e["sha256"]:
                continue
            match = [n for n in names if n.startswith(f"evidence/{e['ref']}_")]
            if not match:
                problems.append(f"{e['ref']}: evidence file missing from bundle")
            elif hashlib.sha256(z.read(match[0])).hexdigest() != e["sha256"]:
                problems.append(f"{e['ref']}: does not match the hash recorded at capture")
    return {"ok": not problems, "problems": problems, "files": len(lines), "case": manifest["case"]["title"]}
