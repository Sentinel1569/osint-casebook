"""A seeded demo case with offline web captures, a file, notes and linked findings.

All pages are fictional and served from fixtures for the reserved ``.example`` TLD.
"""

from __future__ import annotations

from .capture import capture

PAGES = {
    "https://secure-login-northwind.example/": (200, "text/html",
        "<html><head><title>Northwind Bank - Sign in</title></head><body><form action='/post.php' method='post'>"
        "<input name='user'><input name='pass' type='password'></form><script src='https://cdn-kit.example/kit-v3.js'></script></body></html>"),
    "https://secure-login-northwind.example/post.php": (405, "text/html", "<html><head><title>405</title></head><body>Method not allowed</body></html>"),
    "https://paste-site.example/raw/k1t": (200, "text/plain",
        "kit v3 config\nexfil = https://collector.example/gate.php\npanel_user = admin\ntargets = northwind, contoso, fabrikam\n"),
    "https://ct-viewer.example/?q=secure-login-northwind.example": (200, "text/html",
        "<html><head><title>CT results for secure-login-northwind.example</title></head><body><table><tr><td>2026-10-20</td>"
        "<td>Let's Encrypt R11</td><td>secure-login-northwind.example</td></tr></table></body></html>"),
}


class DemoCapturer:
    def fetch(self, url):
        status, mime, body = PAGES[url]
        redirects = ["https://secure-login-northwind.example"] if url == "https://secure-login-northwind.example/" else []
        return {"status": status, "final_url": url, "headers": {"content-type": mime, "server": "nginx", "date": "Fri, 23 Oct 2026 08:00:00 GMT"},
                "content": body.encode(), "mime": mime, "redirects": redirects}

    def archive(self, url):
        return f"https://web.archive.org/web/20261023080000/{url}"


def seed(db, actor: str) -> int:
    cid = db.create_case("Northwind Bank phishing kit (demo)",
                         "Fictional investigation: a credential-phishing page impersonating Northwind Bank, its kit configuration and certificate.",
                         "TLP:AMBER", actor)
    c = DemoCapturer()
    e1 = capture(db, cid, actor, "https://secure-login-northwind.example/", c, archive=True, note="Reported by customer via abuse mailbox.")
    e2 = capture(db, cid, actor, "https://secure-login-northwind.example/post.php", c, note="Form target; GET returns 405 as expected for a POST handler.")
    e3 = capture(db, cid, actor, "https://paste-site.example/raw/k1t", c, archive=True, note="Kit configuration found by searching the kit's JS file name.")
    e4 = capture(db, cid, actor, "https://ct-viewer.example/?q=secure-login-northwind.example", c, note="Certificate issued 3 days before the report.")
    e5 = db.add_evidence(cid, actor, "file", "Abuse mailbox report (headers redacted)",
                         b"From: customer@redacted\nSubject: Strange login email\n\nI received a link to secure-login-northwind.example ...\n",
                         filename="abuse-report.eml.txt", mime="text/plain", note="Personal data redacted before ingestion.")
    e6 = db.add_evidence(cid, actor, "note", "Analyst note: hosting", None, note="IP 203.0.113.11 sits on a VPS range; no other Northwind lookalikes on it.")
    db.save_finding(cid, actor, "secure-login-northwind.example hosts a credential-harvesting page impersonating Northwind Bank",
                    "The page reproduces the bank's sign-in form and posts credentials to `/post.php` [E1] [E2]. The certificate was issued "
                    "**three days** before the first report [E4], consistent with infrastructure prepared for a campaign.", "almost certain", [e1, e2, e4])
    db.save_finding(cid, actor, "The kit is shared with operators targeting other brands",
                    "The configuration retrieved from a paste site [E3] lists northwind, contoso and fabrikam as targets and the same "
                    "`kit-v3.js` loader referenced by the phishing page [E1]. This shows a common kit, **not** necessarily a common operator.",
                    "likely", [e1, e3])
    db.save_finding(cid, actor, "First victim contact came through email",
                    "A customer report [E5] provides the earliest observed lure. Hosting notes in [E6].", "very likely", [e5, e6])
    return cid
