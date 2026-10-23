"""Case reports (Markdown and self-contained printable HTML) with citations and integrity data."""

from __future__ import annotations

import html
import re

from .evidence import utcnow


def build(db, case_id: int) -> dict:
    case = db.case(case_id)
    ev = db.evidence(case_id)
    return {"case": case, "evidence": ev, "findings": db.findings(case_id), "audit": db.audit_log(case_id), "verification": db.verify_case(case_id),
            "generated_at": utcnow()}


def to_markdown(r: dict) -> str:
    c, ev = r["case"], {e["id"]: e for e in r["evidence"]}
    v = r["verification"]
    out = [f"# {c['title']}", "", f"**{c['tlp']}** · status {c['status']} · opened {c['created'][:10]} by {c['created_by']} · report generated {r['generated_at']}", "",
           c["summary"] or "", "", "## Findings", ""]
    for i, f in enumerate(r["findings"], 1):
        cites = " ".join(f"[{ev[e]['ref']}]" for e in f["evidence_ids"] if e in ev)
        out += [f"### {i}. {f['title']}", "", f"_Assessment: **{f['confidence']}** · {f['status']}"
                + (f" (reviewed by {f['reviewed_by']})" if f["reviewed_by"] else "") + f" · evidence {cites or 'none'}_", "", f["body"], ""]
    out += ["## Evidence register", "", "| Ref | Kind | Title / source | Captured (UTC) | By | SHA-256 |", "|---|---|---|---|---|---|"]
    for e in r["evidence"]:
        src = e["url"] or e["filename"] or "note"
        arch = f" · [archived]({e['archive_url']})" if e["archive_url"] else ""
        out.append(f"| {e['ref']} | {e['kind']} | {e['title']}<br>`{src}`{arch} | {e['captured_at'][:19]} | {e['captured_by']} | `{e['sha256'] or '—'}` |")
    out += ["", "## Chain of custody", "", f"Integrity check at {v['at']}: **{'PASS' if v['ok'] else 'FAIL'}**. {v['evidence_checked']} evidence file(s) re-hashed, "
            f"{v['audit_entries']} audit entries verified. Chain head `{v['head']}`.", ""]
    out += [f"- ⚠️ {p}" for p in v["problems"]]
    out += ["", "| # | Time (UTC) | Actor | Action | Detail | Entry hash |", "|---:|---|---|---|---|---|"]
    for a in r["audit"]:
        d = ", ".join(f"{k}={v}" for k, v in a["detail"].items() if k != "sha256")[:120]
        out.append(f"| {a['id']} | {a['at'][:19]} | {a['actor']} | {a['action']} | {d} | `{a['hash'][:16]}…` |")
    return "\n".join(out) + "\n"


def _md_inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    s = re.sub(r"\[(E\d+)\]", r'<a href="#\1">[\1]</a>', s)
    return s


def to_html(r: dict) -> str:
    c, ev = r["case"], {e["id"]: e for e in r["evidence"]}
    v = r["verification"]
    tlp_color = {"TLP:RED": "#c00", "TLP:AMBER": "#d97706", "TLP:AMBER+STRICT": "#d97706", "TLP:GREEN": "#16a34a", "TLP:CLEAR": "#555"}[c["tlp"]]
    parts = []
    for i, f in enumerate(r["findings"], 1):
        cites = " ".join("<a href='#{0}'>[{0}]</a>".format(ev[e]["ref"]) for e in f["evidence_ids"] if e in ev) or "none"
        reviewed = " · reviewed by " + html.escape(f["reviewed_by"]) if f["reviewed_by"] else ""
        paras = "".join("<p>" + _md_inline(p) + "</p>" for p in f["body"].split("\n\n") if p.strip())
        parts.append(f"<section class='f'><h3>{i}. {html.escape(f['title'])}</h3><p class='meta'>Assessment: <b>{html.escape(f['confidence'])}</b> · "
                     f"{f['status']}{reviewed} · evidence {cites}</p>{paras}</section>")
    findings = "".join(parts)
    rows = "".join(
        f"<tr id='{e['ref']}'><td><b>{e['ref']}</b></td><td>{e['kind']}</td><td>{html.escape(e['title'])}<div class='mono'>{html.escape(e['url'] or e['filename'] or '')}</div>"
        f"{('<a href=' + html.escape(e['archive_url']) + '>archived copy</a>') if e['archive_url'] else ''}</td><td>{e['captured_at'][:19]}</td>"
        f"<td>{html.escape(e['captured_by'])}</td><td class='mono'>{e['sha256'] or '—'}</td></tr>" for e in r["evidence"])
    problems = "".join("<p class='bad'>⚠ " + html.escape(p) + "</p>" for p in v["problems"])
    audit = "".join(f"<tr><td>{a['id']}</td><td>{a['at'][:19]}</td><td>{html.escape(a['actor'])}</td><td>{a['action']}</td><td class='mono'>{a['hash'][:24]}…</td></tr>"
                    for a in r["audit"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{html.escape(c['title'])}</title>
<style>body{{font:14px/1.55 system-ui,sans-serif;max-width:960px;margin:32px auto;padding:0 16px;color:#111}}h1{{margin-bottom:4px}}
.tlp{{display:inline-block;background:#000;color:{tlp_color};font-weight:700;padding:2px 8px;border-radius:4px}}.meta{{color:#555;font-size:13px}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}}td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
.mono,code{{font-family:ui-monospace,monospace;font-size:11.5px;word-break:break-all}}.f{{border-left:3px solid #2f6fde;padding-left:12px;margin:18px 0}}
.ok{{color:#16a34a}}.bad{{color:#c00}}@media print{{a{{color:#000}}}}</style></head><body>
<span class="tlp">{c['tlp']}</span><h1>{html.escape(c['title'])}</h1>
<p class="meta">Status {c['status']} · opened {c['created'][:10]} by {html.escape(c['created_by'])} · generated {r['generated_at']}</p>
<p>{html.escape(c['summary'] or '')}</p><h2>Findings</h2>{findings or '<p>No findings.</p>'}
<h2>Evidence register</h2><table><tr><th>Ref</th><th>Kind</th><th>Source</th><th>Captured (UTC)</th><th>By</th><th>SHA-256</th></tr>{rows}</table>
<h2>Chain of custody</h2><p class="{'ok' if v['ok'] else 'bad'}"><b>Integrity {'PASS' if v['ok'] else 'FAIL'}</b>: {v['evidence_checked']} file(s) re-hashed,
{v['audit_entries']} audit entries verified, chain head <code>{v['head']}</code>.</p>{problems}
<table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Entry hash</th></tr>{audit}</table></body></html>"""
