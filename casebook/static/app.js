"use strict";
let S = null, C = null, cid = null, eTab = "url", editId = null;

async function session() {
  S = await api("/api/session");
  $("#auth").hidden = !!S.user; $("#appView").hidden = !S.user; $("#logout").hidden = !S.user;
  $("#who").textContent = S.user ? `${S.user.username} · ${S.user.role}` : "";
  if (!S.user) {
    $("#authTitle").textContent = S.needs_setup ? "Create the administrator account" : "Sign in";
    $("#authHint").textContent = S.needs_setup ? "First run: this account can add analysts, reviewers and viewers." : "";
    $("#aGo").textContent = S.needs_setup ? "Create account" : "Sign in";
    return;
  }
  $("#fConf").innerHTML = S.confidence.map((c) => `<option ${c === "likely" ? "selected" : ""}>${c}</option>`).join("");
  $("#adminCard").hidden = S.user.role !== "admin";
  $("#addCard").hidden = true;
  if (S.user.role === "admin") loadUsers();
  await loadCases();
}

async function loadUsers() {
  const us = await api("/api/users");
  $("#users").innerHTML = us.map((u) => `<div class="row" style="justify-content:space-between"><span>${esc(u.username)}</span><span class="badge b-muted shrink">${esc(u.role)}</span></div>`).join("");
}

async function loadCases(select) {
  const cs = await api("/api/cases");
  if (select) cid = select;
  $("#cases").innerHTML = cs.map((c) => `<div class="cs ${c.id === cid ? "active" : ""}" data-c="${c.id}"><span class="tlp tlp-${c.tlp.slice(4).replace("+", "")}">${esc(c.tlp)}</span> <b>${esc(c.title)}</b>
    <div class="muted">${c.evidence} evidence · ${c.findings} findings · ${esc(c.status)}</div></div>`).join("") || '<div class="muted">No cases yet.</div>';
  $$("[data-c]").forEach((x) => x.onclick = () => { cid = +x.dataset.c; loadCases(); });
  await loadCase();
}

async function loadCase() {
  const has = !!cid;
  ["#caseHead", "#caseBody", "#auditCard", "#bundleCard"].forEach((s) => $(s).hidden = !has);
  $("#noCase").hidden = has;
  $("#addCard").hidden = !has || !["admin", "analyst"].includes(S.user.role);
  if (!has) return;
  C = await api(`/api/cases/${cid}`);
  const c = C.case;
  $("#caseHead").innerHTML = `<div class="row" style="justify-content:space-between"><div><span class="tlp tlp-${c.tlp.slice(4).replace("+", "")}">${esc(c.tlp)}</span>
      <span style="font-size:18px;font-weight:700;margin-left:8px">${esc(c.title)}</span><div class="small muted" style="margin-top:4px">opened ${esc(c.created.slice(0, 10))} by ${esc(c.created_by)} · ${esc(c.status)}</div></div>
    <div class="row shrink" style="gap:6px"><a class="btn ghost sm" href="/api/cases/${cid}/report.html" target="_blank">Report (HTML)</a><a class="btn ghost sm" href="/api/cases/${cid}/report.md" download="case-${cid}.md">Markdown</a>
      <a class="btn sm" href="/api/cases/${cid}/bundle.zip">Export bundle</a>${["admin", "analyst"].includes(S.user.role) ? `<button class="ghost sm" id="toggleStatus">${c.status === "open" ? "Close case" : "Reopen"}</button>` : ""}</div></div>
    <p>${esc(c.summary)}</p>`;
  const ts = $("#toggleStatus");
  if (ts) ts.onclick = async () => { await api(`/api/cases/${cid}`, { method: "PATCH", json: { status: c.status === "open" ? "closed" : "open" } }); loadCases(); };
  const ev = Object.fromEntries(C.evidence.map((e) => [e.id, e]));
  const canReview = ["admin", "reviewer"].includes(S.user.role), canWrite = ["admin", "analyst"].includes(S.user.role);
  $("#findings").innerHTML = C.findings.map((f) => `<div class="fd ${f.status}"><b>${esc(f.title)}</b>
      <div class="small muted">${esc(f.confidence)} · ${f.status === "reviewed" ? `✓ reviewed by ${esc(f.reviewed_by)}` : "draft"} · by ${esc(f.created_by)}</div>
      ${f.body.split(/\n\n+/).map((p) => `<p>${esc(p).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`(.+?)`/g, "<code>$1</code>").replace(/\[(E\d+)\]/g, '<span class="ref" data-ref="$1">[$1]</span>')}</p>`).join("")}
      <div class="small">Evidence: ${f.evidence_ids.map((i) => ev[i] ? `<span class="ref" data-ref="${ev[i].ref}">${ev[i].ref}</span>` : "").join(" ") || "none"}</div>
      <div class="row" style="margin-top:6px;gap:6px">${canWrite ? `<button class="ghost sm shrink" data-edit="${f.id}">Edit</button>` : ""}
      ${canReview && f.created_by !== S.user.username ? `<button class="ghost sm shrink" data-rev="${f.id}" data-ok="${f.status === "reviewed" ? 0 : 1}">${f.status === "reviewed" ? "Withdraw review" : "Approve"}</button>` : ""}</div></div>`).join("") || '<div class="empty">No findings yet.</div>';
  $$("[data-ref]").forEach((x) => x.onclick = () => { const e = C.evidence.find((y) => y.ref === x.dataset.ref); if (e) preview(e); });
  $$("[data-edit]").forEach((x) => x.onclick = () => openEditor(C.findings.find((f) => f.id === +x.dataset.edit)));
  $$("[data-rev]").forEach((x) => x.onclick = () => busy(x, async () => { await api(`/api/cases/${cid}/findings/${x.dataset.rev}/review`, { json: { approve: !!+x.dataset.ok } }); loadCase(); }));
  $("#fNew").hidden = !canWrite;
  $("#evidence").innerHTML = C.evidence.map((e) => `<div class="ev" id="ev-${e.ref}"><span class="ref" data-pv="${e.id}">${e.ref}</span> <span class="badge b-muted">${esc(e.kind)}</span> <b>${esc(e.title)}</b>
      ${e.url ? `<div class="small mono" style="word-break:break-all">${esc(e.url)}${e.final_url && e.final_url !== e.url ? ` → ${esc(e.final_url)}` : ""}${e.http_status ? ` · HTTP ${e.http_status}` : ""}</div>` : ""}
      ${e.filename ? `<div class="small mono">${esc(e.filename)} · ${e.size.toLocaleString()} bytes</div>` : ""}
      ${e.note ? `<div class="small">${esc(e.note)}</div>` : ""}
      <div class="h">${e.sha256 ? "sha256 " + e.sha256 : "no stored content"} · ${esc(e.captured_at.slice(0, 19))} · ${esc(e.captured_by)}</div>
      <div class="small" style="margin-top:3px">${e.sha256 ? `<a href="#" data-pv="${e.id}">preview as text</a> · <a href="/api/evidence/${e.id}/content">download original</a>` : ""}${e.archive_url ? ` · <a href="${esc(e.archive_url)}" target="_blank" rel="noopener noreferrer">archived copy</a>` : ""}</div></div>`).join("") || '<div class="empty">No evidence yet.</div>';
  $$("[data-pv]").forEach((x) => x.onclick = (ev2) => { ev2.preventDefault(); preview(C.evidence.find((e) => e.id === +x.dataset.pv)); });
  $("#audit").innerHTML = C.audit.slice().reverse().map((a) => `<div class="au"><span>${a.id}</span><span class="mono">${esc(a.at.slice(0, 19).replace("T", " "))}</span><span>${esc(a.actor)}</span>
      <span>${esc(a.action)} <span class="muted">${esc(Object.entries(a.detail).filter(([k]) => k !== "sha256").map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ").slice(0, 110))}</span></span><span class="hash">${a.hash.slice(0, 14)}…</span></div>`).join("");
}

async function preview(e) {
  $("#previewCard").hidden = false;
  $("#pvTitle").textContent = `${e.ref} · ${e.title}`;
  $("#pv").textContent = e.sha256 ? await (await fetch(`/api/evidence/${e.id}/preview`)).text() : e.note;
  $("#previewCard").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function openEditor(f) {
  editId = f ? f.id : null;
  $("#fEditor").hidden = false;
  $("#fTitle").value = f ? f.title : ""; $("#fBody").value = f ? f.body : ""; $("#fConf").value = f ? f.confidence : "likely";
  $("#fEv").innerHTML = C.evidence.map((e) => `<label><input type="checkbox" value="${e.id}" ${f && f.evidence_ids.includes(e.id) ? "checked" : ""}> <b>${e.ref}</b> ${esc(e.title)}</label>`).join("") || '<div class="muted small">Add evidence first.</div>';
  $("#fEditor").scrollIntoView({ behavior: "smooth" });
}

function readB64(file) {
  return new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => res(String(fr.result).split(",")[1]); fr.onerror = rej; fr.readAsDataURL(file); });
}

document.addEventListener("DOMContentLoaded", async () => {
  $("#aGo").onclick = () => busy($("#aGo"), async () => {
    await api(S.needs_setup ? "/api/setup" : "/api/login", { json: { username: $("#aUser").value, password: $("#aPass").value } });
    $("#aPass").value = ""; await session();
  });
  $("#aPass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#aGo").click(); });
  $("#logout").onclick = async () => { await api("/api/logout", { method: "POST" }); cid = null; session(); };
  $("#cAdd").onclick = () => busy($("#cAdd"), async () => { const r = await api("/api/cases", { json: { title: $("#cTitle").value, summary: $("#cSummary").value, tlp: $("#cTlp").value } }); await loadCases(r.id); });
  $("#demo").onclick = () => busy($("#demo"), async () => { const r = await api("/api/demo", { method: "POST" }); await loadCases(r.id); });
  $$("#eTabs button").forEach((b) => b.onclick = () => { eTab = b.dataset.t; $$("#eTabs button").forEach((x) => x.classList.toggle("active", x === b)); $$("#addCard [data-p]").forEach((p) => p.hidden = p.dataset.p !== eTab); });
  $("#eAdd").onclick = () => busy($("#eAdd"), async () => {
    if (eTab === "url") await api(`/api/cases/${cid}/capture`, { json: { url: $("#eUrl").value, archive: $("#eArchive").checked, note: $("#eNote").value } });
    else if (eTab === "file") { const f = $("#eFile").files[0]; if (!f) { toast("Choose a file"); return; } await api(`/api/cases/${cid}/upload`, { json: { filename: f.name, mime: f.type || "application/octet-stream", content_b64: await readB64(f), note: $("#eNote").value } }); }
    else await api(`/api/cases/${cid}/note`, { json: { title: $("#eNoteTitle").value || "Note", text: $("#eNote").value } });
    $("#eUrl").value = ""; $("#eNote").value = ""; toast("Evidence added and hashed", "ok"); await loadCases();
  });
  $("#fNew").onclick = () => openEditor(null);
  $("#fCancel").onclick = () => { $("#fEditor").hidden = true; };
  $("#fSave").onclick = () => busy($("#fSave"), async () => {
    await api(`/api/cases/${cid}/findings`, { json: { title: $("#fTitle").value, body: $("#fBody").value, confidence: $("#fConf").value, finding_id: editId, evidence_ids: $$("#fEv input:checked").map((x) => +x.value) } });
    $("#fEditor").hidden = true; await loadCases();
  });
  $("#pvClose").onclick = () => { $("#previewCard").hidden = true; };
  $("#verify").onclick = () => busy($("#verify"), async () => {
    const r = await api(`/api/cases/${cid}/verify`);
    $("#verifyOut").innerHTML = `<div class="banner" style="border-left:4px solid ${r.ok ? "var(--ok)" : "var(--bad)"}"><b>${r.ok ? "Integrity verified" : "Integrity FAILED"}</b>: ${r.evidence_checked} evidence file(s) re-hashed, ${r.audit_entries} audit entries chained. Head <span class="mono">${r.head.slice(0, 24)}…</span>${r.problems.map((p) => `<div style="color:var(--bad)">⚠ ${esc(p)}</div>`).join("")}</div>`;
    loadCase();
  });
  $("#uAdd").onclick = () => busy($("#uAdd"), async () => { await api("/api/users", { json: { username: $("#uName").value, password: $("#uPass").value, role: $("#uRole").value } }); $("#uPass").value = ""; loadUsers(); });
  $("#bFile").onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    const r = await api("/api/verify-bundle", { json: { content_b64: await readB64(f) } });
    $("#bOut").innerHTML = `<b style="color:${r.ok ? "var(--ok)" : "var(--bad)"}">${r.ok ? "✓ Bundle intact" : "✗ Bundle altered"}</b> · ${r.files} files checked${r.case ? " · " + esc(r.case) : ""}${r.problems.map((p) => `<div style="color:var(--bad)">${esc(p)}</div>`).join("")}`;
  };
  await session();
});
