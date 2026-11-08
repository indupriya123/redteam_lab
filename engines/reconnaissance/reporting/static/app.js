"use strict";
const el = id => document.getElementById(id);
let selected = null, after = 0, offset = 0, polling = false;
let apiOffset = 0;
const show = (id, data) => { el(id).textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2); };
async function api(path, method = "GET", body) {
  const response = await fetch("/api/v1/recon/" + path, {
    method, headers: {Authorization: "Bearer " + el("token").value, "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (!response.ok) throw new Error(await response.text());
  return response;
}
function action(fn) { return async event => { if (event) event.preventDefault(); try { await fn(); show("message", ""); } catch (error) { show("message", error.message); } }; }
async function list() {
  const runs = await (await api("assessments")).json();
  el("runs").replaceChildren(...runs.map(run => {
    const button = document.createElement("button");
    button.textContent = run.spec.title + " / " + run.status;
    button.onclick = action(async () => { selected = run.id; after = 0; offset = 0; apiOffset = 0; show("console", ""); await details(); });
    return button;
  }));
}
async function ports() { if (selected) show("ports", await (await api(`assessments/${selected}/ports?offset=${offset}&limit=100&state=${encodeURIComponent(el("state").value)}`.replace(/&state=$/, ""))).json()); }
async function details() {
  if (!selected) return;
  const base = "assessments/" + selected;
  const results = await Promise.all([base, base + "/assets", base + "/graph", base + "/evidence", base + "/report"].map(path => api(path)));
  const assessment = await results[0].json();
  show("progress", assessment); show("api-coverage", assessment.api_coverage || "Not assessed");
  show("assets", await results[1].json());
  show("graph", await results[2].json()); show("evidence", await results[3].json());
  show("report-preview", await results[4].text()); await ports();
  const additional = await Promise.all([
    base + `/intelligence/api_operation?offset=${apiOffset}&limit=100`,
    base + "/intelligence/ad_object", base + "/intelligence/supply_chain_component", base + "/executions"
  ].map(async path => (await api(path)).json()));
  ["api-operations", "ad-inventory", "supply-inventory", "executions"].forEach((id, index) => show(id, additional[index]));
}
async function download(suffix, filename) {
  if (!selected) throw new Error("Select an assessment");
  const response = await api(`assessments/${selected}/${suffix}`);
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}
el("connect").onclick = action(async () => { show("capabilities", await (await api("capabilities")).json()); await list(); });
el("refresh").onclick = action(list);
el("assessment").onsubmit = action(async () => {
  const result = await (await api("assessments", "POST", {
    title: el("title").value, mode: el("mode").value, approved: el("approved").checked,
    targets: el("targets").value.split(/\n/).map(value => value.trim()).filter(Boolean),
    authorization_reference: el("authorization").value, udp: el("udp").checked,
    fingerprint_services: el("fingerprint").checked, inventory: JSON.parse(el("inventory").value),
    domains: el("domains").value.split(",").map(value => value.trim()).filter(Boolean),
    urls: el("urls").value.split(/\n/).map(value => value.trim()).filter(Boolean),
    exclusions: el("exclusions").value.split(/\n/).map(value => value.trim()).filter(Boolean),
    safe_get_paths: el("safe-get").value.split(/\n/).map(value => value.trim()).filter(Boolean),
    documents: JSON.parse(el("documents").value)
  })).json(); selected = result.id; after = 0; offset = 0; show("console", ""); await list(); await details();
});
el("cancel").onclick = action(async () => { if (!selected) throw new Error("Select an assessment"); await api(`assessments/${selected}/cancel`, "POST"); await details(); });
el("previous").onclick = action(async () => { offset = Math.max(0, offset - 100); await ports(); });
el("next").onclick = action(async () => { offset += 100; await ports(); });
el("state").onchange = action(async () => { offset = 0; await ports(); });
el("report").onclick = action(() => download("report", "recon-report.md"));
el("package").onclick = action(() => download("intelligence", "recon-intelligence.json"));
el("export").onclick = action(() => download("ports/export", "recon-ports.jsonl"));
el("json-report").onclick = action(() => download("report?format=json", "recon-report.json"));
el("html-report").onclick = action(() => download("report?format=html", "recon-report.html"));
el("api-previous").onclick = action(async () => { apiOffset = Math.max(0, apiOffset - 100); await details(); });
el("api-next").onclick = action(async () => { apiOffset += 100; await details(); });
setInterval(async () => {
  if (!selected || polling) return;
  polling = true;
  try {
    const id = selected;
    const events = await (await api(`assessments/${id}/events?after=${after}`)).json();
    if (id !== selected) return;
    if (events.length) {
      after = events[events.length - 1].sequence;
      const text = el("console").textContent + events.map(value => JSON.stringify(value)).join("\n") + "\n";
      show("console", text.slice(-50000)); await details();
    }
  } catch (error) { show("message", error.message); } finally { polling = false; }
}, 2000);
