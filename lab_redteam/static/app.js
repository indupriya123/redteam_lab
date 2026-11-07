"use strict";
const token = document.querySelector('meta[name="lab-token"]').content;
const errorBox = document.getElementById("error");
let selected = null;
let catalogue = [];
let timer = null;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

async function api(path, method = "GET", body) {
  const response = await fetch(path, {
    method,
    headers: {"Content-Type": "application/json", "X-Lab-Token": token},
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail));
  return data;
}

async function action(path, body) {
  try {
    errorBox.textContent = "";
    await api(path, "POST", body);
    await refresh();
  } catch (error) { errorBox.textContent = error.message; }
}

function renderDetail(run) {
  const detail = document.getElementById("detail");
  detail.replaceChildren(node("h3", run.engagement.title), node("p", `Status: ${run.status} | Mode: ${run.engagement.mode}`));
  detail.append(node("p", `Objective: ${run.engagement.objective}`));
  detail.append(node("p", `Scope: ${run.engagement.targets.join(", ") || "In-memory synthetic fixtures"}; ports ${run.engagement.ports.join(", ")}`));
  detail.append(node("p", "Plan: " + (run.plan.join("; ") || "Awaiting approval; only built-in checks are executable.")));
  if (run.status === "awaiting_approval") {
    const approve = node("button", "Approve this scope and start");
    approve.onclick = () => {
      if (window.confirm("Run only the displayed scope and built-in checks?")) action(`/api/runs/${run.id}/approve`, {approve: true});
    };
    detail.append(approve);
  }
  if (["queued", "running"].includes(run.status)) {
    const stop = node("button", "Stop execution", "danger");
    stop.onclick = () => action(`/api/runs/${run.id}/stop`, {});
    detail.append(stop);
  }
  for (const format of ["markdown", "json"]) {
    const download = node("a", `Download ${format} report`, "download");
    download.href = `/api/runs/${run.id}/report?format=${format}`;
    detail.append(download);
  }
  detail.append(node("h3", "Findings and observations"));
  if (!run.findings.length) detail.append(node("p", "No findings recorded. This is not a security pass.", "muted"));
  for (const finding of run.findings) {
    const card = node("article", undefined, "finding");
    card.append(node("strong", `${finding.severity} | ${finding.title}`));
    card.append(node("p", `Status: ${finding.status}; confidence: ${finding.confidence}`));
    card.append(node("p", finding.observation), node("p", `Recommendation: ${finding.remediation}`));
    card.append(node("p", `Retest: ${finding.retest}`), node("p", `Evidence: ${finding.evidence_refs.join(", ")}`));
    detail.append(card);
  }
  detail.append(node("h3", "Gaps / untested areas"));
  for (const gap of run.gaps) detail.append(node("p", gap, "gap"));
  if (run.model_review) {
    detail.append(node("h3", "Local model advisory (unverified)"));
    detail.append(node("pre", run.model_review.text || run.model_review.error));
  }
  const evidence = node("details");
  evidence.append(node("summary", `Evidence (${run.evidence.length} records)`), node("pre", JSON.stringify(run.evidence, null, 2)));
  detail.append(evidence, node("h3", "Agent audit trail"));
  for (const event of run.events) detail.append(node("p", `${event.timestamp} | ${event.agent}: ${event.message}`, "event"));
}

async function refresh() {
  clearTimeout(timer);
  try {
    const runs = await api("/api/runs");
    const list = document.getElementById("runs");
    list.replaceChildren();
    if (!runs.length) list.append(node("p", "No engagements yet.", "muted"));
    for (const run of runs) {
      const button = node("button", `${run.engagement.title} - ${run.status}`, "secondary");
      button.onclick = () => { selected = run.id; refresh(); };
      list.append(button);
    }
    if (selected) renderDetail(await api(`/api/runs/${selected}`));
    if (runs.some(run => ["queued", "running"].includes(run.status))) timer = setTimeout(refresh, 1500);
  } catch (error) { errorBox.textContent = error.message; }
}

function renderCatalogue() {
  const query = document.getElementById("search").value.toLowerCase();
  const entries = catalogue.filter(record => JSON.stringify(record).toLowerCase().includes(query));
  const container = document.getElementById("catalogue");
  container.replaceChildren();
  for (const entry of entries) {
    const item = node("details");
    item.append(node("summary", `${entry.id} - ${entry.technique} [reference only]`));
    item.append(node("pre", JSON.stringify(entry, null, 2)));
    container.append(item);
  }
}

document.getElementById("engagement").onsubmit = async event => {
  event.preventDefault();
  errorBox.textContent = "";
  const form = new FormData(event.target);
  try {
    const ports = form.get("ports").split(",").map(value => {
      if (!/^\d+$/.test(value.trim())) throw new Error("Ports must be comma-separated integers.");
      return Number(value.trim());
    });
    const run = await api("/api/runs", "POST", {
      title: form.get("title"), objective: form.get("objective"),
      authorization_reference: form.get("authorization_reference"),
      mode: form.get("mode"),
      targets: form.get("targets").split(",").map(value => value.trim()).filter(Boolean),
      ports, model: form.get("model"), scanners: form.get("nuclei") === "on" ? ["nuclei"] : [],
      isolated_and_authorized: form.get("authorized") === "on"
    });
    selected = run.id;
    await refresh();
  } catch (error) { errorBox.textContent = error.message; }
};
document.getElementById("refresh").onclick = refresh;
document.getElementById("search").oninput = renderCatalogue;
(async () => {
  try {
    const [config, data, tools] = await Promise.all([api("/api/config"), api("/api/catalogue"), api("/api/tools")]);
    document.getElementById("nuclei").disabled = !config.nuclei_version_approved;
    const toolsContainer = document.getElementById("tools");
    for (const tool of tools) {
      const entry = node("details");
      entry.append(node("summary", `${tool.id}: ${tool.status}`), node("pre", JSON.stringify(tool, null, 2)));
      toolsContainer.append(entry);
    }
    document.getElementById("policy").textContent = config.network_enabled ?
      `Operator allowlist: ${config.allowed_cidrs.join(", ")}. Separate approval required for each run.` :
      "Network execution disabled. Configure LAB_ALLOWED_CIDRS to enable explicit-IP lab checks. Synthetic demonstrations are available.";
    catalogue = data.techniques;
    document.getElementById("catalogue-summary").textContent =
      `${data.techniques.length} technique records | ${data.skills.length} skill domains | ${data.capabilities.length} enterprise capabilities`;
    renderCatalogue();
    await refresh();
  } catch (error) { errorBox.textContent = error.message; }
})();
