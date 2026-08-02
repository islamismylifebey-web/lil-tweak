"use strict";

const state = {
  csrf: "", task: null, approval: null, runs: [], evidence: [], submission: "",
  submissionLocked: false,
};
const $ = (id) => document.getElementById(id);
const json = (value) => JSON.stringify(value, null, 2);
let busyCount = 0;

function setBusy(active, message = "Working…") {
  busyCount = Math.max(0, busyCount + (active ? 1 : -1));
  const busy = busyCount > 0;
  $("loading-status").hidden = !busy;
  $("loading-status").textContent = busy ? message : "";
  $("main").setAttribute("aria-busy", String(busy));
}

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 3500);
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const text = await response.text();
  let payload = null;
  try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }
  if (!response.ok) throw new Error((payload && payload.detail) || payload || response.statusText);
  return payload;
}

async function session() {
  try {
    const data = await api("/v1/workbench/session");
    state.csrf = data.csrf_token;
    $("login-panel").hidden = true;
    $("app-shell").hidden = false;
    await refresh();
  } catch {
    $("login-panel").hidden = false;
    $("app-shell").hidden = true;
  }
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-error").textContent = "";
  try {
    const data = await api("/v1/workbench/session", {
      method: "POST",
      body: json({ owner_key: $("owner-key").value }),
    });
    state.csrf = data.csrf_token;
    $("owner-key").value = "";
    await session();
  } catch (error) {
    $("login-error").textContent = error.message;
  }
});

$("logout-button").addEventListener("click", async () => {
  try { await api("/v1/workbench/session", { method: "DELETE" }); }
  finally { location.reload(); }
});

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll(".view").forEach((view) => { view.hidden = view.id !== button.dataset.view; });
  document.querySelectorAll("[data-view]").forEach((item) => {
    item.setAttribute("aria-selected", String(item === button));
  });
  $("main").focus();
}));

function showView(id) {
  const button = document.querySelector('[data-view="' + id + '"]');
  if (button) button.click();
}

$("task-mode").addEventListener("change", () => {
  $("exam-fields").hidden = $("task-mode").value !== "gcp_qualification";
});

$("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true, "Importing immutable task…");
  const mode = $("task-mode").value;
  const body = {
    mode,
    title: $("task-title").value,
    direction: $("task-direction").value,
    repository_id: $("repository-id").value || null,
    source_snapshot_digest: $("source-digest").value,
    examination: null,
  };
  if (mode === "gcp_qualification") {
    body.examination = {
      examination_id: $("exam-id").value,
      examiner: "Sol",
      candidate: "Lil Tweak",
      authorized_project: $("gcp-project").value,
      candidate_service_account: $("gcp-identity").value,
      region: $("gcp-region").value,
      zone: $("gcp-zone").value,
      spending_ceiling_usd: Number($("gcp-ceiling").value),
      current_task_number: Number($("task-number").value),
    };
  }
  try {
    state.task = await api("/v1/workbench/tasks", { method: "POST", body: json(body) });
    toast("Immutable task imported.");
    showView("active-task");
    await refresh();
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
});

async function refresh() {
  setBusy(true, "Refreshing Workbench…");
  try {
    const tasks = await api("/v1/workbench/tasks?limit=100");
    if (!state.task && tasks.length) state.task = tasks[0];
    const suffix = state.task ? "?task_id=" + encodeURIComponent(state.task.id) : "";
    const health = await api("/v1/workbench/health" + suffix);
    renderHealth(health);
    renderProjects(tasks);
    if (!state.task) return;
    const root = "/v1/workbench/tasks/" + encodeURIComponent(state.task.id);
    state.task = await api(root);
    state.runs = await api(root + "/runs");
    state.evidence = await api(root + "/evidence");
    renderTask();
    renderRuns();
    renderEvidence();
    renderGcp();
    renderRecovery();
    const approvalEvent = [...state.evidence].reverse().find(
      (item) => item.event_type === "approval_requested" ||
        item.event_type === "rollback_approval_requested"
    );
    if (approvalEvent && approvalEvent.payload && approvalEvent.payload.approval_id) {
      try { state.approval = await api(root + "/approvals/" + encodeURIComponent(approvalEvent.payload.approval_id)); }
      catch { state.approval = null; }
    }
    renderApproval();
    renderTask();
    try {
      const submission = await api(root + "/submission");
      state.submission = submission.rendered;
      state.submissionLocked = submission.submission.locked;
    } catch {
      state.submission = "";
      state.submissionLocked = false;
    }
    $("submission-output").textContent = state.submission;
    renderTask();
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
}

function renderHealth(health) {
  $("status-strip").innerHTML = Object.entries(health)
    .filter(([key]) => key !== "missing_prerequisites")
    .map(([key, value]) => '<div class="status-item"><strong>' +
      escapeHtml(key.replaceAll("_", " ")) + "</strong><span>" +
      escapeHtml(String(value == null ? "—" : value)) + "</span></div>").join("");
}

function renderTask() {
  $("task-state").textContent = state.task.state;
  $("active-task-json").textContent = json(state.task);
  const map = {
    RECEIVED: ["inspect-button", "cancel-button"],
    ANALYZED: ["analyze-button", "cancel-button"],
    BLOCKED: ["inspect-button", "cancel-button"],
    AWAITING_APPROVAL: ["cancel-button"],
    ROLLED_BACK: ["retry-button"],
    APPROVED: ["execute-button", "cancel-button"],
    EXECUTING: ["cancel-button"],
    TESTING: ["cancel-button"],
    COMPLETED: ["submission-button"],
  };
  const controls = ["inspect-button", "analyze-button", "execute-button", "cancel-button",
    "retry-button", "submission-button", "lock-submission-button",
    "reopen-submission-button",
    "request-rollback-button", "rollback-button"];
  controls.forEach((id) => { $(id).disabled = true; });
  (map[state.task.state] || []).forEach((id) => { $(id).disabled = false; });
  if (state.submission && !state.submissionLocked) $("lock-submission-button").disabled = false;
  if (state.submissionLocked) $("reopen-submission-button").disabled = false;
  if (state.task.state === "FAILED") $("request-rollback-button").disabled = false;
  if (state.task.state === "APPROVED" && state.approval && state.approval.purpose === "rollback") {
    $("execute-button").disabled = true;
    $("rollback-button").disabled = false;
  }
  $("active-prerequisite").textContent =
    state.task.state === "APPROVED" ? "Start Execution consumes the exact approval once." :
    state.task.state === "AWAITING_APPROVAL" ? "Approve or reject the exact digest in Approvals." :
    state.task.state === "FAILED" ? "Request and approve rollback before retrying." :
    state.task.state === "ROLLED_BACK" ? "Retry opens revised planning from the verified original source." :
    "Controls enable only when their state prerequisite is true.";
}

function renderProjects(tasks) {
  $("project-list").innerHTML = tasks.map((item) =>
    '<button class="list-card task-select" data-id="' + escapeHtml(item.id) + '"><strong>' +
    escapeHtml(item.imported.title) + "</strong><br>" +
    escapeHtml(item.imported.repository_id || "No repository") + " · " +
    escapeHtml(item.state) + "</button>").join("");
  document.querySelectorAll(".task-select").forEach((button) => button.addEventListener("click", async () => {
    state.task = { id: button.dataset.id };
    await refresh();
    showView("active-task");
  }));
}

function renderApproval() {
  $("approval-json").textContent = state.approval ? json(state.approval) : "No current approval.";
  ["approve-button", "reject-button", "revision-button"].forEach((id) => {
    $(id).disabled = !state.approval || state.approval.status !== "pending";
  });
}

function renderRuns() {
  $("run-list").innerHTML = state.runs.map((run) =>
    '<article class="list-card"><strong>' + escapeHtml(run.tool_id) + "</strong> " +
    (run.success ? "✓" : "✕") + "<br>exit=" + escapeHtml(String(run.exit_code)) +
    " · output=" + escapeHtml(run.output_digest) +
    "<details><summary>Redacted output</summary><pre>" +
    escapeHtml(run.redacted_output) + "</pre></details></article>").join("") || "<p>No runs.</p>";
}

function evidenceCards() {
  return state.evidence.map((item) =>
    '<article class="list-card"><strong>#' + item.sequence + " " +
    escapeHtml(item.event_type) + "</strong><br>" + escapeHtml(item.kind) + " · " +
    escapeHtml(item.id) + "<details><summary>Payload</summary><pre>" +
    escapeHtml(json(item.payload)) + "</pre></details></article>").join("");
}

function renderEvidence() {
  const cards = evidenceCards();
  $("evidence-list").innerHTML = cards || "<p>No evidence.</p>";
  $("audit-list").innerHTML = cards || "<p>No audit events.</p>";
}

function renderRecovery() {
  $("recovery-list").innerHTML = state.evidence.filter((item) => item.kind === "recovery")
    .map((item) => '<article class="list-card"><strong>' + escapeHtml(item.event_type) +
      "</strong><pre>" + escapeHtml(json(item.payload)) + "</pre></article>").join("") ||
    "<p>No recovery snapshot recorded.</p>";
}

function renderGcp() {
  const exam = state.task && state.task.imported && state.task.imported.examination;
  $("gcp-summary").innerHTML = exam ? Object.entries(exam).map(([key, value]) =>
    '<div class="status-item"><strong>' + escapeHtml(key.replaceAll("_", " ")) +
    "</strong><span>" + escapeHtml(String(value)) + "</span></div>").join("") :
    "<p>The active task is not a GCP qualification task.</p>";
}

async function action(path, body = {}) {
  setBusy(true, "Applying owner action…");
  try {
    await api(path, { method: "POST", body: json(body) });
    await refresh();
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
}

function taskRoot() {
  return "/v1/workbench/tasks/" + encodeURIComponent(state.task.id);
}

$("inspect-button").onclick = () => action(taskRoot() + "/inspect");
$("analyze-button").onclick = () => action(taskRoot() + "/analyze");
$("execute-button").onclick = () => action(taskRoot() + "/execute", { approval_id: state.approval && state.approval.id });
$("cancel-button").onclick = () => action(taskRoot() + "/cancel");
$("retry-button").onclick = () => action(taskRoot() + "/retry-eligible-step");
$("submission-button").onclick = () => action(taskRoot() + "/submission");
$("lock-submission-button").onclick = () => action(taskRoot() + "/submission/lock");
$("reopen-submission-button").onclick = () => action(taskRoot() + "/submission/reopen");
$("request-rollback-button").onclick = () => action(taskRoot() + "/rollback/request");
$("rollback-button").onclick = () => action(
  taskRoot() + "/rollback",
  { approval_id: state.approval && state.approval.id }
);

async function decide(decision) {
  await action(taskRoot() + "/decision", {
    approval_id: state.approval.id,
    decision: { decision, approval_digest: state.approval.approval_digest },
  });
}
$("approve-button").onclick = () => decide("approve");
$("reject-button").onclick = () => decide("reject");
$("revision-button").onclick = () => decide("request_revision");
$("emergency-button").onclick = () => action("/v1/workbench/emergency-stop");
$("refresh-button").onclick = refresh;

$("copy-submission-button").onclick = async () => {
  if (!state.submission) return toast("No submission to copy.");
  await navigator.clipboard.writeText(state.submission);
  toast("Submission copied.");
};
$("copy-evidence-button").onclick = async () => {
  await navigator.clipboard.writeText(state.evidence.map((item) => JSON.stringify(item)).join("\n"));
  toast("Evidence copied.");
};
$("export-evidence-button").onclick = () => {
  if (state.task) location.href = taskRoot() + "/evidence/export";
};
$("export-submission-button").onclick = () => {
  if (state.task && state.submission) location.href = taskRoot() + "/submission/export";
};

function escapeHtml(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value).replace(/[&<>"']/g, (character) => entities[character]);
}

session();
