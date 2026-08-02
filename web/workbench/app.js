"use strict";

const state = {
  csrf: "", task: null, approval: null, runs: [], evidence: [], submission: "",
  submissionLocked: false, health: null, repositories: [], inspection: null,
};
const terminalSubmissionStates = new Set(["COMPLETED", "BLOCKED", "FAILED"]);
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

async function apiText(path) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "text/plain, text/x-diff" },
  });
  const payload = await response.text();
  if (!response.ok) {
    let detail = payload;
    try { detail = JSON.parse(payload).detail || payload; } catch { /* Text response. */ }
    throw new Error(detail || response.statusText);
  }
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

const tabs = [...document.querySelectorAll("[data-view]")];
tabs.forEach((button, index) => { button.tabIndex = index === 0 ? 0 : -1; });
tabs.forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll(".view").forEach((view) => { view.hidden = view.id !== button.dataset.view; });
  tabs.forEach((item) => {
    item.setAttribute("aria-selected", String(item === button));
    item.tabIndex = item === button ? 0 : -1;
  });
  $("main").focus();
}));
tabs.forEach((button, index) => button.addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  let next = index;
  if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
  if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
  if (event.key === "Home") next = 0;
  if (event.key === "End") next = tabs.length - 1;
  tabs[next].focus();
  tabs[next].click();
}));

function showView(id) {
  const button = document.querySelector('[data-view="' + id + '"]');
  if (button) button.click();
}

$("task-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true, "Inspecting and importing repository task…");
  const repositoryId = $("repository-id").value;
  const body = {
    title: $("task-title").value,
    direction: $("task-direction").value,
  };
  try {
    if (!repositoryId) throw new Error("Select a configured repository first.");
    state.task = await api(
      "/v1/workbench/repositories/" + encodeURIComponent(repositoryId) + "/tasks",
      { method: "POST", body: json(body) }
    );
    toast("Repository-bound immutable task imported.");
    showView("active-task");
    await refresh();
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
});

async function refresh() {
  setBusy(true, "Refreshing Workbench…");
  try {
    const repositoryResponse = await api("/v1/workbench/repositories");
    state.repositories = repositoryResponse.repository_ids || [];
    renderRepositoryOptions();
    const tasks = await api("/v1/workbench/tasks?limit=100");
    if (!state.task && tasks.length) state.task = tasks[0];
    const suffix = state.task ? "?task_id=" + encodeURIComponent(state.task.id) : "";
    const health = await api("/v1/workbench/health" + suffix);
    state.health = health;
    renderHealth(health);
    renderProjects(tasks);
    if (!state.task) return;
    const root = "/v1/workbench/tasks/" + encodeURIComponent(state.task.id);
    state.approval = null;
    state.task = await api(root);
    state.runs = await api(root + "/runs");
    state.evidence = await api(root + "/evidence");
    renderTask();
    renderPlan();
    renderRuns();
    renderEvidence();
    renderGcp();
    renderRecovery();
    const approvalEvent = [...state.evidence].reverse().find(
      (item) => item.event_type === "approval_requested" ||
        item.event_type === "rollback_approval_requested" ||
        item.event_type === "approval_reissued"
    );
    const approvalId = approvalEvent && approvalEvent.payload &&
      (approvalEvent.payload.replacement_approval_id || approvalEvent.payload.approval_id);
    if (approvalId) {
      try { state.approval = await api(root + "/approvals/" + encodeURIComponent(approvalId)); }
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

function renderRepositoryOptions() {
  const options = state.repositories.map((repositoryId) =>
    '<option value="' + escapeHtml(repositoryId) + '">' +
    escapeHtml(repositoryId) + "</option>").join("");
  ["repository-id", "inspection-repository"].forEach((id) => {
    const prior = $(id).value;
    $(id).innerHTML = options || '<option value="">No configured repositories</option>';
    if (state.repositories.includes(prior)) $(id).value = prior;
  });
}

function renderPlan() {
  $("plan-json").textContent = state.task && state.task.plan ?
    json({ plan_digest: state.task.plan_digest, plan: state.task.plan }) :
    "No plan produced.";
}

function renderHealth(health) {
  $("status-strip").innerHTML = Object.entries(health)
    .filter(([key]) => !["missing_prerequisites", "capabilities"].includes(key))
    .map(([key, value]) => '<div class="status-item"><strong>' +
      escapeHtml(key.replaceAll("_", " ")) + "</strong><span>" +
      escapeHtml(String(value == null ? "—" : value)) + "</span></div>").join("");
  const capabilities = Array.isArray(health.capabilities) ? health.capabilities : [];
  $("capability-status").innerHTML = capabilities.map((capability) =>
    '<article class="status-item capability-item" data-state="' +
      escapeHtml(capability.state) + '"><strong>' +
      escapeHtml(capability.capability) + "</strong><span>" +
      escapeHtml(capability.state.toUpperCase()) + '</span><small class="capability-facts">' +
      ["configured", "connected", "authorized", "healthy", "qualified"]
        .map((gate) => gate + ": " + (capability[gate] ? "yes" : "no"))
        .map(escapeHtml).join(" · ") + "</small></article>"
  ).join("");
  const blockers = [
    ...(Array.isArray(health.missing_prerequisites) ? health.missing_prerequisites : []),
    ...capabilities.flatMap((capability) =>
      Array.isArray(capability.blockers) ? capability.blockers : []),
  ].filter((blocker, index, all) => all.indexOf(blocker) === index);
  $("capability-blockers").innerHTML = blockers.length ? blockers.map((blocker) =>
    "<li>" + escapeHtml(blocker) + "</li>").join("") :
    "<li>No capability blocker is reported.</li>";
}

function renderTask() {
  $("task-state").textContent = state.task.state;
  $("active-task-json").textContent = json(state.task);
  const map = {
    RECEIVED: ["inspect-button", "cancel-button"],
    ANALYZED: ["analyze-button", "cancel-button"],
    BLOCKED: ["inspect-button", "cancel-button"],
    AWAITING_APPROVAL: ["cancel-button"],
    ROLLED_BACK: [],
    APPROVED: ["execute-button", "cancel-button"],
    EXECUTING: ["cancel-button"],
    TESTING: ["cancel-button"],
  };
  const controls = ["inspect-button", "analyze-button", "execute-button", "cancel-button",
    "retry-button", "submission-button", "lock-submission-button",
    "reopen-submission-button",
    "request-rollback-button", "rollback-button", "open-diff-button",
    "export-patch-button"];
  controls.forEach((id) => { $(id).disabled = true; });
  (map[state.task.state] || []).forEach((id) => { $(id).disabled = false; });
  if (terminalSubmissionStates.has(state.task.state)) {
    $("submission-button").disabled = false;
  }
  if (state.task.state === "ANALYZED" && state.health && !state.health.model_connected) {
    $("analyze-button").disabled = true;
  }
  if (state.task.state === "APPROVED" && state.health && !state.health.runner_connected) {
    $("execute-button").disabled = true;
  }
  if (state.submission && !state.submissionLocked) $("lock-submission-button").disabled = false;
  if (state.submissionLocked) $("reopen-submission-button").disabled = false;
  if (state.task.state === "FAILED") $("request-rollback-button").disabled = false;
  if (["VERIFIED", "COMPLETED"].includes(state.task.state)) {
    $("open-diff-button").disabled = false;
    $("export-patch-button").disabled = false;
  }
  if (state.task.state === "APPROVED" && state.approval && state.approval.purpose === "rollback") {
    $("execute-button").disabled = true;
    $("rollback-button").disabled = false;
  }
  $("active-prerequisite").textContent =
    state.task.state === "ANALYZED" && state.health && !state.health.model_connected ?
      "Produce Exact Plan is disabled: the live Lil Tweak model adapter is disconnected." :
    state.task.state === "APPROVED" && state.health && !state.health.runner_connected ?
      "Start Execution is disabled: no independently qualified runner provider is connected." :
    state.task.state === "APPROVED" ? "Start Execution consumes the exact approval once." :
    state.task.state === "AWAITING_APPROVAL" ? "Approve or reject the exact digest in Approvals." :
    state.task.state === "FAILED" ? "Request and approve rollback before retrying." :
    state.task.state === "ROLLED_BACK" ?
      "Rolled-back tasks are terminal. Import the verified source as a new task revision." :
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
    state.approval = null;
    await refresh();
    showView("active-task");
  }));
}

$("repository-inspection-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const repositoryId = $("inspection-repository").value;
  if (!repositoryId) return toast("No configured repository is available.");
  setBusy(true, "Inspecting registered repository…");
  try {
    state.inspection = await api(
      "/v1/workbench/repositories/" + encodeURIComponent(repositoryId) + "/inspect",
      {
        method: "POST",
        body: json({ direction: $("inspection-direction").value }),
      }
    );
    $("repository-inspection-output").textContent = json(state.inspection);
    toast("Repository inspection completed without changing the owner source.");
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
});

function renderApproval() {
  $("approval-json").textContent = state.approval ? json(state.approval) : "No current approval.";
  ["approve-button", "reject-button"].forEach((id) => {
    $(id).disabled = !state.approval || state.approval.status !== "pending" ||
      !state.task || state.task.state !== "AWAITING_APPROVAL";
  });
  $("revision-button").disabled = true;
  $("revision-button").title =
    "Canonical tasks are monotonic; import a new task revision instead.";
  $("reissue-approval-button").disabled = !state.approval ||
    state.approval.status !== "expired" || !state.task ||
    !["AWAITING_APPROVAL", "APPROVED"].includes(state.task.state);
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
  $("gcp-summary").innerHTML =
    '<div class="status-item"><strong>connection</strong><span>DISABLED</span></div>' +
    '<div class="status-item"><strong>network</strong><span>DENIED</span></div>' +
    '<div class="status-item"><strong>deployment</strong><span>NONE</span></div>';
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
$("reissue-approval-button").onclick = () => action(
  taskRoot() + "/approvals/" + encodeURIComponent(state.approval.id) + "/reissue"
);
$("emergency-button").onclick = async () => {
  const confirmed = window.confirm(
    "Emergency Stop blocks approvals and execution and cancels active tasks. Continue?"
  );
  if (!confirmed) return;
  await action("/v1/workbench/emergency-stop");
};
$("emergency-reset-button").onclick = async () => {
  const ownerKey = $("emergency-reset-key").value;
  if (!ownerKey) return toast("Re-enter the owner key before emergency reset.");
  const confirmed = window.confirm(
    "Reset Emergency Stop only after all tasks are terminal and the runner is disconnected. Continue?"
  );
  if (!confirmed) return;
  try {
    await action("/v1/workbench/emergency-stop/reset", { owner_key: ownerKey });
  } finally {
    $("emergency-reset-key").value = "";
  }
};
$("refresh-button").onclick = refresh;

$("open-diff-button").onclick = async () => {
  if (!state.task) return;
  setBusy(true, "Opening verified diff…");
  try {
    $("diff-output").textContent = await apiText(taskRoot() + "/patch/export");
    showView("diff");
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
};
$("export-patch-button").onclick = () => {
  if (state.task) location.href = taskRoot() + "/patch/export";
};

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
