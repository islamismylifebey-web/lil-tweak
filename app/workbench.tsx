"use client";

import {
  FormEvent,
  KeyboardEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ArrowUp, Camera, Mic, MoreVertical, Paperclip, Plus } from "lucide-react";
import { UdjatSignal } from "./udjat-signal";
import { sendDirectChat, type DirectChatMessage } from "./direct-chat-client";
import {
  cancelEngineeringJob,
  createEngineeringJob,
  decideEngineeringJob,
  dispatchEngineeringJob,
  exportEngineeringPatch,
  getEngineeringConnectionStatus,
  getEngineeringJob,
  jobIsPolling,
  jobCanCancel,
  jobNeedsApproval,
  jobStateLabel,
  listEngineeringJobs,
  uploadSourcesForJob,
  type EngineeringConnectionStatus,
} from "./engineering-client";
import { measureLocalPreparation } from "@/lib/local-preparation";
import { startBrowserDownload } from "@/lib/browser-download";
import {
  approvalProposalIsExpired,
  type EngineerMode,
  type EngineeringJob,
  type EngineeringJobDetail,
} from "@/lib/engineering";
import { parseGitSource } from "@/lib/engineering-input";
import {
  selectStagedSourceCandidates,
  type StagedSourceKind,
} from "@/lib/source-staging";
import {
  WORKBENCH_CAPACITY_LABEL,
  WORKBENCH_CONTEXT_TOKEN_LABEL,
  WORKBENCH_MAX_CONVERSATION_CHARACTERS,
  WORKBENCH_OUTPUT_TOKEN_LABEL,
} from "@/lib/workbench-capacity";
import type {
  BoardColumn,
  ProjectDocument,
  ProjectStatus,
  RequirementStatus,
} from "@/lib/workspace";

type View = "tweak" | "projects" | "engineering" | "evidence";
type ChatMenuDetail = "access" | "files" | "usage" | null;

type LilTweakWorkbenchProps = {
  signedIn: boolean;
};

const views: { id: View; label: string }[] = [
  { id: "tweak", label: "Chat" },
  { id: "projects", label: "Work" },
  { id: "engineering", label: "Engineering" },
  { id: "evidence", label: "Evidence" },
];

const projectStatuses: ProjectStatus[] = ["planned", "active", "complete", "archived"];
const requirementStatuses: RequirementStatus[] = [
  "planned",
  "active",
  "complete",
  "blocked",
];
const boardColumns: BoardColumn[] = ["backlog", "ready", "active", "review", "done"];
const MAX_ENGINEERING_PROMPT_CHARACTERS = 16_000;

const engineerModes: Array<{ id: EngineerMode; label: string }> = [
  { id: "build", label: "Build" },
  { id: "debug", label: "Debug" },
  { id: "refactor", label: "Refactor" },
  { id: "test", label: "Test" },
  { id: "architect", label: "Architect" },
  { id: "chat", label: "Chat" },
];

const capabilityGaps = [
  {
    name: "DAG",
    status: "Biggest upgrade",
    detail: "Turns one mission into ordered steps, parallel jobs, retries, and clean recovery.",
  },
  {
    name: "Tool Registry",
    status: "Needs explicit map",
    detail: "Lets Lil'Tweak know exactly what it can call, what each tool costs, and where the limits are.",
  },
  {
    name: "Repository Mapper",
    status: "High leverage",
    detail: "Finds apps, packages, APIs, tests, and dependencies before changing code.",
  },
  {
    name: "Contract Registry",
    status: "Correctness anchor",
    detail: "Stores the rules the software must satisfy so the agent can prove correct behavior.",
  },
  {
    name: "Reviewer/Critic",
    status: "Quality multiplier",
    detail: "A second process checks the work so Lil'Tweak is not the only judge of its own patch.",
  },
  {
    name: "Failure Recovery Engine",
    status: "Mission saver",
    detail: "Diagnoses, changes strategy, rolls back, or escalates instead of stopping at the first failure.",
  },
];

type StagedFileSource = StagedSourceKind;

type StagedFile = {
  id: string;
  file: File;
  name: string;
  size: number;
  source: StagedFileSource;
  type: string;
};

function lines(value: string) {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function newId(prefix: string) {
  return `${prefix}:${crypto.randomUUID().replaceAll("-", "")}`;
}

function formatFileSize(bytes: number) {
  if (bytes < 1_000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${Math.ceil(bytes / 1_000)} KB`;
  return `${(bytes / 1_000_000).toFixed(bytes >= 10_000_000 ? 0 : 1)} MB`;
}

function parseRequirements(value: string, project: ProjectDocument) {
  return lines(value).map((line, index) => {
    const [rawStatus, ...rest] = line.split("|").map((part) => part.trim());
    const status = requirementStatuses.includes(rawStatus as RequirementStatus)
      ? (rawStatus as RequirementStatus)
      : "planned";
    return {
      id: project.requirements[index]?.id ?? newId("requirement"),
      status,
      text: rest.join(" | ") || rawStatus,
    };
  });
}

function parseMilestones(value: string, project: ProjectDocument) {
  return lines(value).map((line, index) => {
    const [rawStatus, rawDate, ...rest] = line.split("|").map((part) => part.trim());
    const status = requirementStatuses.includes(rawStatus as RequirementStatus)
      ? (rawStatus as RequirementStatus)
      : "planned";
    const targetDate = /^\d{4}-\d{2}-\d{2}$/.test(rawDate) ? rawDate : null;
    return {
      id: project.milestones[index]?.id ?? newId("milestone"),
      status,
      target_date: targetDate,
      title: rest.join(" | ") || rawDate || rawStatus,
    };
  });
}

function parseBoard(value: string, project: ProjectDocument) {
  return lines(value).map((line, index) => {
    const [rawColumn, rawTitle, ...rest] = line.split("|").map((part) => part.trim());
    const column = boardColumns.includes(rawColumn as BoardColumn)
      ? (rawColumn as BoardColumn)
      : "backlog";
    return {
      id: project.board[index]?.id ?? newId("board"),
      column,
      title: rawTitle || rawColumn,
      detail: rest.join(" | "),
    };
  });
}

function parseNotes(value: string, project: ProjectDocument) {
  return lines(value).map((text, index) => ({
    id: project.notes[index]?.id ?? newId("note"),
    text,
    created_at: project.notes[index]?.created_at ?? new Date().toISOString(),
  }));
}

class WorkspaceRequestError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly project?: ProjectDocument;

  constructor(
    status: number,
    payload: { error?: string; code?: string; project?: ProjectDocument },
  ) {
    super(payload.error ?? "Workspace request failed.");
    this.name = "WorkspaceRequestError";
    this.status = status;
    this.code = payload.code;
    this.project = payload.project;
  }
}

async function workspaceRequest<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      Accept: "application/json",
      ...(options?.body ? { "Content-Type": "application/json" } : {}),
      ...options?.headers,
    },
  });
  const payload = (await response.json()) as T & {
    error?: string;
    code?: string;
    project?: ProjectDocument;
  };
  if (!response.ok) throw new WorkspaceRequestError(response.status, payload);
  return payload;
}

export function LilTweakWorkbench({ signedIn }: LilTweakWorkbenchProps) {
  const [view, setView] = useState<View>("tweak");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [chatMenuOpen, setChatMenuOpen] = useState(false);
  const [chatMenuDetail, setChatMenuDetail] = useState<ChatMenuDetail>(null);
  const [engineerMode, setEngineerMode] = useState<EngineerMode>("chat");
  const [chatMessages, setChatMessages] = useState<Array<DirectChatMessage & { id: string }>>([]);
  const [engineeringJobs, setEngineeringJobs] = useState<EngineeringJob[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<EngineeringConnectionStatus | null>(null);
  const [connectionStatusError, setConnectionStatusError] = useState("");
  const [activeJob, setActiveJob] = useState<EngineeringJobDetail | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [rejectionReason, setRejectionReason] = useState("");
  const [taskDraft, setTaskDraft] = useState("");
  const [gitRepositoryUrl, setGitRepositoryUrl] = useState("");
  const [gitCommit, setGitCommit] = useState("");
  const [composerMenuOpen, setComposerMenuOpen] = useState(false);
  const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);
  const [composerStatus, setComposerStatus] = useState("");
  const [projects, setProjects] = useState<ProjectDocument[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("");
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [approvalClock, setApprovalClock] = useState(() => Date.now());
  const sidebarToggleRef = useRef<HTMLButtonElement>(null);
  const chatMenuRef = useRef<HTMLDivElement>(null);
  const chatMenuToggleRef = useRef<HTMLButtonElement>(null);
  const chatMenuFirstRef = useRef<HTMLButtonElement>(null);
  const composerMenuRef = useRef<HTMLDivElement>(null);
  const composerPlusRef = useRef<HTMLButtonElement>(null);
  const composerPaperclipRef = useRef<HTMLButtonElement>(null);
  const composerCameraRef = useRef<HTMLButtonElement>(null);
  const composerMenuFirstRef = useRef<HTMLButtonElement>(null);
  const composerFileInputRef = useRef<HTMLInputElement>(null);
  const composerCameraInputRef = useRef<HTMLInputElement>(null);
  const taskInputRef = useRef<HTMLTextAreaElement>(null);
  const createAttemptRef = useRef<{ fingerprint: string; requestId: string } | null>(null);

  const mergeEngineeringJob = useCallback((job: EngineeringJobDetail) => {
    setActiveJob(job);
    setEngineeringJobs((current) => {
      const summary: EngineeringJob = job;
      const next = [summary, ...current.filter((item) => item.id !== job.id)];
      return next.slice(0, 30);
    });
  }, []);

  const refreshConnectionStatus = useCallback(async () => {
    try {
      const status = await getEngineeringConnectionStatus();
      setConnectionStatus(status);
      setConnectionStatusError("");
    } catch (caught) {
      setConnectionStatusError(
        caught instanceof Error ? caught.message : "Connection status is unavailable.",
      );
    }
  }, []);

  async function loadProjects(query = search, status = filter) {
    setBusy(true);
    setError("");
    try {
      const params = new URLSearchParams({ query, status });
      const result = await workspaceRequest<{ projects: ProjectDocument[] }>(
        `/api/workspace?${params}`,
      );
      setProjects(result.projects);
      setSelectedId((current) =>
        current && result.projects.some((project) => project.id === current)
          ? current
          : result.projects[0]?.id ?? "",
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Workspace could not be loaded.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    let cancelled = false;
    async function initialLoad() {
      setBusy(true);
      try {
        const result = await workspaceRequest<{ projects: ProjectDocument[] }>(
          "/api/workspace?query=&status=",
        );
        if (!cancelled) {
          setProjects(result.projects);
          setSelectedId(result.projects[0]?.id ?? "");
        }
      } catch (caught) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : "Workspace could not be loaded.");
        }
      } finally {
        if (!cancelled) setBusy(false);
      }
    }
    void initialLoad();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void listEngineeringJobs()
      .then((jobs) => {
        if (!cancelled) setEngineeringJobs(jobs);
      })
      .catch((caught) => {
        if (!cancelled) {
          setComposerStatus(
            caught instanceof Error ? caught.message : "Engineering history is unavailable.",
          );
        }
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    void getEngineeringConnectionStatus()
      .then((status) => {
        if (!cancelled) {
          setConnectionStatus(status);
          setConnectionStatusError("");
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setConnectionStatusError(
            caught instanceof Error ? caught.message : "Connection status is unavailable.",
          );
        }
      });
    return () => { cancelled = true; };
  }, []);

  const activeJobId = activeJob?.id;
  const activeJobState = activeJob?.state;

  useEffect(() => {
    if (activeJobId == null || activeJobState == null || !jobIsPolling(activeJobState)) return;
    const jobId = activeJobId;
    let cancelled = false;
    let timer: number | undefined;
    let delay = 3_500;
    async function refresh() {
      if (cancelled) return;
      if (document.visibilityState !== "visible") {
        timer = window.setTimeout(() => { void refresh(); }, delay);
        return;
      }
      try {
        const job = await getEngineeringJob(jobId);
        if (!cancelled) {
          delay = 3_500;
          mergeEngineeringJob(job);
        }
      } catch (caught) {
        if (!cancelled) {
          delay = Math.min(delay * 2, 30_000);
          setComposerStatus(caught instanceof Error ? caught.message : "Job status is unavailable.");
        }
      } finally {
        if (!cancelled) timer = window.setTimeout(() => { void refresh(); }, delay);
      }
    }
    timer = window.setTimeout(() => { void refresh(); }, delay);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeJobId, activeJobState, mergeEngineeringJob]);

  useEffect(() => {
    if (!activeJob?.approvalProposal || !jobNeedsApproval(activeJob.state)) return;
    const timer = window.setInterval(() => setApprovalClock(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [activeJob?.approvalProposal, activeJob?.state]);

  useEffect(() => {
    if (!message) return;
    const timer = window.setTimeout(() => setMessage(""), 4200);
    return () => window.clearTimeout(timer);
  }, [message]);

  const selected = projects.find((project) => project.id === selectedId) ?? null;
  const approvalExpired = Boolean(
    activeJob?.approvalProposal &&
    approvalProposalIsExpired(activeJob.approvalProposal, approvalClock),
  );
  const runnerState = connectionStatus?.runner.connection ?? "pending_configuration";
  const runnerLabel = !connectionStatus
    ? "Checking Tueiq Core"
    : runnerState === "ready"
      ? "Tueiq Core ready"
      : "Direct Tueiq Core runner";

  function recoverStaleProject(caught: unknown, retryMessage: string) {
    if (
      !(caught instanceof WorkspaceRequestError) ||
      caught.status !== 409 ||
      caught.code !== "stale_project_revision" ||
      !caught.project
    ) {
      return false;
    }
    setProjects((current) =>
      current.some((item) => item.id === caught.project?.id)
        ? current.map((item) => (item.id === caught.project?.id ? caught.project! : item))
        : [caught.project!, ...current],
    );
    setSelectedId(caught.project.id);
    setError(retryMessage);
    return true;
  }

  async function submitEngineeringTask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const prompt = taskDraft.trim();
    if (!prompt) {
      setComposerStatus("Describe what Lil'Tweak.AI should do.");
      taskInputRef.current?.focus();
      return;
    }
    if (engineerMode === "chat") {
      const userMessage = { id: newId("chat"), role: "user" as const, content: prompt };
      const conversation = [...chatMessages, userMessage];
      setChatMessages(conversation);
      setTaskDraft("");
      setBusy(true);
      setError("");
      setComposerStatus("Thinking…");
      try {
        const answer = await sendDirectChat(conversation.map(({ role, content }) => ({ role, content })));
        setChatMessages([...conversation, { id: newId("chat"), role: "assistant", content: answer }]);
        setComposerStatus("");
      } catch (caught) {
        setError(caught instanceof Error ? caught.message : "Direct chat is unavailable.");
        setTaskDraft(prompt);
        setComposerStatus("");
      } finally {
        setBusy(false);
      }
      return;
    }
    setBusy(true);
    setError("");
    setRejectOpen(false);
    setUploadProgress(0);
    try {
      const files = stagedFiles.map((item) => item.file);
      const gitSource = parseGitSource(
        gitRepositoryUrl.trim() || gitCommit.trim()
          ? { repositoryUrl: gitRepositoryUrl, commit: gitCommit }
          : null,
      );
      if (gitSource && files.length) throw new Error("Use uploaded files or a Git source, not both.");
      const createFingerprint = JSON.stringify({
        mode: engineerMode,
        prompt: taskDraft.trim(),
        projectId: selected?.id ?? null,
        gitSource,
        sources: stagedFiles
          .map((item) => ({
            fileIdentity: item.id,
            filename: item.file.name.trim(),
            mediaType: item.file.type || "application/octet-stream",
            sizeBytes: item.file.size,
            lastModified: item.file.lastModified,
          }))
          .sort((left, right) => left.filename.localeCompare(right.filename)),
      });
      const attempt = createAttemptRef.current?.fingerprint === createFingerprint
        ? createAttemptRef.current
        : { fingerprint: createFingerprint, requestId: crypto.randomUUID() };
      createAttemptRef.current = attempt;
      let job = await createEngineeringJob({
        requestId: attempt.requestId,
        mode: engineerMode,
        prompt: taskDraft.trim(),
        projectId: selected?.id ?? null,
        files,
        gitSource,
      });
      mergeEngineeringJob(job);
      const pendingSources = job.sources.filter((source) => !source.uploadedAt);
      if (pendingSources.length) {
        const fileByName = new Map(files.map((file) => [file.name.trim(), file]));
        const pendingFiles = pendingSources.map((source) => fileByName.get(source.filename));
        if (pendingFiles.some((file) => !file)) {
          throw new Error("The original source files are required to resume this upload.");
        }
        await uploadSourcesForJob(job.id, pendingFiles as File[], pendingSources, undefined, (completed, total) => {
          setUploadProgress(Math.round((completed / total) * 100));
          setComposerStatus(`Uploaded ${completed} of ${total} private source files.`);
        });
        job = await getEngineeringJob(job.id);
        mergeEngineeringJob(job);
      }
      if (job.state === "uploading") {
        job = await getEngineeringJob(job.id);
        mergeEngineeringJob(job);
      }
      if (job.state === "queued") {
        job = await dispatchEngineeringJob(job);
        mergeEngineeringJob(job);
      }
      createAttemptRef.current = null;
      setTaskDraft("");
      setStagedFiles([]);
      setGitRepositoryUrl("");
      setGitCommit("");
      setUploadProgress(100);
      setComposerStatus("Job accepted by the secure code gateway.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Engineering job could not be started.");
    } finally {
      setBusy(false);
    }
  }

  async function selectEngineeringJob(jobId: string) {
    setBusy(true);
    setError("");
    try {
      mergeEngineeringJob(await getEngineeringJob(jobId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Engineering job could not be loaded.");
    } finally {
      setBusy(false);
    }
  }

  async function decideActiveJob(decision: "approve" | "reject") {
    if (!activeJob) return;
    if (
      decision === "approve" && activeJob.approvalProposal &&
      approvalProposalIsExpired(activeJob.approvalProposal)
    ) {
      setError("This approval proposal expired. Reject or cancel it, then request a new proposal.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const job = await decideEngineeringJob(activeJob, decision, rejectionReason);
      mergeEngineeringJob(job);
      setRejectOpen(false);
      setRejectionReason("");
      setMessage(decision === "approve" ? "Approved; one-time patch export is ready" : "Proposal rejected");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Decision could not be recorded.");
    } finally {
      setBusy(false);
    }
  }

  async function downloadPatchOnce(
    evidence: EngineeringJobDetail["evidence"][number],
  ) {
    if (!activeJob) return;
    setBusy(true);
    setError("");
    try {
      const blob = await exportEngineeringPatch(activeJob, evidence);
      startBrowserDownload(blob, evidence.filename);
      mergeEngineeringJob(await getEngineeringJob(activeJob.id));
      setMessage("One-time patch export downloaded");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Patch export could not be downloaded.");
    } finally {
      setBusy(false);
    }
  }

  async function cancelActiveJob() {
    if (!activeJob || !jobCanCancel(activeJob.state)) return;
    setBusy(true);
    setError("");
    try {
      const job = await cancelEngineeringJob(activeJob);
      mergeEngineeringJob(job);
      setRejectOpen(false);
      setRejectionReason("");
      setMessage("Job cancelled");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Job could not be cancelled.");
    } finally {
      setBusy(false);
    }
  }

  async function resumeActiveDispatch() {
    if (!activeJob || activeJob.state !== "queued") return;
    setBusy(true);
    setError("");
    try {
      const job = await dispatchEngineeringJob(activeJob);
      mergeEngineeringJob(job);
      setMessage("Dispatch reconciled with the secure code gateway");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Dispatch could not be reconciled.");
    } finally {
      setBusy(false);
    }
  }

  async function createProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await workspaceRequest<{ project: ProjectDocument }>("/api/workspace", {
        method: "POST",
        body: JSON.stringify({
          action: "create",
          project: {
            name: newName,
            description: newDescription,
            status: "planned",
            requirements: [],
            milestones: [],
            board: [],
            notes: [],
          },
        }),
      });
      setNewName("");
      setNewDescription("");
      setShowCreate(false);
      setProjects((current) => [result.project, ...current]);
      setSelectedId(result.project.id);
      setMessage("Created");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Project could not be created.");
    } finally {
      setBusy(false);
    }
  }

  async function saveProject(
    event: FormEvent<HTMLFormElement>,
    values: { requirements: string; milestones: string; board: string; notes: string },
    editedProject?: ProjectDocument,
  ) {
    event.preventDefault();
    const base = editedProject ?? selected;
    if (!base) return;
    setBusy(true);
    setError("");
    try {
      const project = {
        ...base,
        requirements: parseRequirements(values.requirements, base),
        milestones: parseMilestones(values.milestones, base),
        board: parseBoard(values.board, base),
        notes: parseNotes(values.notes, base),
      };
      const result = await workspaceRequest<{ project: ProjectDocument }>("/api/workspace", {
        method: "POST",
        body: JSON.stringify({
          action: "update",
          id: base.id,
          expectedRevision: base.revision,
          project,
        }),
      });
      setProjects((current) =>
        current.map((item) => (item.id === result.project.id ? result.project : item)),
      );
      setMessage("Saved");
    } catch (caught) {
      if (
        !recoverStaleProject(
          caught,
          "Project changed in another request. Your unsaved fields remain; review and save again.",
        )
      ) {
        setError(caught instanceof Error ? caught.message : "Project could not be saved.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function attachFile(file: File | undefined) {
    if (!file || !selected) return;
    setBusy(true);
    setError("");
    try {
      if (file.size > 1_000_000) throw new Error("Attachments are limited to 1 MB each.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      const result = await workspaceRequest<{ project: ProjectDocument }>("/api/workspace", {
        method: "POST",
        body: JSON.stringify({
          action: "attach",
          id: selected.id,
          expectedRevision: selected.revision,
          attachment: {
            filename: file.name,
            media_type: file.type || "application/octet-stream",
            content_base64: btoa(binary),
          },
        }),
      });
      setProjects((current) =>
        current.map((item) => (item.id === result.project.id ? result.project : item)),
      );
      setMessage("Attached");
    } catch (caught) {
      if (
        !recoverStaleProject(
          caught,
          "Project changed in another request. The latest revision is loaded; check the file list before retrying.",
        )
      ) {
        setError(caught instanceof Error ? caught.message : "Attachment could not be stored.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function exportSelected() {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      const result = await workspaceRequest<{ exported: unknown }>(
        `/api/workspace?action=export&id=${encodeURIComponent(selected.id)}`,
      );
      const blob = new Blob([JSON.stringify(result.exported)], {
        type: "application/json",
      });
      startBrowserDownload(
        blob,
        `${selected.name.toLowerCase().replace(/[^a-z0-9]+/g, "-") || "project"}.json`,
      );
      setMessage("Exported");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Project could not be exported.");
    } finally {
      setBusy(false);
    }
  }

  async function importFile(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      if (file.size > 4_000_000) throw new Error("Project import is too large.");
      const exported = JSON.parse(await file.text()) as unknown;
      const result = await workspaceRequest<{ project: ProjectDocument }>("/api/workspace", {
        method: "POST",
        body: JSON.stringify({ action: "import", exported }),
      });
      setProjects((current) => [result.project, ...current]);
      setSelectedId(result.project.id);
      setMessage("Imported");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Project could not be imported.");
    } finally {
      setBusy(false);
    }
  }

  function activateView(next: View) {
    setView(next);
    setSidebarOpen(false);
    setChatMenuOpen(false);
    setChatMenuDetail(null);
    setComposerMenuOpen(false);
    window.requestAnimationFrame(() => document.getElementById("workspace-main")?.focus());
  }

  function handleNavKey(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    let next = index;
    if (event.key === "ArrowUp") next = (index - 1 + views.length) % views.length;
    if (event.key === "ArrowDown") next = (index + 1) % views.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = views.length - 1;
    setView(views[next].id);
    document.getElementById(`tab-${views[next].id}`)?.focus();
  }

  useEffect(() => {
    if (!sidebarOpen) return;
    function closeSidebar(event: globalThis.KeyboardEvent) {
      if (event.key !== "Escape") return;
      setSidebarOpen(false);
      window.requestAnimationFrame(() => sidebarToggleRef.current?.focus());
    }
    document.addEventListener("keydown", closeSidebar);
    return () => document.removeEventListener("keydown", closeSidebar);
  }, [sidebarOpen]);

  useEffect(() => {
    if (!chatMenuOpen) return;
    function closeChatMenu(event: Event) {
      if (event.type === "keydown" && (event as globalThis.KeyboardEvent).key === "Escape") {
        setChatMenuOpen(false);
        setChatMenuDetail(null);
        window.requestAnimationFrame(() => chatMenuToggleRef.current?.focus());
        return;
      }
      if (
        event.type === "pointerdown" &&
        event.target instanceof Node &&
        !chatMenuRef.current?.contains(event.target)
      ) {
        setChatMenuOpen(false);
        setChatMenuDetail(null);
      }
    }
    document.addEventListener("keydown", closeChatMenu);
    document.addEventListener("pointerdown", closeChatMenu);
    return () => {
      document.removeEventListener("keydown", closeChatMenu);
      document.removeEventListener("pointerdown", closeChatMenu);
    };
  }, [chatMenuOpen]);

  useEffect(() => {
    if (!composerMenuOpen) return;
    function closeComposerMenu(event: Event) {
      if (event.type === "keydown" && (event as globalThis.KeyboardEvent).key === "Escape") {
        setComposerMenuOpen(false);
        window.requestAnimationFrame(() => composerPlusRef.current?.focus());
        return;
      }
      if (
        event.type === "pointerdown" &&
        event.target instanceof Node &&
        !composerMenuRef.current?.contains(event.target)
      ) {
        setComposerMenuOpen(false);
      }
    }
    document.addEventListener("keydown", closeComposerMenu);
    document.addEventListener("pointerdown", closeComposerMenu);
    return () => {
      document.removeEventListener("keydown", closeComposerMenu);
      document.removeEventListener("pointerdown", closeComposerMenu);
    };
  }, [composerMenuOpen]);

  useEffect(() => {
    const input = composerFileInputRef.current;
    if (!input) return;
    function restoreFileTriggerFocus() {
      window.requestAnimationFrame(() => composerPaperclipRef.current?.focus());
    }
    input.addEventListener("cancel", restoreFileTriggerFocus);
    return () => input.removeEventListener("cancel", restoreFileTriggerFocus);
  }, []);

  useEffect(() => {
    const input = composerCameraInputRef.current;
    if (!input) return;
    function restoreCameraTriggerFocus() {
      window.requestAnimationFrame(() => composerCameraRef.current?.focus());
    }
    input.addEventListener("cancel", restoreCameraTriggerFocus);
    return () => input.removeEventListener("cancel", restoreCameraTriggerFocus);
  }, []);

  function openComposerFiles() {
    setComposerMenuOpen(false);
    composerPaperclipRef.current?.focus();
    composerFileInputRef.current?.click();
  }

  function openComposerCamera() {
    setComposerMenuOpen(false);
    composerCameraRef.current?.focus();
    composerCameraInputRef.current?.click();
  }

  function toggleComposerMenu() {
    setSidebarOpen(false);
    setChatMenuOpen(false);
    setChatMenuDetail(null);
    if (composerMenuOpen) {
      setComposerMenuOpen(false);
      return;
    }
    setComposerMenuOpen(true);
    window.requestAnimationFrame(() => composerMenuFirstRef.current?.focus());
  }

  function stageComposerFiles(fileList: FileList | null, source: StagedFileSource = "file") {
    if (gitRepositoryUrl.trim() || gitCommit.trim()) {
      setComposerStatus("Clear the Git source before selecting uploaded files.");
      return;
    }
    if (!fileList?.length) return;
    const chosen = Array.from(fileList);
    const selection = selectStagedSourceCandidates(stagedFiles, chosen, source);
    const next: StagedFile[] = selection.accepted.map((file) => ({
      id: `${file.name}:${file.size}:${file.lastModified}`,
      file,
      name: file.name,
      size: file.size,
      source,
      type: file.type || "file",
    }));

    if (next.length) setStagedFiles((current) => [...current, ...next]);
    if (!next.length) setComposerStatus(selection.rejectionReason);
    else if (selection.rejected) setComposerStatus(`${next.length} selected privately; ${selection.rejected} skipped. ${selection.rejectionReason}`);
    else setComposerStatus(`${next.length} selected for private source upload.`);
  }

  function removeStagedFile(id: string) {
    setStagedFiles((current) => current.filter((file) => file.id !== id));
    setComposerStatus("Removed");
  }

  function toggleChatMenu() {
    setSidebarOpen(false);
    setComposerMenuOpen(false);
    if (chatMenuOpen) {
      setChatMenuOpen(false);
      setChatMenuDetail(null);
      return;
    }
    setChatMenuOpen(true);
    window.requestAnimationFrame(() => chatMenuFirstRef.current?.focus());
  }

  const preparation = useMemo(
    () => measureLocalPreparation(taskDraft, stagedFiles),
    [taskDraft, stagedFiles],
  );

  return (
    <div className="workbench-shell" data-surface="lil-tweak-workbench">
      <a className="skip-link" href="#workspace-main">Skip to workspace</a>

      <button
        ref={sidebarToggleRef}
        type="button"
        className="sidebar-toggle"
        aria-label={sidebarOpen ? "Close sidebar" : "Open sidebar"}
        aria-expanded={sidebarOpen}
        aria-controls="workspace-sidebar"
        onClick={() => {
          setComposerMenuOpen(false);
          setChatMenuOpen(false);
          setChatMenuDetail(null);
          setSidebarOpen((current) => !current);
        }}
      >
        <span aria-hidden="true">{sidebarOpen ? "‹" : "›"}</span>
      </button>

      <aside
        id="workspace-sidebar"
        className="workspace-sidebar"
        aria-label="Lil'Tweak.AI sections"
        hidden={!sidebarOpen}
      >
        <div className="sidebar-nav" role="tablist" aria-label="Workspace sections">
          {views.map((item, index) => (
            <button
              type="button"
              id={`tab-${item.id}`}
              key={item.id}
              className={view === item.id ? "active" : ""}
              aria-selected={view === item.id}
              aria-controls={`panel-${item.id}`}
              role="tab"
              tabIndex={view === item.id ? 0 : -1}
              onClick={() => activateView(item.id)}
              onKeyDown={(event) => handleNavKey(event, index)}
            >
              {item.label}
            </button>
          ))}
        </div>

        {view === "projects" && (
          <div className="sidebar-projects">
            <form className="search-row" onSubmit={(event) => { event.preventDefault(); void loadProjects(); }}>
              <label><span className="sr-only">Search projects</span><input placeholder="Search" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
              <select aria-label="Filter project status" value={filter} onChange={(event) => setFilter(event.target.value)}>
                <option value="">All</option>
                {projectStatuses.map((status) => <option key={status}>{status}</option>)}
              </select>
              <button aria-label="Apply project filters" disabled={busy}>Go</button>
            </form>
            <div className="project-list">
              {projects.length ? projects.map((project) => (
                <button
                  type="button"
                  key={project.id}
                  className={selectedId === project.id ? "selected" : ""}
                  onClick={() => { setSelectedId(project.id); setSidebarOpen(false); }}
                >
                  <strong>{project.name}</strong>
                  <small>{project.status}</small>
                </button>
              )) : <p className="empty-state">No projects</p>}
            </div>
          </div>
        )}
      </aside>

      <header className="tweak-header">
        <div
          className="header-identity"
          ref={chatMenuRef}
          onBlur={(event) => {
            const nextFocus = event.relatedTarget;
            if (nextFocus instanceof Node && event.currentTarget.contains(nextFocus)) return;
            setChatMenuOpen(false);
            setChatMenuDetail(null);
          }}
        >
          <button type="button" className="tweak-name" onClick={() => activateView("tweak")}>Lil&apos;Tweak.AI</button>
          <button
            ref={chatMenuToggleRef}
            type="button"
            className="chat-menu-toggle"
            aria-label="Chat controls"
            aria-haspopup="dialog"
            aria-expanded={chatMenuOpen}
            aria-controls="chat-controls-panel"
            onClick={toggleChatMenu}
          >
            <MoreVertical aria-hidden="true" focusable="false" strokeWidth={1.8} />
          </button>
          <div
            id="chat-controls-panel"
            className="chat-controls"
            role="dialog"
            aria-modal="false"
            aria-label="Chat controls"
            hidden={!chatMenuOpen}
          >
            <div className="chat-mode-toggle" role="group" aria-label="Chat or work">
              <button
                ref={chatMenuFirstRef}
                type="button"
                aria-pressed={view === "tweak"}
                onClick={() => activateView("tweak")}
              >
                Chat
              </button>
              <button
                type="button"
                aria-pressed={view === "projects"}
                onClick={() => activateView("projects")}
              >
                Work
              </button>
            </div>
            <div className="chat-control-row account-control" aria-live="polite">
              <span>{signedIn ? "Logged in" : "Log in required"}</span>
              <small>{signedIn ? "ChatGPT" : "Open from ChatGPT"}</small>
            </div>
            <button
              type="button"
              className="chat-control-row"
              aria-expanded={chatMenuDetail === "access"}
              aria-controls="chat-access-detail"
              onClick={() => setChatMenuDetail((current) => current === "access" ? null : "access")}
            >
              <span>Access controls</span><small>Owner only</small>
            </button>
            <div id="chat-access-detail" className="chat-control-detail" hidden={chatMenuDetail !== "access"}>
              <p>Owner only. Private Sites access and dispatch-owned identity are enforced before every server authorization check.</p>
            </div>
            <button type="button" className="chat-control-row" disabled><span>Archive chat</span><small>No saved chat</small></button>
            <button type="button" className="chat-control-row danger-row" disabled><span>Delete chat</span><small>No saved chat</small></button>
            <button type="button" className="chat-control-row" disabled><span>Share</span><small>Private</small></button>
            <button
              type="button"
              className="chat-control-row"
              aria-expanded={chatMenuDetail === "files"}
              aria-controls="chat-files-detail"
              onClick={() => setChatMenuDetail((current) => current === "files" ? null : "files")}
            >
              <span>Files</span><small>{preparation.stagedItems}</small>
            </button>
            <div id="chat-files-detail" className="chat-control-detail" hidden={chatMenuDetail !== "files"}>
              <p>{preparation.stagedItems} selected · {formatFileSize(preparation.selectedBytes)} · uploaded only when you submit.</p>
            </div>
            <button type="button" className="chat-control-row" onClick={() => activateView("engineering")}><span>Code</span><small>Tueiq Core runner</small></button>
            <button
              type="button"
              className="chat-control-row"
              aria-expanded={chatMenuDetail === "usage"}
              aria-controls="chat-usage-detail"
              onClick={() => setChatMenuDetail((current) => current === "usage" ? null : "usage")}
            >
              <span>Data usage</span><small>{WORKBENCH_CAPACITY_LABEL}</small>
            </button>
            <div id="chat-usage-detail" className="chat-control-detail" hidden={chatMenuDetail !== "usage"}>
              <p>{preparation.draftCharacters} characters · {preparation.draftWords} words · {formatFileSize(preparation.selectedBytes)} selected.</p>
              <p>Direct chat capacity is {WORKBENCH_CONTEXT_TOKEN_LABEL} input tokens and {WORKBENCH_OUTPUT_TOKEN_LABEL} output tokens. Engineering jobs keep their approval and source limits.</p>
            </div>
          </div>
        </div>
        <UdjatSignal usage={preparation} />
        <span className="connection-state" data-runner-route="direct-core-to-local-podman" data-live-runner-state={runnerState}>{engineerMode === "chat" ? null : runnerLabel}</span>
      </header>

      {(error || message) && (
        <div className={`notice ${error ? "notice-error" : "notice-success"}`} role={error ? "alert" : "status"}>
          <span>{error || message}</span>
          <button type="button" onClick={() => { setError(""); setMessage(""); }} aria-label="Dismiss message">×</button>
        </div>
      )}

      <main id="workspace-main" className="tweak-stage" tabIndex={-1} aria-busy={busy}>
        {view === "tweak" && (
          <section id="panel-tweak" className="tweak-view" role="tabpanel" aria-labelledby="tab-tweak">
            <div className="task-box" data-pressure={preparation.pressure}>
              <div className="task-output" aria-label="Lil'Tweak.AI output" aria-live="polite">
                {engineerMode === "chat" ? (
                  chatMessages.length ? (
                    <ol className="chat-transcript" aria-label="Chat conversation">
                      {chatMessages.map((item) => (
                        <li key={item.id} className={`chat-message chat-message-${item.role}`}>
                          <span>{item.role === "user" ? "You" : "Lil'Tweak.AI"}</span>
                          <p>{item.content}</p>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <div className="engineering-empty">
                      <img className="tweak-stage-avatar" src="/lil-tueeq-avatar.png" alt="" aria-hidden="true" />
                      <h1>What can I help you create?</h1>
                      <p>Model calls are temporarily disabled. Engineering work remains available through the approval-gated runner.</p>
                    </div>
                  )
                ) : activeJob ? (
                  <article className="engineering-job-card">
                    <header>
                      <div>
                        <span className="job-mode">{activeJob.mode}</span>
                        <h1>{jobStateLabel(activeJob.state)}</h1>
                      </div>
                      <div className="job-card-actions">
                        <span className={`job-state job-state-${activeJob.state}`}>{activeJob.state.replaceAll("_", " ")}</span>
                        {activeJob.state === "queued" && (
                          <button type="button" className="secondary-action" disabled={busy} onClick={() => { void resumeActiveDispatch(); }}>Resume dispatch</button>
                        )}
                        {jobCanCancel(activeJob.state) && (
                          <button type="button" className="secondary-action" disabled={busy} onClick={() => { void cancelActiveJob(); }}>Cancel job</button>
                        )}
                      </div>
                    </header>
                    <p className="job-summary">{activeJob.summary || "Lil'Tweak.AI is processing this job."}</p>
                    <dl className="job-metadata">
                      <div><dt>Revision</dt><dd>{activeJob.revision}</dd></div>
                      <div><dt>Sources</dt><dd>{activeJob.sources.length}</dd></div>
                      {activeJob.gitSource && <div><dt>Git commit</dt><dd><code>{activeJob.gitSource.commit.slice(0, 12)}</code></dd></div>}
                      <div><dt>Evidence</dt><dd>{activeJob.evidence.length}</dd></div>
                      <div><dt>Proposal</dt><dd>{activeJob.proposalDigest ? activeJob.proposalDigest.slice(0, 12) : "Pending"}</dd></div>
                    </dl>
                    <ol className="job-timeline" aria-label="Engineering job timeline">
                      {activeJob.events.length ? activeJob.events.map((item) => (
                        <li key={item.id}><span>{item.type.replaceAll("_", " ")}</span><p>{item.summary}</p></li>
                      )) : <li><span>accepted</span><p>Tueiq Core accepted this job.</p></li>}
                    </ol>
                    {activeJob.evidence.length > 0 && (
                      <div className="job-evidence" aria-label="Engineering evidence">
                        {activeJob.evidence.map((item) => (
                          <a key={item.id} target="_blank" rel="noreferrer" href={`/api/engineering/evidence/${encodeURIComponent(item.id)}?preview=1`}>
                            <span>{item.category}</span><strong>{item.filename}</strong><small>{formatFileSize(item.sizeBytes)}</small>
                          </a>
                        ))}
                      </div>
                    )}
                    {jobNeedsApproval(activeJob.state) && (
                      <div className="approval-gate" role="group" aria-label="Proposal decision">
                        <strong>External actions require your approval.</strong>
                        <p>Approval is bound to this exact proposal digest and revision. A changed proposal requires a new decision.</p>
                        {activeJob.approvalProposal && (
                          <dl className="approval-proposal">
                            <div><dt>Action</dt><dd>{activeJob.approvalProposal.action}</dd></div>
                            <div><dt>Target</dt><dd>{activeJob.approvalProposal.target}</dd></div>
                            <div><dt>Policy</dt><dd>{activeJob.approvalProposal.policyVersion}</dd></div>
                            <div><dt>Source</dt><dd><code>{activeJob.approvalProposal.sourceDigest.slice(0, 16)}</code></dd></div>
                            <div><dt>Proposal</dt><dd><code>{activeJob.approvalProposal.proposalDigest.slice(0, 16)}</code></dd></div>
                            <div><dt>Expires</dt><dd>{new Date(activeJob.approvalProposal.expiresAt).toLocaleString()}</dd></div>
                            <div className="approval-resources"><dt>Resources</dt><dd>{Object.entries(activeJob.approvalProposal.resourceProfile).map(([key, value]) => `${key}=${String(value)}`).join(" · ")}</dd></div>
                          </dl>
                        )}
                        {approvalExpired && <p role="status">This proposal expired. Reject or cancel it, then request a new proposal.</p>}
                        {!rejectOpen ? (
                          <div>
                            <button type="button" className="primary-action" disabled={busy || approvalExpired} onClick={() => { void decideActiveJob("approve"); }}>Approve for one-time patch export</button>
                            <button type="button" className="secondary-action" disabled={busy} onClick={() => setRejectOpen(true)}>Reject</button>
                          </div>
                        ) : (
                          <div className="rejection-form">
                            <label><span>Reason for rejection</span><textarea value={rejectionReason} maxLength={2000} onChange={(event) => setRejectionReason(event.target.value)} required /></label>
                            <div>
                              <button type="button" className="danger-action" disabled={busy || !rejectionReason.trim()} onClick={() => { void decideActiveJob("reject"); }}>Confirm rejection</button>
                              <button type="button" className="secondary-action" onClick={() => { setRejectOpen(false); setRejectionReason(""); }}>Cancel</button>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </article>
                ) : (
                  <div className="engineering-empty">
                    <h1>No engineering jobs yet</h1>
                    <p>Choose a mode, describe the outcome, and optionally attach source. Lil&apos;Tweak.AI works inside a disposable sandbox and returns a patch, tests, and evidence.</p>
                    <strong>External actions require your approval.</strong>
                  </div>
                )}
              </div>
              <form className="task-composer" onSubmit={submitEngineeringTask}>
                <div className="engineer-modes" role="group" aria-label="Engineering modes">
                  {engineerModes.map((mode) => (
                    <button
                      type="button"
                      key={mode.id}
                      aria-pressed={engineerMode === mode.id}
                      onClick={() => {
                        setEngineerMode(mode.id);
                        if (mode.id === "chat") {
                          setStagedFiles([]);
                          setGitRepositoryUrl("");
                          setGitCommit("");
                        }
                      }}
                    >
                      {mode.label}
                    </button>
                  ))}
                </div>
                {engineerMode !== "chat" && <div className="git-source-fields" aria-label="Immutable Git source">
                  <label><span>Git repository (optional)</span><input type="url" inputMode="url" placeholder="https://github.com/owner/repository.git" value={gitRepositoryUrl} maxLength={2048} disabled={stagedFiles.length > 0} onChange={(event) => setGitRepositoryUrl(event.target.value)} /></label>
                  <label><span>Exact commit</span><input type="text" spellCheck={false} placeholder="40- or 64-character commit" value={gitCommit} maxLength={64} disabled={stagedFiles.length > 0} onChange={(event) => setGitCommit(event.target.value)} /></label>
                </div>}
                {stagedFiles.length > 0 && (
                  <div className="staged-files" aria-label="Private source files selected">
                    {stagedFiles.map((file) => (
                      <span className="staged-file" key={file.id}>
                        <span><strong>{file.name}</strong><small>{file.type} · {formatFileSize(file.size)}</small></span>
                        <button type="button" aria-label={`Remove ${file.name}`} onClick={() => removeStagedFile(file.id)}>×</button>
                      </span>
                    ))}
                  </div>
                )}
                <label className="sr-only" htmlFor="next-task">Next task</label>
                <div className="composer-shell">
                  <textarea
                    ref={taskInputRef}
                    id="next-task"
                    rows={1}
                    value={taskDraft}
                    placeholder={engineerMode === "chat" ? "Message Lil'Tweak.AI" : "What needs doing?"}
                    maxLength={engineerMode === "chat" ? WORKBENCH_MAX_CONVERSATION_CHARACTERS : MAX_ENGINEERING_PROMPT_CHARACTERS}
                    aria-describedby="task-connection-status"
                    onChange={(event) => setTaskDraft(event.target.value)}
                    onInput={(event) => {
                      const input = event.currentTarget;
                      input.style.height = "auto";
                      input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
                      input.style.overflowY = input.scrollHeight > 160 ? "auto" : "hidden";
                    }}
                  />
                  <div className="composer-toolbar">
                    <div className="composer-tools" ref={composerMenuRef}>
                    <button
                      ref={composerPlusRef}
                      type="button"
                      className="composer-icon-button"
                      aria-label="Add to task"
                      aria-expanded={composerMenuOpen}
                      aria-controls="composer-tools-panel"
                      onClick={toggleComposerMenu}
                    >
                      <Plus className="composer-icon" aria-hidden="true" focusable="false" strokeWidth={1.8} />
                    </button>
                    <button ref={composerPaperclipRef} type="button" className="composer-icon-button" aria-label="Add files or photos" disabled={engineerMode === "chat"} onClick={openComposerFiles}>
                      <Paperclip className="composer-icon composer-paperclip" aria-hidden="true" focusable="false" strokeWidth={1.8} />
                    </button>
                    <button
                      ref={composerCameraRef}
                      type="button"
                      className="composer-icon-button"
                      aria-label="Use camera for document photos, pictures, or video clips"
                      title="Camera"
                      disabled={engineerMode === "chat"}
                      onClick={openComposerCamera}
                    >
                      <Camera className="composer-icon" aria-hidden="true" focusable="false" strokeWidth={1.8} />
                    </button>
                    <button
                      type="button"
                      className="composer-icon-button unavailable"
                      aria-label="Voice input unavailable in the code lane"
                      aria-disabled="true"
                      onClick={() => setComposerStatus("Voice input is not part of the Code Engineer lane yet.")}
                    >
                      <Mic className="composer-icon" aria-hidden="true" focusable="false" strokeWidth={1.8} />
                    </button>
                    <input
                      ref={composerFileInputRef}
                      className="composer-file-input"
                      type="file"
                      multiple
                      disabled={engineerMode === "chat"}
                      tabIndex={-1}
                      aria-hidden="true"
                      onChange={(event) => {
                        stageComposerFiles(event.currentTarget.files);
                        event.currentTarget.value = "";
                        window.requestAnimationFrame(() => composerPaperclipRef.current?.focus());
                      }}
                    />
                    <input
                      ref={composerCameraInputRef}
                      className="composer-file-input"
                      type="file"
                      accept="image/*,video/*"
                      capture="environment"
                      disabled={engineerMode === "chat"}
                      tabIndex={-1}
                      aria-hidden="true"
                      onChange={(event) => {
                        stageComposerFiles(event.currentTarget.files, "camera");
                        event.currentTarget.value = "";
                        window.requestAnimationFrame(() => composerCameraRef.current?.focus());
                      }}
                    />

                    <div
                      id="composer-tools-panel"
                      className="composer-menu"
                      role="group"
                      aria-label="Tools and settings"
                      hidden={!composerMenuOpen}
                    >
                      <button ref={composerMenuFirstRef} type="button" className="composer-menu-action" disabled={engineerMode === "chat"} onClick={openComposerFiles}>
                        <span>Files &amp; photos</span><small>Private source</small>
                      </button>
                      <div className="composer-menu-row" aria-disabled="true"><span>Connectors</span><small>Approval gated</small></div>
                      <div className="composer-menu-row" aria-disabled="true"><span>Plugins</span><small>Unavailable</small></div>
                      <div className="composer-menu-row" aria-disabled="true"><span>Skills</span><small>Unavailable</small></div>
                      <div className="composer-menu-row" aria-disabled="true"><span>Model</span><small>OpenAI</small></div>
                      <div className="composer-menu-row" aria-disabled="true"><span>Reasoning</span><small>Adaptive</small></div>
                    </div>
                    </div>
                    <span className="composer-status" role="status" aria-live="polite">
                      {uploadProgress > 0 && uploadProgress < 100 ? `${uploadProgress}% · ` : ""}{composerStatus}
                    </span>
                    <button type="submit" className="engineer-send" aria-label={engineerMode === "chat" ? "Send chat message" : "Send engineering task"} disabled={busy || !taskDraft.trim()}>
                      <ArrowUp aria-hidden="true" focusable="false" strokeWidth={2} />
                    </button>
                  </div>
                </div>
                <span id="task-connection-status" className="sr-only">{engineerMode === "chat" ? "Model calls are temporarily disabled." : "Secure code gateway. Source is uploaded only when the task is submitted."}</span>
              </form>
            </div>
          </section>
        )}

        {view === "projects" && (
          <section id="panel-projects" className="projects-view" role="tabpanel" aria-labelledby="tab-projects">
            <div className="section-bar">
              <h1>Projects</h1>
              <div className="section-actions">
                <label className="file-action">Import<input type="file" accept="application/json" onChange={(event) => { void importFile(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
                <button type="button" className="primary-action" onClick={() => setShowCreate((current) => !current)}>New</button>
              </div>
            </div>

            {showCreate && (
              <form className="create-bar" onSubmit={createProject}>
                <label><span>Project</span><input value={newName} maxLength={256} onChange={(event) => setNewName(event.target.value)} required /></label>
                <label className="grow"><span>Mission</span><input value={newDescription} maxLength={16000} onChange={(event) => setNewDescription(event.target.value)} /></label>
                <button className="primary-action" disabled={busy}>Create</button>
              </form>
            )}

            <div className="project-editor">
              {selected ? (
                <ProjectEditor
                  key={selected.id}
                  project={selected}
                  busy={busy}
                  onSave={saveProject}
                  onAttach={attachFile}
                  onExport={exportSelected}
                />
              ) : (
                <div className="empty-workspace"><h2>No projects</h2></div>
              )}
            </div>
          </section>
        )}

        {view === "engineering" && (
          <section id="panel-engineering" className="quiet-view engineering-dashboard" role="tabpanel" aria-labelledby="tab-engineering">
            <div className="section-bar">
              <div><h1>Engineering</h1><p>Private sandbox jobs and approval state</p></div>
              <div className="section-actions">
                <button type="button" className="secondary-action" onClick={() => { void refreshConnectionStatus(); }}>Refresh</button>
                <button type="button" className="primary-action" onClick={() => activateView("tweak")}>New task</button>
              </div>
            </div>
            <ConnectionStatusPanel status={connectionStatus} error={connectionStatusError} />
            <CapabilityGapPanel />
            {engineeringJobs.length > 0 ? (
              <div className="engineering-job-list" aria-label="Engineering job history">
                {engineeringJobs.map((job) => (
                  <button
                    type="button"
                    key={job.id}
                    className={activeJob?.id === job.id ? "selected" : ""}
                    aria-pressed={activeJob?.id === job.id}
                    onClick={() => { void selectEngineeringJob(job.id); }}
                  >
                    <span>
                      <strong>{job.mode} · {jobStateLabel(job.state)}</strong>
                      <small>{job.promptPreview}</small>
                    </span>
                    <time dateTime={job.updatedAt}>{new Date(job.updatedAt).toLocaleString()}</time>
                  </button>
                ))}
              </div>
            ) : (
              <div className="engineering-empty compact">
                <h2>No engineering history</h2>
                <p>Completed, active, rejected, and cancelled jobs will appear here.</p>
              </div>
            )}
            {activeJob && (
              <article className="engineering-detail" aria-live="polite">
                <div className="engineering-detail-head">
                  <h2>{jobStateLabel(activeJob.state)}</h2>
                  <strong>{activeJob.mode} · revision {activeJob.revision}</strong>
                </div>
                <p>{activeJob.summary || activeJob.promptPreview}</p>
                <dl>
                  <div><dt>State</dt><dd>{activeJob.state.replaceAll("_", " ")}</dd></div>
                  <div><dt>Sources</dt><dd>{activeJob.sources.length}</dd></div>
                  <div><dt>Evidence</dt><dd>{activeJob.evidence.length}</dd></div>
                  <div><dt>Proposal</dt><dd>{activeJob.proposalDigest?.slice(0, 12) ?? "Pending"}</dd></div>
                </dl>
                <ol className="job-timeline" aria-label="Selected engineering job timeline">
                  {activeJob.events.map((item) => (
                    <li key={item.id}><span>{item.type.replaceAll("_", " ")}</span><p>{item.summary}</p></li>
                  ))}
                </ol>
                {jobNeedsApproval(activeJob.state) && (
                  <p className="engineering-boundary">This exact proposal is waiting for your decision in Chat. Nothing external is applied without it.</p>
                )}
              </article>
            )}
          </section>
        )}

        {view === "evidence" && (
          <section id="panel-evidence" className="quiet-view" role="tabpanel" aria-labelledby="tab-evidence">
            <div className="section-bar">
              <div><h1>Evidence</h1><p>Downloadable artifacts produced by real jobs</p></div>
              {activeJob && <button type="button" className="secondary-action" onClick={() => activateView("engineering")}>Job details</button>}
            </div>
            {activeJob?.evidence.length ? (
              <div className="evidence-list">
                {activeJob.evidence.map((item) => (
                  <details key={item.id}>
                    <summary><span>{item.filename}</span><strong>{item.category}</strong></summary>
                    <dl>
                      <div><dt>SHA-256</dt><dd><code>{item.sha256}</code></dd></div>
                      <div><dt>Type</dt><dd>{item.mediaType}</dd></div>
                      <div><dt>Size</dt><dd>{formatFileSize(item.sizeBytes)}</dd></div>
                      <div><dt>Created</dt><dd>{new Date(item.createdAt).toLocaleString()}</dd></div>
                    </dl>
                    <a className="secondary-action" target="_blank" rel="noreferrer" href={`/api/engineering/evidence/${encodeURIComponent(item.id)}?preview=1`}>{item.category === "patch" ? "Preview patch" : "Review evidence"}</a>
                    {item.category !== "patch" && (
                      <a className="secondary-action" href={`/api/engineering/evidence/${encodeURIComponent(item.id)}`}>Download evidence</a>
                    )}
                    {item.category === "patch" && activeJob.state === "applying" && !activeJob.approvalConsumed && (
                      <button type="button" className="primary-action" disabled={busy} onClick={() => { void downloadPatchOnce(item); }}>Download patch once</button>
                    )}
                    {item.category === "patch" && activeJob.state === "awaiting_approval" && <p>Approve this exact proposal to prepare its one-time patch export.</p>}
                    {item.category === "patch" && activeJob.approvalConsumed && <p>This patch export has been consumed.</p>}
                  </details>
                ))}
              </div>
            ) : (
              <div className="engineering-empty compact">
                <h2>No evidence yet</h2>
                <p>Select a job after its sandbox run. Lil&apos;Tweak.AI records only artifacts actually produced by that job.</p>
              </div>
            )}
          </section>
        )}
      </main>

      {busy && <span className="sr-only" role="status">Working</span>}
    </div>
  );
}

function CapabilityGapPanel() {
  return (
    <article className="capability-gap-panel">
      <div className="capability-gap-head">
        <div>
          <strong>What would make the biggest difference?</strong>
          <p>Lil&apos;Tweak already has chat, direct runner jobs, evidence, and approvals. These are the upgrades that would change how strong it feels.</p>
        </div>
        <span>Priority stack</span>
      </div>
      <div className="capability-gap-list">
        {capabilityGaps.map((item) => (
          <div key={item.name}>
            <span>{item.status}</span>
            <strong>{item.name}</strong>
            <p>{item.detail}</p>
          </div>
        ))}
      </div>
    </article>
  );
}

function bridgeOriginLabel(status: EngineeringConnectionStatus) {
  if (status.bridge.origin === "sites_private_tunnel") return "Sites private tunnel";
  if (status.bridge.origin === "core_origin") return "Core origin";
  return "Missing origin";
}

function bridgeNote(status: EngineeringConnectionStatus | null, error: string) {
  if (error) return `Status endpoint unavailable: ${error}`;
  if (!status) return "Checking the direct Tueiq Core runner settings.";
  if (status.runner.connection === "ready") return "Tueiq Core ready through a signed owner-scoped readiness proof.";
  if (status.runner.connection === "unreachable") return "Core settings are present, but the signed readiness proof did not pass.";
  if (status.runner.connection === "configured_pending_probe") return "Core settings are present and waiting on a signed readiness probe.";
  return `Waiting for ${status.bridge.missing.join(", ") || "runtime bridge configuration"}.`;
}

function ConnectionStatusPanel({
  status,
  error,
}: {
  status: EngineeringConnectionStatus | null;
  error: string;
}) {
  const state = status?.runner.connection ?? "pending_configuration";
  const label = !status
    ? "Checking Tueiq Core"
    : state === "ready"
      ? "Tueiq Core ready"
      : "Direct Tueiq Core runner";
  return (
    <article className="connection-panel" aria-live="polite">
      <div className="connection-panel-head">
        <div>
          <strong>Tueiq Core runner</strong>
          <p>{bridgeNote(status, error)}</p>
        </div>
        <span className="connection-pill" data-connection-state={state}>{label}</span>
      </div>
      {status ? (
        <div className="status-list connection-list">
          <div>
            <span>Runner owner</span>
            <strong>{status.runner.owner} · no intermediary</strong>
          </div>
          <div>
            <span>Runner identity</span>
            <strong>{status.runner.provider} · {status.runner.dropletId} · {status.runner.host}</strong>
          </div>
          <div>
            <span>Runner path</span>
            <strong>Tueiq Core → local digest-pinned Podman sandbox</strong>
          </div>
          <div>
            <span>Core bridge</span>
            <strong>{bridgeOriginLabel(status)} · {status.bridge.signing} signing</strong>
          </div>
          <div>
            <span>Control plane storage</span>
            <strong>D1 {status.controlPlane.d1} · R2 {status.controlPlane.r2}</strong>
          </div>
        </div>
      ) : (
        <p className="connection-note">{error || "Loading connection status..."}</p>
      )}
    </article>
  );
}

function ProjectEditor({
  project,
  busy,
  onSave,
  onAttach,
  onExport,
}: {
  project: ProjectDocument;
  busy: boolean;
  onSave: (
    event: FormEvent<HTMLFormElement>,
    values: { requirements: string; milestones: string; board: string; notes: string },
    editedProject?: ProjectDocument,
  ) => Promise<void>;
  onAttach: (file: File | undefined) => Promise<void>;
  onExport: () => Promise<void>;
}) {
  const [requirements, setRequirements] = useState(
    project.requirements.map((item) => `${item.status} | ${item.text}`).join("\n"),
  );
  const [milestones, setMilestones] = useState(
    project.milestones
      .map((item) => `${item.status} | ${item.target_date ?? ""} | ${item.title}`)
      .join("\n"),
  );
  const [board, setBoard] = useState(
    project.board
      .map((item) => `${item.column} | ${item.title} | ${item.detail}`)
      .join("\n"),
  );
  const [notes, setNotes] = useState(
    project.notes.map((item) => item.text).join("\n"),
  );
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description);
  const [status, setStatus] = useState(project.status);

  function submit(event: FormEvent<HTMLFormElement>) {
    const editedProject = { ...project, name, description, status };
    void onSave(event, { requirements, milestones, board, notes }, editedProject);
  }

  return (
    <form className="project-form" onSubmit={submit}>
      <div className="editor-head">
        <h2>{name}</h2>
        <div><button type="button" className="secondary-action" onClick={() => void onExport()}>Export</button><button className="primary-action" disabled={busy}>Save</button></div>
      </div>
      <div className="editor-fields">
        <label className="wide"><span>Project</span><input maxLength={256} required value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label><span>Status</span><select value={status} onChange={(event) => setStatus(event.target.value as ProjectStatus)}>{projectStatuses.map((item) => <option key={item}>{item}</option>)}</select></label>
        <label className="wide"><span>Mission</span><textarea rows={3} maxLength={16000} value={description} onChange={(event) => setDescription(event.target.value)} /></label>
        <label className="wide"><span>Requirements</span><textarea rows={5} value={requirements} onChange={(event) => setRequirements(event.target.value)} placeholder="planned | requirement" /></label>
        <label className="wide"><span>Milestones</span><textarea rows={4} value={milestones} onChange={(event) => setMilestones(event.target.value)} placeholder="active | 2026-08-12 | milestone" /></label>
        <label className="wide"><span>Tasks</span><textarea rows={6} value={board} onChange={(event) => setBoard(event.target.value)} placeholder="ready | title | detail" /></label>
        <label className="wide"><span>Notes</span><textarea rows={4} value={notes} onChange={(event) => setNotes(event.target.value)} /></label>
      </div>
      <div className="attachment-section">
        <h3>Files</h3>
        <label className="file-action">Attach<input type="file" onChange={(event) => { void onAttach(event.target.files?.[0]); event.currentTarget.value = ""; }} /></label>
      </div>
      {project.attachments.length > 0 && <div className="attachment-list">{project.attachments.map((item) => <article key={item.id}><div><strong>{item.filename}</strong><small>{item.size_bytes.toLocaleString()} bytes</small></div><code>{item.sha256.slice(0, 12)}…</code></article>)}</div>}
    </form>
  );
}
