export interface GitSourceInput {
  repositoryUrl: string;
  commit: string;
}

export interface ProjectContext {
  schemaVersion: "project-context-v1";
  projectId: string;
  name: string;
  description: string;
  status: string;
  requirements: Array<{ text: string; status: string }>;
  milestones: Array<{ title: string; status: string; targetDate: string | null }>;
  board: Array<{ title: string; detail: string; column: string }>;
  notes: Array<{ text: string; createdAt: string }>;
}

const GIT_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
const MAX_CONTEXT_BYTES = 8 * 1024;

function object(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  return value as Record<string, unknown>;
}

export function parseGitSource(value: unknown): GitSourceInput | null {
  if (value === undefined || value === null) return null;
  const input = object(value, "Git source must be an object.");
  if (Object.keys(input).some((key) => !["repositoryUrl", "commit"].includes(key))) {
    throw new Error("Git source contains unsupported fields.");
  }
  const repositoryUrl = typeof input.repositoryUrl === "string" ? input.repositoryUrl.trim() : "";
  const commit = typeof input.commit === "string" ? input.commit.trim().toLowerCase() : "";
  let parsed: URL;
  try {
    parsed = new URL(repositoryUrl);
  } catch {
    throw new Error("Git source repository URL is invalid.");
  }
  if (
    repositoryUrl.length > 2_048 || parsed.protocol !== "https:" ||
    parsed.username || parsed.password || parsed.search || parsed.hash ||
    !parsed.hostname || parsed.pathname === "/" || !GIT_COMMIT.test(commit)
  ) throw new Error("Git source requires an HTTPS repository and exact commit.");
  return { repositoryUrl: parsed.toString(), commit };
}

export function enforceModeSourcePolicy(
  mode: string,
  projectId: string | null,
  sources: unknown[],
  gitSource: GitSourceInput | null,
): void {
  if (mode !== "chat") return;
  if (!projectId) throw new Error("Chat mode requires a selected project.");
  if (sources.length || gitSource) {
    throw new Error("Chat mode does not accept source uploads or Git sources.");
  }
}

function text(value: unknown, max: number): string {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function fits(value: ProjectContext): boolean {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength <= MAX_CONTEXT_BYTES;
}

export function boundedProjectContext(value: unknown): ProjectContext {
  const project = object(value, "Project context is invalid.");
  const context: ProjectContext = {
    schemaVersion: "project-context-v1",
    projectId: text(project.projectId ?? project.id, 128),
    name: text(project.name, 256),
    description: text(project.description, 2_000),
    status: text(project.status, 32),
    requirements: [],
    milestones: [],
    board: [],
    notes: [],
  };
  const candidates: Array<[keyof Pick<ProjectContext, "requirements" | "milestones" | "board" | "notes">, unknown]> = [
    ["requirements", list(project.requirements).slice(0, 100).map((item) => {
      const entry = object(item, "Project requirement is invalid.");
      return { text: text(entry.text, 500), status: text(entry.status, 32) };
    })],
    ["milestones", list(project.milestones).slice(0, 50).map((item) => {
      const entry = object(item, "Project milestone is invalid.");
      return { title: text(entry.title, 256), status: text(entry.status, 32), targetDate: text(entry.targetDate ?? entry.target_date, 10) || null };
    })],
    ["board", list(project.board).slice(0, 100).map((item) => {
      const entry = object(item, "Project board item is invalid.");
      return { title: text(entry.title, 256), detail: text(entry.detail, 500), column: text(entry.column, 32) };
    })],
    ["notes", list(project.notes).slice(0, 50).map((item) => {
      const entry = object(item, "Project note is invalid.");
      return { text: text(entry.text, 500), createdAt: text(entry.createdAt ?? entry.created_at, 40) };
    })],
  ];
  for (const [key, values] of candidates) {
    for (const item of values as never[]) {
      (context[key] as unknown[]).push(item);
      if (!fits(context)) {
        (context[key] as unknown[]).pop();
        return context;
      }
    }
  }
  return context;
}
