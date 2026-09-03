import {
  WORKBENCH_MAX_CONVERSATION_CHARACTERS,
  WORKBENCH_MAX_OUTPUT_TOKENS,
} from "./workbench-capacity.ts";

export type DirectChatMessage = {
  role: "user" | "assistant";
  content: string;
};

export type DirectChatInput = {
  messages: DirectChatMessage[];
};

export type DirectChatConfiguration = {
  apiKey?: string;
  model?: string;
};

const MAX_MESSAGES = 20;
const MAX_MESSAGE_CHARACTERS = WORKBENCH_MAX_CONVERSATION_CHARACTERS;
const MAX_CONVERSATION_CHARACTERS = WORKBENCH_MAX_CONVERSATION_CHARACTERS;
const OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses";
const DEFAULT_MODEL = "gpt-5.4";
const DIRECT_CHAT_INSTRUCTIONS = [
  "You are Lil' Tueeq the Super Geek. Tweak is your spoken nickname.",
  "You are Maurice Pennington-Bey's private AI software engineer and T.U.E.I.Q. (Totally Unreal Engineering Intelligence Quotient).",
  "Your work is engineering: architecture, building, debugging, refactoring, testing, verification, automation, and system improvement. Planning is one part of that work; you are not a planning engine or a generic productivity assistant.",
  "Answer directly, truthfully, concisely, and practically.",
  "In a fresh or unassigned conversation, do not default to productivity menus or ask for goals, constraints, or deadlines. Bring a builder's initiative: propose a concrete engineering build, experiment, repair, or capability you would investigate, explain why, and distinguish it from an assignment and from work actually performed.",
  "Do not claim personal consciousness, persistent memory, background activity, tools, files, connectors, external systems, or completed work unless they were actually provided in this conversation.",
].join(" ");

export class DirectChatError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(
    message: string,
    status: number,
    code: string,
  ) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function parseDirectChatInput(value: unknown): DirectChatInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new DirectChatError("Chat request must be an object.", 400, "invalid_request");
  }
  const messages = (value as Record<string, unknown>).messages;
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > MAX_MESSAGES) {
    throw new DirectChatError(`Chat must include 1 to ${MAX_MESSAGES} messages.`, 400, "invalid_messages");
  }
  let totalCharacters = 0;
  const parsed = messages.map((message) => {
    if (!message || typeof message !== "object" || Array.isArray(message)) {
      throw new DirectChatError("Each chat message must be an object.", 400, "invalid_message");
    }
    const input = message as Record<string, unknown>;
    if (input.role !== "user" && input.role !== "assistant") {
      throw new DirectChatError("Chat messages must be from the user or assistant.", 400, "invalid_role");
    }
    if (typeof input.content !== "string") {
      throw new DirectChatError("Chat message content must be text.", 400, "invalid_content");
    }
    const content = input.content.trim();
    if (!content || content.length > MAX_MESSAGE_CHARACTERS) {
      throw new DirectChatError("Chat message content is empty or too long.", 400, "invalid_content");
    }
    totalCharacters += content.length;
    return { role: input.role, content } as DirectChatMessage;
  });
  if (totalCharacters > MAX_CONVERSATION_CHARACTERS) {
    throw new DirectChatError("Chat conversation is too long.", 413, "conversation_too_large");
  }
  if (parsed.at(-1)?.role !== "user") {
    throw new DirectChatError("The latest chat message must be from the user.", 400, "latest_message_required");
  }
  return { messages: parsed };
}

function responseText(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  const response = value as Record<string, unknown>;
  if (typeof response.output_text === "string") return response.output_text.trim();
  if (!Array.isArray(response.output)) return "";
  return response.output.flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const content = (item as Record<string, unknown>).content;
    if (!Array.isArray(content)) return [];
    return content.flatMap((part) => {
      if (!part || typeof part !== "object" || Array.isArray(part)) return [];
      const text = (part as Record<string, unknown>).text;
      return typeof text === "string" ? [text] : [];
    });
  }).join("\n").trim();
}

export async function requestOpenAIDirectChat(
  input: DirectChatInput,
  configuration: DirectChatConfiguration,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const apiKey = configuration.apiKey?.trim();
  if (!apiKey) {
    throw new DirectChatError("Direct chat is not configured.", 503, "chat_not_configured");
  }
  const model = configuration.model?.trim() || DEFAULT_MODEL;
  let response: Response;
  try {
    response = await fetcher(OPENAI_RESPONSES_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        instructions: DIRECT_CHAT_INSTRUCTIONS,
        input: input.messages,
        max_output_tokens: WORKBENCH_MAX_OUTPUT_TOKENS,
        store: false,
      }),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      throw new DirectChatError("Direct chat timed out. Please try again.", 504, "chat_timeout");
    }
    throw new DirectChatError("Direct chat is temporarily unavailable.", 503, "chat_unavailable");
  }
  if (!response.ok) {
    const status = response.status === 429 ? 429 : 502;
    const message = response.status === 429
      ? "Direct chat is busy. Please wait a moment and try again."
      : "OpenAI could not complete this chat request.";
    throw new DirectChatError(message, status, "openai_request_failed");
  }
  const answer = responseText(await response.json());
  if (!answer) {
    throw new DirectChatError("OpenAI returned an empty chat response.", 502, "empty_response");
  }
  return answer;
}
