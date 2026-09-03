import type { DirectChatMessage } from "@/lib/direct-chat";

export async function sendDirectChat(
  messages: DirectChatMessage[],
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const response = await fetcher("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages }),
  });
  const body = await response.json().catch(() => null) as { answer?: unknown; error?: unknown } | null;
  if (!response.ok) {
    throw new Error(typeof body?.error === "string" ? body.error : "Direct chat is unavailable.");
  }
  if (typeof body?.answer !== "string" || !body.answer.trim()) {
    throw new Error("Direct chat returned an empty response.");
  }
  return body.answer.trim();
}

export type { DirectChatMessage };
