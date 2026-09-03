import { env } from "cloudflare:workers";
import { readBoundedJson } from "@/lib/bounded-request";
import { DirectChatError, parseDirectChatInput, requestOpenAIDirectChat } from "@/lib/direct-chat";
import { json, ownerFor, publicError, requireSameOriginMutation } from "@/lib/engineering-api";
import { WORKBENCH_MAX_CHAT_JSON_BYTES } from "@/lib/workbench-capacity";

interface DirectChatBindings {
  OPENAI_API_KEY?: string;
  LIL_TWEAK_OPENAI_MODEL?: string;
  OPENAI_MODEL?: string;
}

export async function POST(request: Request) {
  try {
    ownerFor(request);
    requireSameOriginMutation(request);
    const input = parseDirectChatInput(await readBoundedJson(request, WORKBENCH_MAX_CHAT_JSON_BYTES));
    const bindings = env as unknown as DirectChatBindings;
    const answer = await requestOpenAIDirectChat(input, {
      apiKey: bindings.OPENAI_API_KEY,
      model: bindings.LIL_TWEAK_OPENAI_MODEL || bindings.OPENAI_MODEL,
    });
    return json({ answer });
  } catch (error) {
    if (error instanceof DirectChatError) {
      return json({ error: error.message, code: error.code }, error.status);
    }
    return publicError(error);
  }
}
