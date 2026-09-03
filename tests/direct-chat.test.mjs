import assert from "node:assert/strict";
import test from "node:test";

import {
  DirectChatError,
  parseDirectChatInput,
  requestOpenAIDirectChat,
} from "../lib/direct-chat.ts";
import { sendDirectChat } from "../app/direct-chat-client.ts";
import {
  WORKBENCH_MAX_CONVERSATION_CHARACTERS,
  WORKBENCH_MAX_OUTPUT_TOKENS,
} from "../lib/workbench-capacity.ts";

test("direct chat rejects an empty conversation before calling OpenAI", async () => {
  assert.throws(
    () => parseDirectChatInput({ messages: [] }),
    (error) => error instanceof DirectChatError && error.status === 400,
  );
});

test("direct chat sends bounded conversation context without enabling tools or storage", async () => {
  const calls = [];
  const result = await requestOpenAIDirectChat(
    {
      messages: [
        { role: "user", content: "Who are you?" },
        { role: "assistant", content: "I am Lil'Tweak.AI." },
        { role: "user", content: "Help me plan the smallest fix." },
      ],
    },
    { apiKey: "server-only-key", model: "gpt-test" },
    async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ output_text: "Start with one failing test." }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  );

  assert.equal(result, "Start with one failing test.");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://api.openai.com/v1/responses");
  assert.equal(calls[0].init.headers.Authorization, "Bearer server-only-key");
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.model, "gpt-test");
  assert.equal(body.store, false);
  assert.equal(body.max_output_tokens, WORKBENCH_MAX_OUTPUT_TOKENS);
  assert.equal("tools" in body, false);
  assert.match(body.instructions, /Lil' Tueeq the Super Geek/);
  assert.match(body.instructions, /Totally Unreal Engineering Intelligence Quotient/);
  assert.match(body.instructions, /not a planning engine or a generic productivity assistant/);
  assert.match(body.instructions, /do not default to productivity menus or ask for goals, constraints, or deadlines/);
  assert.match(body.instructions, /Do not claim personal consciousness, persistent memory, background activity/);
  assert.deepEqual(body.input, [
    { role: "user", content: "Who are you?" },
    { role: "assistant", content: "I am Lil'Tweak.AI." },
    { role: "user", content: "Help me plan the smallest fix." },
  ]);
});

test("direct chat accepts the expanded workbench conversation envelope", () => {
  assert.doesNotThrow(() => parseDirectChatInput({
    messages: [{ role: "user", content: "x".repeat(WORKBENCH_MAX_CONVERSATION_CHARACTERS) }],
  }));
  assert.throws(
    () => parseDirectChatInput({
      messages: [{ role: "user", content: "x".repeat(WORKBENCH_MAX_CONVERSATION_CHARACTERS + 1) }],
    }),
    (error) => error instanceof DirectChatError && error.status === 400,
  );
});

test("the browser client uses only the same-origin direct-chat route", async () => {
  const calls = [];
  const answer = await sendDirectChat(
    [{ role: "user", content: "Hello" }],
    async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ answer: "Hello back." }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  );

  assert.equal(answer, "Hello back.");
  assert.equal(calls[0].url, "/api/chat");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    messages: [{ role: "user", content: "Hello" }],
  });
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");
});
