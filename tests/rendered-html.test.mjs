import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function render(path = "/", headers = {}, init = {}) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`https://lil-tweak.example${path}`, {
      headers: { accept: "text/html", ...headers },
      ...init,
    }),
    {
      ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
      DB: {
        prepare() {
          throw new Error("Database must not be read while server-rendering the shell.");
        },
      },
      FILES: {},
      LIL_TWEAK_ENVIRONMENT: "test",
    },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

function renderedElement(html, className) {
  const opening = new RegExp(`<div[^>]*class="[^"]*\\b${className}\\b[^"]*"[^>]*>`).exec(html);
  assert.ok(opening, `Expected rendered element with class ${className}`);
  const start = opening.index;
  const tags = /<\/?div\b[^>]*>/g;
  tags.lastIndex = start;
  let depth = 0;
  for (let tag = tags.exec(html); tag; tag = tags.exec(html)) {
    depth += tag[0].startsWith("</") ? -1 : 1;
    if (depth === 0) return html.slice(start, tags.lastIndex);
  }
  assert.fail(`Rendered element with class ${className} was not closed`);
}

test("official branding and two-header authentication stay release-bound", async () => {
  const [layout, auth, page, workbench, vite] = await Promise.all([
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/chatgpt-auth.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/workbench.tsx", import.meta.url), "utf8"),
    readFile(new URL("../vite.config.ts", import.meta.url), "utf8"),
  ]);

  assert.match(layout, /Lil'Tweak\.AI/);
  assert.match(layout, /manifest:\s*["']\/manifest\.webmanifest["']/);
  assert.match(layout, /lil-tueeq-galor-icon\.jpg/);
  assert.match(auth, /if \(!userId \|\| !email\) return null/);
  assert.doesNotMatch(auth, /userId:\s*userId\s*\|\|\s*email/);
  assert.match(page, /<LilTweakWorkbench\s+signedIn=\{Boolean\(user\)\}/);
  assert.match(workbench, /signedIn:\s*boolean/);
  assert.match(vite, /allowedHosts:\s*\[["']terminal\.local["']\]/);
});

test("server-renders a public shell without private workbench controls", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Lil(?:'|&#x27;|&apos;)Tweak\.AI<\/title>/i);
  assert.match(html, /data-surface="lil-tweak-entry"/);
  assert.match(html, /Lil(?:'|&#x27;|&apos;)Tweak\.AI/);
  assert.match(html, />Private</);
  assert.match(html, />Sign in</);
  assert.match(html, /aria-label="Lil Tweak at rest"/);
  assert.match(html, /data-tier="0"/);
  assert.doesNotMatch(html, /aria-label="Chat controls"|Access controls|Data usage/);
  assert.doesNotMatch(html, /Use camera for document photos, pictures, or video clips/);
  assert.doesNotMatch(html, /New Project|Import verified JSON|Save Project/);
  assert.doesNotMatch(html, /Plan with|truth-strip|boundary-orbit|brand-mark/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton/i);
});

test("renders the workbench only for an approved signed-in identity", async () => {
  for (const email of [
    "islamismylifebey@gmail.com",
  ]) {
    const response = await render("/", {
      "oai-authenticated-user-id": `site-scoped-${email}`,
      "oai-authenticated-user-email": email,
    });
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /data-surface="lil-tweak-workbench"/);
    assert.match(html, /aria-label="Open sidebar"/);
    assert.match(html, /aria-expanded="false"/);
    assert.match(html, /aria-controls="workspace-sidebar"/);
    assert.match(html, /data-runner-route="direct-core-to-local-podman"/);
    assert.match(html, /data-live-runner-state="pending_configuration"/);
    assert.match(html, /aria-label="Local preparation load estimated at 0 percent/);
    assert.match(html, /data-tier="0"/);
    assert.match(html, /aria-label="Chat controls"/);
    assert.match(html, /aria-controls="chat-controls-panel"/);
    assert.match(html, /id="chat-controls-panel"[^>]*hidden/);
    assert.match(html, /placeholder="Message Lil&#x27;Tweak\.AI"/);
    assert.match(html, /aria-label="Engineering modes"/);
    assert.match(html, /aria-label="Send chat message"/);
    assert.match(html, /aria-label="Add to task"/);
    assert.match(html, /aria-controls="composer-tools-panel"/);
    assert.match(html, /aria-label="Add files or photos"/);
    assert.match(html, /aria-label="Use camera for document photos, pictures, or video clips"/);
    assert.match(html, /aria-label="Voice input unavailable in the code lane"/);
    assert.match(html, /lucide-paperclip/);
    assert.match(html, /lucide-camera/);
    assert.match(html, /lucide-mic/);
    assert.match(html, /id="composer-tools-panel"[^>]*hidden/);
    for (const label of [
      "Build",
      "Debug",
      "Refactor",
      "Test",
      "Architect",
      "Chat",
      "Files &amp; photos",
      "Connectors",
      "Plugins",
      "Skills",
      "Model",
      "Reasoning",
      "Access controls",
      "Archive chat",
      "Delete chat",
      "Share",
      "Data usage",
    ]) {
      assert.match(html, new RegExp(label));
    }
    assert.match(html, /OpenAI direct chat/);
    assert.match(html, /144k \/ 25,772/);
    assert.match(html, /What can I help you create\?/);
    assert.match(html, /Direct OpenAI chat\. No tools are enabled\./);
    assert.doesNotMatch(html, /Refactor this code|Explain this code|Write tests/);
    assert.doesNotMatch(html, />Disconnected</);
    assert.doesNotMatch(html, />Sign in</);
  }
});

test("keeps task entry and primary controls inside one composer surface", async () => {
  const response = await render("/", {
    "oai-authenticated-user-id": "site-scoped-owner-id",
    "oai-authenticated-user-email": "islamismylifebey@gmail.com",
  });
  assert.equal(response.status, 200);

  const composer = renderedElement(await response.text(), "composer-shell");
  for (const control of [
    /<textarea[^>]*id="next-task"/,
    /aria-label="Add to task"/,
    /aria-label="Add files or photos"/,
    /aria-label="Use camera for document photos, pictures, or video clips"/,
    /aria-label="Voice input unavailable in the code lane"/,
    /aria-label="Send chat message"/,
  ]) {
    assert.match(composer, control);
  }
});

test("requires both trusted identity headers before rendering the workbench", async () => {
  for (const headers of [
    { "oai-authenticated-user-email": "islamismylifebey@gmail.com" },
    { "oai-authenticated-user-id": "site-scoped-owner-id" },
  ]) {
    const response = await render("/", headers);
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /data-surface="lil-tweak-entry"/);
    assert.doesNotMatch(html, /data-surface="lil-tweak-workbench"/);
    assert.doesNotMatch(html, /aria-label="Chat controls"|Access controls|Data usage/);
  }
});

test("shows a safe denial shell to a signed-in but unapproved identity", async () => {
  for (const email of [
    "beythetruth4ever@paradigmshiftingthepodcast.net",
    "not-the-owner@example.com",
  ]) {
    const response = await render("/", {
      "oai-authenticated-user-id": "site-scoped-other-id",
      "oai-authenticated-user-email": email,
    });
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /Not authorized/i);
    assert.match(html, /Switch account/i);
    assert.match(html, /aria-label="Lil Tweak at rest"/);
    assert.doesNotMatch(html, /aria-label="Chat controls"|Access controls|Data usage/);
    assert.doesNotMatch(html, /Use camera for document photos, pictures, or video clips/);
    assert.doesNotMatch(html, /New Project|Import verified JSON|Save Project/);
  }
});

test("owner authorization requires both trusted headers and canonicalizes the approved identity", async () => {
  const [typescript, source] = await Promise.all([
    import("typescript"),
    readFile(new URL("../lib/owner-auth.ts", import.meta.url), "utf8"),
  ]);
  const transpiled = typescript.transpileModule(source, {
    compilerOptions: {
      module: typescript.ModuleKind.ESNext,
      target: typescript.ScriptTarget.ES2022,
    },
  }).outputText;
  const ownerAuth = await import(
    `data:text/javascript;base64,${Buffer.from(transpiled).toString("base64")}`
  );

  for (const email of [
    "islamismylifebey@gmail.com",
    "ISLAMISMYLIFEBEY@GMAIL.COM",
  ]) {
    const request = new Request("https://lil-tweak.example/api/workspace", {
      headers: {
        "oai-authenticated-user-id": "site-scoped-owner-id",
        "oai-authenticated-user-email": email,
      },
    });
    assert.equal(
      ownerAuth.authenticatedOwner(request),
      "beythetruth4ever@paradigmshiftingthepodcast.net",
    );
  }

  for (const headers of [
    {},
    { "oai-authenticated-user-email": "islamismylifebey@gmail.com" },
    { "oai-authenticated-user-id": "site-scoped-owner-id" },
    {
      "oai-authenticated-user-id": "site-scoped-other-id",
      "oai-authenticated-user-email": "not-the-owner@example.com",
    },
  ]) {
    const request = new Request("https://lil-tweak.example/api/workspace", { headers });
    assert.equal(ownerAuth.authenticatedOwner(request), null);
  }

  assert.equal(
    ownerAuth.mutationRequestIsSafe(
      new Request("https://lil-tweak.example/api/workspace", {
        headers: { "sec-fetch-site": "cross-site" },
      }),
    ),
    false,
  );
  assert.equal(
    ownerAuth.mutationRequestIsSafe(
      new Request("https://lil-tweak.example/api/workspace", {
        headers: { origin: "https://lil-tweak.example", "sec-fetch-site": "same-origin" },
      }),
    ),
    true,
  );
  assert.equal(
    ownerAuth.mutationRequestIsSafe(new Request("https://lil-tweak.example/api/workspace")),
    false,
  );
});

test("workspace API is owner-first and non-cacheable", async () => {
  const route = await readFile(
    new URL("../app/api/workspace/route.ts", import.meta.url),
    "utf8",
  );
  const post = route.slice(route.indexOf("export async function POST"));
  assert.match(route, /Cache-Control": "private, no-store"/);
  assert.match(route, /X-Content-Type-Options": "nosniff"/);
  assert.match(route, /readBoundedJson\(request, MAX_REQUEST_BYTES\)/);
  assert.match(post, /if \(!ownerEmail\) return jsonResponse\([^;]+401\)/);
  assert.ok(post.indexOf("if (!ownerEmail)") < post.indexOf("readBoundedJson"));
  assert.ok(post.indexOf("mutationRequestIsSafe") < post.indexOf("readBoundedJson"));
});

test("locks the document to a snow-white viewport and contains scrolling", async () => {
  const [css, layout, workbench, publicShell] = await Promise.all([
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/workbench.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/public-shell.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(css, /html,\s*body\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(css, /\.workbench-shell,\s*\.public-shell\s*\{[^}]*min-height:\s*100dvh[^}]*overflow:\s*visible/s);
  assert.doesNotMatch(css, /\.task-output\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(css, /\.task-box\s*\{[^}]*overflow:\s*visible/s);
  assert.match(css, /\.task-composer textarea\s*\{[^}]*max-height:\s*160px[^}]*resize:\s*none/s);
  assert.match(css, /\.staged-files\s*\{[^}]*overflow-x:\s*auto/s);
  assert.match(css, /\.composer-icon-button\s*\{[^}]*width:\s*44px[^}]*height:\s*44px/s);
  assert.match(css, /\.composer-icon-button\s*\{[^}]*background:\s*transparent[^}]*border:\s*0[^}]*border-radius:\s*0/s);
  assert.match(css, /\.composer-icon-button:hover\s*\{[^}]*background:\s*transparent/s);
  assert.match(css, /\.composer-menu\s*\{[^}]*max-height:[^}]*overflow-y:\s*auto/s);
  assert.match(css, /\.composer-menu\[hidden\]\s*\{[^}]*display:\s*none/s);
  assert.match(css, /\.staged-file button\s*\{[^}]*width:\s*44px[^}]*height:\s*44px/s);
  assert.match(css, /\.task-box\s*\{[^}]*border:\s*0[^}]*box-shadow:\s*none/s);
  assert.match(css, /\.composer-icon\s*\{[^}]*width:\s*15px[^}]*height:\s*15px/s);
  assert.match(css, /\.composer-paperclip\s*\{[^}]*transform:\s*rotate\(-45deg\)/s);
  assert.match(css, /\.lil-tueeq-avatar\s*\{[^}]*url\("\/lil-tueeq-avatar\.png"\)[^}]*animation:\s*tueeq-pulse[^}]*2;/s);
  assert.match(css, /\.lil-tueeq-fraction\s*\{[^}]*transition:/s);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)[\s\S]*animation:\s*none !important[\s\S]*transition:\s*none !important/);
  assert.match(css, /\.chat-controls\s*\{[^}]*max-height:[^}]*overflow-y:\s*auto/s);
  assert.match(css, /@media \(max-width: 720px\)[\s\S]*\.tweak-header\s*\{[^}]*grid-template-columns:\s*auto minmax\(0, 1fr\) auto[^}]*gap:\s*0\.35rem/s);
  assert.match(css, /@media \(max-width: 720px\)[\s\S]*\.lil-tueeq-signal\s*\{[^}]*width:\s*60px[^}]*height:\s*40px/s);
  assert.match(css, /\.editor-fields textarea\s*\{[^}]*overflow-y:\s*auto[^}]*resize:\s*none/s);
  assert.match(css, /\.workspace-sidebar\s*\{[^}]*position:\s*fixed/s);
  assert.match(css, /\.workspace-sidebar\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(css, /\.file-action:focus-within\s*\{[^}]*outline:/s);
  assert.match(layout, /colorScheme:\s*"light"/);
  assert.match(layout, /themeColor:\s*"#146cff"/);
  assert.match(workbench, /aria-expanded=\{sidebarOpen\}/);
  assert.match(workbench, /event\.key !== "Escape"/);
  assert.match(workbench, /measureLocalPreparation/);
  assert.doesNotMatch(workbench, /estimateComplexity|LivingSpark/);
  assert.match(publicShell, /UdjatSignal/);
  assert.doesNotMatch(workbench, /Command Center|truth-strip|brand-mark|orbit-card|FOUNDER-AUTHORIZED/);
  assert.doesNotMatch(publicShell, /boundary-orbit|public-truth|brand-mark|SECURE PUBLIC ENTRY/);
});

test("removes the disposable starter and declares durable bindings", async () => {
  const [hosting, layout, page, packageJson] = await Promise.all([
    readFile(new URL("../.openai/hosting.json", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.deepEqual(JSON.parse(hosting), {
    d1: "DB",
    project_id: "appgprj_6a7c11351b548191a9f9e936ae8ff837",
    r2: "FILES",
  });
  assert.match(layout, /title: "Lil'Tweak\.AI"/);
  assert.match(layout, /manifest:\s*"\/manifest\.webmanifest"/);
  assert.match(layout, /lil-tueeq-galor-icon\.jpg/);
  assert.match(layout, /robots:\s*\{ index: false/);
  assert.match(page, /LilTweakWorkbench/);
  assert.match(page, /PublicShell/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await Promise.all([
    assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url))),
    assert.rejects(access(new URL("../app/_sites-preview/preview.css", import.meta.url))),
  ]);
});

test("ships a real approval-gated engineering workflow without fabricated evidence", async () => {
  const [workbench, dispatchRoute, decisionRoute] = await Promise.all([
    readFile(new URL("../app/workbench.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/engineering/jobs/[id]/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/engineering/jobs/[id]/decision/route.ts", import.meta.url), "utf8"),
  ]);
  assert.match(workbench, /data-runner-route="direct-core-to-local-podman"/);
  assert.match(workbench, /data-live-runner-state=\{runnerState\}/);
  assert.match(workbench, /createEngineeringJob/);
  assert.match(workbench, /uploadSourcesForJob/);
  assert.match(workbench, /dispatchEngineeringJob/);
  assert.match(workbench, /getEngineeringJob/);
  assert.match(workbench, /decideEngineeringJob/);
  assert.match(workbench, /cancelEngineeringJob/);
  assert.match(workbench, /Cancel job/);
  assert.match(workbench, /Resume dispatch/);
  assert.match(workbench, /jobNeedsApproval/);
  assert.match(workbench, /External actions require your approval/);
  assert.doesNotMatch(workbench, /Prior localhost candidate|2026-08-03 handoff|0dc31d8/);
  assert.doesNotMatch(workbench, /GALOR Library not connected|Manifest generation not connected|No execution authority is exposed/);
  assert.doesNotMatch(workbench, /Deploy now|Publish now|Push now/);
  assert.match(decisionRoute, /recordDecisionIntent/);
  assert.match(decisionRoute, /approvalProposal: proposal/);
  assert.match(workbench, /approvalProposal\.resourceProfile/);
  const dispatchPost = dispatchRoute.slice(dispatchRoute.indexOf("export async function POST"));
  assert.match(dispatchPost, /if \(existingRemoteJobId\)/);
  assert.ok(
    dispatchPost.indexOf("reserveDispatch") < dispatchPost.indexOf("createCoreJob"),
    "dispatch must be durably reserved before the external core call",
  );
  assert.ok(
    dispatchPost.indexOf("getRemoteJobId") < dispatchPost.indexOf("createCoreJob"),
    "dispatch retries must reconcile a persisted remote ID before creating a core job",
  );
  assert.ok(
    decisionRoute.indexOf("await jobStore.recordDecisionIntent") <
      decisionRoute.indexOf("core = await decideCoreJob"),
  );
});

test("keeps chat controls truthful, reversible, and owner-only", async () => {
  const workbench = await readFile(new URL("../app/workbench.tsx", import.meta.url), "utf8");
  const controls = workbench.slice(
    workbench.indexOf('className="header-identity"'),
    workbench.indexOf("<UdjatSignal usage={preparation}"),
  );

  assert.match(workbench, /document\.addEventListener\("pointerdown", closeChatMenu\)/);
  assert.match(workbench, /chatMenuToggleRef\.current\?\.focus\(\)/);
  assert.match(workbench, /aria-haspopup="dialog"/);
  assert.match(workbench, /role="dialog"/);
  assert.match(workbench, /onBlur=\{\(event\) =>/);
  assert.match(workbench, /event\.currentTarget\.contains\(nextFocus\)/);
  assert.match(workbench, /aria-label="Chat or work"/);
  assert.match(controls, /disabled><span>Archive chat/);
  assert.match(controls, /disabled><span>Delete chat/);
  assert.match(controls, /disabled><span>Share/);
  assert.match(controls, /No saved chat/);
  assert.match(controls, /Owner only\. Private Sites access and dispatch-owned identity are enforced before every server authorization check\./);
  assert.match(controls, /Direct chat capacity is/);
  assert.match(controls, /<span>Code<\/span><small>Tueiq Core runner/);
  for (const id of ["chat-access-detail", "chat-files-detail", "chat-usage-detail"]) {
    assert.match(controls, new RegExp(`aria-controls="${id}"`));
    assert.match(controls, new RegExp(`id="${id}"`));
  }
  assert.doesNotMatch(controls, /workspaceRequest|fetch\(|method:\s*"POST"/);
});

test("measures only real local preparation pressure", async () => {
  const [typescript, source] = await Promise.all([
    import("typescript"),
    readFile(new URL("../lib/local-preparation.ts", import.meta.url), "utf8"),
  ]);
  const transpiled = typescript.transpileModule(source, {
    compilerOptions: {
      module: typescript.ModuleKind.ESNext,
      target: typescript.ScriptTarget.ES2022,
    },
  }).outputText;
  const meter = await import(
    `data:text/javascript;base64,${Buffer.from(transpiled).toString("base64")}`
  );

  assert.deepEqual(meter.measureLocalPreparation("", []), {
    ratio: 0,
    percent: 0,
    pressure: "steady",
    draftCharacters: 0,
    draftWords: 0,
    stagedItems: 0,
    fileBytes: 0,
    cameraBytes: 0,
    selectedBytes: 0,
  });
  assert.equal(meter.measureLocalPreparation("build", []).ratio, 1 / 64);
  assert.equal(meter.measureLocalPreparation("x".repeat(10_000), []).ratio, 1);
  assert.equal(meter.measureLocalPreparation("x".repeat(10_000), []).pressure, "high");
  assert.equal(meter.measureLocalPreparation(Array(70).fill("word").join(" "), []).pressure, "elevated");
  assert.equal(meter.measureLocalPreparation(Array(140).fill("word").join(" "), []).pressure, "high");
  assert.equal(
    meter.measureLocalPreparation("", Array(5).fill({ size: 1, source: "file" })).pressure,
    "limit",
  );
  assert.equal(
    meter.measureLocalPreparation("", [{ size: 150_000_000, source: "camera" }]).pressure,
    "limit",
  );
  assert.doesNotMatch(source, /token|context window|model capacity|runner capacity/i);
});

test("ships the transparent Lil Tueeq avatar extracted from the lighter GALOR artwork", async () => {
  const png = await readFile(new URL("../public/lil-tueeq-avatar.png", import.meta.url));
  assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  assert.equal(png[25], 6);
  assert.ok(png.length > 100_000);
});

test("uses Lil Tueeq visuals with one stable owner composer and viewport scrolling", async () => {
  const [css, signal, workbench, publicShell] = await Promise.all([
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../app/udjat-signal.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/workbench.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/public-shell.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(signal, /className="lil-tueeq-avatar"/);
  assert.match(css, /url\("\/lil-tueeq-avatar\.png"\)/);
  assert.doesNotMatch(`${signal}\n${workbench}\n${publicShell}\n${css}`, /udjat-gold\.png/i);
  assert.match(css, /--navy:\s*#0b1f3a/i);
  assert.match(css, /--blue:\s*#146cff/i);
  assert.match(css, /--cyan:\s*#00b8d9/i);
  assert.match(css, /html,\s*body\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(css, /\.workbench-shell,\s*\.public-shell\s*\{[^}]*min-height:\s*100dvh[^}]*overflow:\s*visible/s);
  assert.doesNotMatch(css, /\.task-output\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(css, /\.task-composer textarea\s*\{[^}]*min-height:\s*46px[^}]*resize:\s*none/s);
  assert.match(workbench, /input\.style\.height\s*=\s*"auto"/);
  assert.doesNotMatch(workbench, /input\.style\.height\s*=\s*"0px"/);

  const response = await render("/", {
    "oai-authenticated-user-id": "site-scoped-owner-id",
    "oai-authenticated-user-email": "islamismylifebey@gmail.com",
  });
  const html = await response.text();
  assert.equal((html.match(/class="composer-shell"/g) ?? []).length, 1);
  assert.equal((html.match(/id="next-task"/g) ?? []).length, 1);
  assert.match(html, /class="lil-tueeq-avatar"/);
  assert.match(css, /@media \(max-width: 720px\)[\s\S]*\.lil-tueeq-signal\s*\{[^}]*width:\s*60px[^}]*height:\s*40px/s);
});

test("leaves authentication, API, model, runner, and approval contracts untouched", async () => {
  const [auth, chatRoute, engineeringRoute, decisionRoute] = await Promise.all([
    readFile(new URL("../app/chatgpt-auth.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/chat/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/engineering/jobs/[id]/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/engineering/jobs/[id]/decision/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(auth, /if \(!userId \|\| !email\) return null/);
  assert.match(chatRoute, /ownerFor\(request\)/);
  assert.match(chatRoute, /MODEL_CALLS_DISABLED/);
  assert.doesNotMatch(chatRoute, /OPENAI_API_KEY|responses\.create|fetch\(/);
  assert.match(engineeringRoute, /createCoreJob/);
  assert.match(engineeringRoute, /reserveDispatch/);
  assert.match(decisionRoute, /recordDecisionIntent/);
  assert.match(decisionRoute, /approvalProposal/);
});

test("keeps engineering source intake bounded and accessible", async () => {
  const [workbench, sourceStaging] = await Promise.all([
    readFile(new URL("../app/workbench.tsx", import.meta.url), "utf8"),
    readFile(new URL("../lib/source-staging.ts", import.meta.url), "utf8"),
  ]);
  const staging = workbench.slice(
    workbench.indexOf("function stageComposerFiles"),
    workbench.indexOf("function removeStagedFile"),
  );

  assert.match(workbench, /document\.addEventListener\("pointerdown", closeComposerMenu\)/);
  assert.match(workbench, /key === "Escape"/);
  assert.match(workbench, /composerPlusRef\.current\?\.focus\(\)/);
  assert.match(workbench, /composerFileInputRef\.current\?\.click\(\)/);
  assert.match(workbench, /composerPaperclipRef\.current\?\.focus\(\)/);
  assert.match(workbench, /composerCameraInputRef\.current\?\.click\(\)/);
  assert.match(workbench, /composerCameraRef\.current\?\.focus\(\)/);
  assert.match(workbench, /input\.addEventListener\("cancel", restoreFileTriggerFocus\)/);
  assert.match(workbench, /input\.addEventListener\("cancel", restoreCameraTriggerFocus\)/);
  assert.match(workbench, /accept="image\/\*,video\/\*"/);
  assert.match(workbench, /capture="environment"/);
  assert.match(sourceStaging, /MAX_STAGED_FILES\s*=\s*10/);
  assert.match(sourceStaging, /MAX_STAGED_FILE_BYTES\s*=\s*25_000_000/);
  assert.match(sourceStaging, /MAX_STAGED_TOTAL_BYTES\s*=\s*100_000_000/);
  assert.match(sourceStaging, /MAX_CAMERA_IMAGE_BYTES\s*=\s*25_000_000/);
  assert.match(sourceStaging, /MAX_CAMERA_VIDEO_BYTES\s*=\s*25_000_000/);
  assert.match(sourceStaging, /candidate\.type\.startsWith\("image\/"\)/);
  assert.match(sourceStaging, /candidate\.type\.startsWith\("video\/"\)/);
  assert.match(staging, /selectStagedSourceCandidates\(stagedFiles, chosen, source\)/);
  assert.match(staging, /selection\.accepted\.map/);
  assert.match(workbench, /stageComposerFiles\(event\.currentTarget\.files, "camera"\)/);
  assert.match(workbench, /uploadSourcesForJob/);
  assert.match(workbench, /Send engineering task/);
  assert.match(workbench, /role="group"\s+aria-label="Tools and settings"/);
  assert.doesNotMatch(
    workbench,
    /navigator\.mediaDevices|getUserMedia|enumerateDevices|MediaRecorder|SpeechRecognition|webkitSpeechRecognition|RTCPeerConnection|srcObject|WebSocket|EventSource/,
  );
});
