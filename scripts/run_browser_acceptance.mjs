#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("arguments must be --name value pairs");
    }
    values[key.slice(2)] = value;
  }
  for (const required of ["cdp", "base-url", "owner-key-file", "screenshot"]) {
    if (!values[required]) throw new Error(`--${required} is required`);
  }
  return values;
}

class CdpClient {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const waiter = this.pending.get(message.id);
        if (!waiter) return;
        this.pending.delete(message.id);
        if (message.error) waiter.reject(new Error(message.error.message));
        else waiter.resolve(message.result || {});
        return;
      }
      this.events.push(message);
    });
  }

  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("CDP connection timed out")), 10_000);
      socket.addEventListener("open", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("CDP connection failed"));
      });
    });
    return new CdpClient(socket);
  }

  async send(method, params = {}, sessionId = undefined) {
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP ${method} timed out`));
      }, 20_000);
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
    this.socket.send(JSON.stringify(message));
    return response;
  }

  close() {
    this.socket.close();
  }
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitFor(evaluate, expression, timeoutMilliseconds = 10_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await sleep(100);
  }
  throw new Error(`browser condition timed out: ${expression}`);
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const ownerKey = (await readFile(args["owner-key-file"], "utf8")).trim();
  if (!ownerKey) throw new Error("owner key file is empty");
  const baseUrl = new URL(args["base-url"]);
  if (!["127.0.0.1", "localhost"].includes(baseUrl.hostname)) {
    throw new Error("browser acceptance is restricted to a loopback server");
  }

  const version = await (await fetch(new URL("/json/version", args.cdp))).json();
  const client = await CdpClient.connect(version.webSocketDebuggerUrl);
  const results = [];
  const record = (id, status, evidence) => results.push({ id, status, evidence });
  const pass = (id, evidence) => record(id, "PASS", evidence);
  const blocked = (id, evidence) => record(id, "BLOCKED", evidence);
  const failures = [];
  let sessionId;

  const check = async (id, operation) => {
    try {
      pass(id, await operation());
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      record(id, "FAIL", message);
      failures.push(`${id}: ${message}`);
    }
  };

  try {
    const browser = await client.send("Browser.getVersion");
    await check("browser.real_chromium", async () => {
      if (!browser.product?.startsWith("HeadlessChrome/")) throw new Error("not Chromium");
      return browser.product;
    });

    const context = await client.send("Target.createBrowserContext");
    const target = await client.send("Target.createTarget", {
      url: `${baseUrl.origin}/workbench`,
      browserContextId: context.browserContextId,
    });
    const attached = await client.send("Target.attachToTarget", {
      targetId: target.targetId,
      flatten: true,
    });
    sessionId = attached.sessionId;
    for (const domain of ["Page", "Runtime", "Network", "Log", "Accessibility"]) {
      await client.send(`${domain}.enable`, {}, sessionId);
    }
    await client.send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 1000,
      deviceScaleFactor: 1,
      mobile: false,
    }, sessionId);

    const evaluateRaw = async (expression) => client.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
      userGesture: true,
    }, sessionId);
    const evaluate = async (expression) => {
      const response = await evaluateRaw(expression);
      if (response.exceptionDetails) {
        throw new Error(response.exceptionDetails.text || "browser evaluation failed");
      }
      return response.result?.value;
    };
    const clickAndAcceptDialog = async (expression) => {
      const firstEvent = client.events.length;
      const evaluation = client.send("Runtime.evaluate", {
        expression,
        awaitPromise: true,
        returnByValue: true,
        userGesture: true,
      }, sessionId);
      const deadline = Date.now() + 10_000;
      while (
        !client.events.slice(firstEvent).some((event) => event.method === "Page.javascriptDialogOpening")
        && Date.now() < deadline
      ) {
        await sleep(50);
      }
      if (!client.events.slice(firstEvent).some((event) => event.method === "Page.javascriptDialogOpening")) {
        throw new Error("confirmation dialog did not open");
      }
      await client.send("Page.handleJavaScriptDialog", { accept: true }, sessionId);
      const response = await evaluation;
      if (response.exceptionDetails) throw new Error("confirmed browser action failed");
    };

    await waitFor(evaluate, "document.readyState === 'complete'");
    await check("page.meaningful_content", async () => {
      const text = await evaluate("document.body.innerText.trim()");
      if (!text.includes("LIL TWEAK WORKBENCH") || text.length < 100) {
        throw new Error("Workbench content is missing or blank");
      }
      return `${text.length} visible characters`;
    });
    await check("page.no_error_overlay", async () => {
      const overlay = await evaluate(
        "Boolean(document.querySelector('[data-nextjs-dialog],.vite-error-overlay,#webpack-dev-server-client-overlay'))",
      );
      if (overlay) throw new Error("framework error overlay is visible");
      return "no framework error overlay";
    });
    await check("security.response_headers", async () => {
      const headers = await evaluate(`fetch('/workbench').then(response => ({
        cache: response.headers.get('cache-control'),
        csp: response.headers.get('content-security-policy'),
        frame: response.headers.get('x-frame-options'),
        nosniff: response.headers.get('x-content-type-options'),
        referrer: response.headers.get('referrer-policy'),
        cors: response.headers.get('access-control-allow-origin')
      }))`);
      if (
        !headers.cache?.includes("no-store")
        || !headers.csp?.includes("default-src 'self'")
        || headers.frame !== "DENY"
        || headers.nosniff !== "nosniff"
        || headers.referrer !== "no-referrer"
        || headers.cors !== null
      ) {
        throw new Error(`private response headers are incomplete: ${JSON.stringify(headers)}`);
      }
      return "no-store, CSP, frame denial, nosniff, and no-referrer are present";
    });
    await check("page.private_identity_not_public", async () => {
      const text = await evaluate("document.body.innerText");
      if (/maurice-pennington-bey/i.test(text) || /administrative route/i.test(text)) {
        throw new Error("private identity or administrative route is visible before login");
      }
      return "no owner identifier or administrative route in public DOM";
    });
    await check("accessibility.login_labels", async () => {
      const outcome = await evaluate(`(() => {
        const field = document.querySelector('#owner-key');
        const label = document.querySelector('label[for="owner-key"]');
        const button = document.querySelector('#login-form button[type="submit"]');
        return Boolean(field && label?.textContent.trim() && button?.textContent.trim());
      })()`);
      if (!outcome) throw new Error("login controls do not have explicit labels");
      return "password field and submit button have explicit accessible names";
    });
    await check("keyboard.skip_link", async () => {
      await client.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab" }, sessionId);
      await client.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab" }, sessionId);
      const focused = await evaluate(`(() => {
        const node = document.activeElement;
        const style = getComputedStyle(node);
        const box = node.getBoundingClientRect();
        return {
          identity: node?.className || node?.id,
          visible: box.left >= 0 && box.top >= 0 && box.width > 0 && box.height > 0,
          focusIndicator: style.outlineStyle !== 'none' || style.boxShadow !== 'none'
        };
      })()`);
      if (focused.identity !== "skip-link" || !focused.visible || !focused.focusIndicator) {
        throw new Error(`first keyboard focus was not visibly indicated: ${JSON.stringify(focused)}`);
      }
      return "first Tab visibly focuses the skip link";
    });

    await evaluate(`(() => {
      document.querySelector('#owner-key').value = 'wrong-ephemeral-key';
      document.querySelector('#login-form').requestSubmit();
    })()`);
    await waitFor(evaluate, "document.querySelector('#login-error').textContent.length > 0");
    await check("authentication.invalid_key_rejected", async () => {
      const error = await evaluate("document.querySelector('#login-error').textContent");
      const locked = await evaluate("!document.querySelector('#login-panel').hidden");
      if (!/invalid owner credentials/i.test(error) || !locked) {
        throw new Error("invalid key did not stay on the locked screen");
      }
      return "401 surfaced without unlocking";
    });

    await evaluate(`(() => {
      document.querySelector('#owner-key').value = ${JSON.stringify(ownerKey)};
      document.querySelector('#login-form').requestSubmit();
    })()`);
    await waitFor(evaluate, "document.querySelector('#app-shell').hidden === false", 20_000);
    await check("authentication.valid_key_unlocks", async () => {
      const unlocked = await evaluate("document.querySelector('#login-panel').hidden");
      if (!unlocked) throw new Error("valid ephemeral owner key did not unlock");
      return "authenticated private shell rendered";
    });

    const cookiesBeforeLogout = (await client.send("Network.getAllCookies", {}, sessionId)).cookies;
    const ownerCookie = cookiesBeforeLogout.find((cookie) => cookie.name === "liltweak_owner_session");
    await check("session.cookie_security", async () => {
      if (!ownerCookie?.httpOnly || ownerCookie.sameSite !== "Strict") {
        throw new Error("owner session cookie is not HttpOnly and SameSite=Strict");
      }
      return "HttpOnly; SameSite=Strict; path=/";
    });

    const health = await evaluate(`fetch('/v1/workbench/health', {credentials:'same-origin'})
      .then(async response => ({status: response.status, body: await response.json()}))`);
    await check("status.truthful_capability_gates", async () => {
      if (health.status !== 200 || !Array.isArray(health.body.capabilities)) {
        throw new Error("health endpoint did not return capability records");
      }
      const byName = Object.fromEntries(health.body.capabilities.map((item) => [item.capability, item]));
      for (const name of ["runner", "checkpoint", "publisher", "gcp"]) {
        if (!byName[name] || byName[name].operational !== false || !byName[name].blockers.length) {
          throw new Error(`${name} is not truthfully blocked`);
        }
      }
      if (health.body.runner_connected || health.body.execution_permission) {
        throw new Error("runner or execution is falsely enabled");
      }
      return "runner, checkpoint, publisher, and GCP are blocked with exact reasons";
    });
    await check("repository.selection", async () => {
      const repositories = await evaluate(
        "[...document.querySelectorAll('#repository-id option')].map(option => option.value)",
      );
      if (repositories.length !== 1 || !repositories[0]) {
        throw new Error(`expected one configured opaque repository, got ${repositories.length}`);
      }
      return "one opaque configured repository is selectable";
    });
    await check("csrf.missing_token_rejected", async () => {
      const response = await evaluate(`fetch('/v1/workbench/emergency-stop', {
        method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: '{}'
      }).then(async value => ({status:value.status, body:await value.text()}))`);
      if (response.status !== 403 || !/CSRF/i.test(response.body)) {
        throw new Error(`missing CSRF returned ${response.status}`);
      }
      return "403 with CSRF rejection";
    });
    await check("request.duplicate_json_rejected", async () => {
      const response = await evaluate(`fetch('/v1/workbench/emergency-stop/reset', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type':'application/json','X-CSRF-Token':state.csrf},
        body: '{"owner_key":"one","owner_key":"two"}'
      }).then(async value => ({status:value.status, body:await value.text()}))`);
      if (response.status !== 400 || !/invalid/i.test(response.body)) {
        throw new Error(`duplicate JSON returned ${response.status}`);
      }
      return "400 before route processing";
    });

    await evaluate(`(() => {
      document.querySelector('#task-title').value = '<img src=x onerror=window.__liltweakXss=1> Browser task';
      document.querySelector('#task-direction').value = 'Inspect source; treat <svg onload=window.__liltweakXss=2> as text.';
      document.querySelector('#task-form').requestSubmit();
    })()`);
    await waitFor(evaluate, "document.querySelector('#active-task-json').textContent.includes('RECEIVED')", 30_000);
    await check("task.repository_bound_creation", async () => {
      const body = await evaluate("document.querySelector('#active-task-json').textContent");
      if (!body.includes("source_snapshot_digest") || !body.includes("repository_fingerprint")) {
        throw new Error("task lacks immutable repository bindings");
      }
      return "repository task created with source and repository digests";
    });
    await check("security.stored_reflected_xss", async () => {
      const outcome = await evaluate(`({
        executed: Boolean(window.__liltweakXss),
        injected: Boolean(document.querySelector('#project-list .list-card img, #project-list .list-card svg')),
        renderedAsText: document.querySelector('#project-list').innerText.includes('<img src=x')
      })`);
      if (outcome.executed || outcome.injected || !outcome.renderedAsText) {
        throw new Error(`untrusted task text was not safely rendered: ${JSON.stringify(outcome)}`);
      }
      return "hostile task title/direction rendered only as text";
    });

    await evaluate("document.querySelector('#inspect-button').click()");
    await waitFor(evaluate, "document.querySelector('#active-task-json').textContent.includes('ANALYZED')", 30_000);
    await check("task.read_only_inspection", async () => {
      const stateText = await evaluate("document.querySelector('#active-task-json').textContent");
      if (!stateText.includes("ANALYZED")) throw new Error("inspection did not reach ANALYZED");
      return "read-only inspection reached ANALYZED";
    });
    await check("planning.disabled_without_qualification", async () => {
      const disabled = await evaluate("document.querySelector('#analyze-button').disabled");
      const blockers = await evaluate("document.querySelector('#capability-blockers').innerText");
      if (!disabled || !/qualification|connection/i.test(blockers)) {
        throw new Error("planning is not visibly fail-closed");
      }
      return "plan control disabled with visible model qualification blocker";
    });
    blocked("planning.live_plan_and_approval_digest", "no injected complete live qualification receipt");
    blocked("delivery.patch_review_and_rollback", "no qualified runner, publisher, apply, or rollback authority");
    blocked("session.real_time_expiry", "minimum private TTL is 300 seconds; clock control is unit-tested only");

    await evaluate("document.querySelector('#cancel-button').click()");
    await waitFor(evaluate, "document.querySelector('#active-task-json').textContent.includes('CANCELED')");
    await check("task.cancellation", async () => "active task canceled through the browser");

    await clickAndAcceptDialog("document.querySelector('#emergency-button').click()");
    await waitFor(evaluate, "state.health?.emergency_stopped === true");
    await check("control.emergency_stop", async () => "emergency stop visibly engaged");

    await evaluate("document.querySelector('[data-view=\"settings\"]').click()");
    await evaluate(`document.querySelector('#emergency-reset-key').value = ${JSON.stringify(ownerKey)}`);
    await clickAndAcceptDialog("document.querySelector('#emergency-reset-button').click()");
    await waitFor(evaluate, "state.health?.emergency_stopped === false");
    await check("control.emergency_reset", async () => "fresh owner reauthentication reset the stop");

    await client.send("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 844,
      deviceScaleFactor: 2,
      mobile: true,
    }, sessionId);
    await check("responsive.mobile_layout", async () => {
      const metrics = await evaluate(`(() => ({
        viewport: document.documentElement.clientWidth,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        smallTargets: [...document.querySelectorAll('button:not([hidden])')]
          .filter(button => {
            const box = button.getBoundingClientRect();
            return box.width > 0 && box.height > 0 && (box.width < 44 || box.height < 44);
          }).length
      }))()`);
      if (metrics.viewport !== 390 || metrics.overflow > 1 || metrics.smallTargets > 0) {
        throw new Error(`mobile metrics ${JSON.stringify(metrics)}`);
      }
      return "390px viewport has no horizontal overflow and no sub-44px visible buttons";
    });
    await check("accessibility.control_names", async () => {
      const unnamed = await evaluate(`[...document.querySelectorAll('button,input,select,textarea')]
        .filter(node => !node.hidden && !node.disabled)
        .filter(node => {
          const label = node.labels?.[0]?.textContent || node.getAttribute('aria-label') || node.textContent;
          return !label?.trim();
        }).map(node => node.id || node.tagName)`);
      if (unnamed.length) throw new Error(`unnamed controls: ${unnamed.join(', ')}`);
      return "all enabled form controls have accessible names";
    });

    const screenshot = await client.send("Page.captureScreenshot", {
      format: "png",
      fromSurface: true,
      captureBeyondViewport: false,
    }, sessionId);
    const screenshotBytes = Buffer.from(screenshot.data, "base64");
    await writeFile(args.screenshot, screenshotBytes);
    await check("evidence.screenshot", async () => ({
      bytes: screenshotBytes.length,
      sha256: createHash("sha256").update(screenshotBytes).digest("hex"),
    }));

    await evaluate("document.querySelector('#logout-button').click()");
    await waitFor(evaluate, "document.querySelector('#login-panel').hidden === false");
    await check("session.logout", async () => {
      const response = await evaluate(
        "fetch('/v1/workbench/session',{credentials:'same-origin'}).then(value => value.status)",
      );
      if (response !== 401) throw new Error(`post-logout session returned ${response}`);
      return "logout revoked the active browser session";
    });

    if (ownerCookie) {
      await client.send("Network.setCookie", {
        name: ownerCookie.name,
        value: ownerCookie.value,
        url: baseUrl.origin,
        path: ownerCookie.path,
        httpOnly: ownerCookie.httpOnly,
        sameSite: ownerCookie.sameSite,
      }, sessionId);
      await check("session.revoked_cookie_replay", async () => {
        const response = await evaluate(
          "fetch('/v1/workbench/session',{credentials:'same-origin'}).then(value => value.status)",
        );
        if (response !== 401) throw new Error(`replayed cookie returned ${response}`);
        return "replayed signed cookie remained revoked";
      });
    }

    const browserErrors = client.events.filter((event) =>
      event.method === "Runtime.exceptionThrown"
      || (
        event.method === "Log.entryAdded"
        && event.params?.entry?.level === "error"
        && event.params?.entry?.source !== "network"
      )
      || (event.method === "Runtime.consoleAPICalled" && event.params?.type === "error")
    );
    await check("browser.no_console_or_runtime_errors", async () => {
      if (browserErrors.length) {
        const summaries = browserErrors.slice(0, 20).map((event) => ({
          method: event.method,
          source: event.params?.entry?.source,
          text: event.params?.entry?.text || event.params?.exceptionDetails?.text,
          url: event.params?.entry?.url,
        }));
        throw new Error(`${browserErrors.length} browser errors captured: ${JSON.stringify(summaries)}`);
      }
      return "zero console, log, or runtime exceptions";
    });
    await check("browser.expected_negative_http_only", async () => {
      const networkErrors = client.events.filter((event) =>
        event.method === "Log.entryAdded"
        && event.params?.entry?.level === "error"
        && event.params?.entry?.source === "network"
      );
      const allowed = networkErrors.every((event) => {
        const text = event.params.entry.text || "";
        const url = event.params.entry.url || "";
        return (
          (/status of 401/.test(text) && url.endsWith("/v1/workbench/session"))
          || (/status of 403/.test(text) && url.endsWith("/v1/workbench/emergency-stop"))
          || (/status of 400/.test(text) && url.endsWith("/v1/workbench/emergency-stop/reset"))
          || (/status of 404/.test(text) && /\/v1\/workbench\/tasks\/[^/]+\/submission$/.test(url))
        );
      });
      if (!allowed) throw new Error("an unexpected HTTP resource failure was captured");
      return `${networkErrors.length} intentional negative/absent-resource responses classified`;
    });
    await check("security.rate_limit", async () => {
      const statuses = await evaluate(`Promise.all(Array.from({length: 130}, () =>
        fetch('/v1/workbench/session', {credentials:'same-origin'}).then(response => response.status)
      ))`);
      if (!statuses.includes(429) || statuses.some((status) => status >= 500)) {
        throw new Error(`rate-limit statuses ${JSON.stringify(statuses)}`);
      }
      return `${statuses.filter((status) => status === 429).length} requests were rate-limited without 5xx`;
    });
    await check("security.login_lockout", async () => {
      const statuses = await evaluate(`Promise.all(Array.from({length: 130}, (_, index) =>
        fetch('/v1/workbench/session', {
          method: 'POST', credentials:'same-origin',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({owner_key: 'invalid-lockout-' + index})
        }).then(response => response.status)
      ))`);
      if (!statuses.includes(429) || statuses.some((status) => status >= 500)) {
        throw new Error(`login-lockout statuses ${JSON.stringify(statuses)}`);
      }
      return `${statuses.filter((status) => status === 429).length} invalid logins were locked out without 5xx`;
    });

    await client.send("Target.closeTarget", { targetId: target.targetId });
    await client.send("Target.disposeBrowserContext", { browserContextId: context.browserContextId });
  } finally {
    client.close();
  }

  const summary = {
    schema_version: "liltweak-browser-acceptance-v1",
    browser: version.Browser,
    base_origin: baseUrl.origin,
    counts: {
      PASS: results.filter((item) => item.status === "PASS").length,
      BLOCKED: results.filter((item) => item.status === "BLOCKED").length,
      FAIL: results.filter((item) => item.status === "FAIL").length,
    },
    results,
  };
  console.log(JSON.stringify(summary, null, 2));
  if (failures.length) process.exitCode = 1;
}

main().catch((error) => {
  console.error(JSON.stringify({
    schema_version: "liltweak-browser-acceptance-v1",
    fatal: error instanceof Error ? error.message : String(error),
  }));
  process.exitCode = 1;
});
