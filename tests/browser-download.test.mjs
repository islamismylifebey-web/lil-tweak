import assert from "node:assert/strict";
import test from "node:test";

import { startBrowserDownload } from "../lib/browser-download.ts";

function harness({ clickError } = {}) {
  const events = [];
  const deferred = [];
  const link = {
    href: "",
    download: "",
    click() {
      events.push("click");
      if (clickError) throw clickError;
    },
    remove() {
      events.push("remove");
    },
  };
  return {
    events,
    deferred,
    link,
    environment: {
      createObjectURL() {
        events.push("create-url");
        return "blob:download";
      },
      revokeObjectURL(url) {
        events.push(`revoke:${url}`);
      },
      createLink() {
        events.push("create-link");
        return link;
      },
      appendLink(value) {
        assert.equal(value, link);
        events.push("append");
      },
      defer(callback) {
        events.push("defer");
        deferred.push(callback);
      },
    },
  };
}

test("dispatches a connected download before deferring blob URL revocation", () => {
  const state = harness();

  startBrowserDownload(new Blob(["patch"]), "changes.patch", state.environment);

  assert.equal(state.link.href, "blob:download");
  assert.equal(state.link.download, "changes.patch");
  assert.deepEqual(state.events, ["create-url", "create-link", "append", "click", "remove", "defer"]);
  assert.equal(state.deferred.length, 1);
  state.deferred[0]();
  assert.deepEqual(state.events.at(-1), "revoke:blob:download");
});

test("revokes immediately when the browser rejects download dispatch", () => {
  const failure = new Error("click failed");
  const state = harness({ clickError: failure });

  assert.throws(
    () => startBrowserDownload(new Blob(["patch"]), "changes.patch", state.environment),
    failure,
  );
  assert.deepEqual(state.events, [
    "create-url",
    "create-link",
    "append",
    "click",
    "remove",
    "revoke:blob:download",
  ]);
  assert.equal(state.deferred.length, 0);
});
