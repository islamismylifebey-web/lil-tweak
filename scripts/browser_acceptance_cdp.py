from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import websockets


class BrowserAcceptanceError(RuntimeError):
    pass


def _http_json(url: str, *, method: str = "GET") -> dict[str, Any]:
    request = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise BrowserAcceptanceError("CDP endpoint returned an invalid document")
    return value


class CDP:
    def __init__(self, websocket_url: str) -> None:
        self.websocket_url = websocket_url
        self.socket: Any = None
        self.sequence = 0
        self.events: list[dict[str, Any]] = []

    async def __aenter__(self) -> CDP:
        self.socket = await websockets.connect(self.websocket_url, max_size=16_000_000)
        return self

    async def __aexit__(self, *_values: object) -> None:
        await self.socket.close()

    async def command(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.sequence += 1
        request_id = self.sequence
        await self.socket.send(
            json.dumps({"id": request_id, "method": method, "params": params or {}})
        )
        while True:
            message = json.loads(await self.socket.recv())
            if message.get("id") == request_id:
                if "error" in message:
                    raise BrowserAcceptanceError(f"CDP {method} failed: {message['error']}")
                result = message.get("result", {})
                return result if isinstance(result, dict) else {}
            if isinstance(message, dict):
                self.events.append(message)

    async def evaluate(self, expression: str, *, await_promise: bool = False) -> Any:
        result = await self.command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": await_promise,
                "returnByValue": True,
                "userGesture": True,
            },
        )
        remote = result.get("result", {})
        if remote.get("subtype") == "error":
            raise BrowserAcceptanceError(
                str(remote.get("description", "browser expression failed"))
            )
        return remote.get("value")

    async def wait_for(self, expression: str, *, timeout: float = 45) -> Any:
        deadline = asyncio.get_running_loop().time() + timeout
        last: Any = None
        while asyncio.get_running_loop().time() < deadline:
            last = await self.evaluate(expression, await_promise=True)
            if last:
                return last
            await asyncio.sleep(0.2)
        raise BrowserAcceptanceError(f"browser condition timed out: {expression}; last={last!r}")

    async def screenshot(self, path: Path) -> str:
        result = await self.command("Page.captureScreenshot", {"format": "png"})
        data = base64.b64decode(result["data"])
        path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()


def _js_string(value: str) -> str:
    return json.dumps(value)


async def _fill(cdp: CDP, selector: str, value: str) -> None:
    result = await cdp.evaluate(
        "(() => { const node=document.querySelector(" + _js_string(selector) + ");"
        "if(!node) return false; node.value=" + _js_string(value) + ";"
        "node.dispatchEvent(new Event('input',{bubbles:true}));"
        "node.dispatchEvent(new Event('change',{bubbles:true})); return true; })()"
    )
    if result is not True:
        raise BrowserAcceptanceError(f"browser field was not found: {selector}")


async def _submit(cdp: CDP, selector: str) -> None:
    result = await cdp.evaluate(
        "(() => { const node=document.querySelector(" + _js_string(selector) + ");"
        "if(!node) return false; node.requestSubmit(); return true; })()"
    )
    if result is not True:
        raise BrowserAcceptanceError(f"browser form was not found: {selector}")


async def run(arguments: argparse.Namespace) -> int:
    output = arguments.output
    output.mkdir(parents=True, exist_ok=True)
    new_target = (
        "http://127.0.0.1:"
        + str(arguments.cdp_port)
        + "/json/new?"
        + urllib.parse.quote(arguments.url, safe=":/")
    )
    target = _http_json(new_target, method="PUT")
    websocket_url = target.get("webSocketDebuggerUrl")
    if not isinstance(websocket_url, str):
        raise BrowserAcceptanceError("CDP target did not expose a websocket")
    checks: dict[str, object] = {}
    async with CDP(websocket_url) as cdp:
        await cdp.command("Page.enable")
        await cdp.command("Runtime.enable")
        await cdp.command("Network.enable")
        await cdp.command(
            "Emulation.setDeviceMetricsOverride",
            {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False},
        )
        await cdp.command("Page.navigate", {"url": arguments.url})
        await cdp.wait_for("document.readyState === 'complete'")
        checks["page_content"] = await cdp.evaluate("document.body.innerText.trim().length > 100")
        checks["login_visible"] = await cdp.evaluate(
            "!document.querySelector('#login-panel').hidden"
        )
        await _fill(cdp, "#owner-key", arguments.owner_key)
        await _submit(cdp, "#login-form")
        await cdp.wait_for("document.querySelector('#app-shell').hidden === false")
        checks["authentication"] = True
        checks["operational_states"] = await cdp.evaluate(
            "fetch('/v1/workbench/operational-status').then(r=>r.json())", await_promise=True
        )
        checks["desktop_screenshot_sha256"] = await cdp.screenshot(output / "desktop.png")

        await _fill(cdp, "#project-name", "Browser acceptance project")
        await _fill(cdp, "#project-description", "Private localhost zero-token workspace")
        await _submit(cdp, "#project-create-form")
        await cdp.wait_for("document.querySelectorAll('.workspace-project-select').length === 1")
        await cdp.evaluate("document.querySelector('.workspace-project-select').click()")
        await cdp.wait_for("document.querySelector('#project-editor-form').hidden === false")
        await _fill(cdp, "#editor-requirements", "active | Private localhost acceptance")
        await _fill(cdp, "#editor-milestones", "active | 2026-08-03 | Operational checkpoint")
        await _fill(cdp, "#editor-board", "active | Browser qualification | Real CDP")
        await _fill(cdp, "#editor-notes", "Runner and execution remain disconnected.")
        await cdp.evaluate("document.querySelector('#toast').textContent = ''")
        await _submit(cdp, "#project-editor-form")
        toast = await cdp.wait_for("document.querySelector('#toast').textContent", timeout=20)
        if "ZERO TOKENS" not in str(toast):
            raise BrowserAcceptanceError(f"project editor failed: {toast}")
        checks["project_workspace"] = await cdp.evaluate(
            "fetch('/v1/workbench/projects').then(r=>r.json()).then(p=>({count:p.length,"
            "model_call:p[0].model_call,model_tokens:p[0].model_tokens,requirements:p[0].requirements.length,"
            "milestones:p[0].milestones.length,board:p[0].board.length,notes:p[0].notes.length}))",
            await_promise=True,
        )

        if not arguments.skip_planning:
            await cdp.evaluate("document.querySelector('#tab-planning-chat').click()")
            await _fill(cdp, "#planning-title", "Live planning acceptance")
            await _submit(cdp, "#planning-create-form")
            await cdp.wait_for("document.querySelectorAll('.planning-select').length === 1")
            await cdp.evaluate("document.querySelector('.planning-select').click()")
            await _fill(
                cdp,
                "#planning-message",
                "Give one concise local-only activation milestone.",
            )
            await cdp.evaluate("document.querySelector('#toast').textContent = ''")
            await _submit(cdp, "#planning-turn-form")
            planning_result = await cdp.wait_for(
                "(() => { const usage=document.querySelector('#planning-usage').textContent; "
                "const error=document.querySelector('#toast').textContent; "
                "return usage.includes('current_model') ? {ok:true} : "
                "(error ? {ok:false,error} : false); })()",
                timeout=150,
            )
            if not planning_result.get("ok"):
                raise BrowserAcceptanceError(
                    f"Planning Chat failed: {planning_result.get('error')}"
                )
            checks["planning_chat"] = json.loads(
                await cdp.evaluate("document.querySelector('#planning-usage').textContent")
            )
            checks["planning_usage_ledger"] = await cdp.evaluate(
                "fetch('/v1/workbench/planning/conversations/' + "
                "encodeURIComponent(state.planningConversation.id) + '/usage')"
                ".then(r=>r.json()).then(v=>({count:v.length,current_model:v[0].current_model,"
                "total_tokens:v[0].usage.total_tokens,cost_usd:v[0].usage.estimated_cost_usd}))",
                await_promise=True,
            )
        else:
            checks["planning_chat"] = "SKIPPED_DIAGNOSTIC"

        await cdp.evaluate("document.querySelector('#tab-new-task').click()")
        await _fill(cdp, "#task-title", "Review private operational boundary")
        await _fill(
            cdp,
            "#task-direction",
            "Inspect the repository and plan a read-only verification of the private Workbench.",
        )
        await cdp.evaluate("document.querySelector('#toast').textContent = ''")
        await _submit(cdp, "#task-form")
        task_toast = await cdp.wait_for("document.querySelector('#toast').textContent", timeout=90)
        if "imported" not in str(task_toast):
            raise BrowserAcceptanceError(f"engineering task import failed: {task_toast}")
        await cdp.wait_for(
            "document.querySelector('#active-task-json').textContent.includes('RECEIVED')"
        )
        await cdp.wait_for("document.querySelector('#loading-status').hidden === true")
        await cdp.evaluate("document.querySelector('#inspect-button').click()")
        await cdp.wait_for(
            "document.querySelector('#task-state').textContent === 'ANALYZED'", timeout=90
        )
        await cdp.wait_for("document.querySelector('#loading-status').hidden === true")
        analyze_ready = await cdp.evaluate(
            "({disabled:document.querySelector('#analyze-button').disabled,"
            "model_connected:state.health.model_connected,task_state:state.task.state})"
        )
        if analyze_ready.get("disabled"):
            raise BrowserAcceptanceError(
                f"Engineering Analyze control is disabled: {analyze_ready}"
            )
        await cdp.evaluate("document.querySelector('#toast').textContent = ''")
        await cdp.evaluate("document.querySelector('#analyze-button').click()")
        await cdp.wait_for("document.querySelector('#loading-status').hidden === false")
        await cdp.wait_for("document.querySelector('#loading-status').hidden === true", timeout=180)
        analyze_result = await cdp.evaluate(
            "({task_state:document.querySelector('#task-state').textContent,"
            "toast:document.querySelector('#toast').textContent})"
        )
        if analyze_result.get("task_state") != "PLAN_READY":
            raise BrowserAcceptanceError(f"Engineering Analyze failed: {analyze_result}")
        checks["engineering_mode"] = await cdp.evaluate(
            "({state:document.querySelector('#task-state').textContent,"
            "plan:document.querySelector('#plan-json').textContent.includes('plan_digest'),"
            "execute_disabled:document.querySelector('#execute-button').disabled,"
            "runner:state.health.runner_connection})"
        )
        await cdp.evaluate("document.querySelector('#tab-approvals').click()")
        checks["approval_ui"] = await cdp.evaluate(
            "document.querySelector('#approval-json').textContent === 'No current approval.'"
        )
        checks["delivery_ui"] = await cdp.evaluate(
            "Boolean(document.querySelector('#diff-output') && "
            "document.querySelector('#export-patch-button'))"
        )
        checks["rollback_ui"] = await cdp.evaluate(
            "Boolean(document.querySelector('#request-rollback-button') && "
            "document.querySelector('#rollback-button'))"
        )

        cookies = await cdp.command("Network.getCookies", {"urls": [arguments.url]})
        session_cookie = next(
            (
                item
                for item in cookies.get("cookies", [])
                if item.get("name") == "liltweak_owner_session"
            ),
            None,
        )
        if session_cookie is None:
            raise BrowserAcceptanceError("authenticated session cookie was not created")
        await cdp.command(
            "Network.deleteCookies",
            {"name": "liltweak_owner_session", "url": arguments.url},
        )
        await cdp.command("Page.reload")
        await cdp.wait_for(
            "Boolean(document.querySelector('#login-panel') && "
            "!document.querySelector('#login-panel').hidden)"
        )
        checks["session_expiry_behavior"] = True

        await cdp.command(
            "Emulation.setDeviceMetricsOverride",
            {"width": 390, "height": 844, "deviceScaleFactor": 2, "mobile": True},
        )
        await cdp.command("Page.reload")
        await cdp.wait_for("document.readyState === 'complete'")
        checks["mobile_no_horizontal_overflow"] = await cdp.evaluate(
            "document.documentElement.scrollWidth <= window.innerWidth"
        )
        checks["mobile_screenshot_sha256"] = await cdp.screenshot(output / "mobile.png")
        checks["console_errors"] = [
            event
            for event in cdp.events
            if event.get("method") in {"Runtime.exceptionThrown", "Log.entryAdded"}
        ]
        checks["user_agent"] = await cdp.evaluate("navigator.userAgent")
        checks["completed_at"] = datetime.now(UTC).isoformat()
        checks["status"] = (
            "PASSED"
            if all(
                (
                    checks["page_content"],
                    checks["login_visible"],
                    checks["authentication"],
                    checks["approval_ui"],
                    checks["delivery_ui"],
                    checks["rollback_ui"],
                    checks["session_expiry_behavior"],
                    checks["mobile_no_horizontal_overflow"],
                    not checks["console_errors"],
                )
            )
            else "FAILED"
        )
        await cdp.command("Page.close")
    report = json.dumps(checks, indent=2, sort_keys=True)
    (output / "browser-acceptance.json").write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0 if checks["status"] == "PASSED" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Real Chrome CDP acceptance for Lil Tweak.")
    parser.add_argument("--url", default="http://127.0.0.1:8787/workbench")
    parser.add_argument("--cdp-port", type=int, default=9222)
    parser.add_argument("--owner-key", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-planning", action="store_true")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
