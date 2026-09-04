"""Conservative route discovery."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class RouteRecord:
    path: str
    method: str
    line: int
    framework: str


PY_ROUTE_DECORATOR_RE = re.compile(r"^(get|post|put|patch|delete|options|head|route)$")
JS_ROUTE_RE = re.compile(
    r"""\b(?:app|router)\.(?P<method>get|post|put|patch|delete|options|head)\(\s*["'](?P<path>[^"']+)["']"""
)
NEXT_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


def python_routes(source: str) -> list[RouteRecord]:
    tree = ast.parse(source)
    routes: list[RouteRecord] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            if call is None:
                continue
            func = call.func
            method = ""
            if isinstance(func, ast.Attribute) and PY_ROUTE_DECORATOR_RE.match(func.attr):
                method = func.attr.upper()
            if not method or not call.args or not isinstance(call.args[0], ast.Constant):
                continue
            value = call.args[0].value
            if isinstance(value, str) and value.startswith("/"):
                routes.append(RouteRecord(value, method, node.lineno, "python-decorator"))
    return sorted(routes, key=lambda item: (item.path, item.method, item.line))


def js_routes(source: str, path: str) -> list[RouteRecord]:
    routes: list[RouteRecord] = []
    for match in JS_ROUTE_RE.finditer(source):
        routes.append(
            RouteRecord(
                match.group("path"),
                match.group("method").upper(),
                source.count("\n", 0, match.start()) + 1,
                "javascript-router",
            )
        )
    pure = PurePosixPath(path)
    if pure.parts[:2] == ("app", "api") and pure.name.startswith("route."):
        route = "/" + "/".join(part for part in pure.parts[1:-1])
        for method in sorted(NEXT_METHODS):
            if re.search(rf"\bexport\s+async\s+function\s+{method}\b|\bexport\s+function\s+{method}\b", source):
                line = next(
                    (
                        index
                        for index, text in enumerate(source.splitlines(), start=1)
                        if re.search(rf"\bfunction\s+{method}\b", text)
                    ),
                    1,
                )
                routes.append(RouteRecord(route, method, line, "next-route-handler"))
    return sorted(routes, key=lambda item: (item.path, item.method, item.line))
